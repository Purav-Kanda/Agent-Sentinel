# mcp_server/server.py
# ─────────────────────────────────────────────────────────────────────────────
# AgentSentinel MCP Server
# ------------------------
# Exposes AgentSentinel's monitoring capabilities as MCP tools so any
# MCP-compatible AI assistant (Claude, Splunk AI Assistant, etc.) can query
# and control agent sessions in natural language.
#
# Tools exposed:
#   get_agent_health       – overall health summary of all active sessions
#   get_session_status     – detailed status for one or all sessions
#   get_recent_anomalies   – latest anomaly alerts with scores
#   resume_session         – resume a PAUSED session after human review
#   abort_session          – force-abort a specific session
#   score_span             – score an arbitrary telemetry span on-demand
#   list_active_sessions   – list all sessions currently being tracked
#
# Run (stdio transport, for use with Claude Desktop / Splunk AI Assistant):
#   python -m mcp_server.server
#
# Run (SSE transport, for HTTP-based MCP clients):
#   python -m mcp_server.server --transport sse --port 8765
#
# Wire up to Claude Desktop by adding to claude_desktop_config.json:
#   {
#     "mcpServers": {
#       "agent-sentinel": {
#         "command": "python",
#         "args": ["-m", "mcp_server.server"],
#         "cwd": "/path/to/AgentSentinel"
#       }
#     }
#   }
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any, Optional

# Allow running from repo root without pip install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from agent_sentinel.detection.scorer import AnomalyScorer
from agent_sentinel.telemetry.span import Span, SpanType
from agent_sentinel.remediation.handler import RemediationHandler
from agent_sentinel.telemetry.splunk_writer import StdoutWriter, SplunkWriter
from config import cfg

# ─── In-process session registry ─────────────────────────────────────────────
# When running without a live Splunk instance the server maintains an
# in-process registry of sessions.  With Splunk configured it reads from
# the agent_telemetry index via the Splunk SDK.
#
# Structure:
#   _sessions[session_id] = {
#       "agent_id":        str,
#       "status":          "active" | "paused" | "aborted" | "completed",
#       "started_at":      float (epoch),
#       "last_seen_at":    float (epoch),
#       "span_count":      int,
#       "scores":          dict,   # latest AnomalyScorer output
#       "alerts":          list[dict],
#   }

_sessions: dict[str, dict[str, Any]] = {}
_anomaly_log: list[dict[str, Any]] = []
_scorer = AnomalyScorer()

# ─── Writer (stdout in demo mode, HEC in production) ─────────────────────────
_hec_url   = os.getenv("SPLUNK_HEC_URL", "")
_hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
if _hec_url and _hec_token:
    _writer = SplunkWriter(hec_url=_hec_url, hec_token=_hec_token, verify_ssl=False)
else:
    _writer = StdoutWriter()

_handler = RemediationHandler(
    writer=_writer,
    warn_threshold=cfg.WARN_THRESHOLD,
    pause_threshold=cfg.PAUSE_THRESHOLD,
    abort_threshold=cfg.ABORT_THRESHOLD,
)


# ─── MCP Server setup ─────────────────────────────────────────────────────────

app = Server("agent-sentinel")


# ─── Tool: list_active_sessions ──────────────────────────────────────────────

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_active_sessions",
            description=(
                "List all agent sessions currently tracked by AgentSentinel. "
                "Returns session IDs, agent names, status (active/paused/aborted), "
                "and the latest composite anomaly score for each."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status_filter": {
                        "type": "string",
                        "description": "Filter by status: 'active', 'paused', 'aborted', 'completed', or 'all' (default).",
                        "default": "all",
                    }
                },
            },
        ),
        types.Tool(
            name="get_agent_health",
            description=(
                "Overall health dashboard: total sessions, how many are anomalous, "
                "average composite score, and a risk level (OK / WARNING / CRITICAL). "
                "Use this for a quick pulse check on all running agents."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_session_status",
            description=(
                "Detailed status report for a specific agent session: all anomaly "
                "scores (hallucination, tool_loop, reasoning_drift, cascade_risk, composite), "
                "alert history, span count, and current status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session_id to inspect (from list_active_sessions).",
                    }
                },
                "required": ["session_id"],
            },
        ),
        types.Tool(
            name="get_recent_anomalies",
            description=(
                "Fetch the most recent anomaly alerts across all sessions. "
                "Each entry shows: session_id, agent_id, timestamp, action taken "
                "(WARN / PAUSE / ABORT), and the full score breakdown."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return (default 20).",
                        "default": 20,
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Only return alerts with composite score >= this value (0.0–1.0).",
                        "default": 0.0,
                    },
                },
            },
        ),
        types.Tool(
            name="resume_session",
            description=(
                "Resume an agent session that was PAUSED by AgentSentinel. "
                "Call this after a human analyst reviews the anomaly and decides the "
                "agent should continue. Logs the operator name in the audit trail."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session_id to resume.",
                    },
                    "operator": {
                        "type": "string",
                        "description": "Name/ID of the human analyst authorising the resume.",
                        "default": "human-analyst",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Optional review notes to attach to the audit trail.",
                        "default": "",
                    },
                },
                "required": ["session_id"],
            },
        ),
        types.Tool(
            name="abort_session",
            description=(
                "Force-abort a specific agent session. Use when a human analyst "
                "confirms the agent is behaving incorrectly and should be stopped immediately. "
                "This emits an ABORT span to Splunk and marks the session as aborted."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session_id to abort.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for the manual abort (logged to audit trail).",
                        "default": "manual abort by operator",
                    },
                },
                "required": ["session_id"],
            },
        ),
        types.Tool(
            name="score_span",
            description=(
                "Score an arbitrary telemetry span on-demand. Useful for testing "
                "detection logic or scoring a span that was not automatically captured. "
                "Returns the full score breakdown."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "span_type": {
                        "type": "string",
                        "enum": ["llm_call", "tool_call", "reasoning_step"],
                        "description": "Type of span to score.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to associate the span with.",
                        "default": "mcp-test-session",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID to associate the span with.",
                        "default": "test-agent",
                    },
                    "metadata": {
                        "type": "object",
                        "description": (
                            "Span metadata. For llm_call: {prompt, response, tokens_in, tokens_out, latency_ms}. "
                            "For tool_call: {tool_name, inputs, status, retry_count}. "
                            "For reasoning_step: {reasoning_text, step_index}."
                        ),
                        "default": {},
                    },
                },
                "required": ["span_type"],
            },
        ),
    ]


# ─── Tool call handler ────────────────────────────────────────────────────────

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any]
) -> list[types.TextContent]:

    try:
        result = _dispatch(name, arguments)
    except Exception as exc:
        result = {"error": str(exc)}

    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


def _dispatch(name: str, args: dict[str, Any]) -> Any:
    if name == "list_active_sessions":
        return _list_active_sessions(args.get("status_filter", "all"))
    elif name == "get_agent_health":
        return _get_agent_health()
    elif name == "get_session_status":
        return _get_session_status(args["session_id"])
    elif name == "get_recent_anomalies":
        return _get_recent_anomalies(
            limit=args.get("limit", 20),
            min_score=args.get("min_score", 0.0),
        )
    elif name == "resume_session":
        return _resume_session(
            session_id=args["session_id"],
            operator=args.get("operator", "human-analyst"),
            notes=args.get("notes", ""),
        )
    elif name == "abort_session":
        return _abort_session(
            session_id=args["session_id"],
            reason=args.get("reason", "manual abort by operator"),
        )
    elif name == "score_span":
        return _score_span(args)
    else:
        return {"error": f"Unknown tool: {name}"}


# ─── Tool implementations ─────────────────────────────────────────────────────

def _list_active_sessions(status_filter: str = "all") -> dict:
    sessions = list(_sessions.values())
    if status_filter != "all":
        sessions = [s for s in sessions if s.get("status") == status_filter]

    return {
        "count": len(sessions),
        "sessions": [
            {
                "session_id":    s["session_id"],
                "agent_id":      s["agent_id"],
                "status":        s["status"],
                "composite":     s.get("scores", {}).get("composite", 0.0),
                "span_count":    s["span_count"],
                "started_ago_s": round(time.time() - s["started_at"]),
            }
            for s in sorted(sessions, key=lambda x: x.get("scores", {}).get("composite", 0), reverse=True)
        ],
    }


def _get_agent_health() -> dict:
    if not _sessions:
        return {
            "status": "NO_DATA",
            "message": "No sessions tracked yet. Start an agent with AgentTracer to populate.",
            "total_sessions": 0,
            "anomalous_sessions": 0,
            "avg_composite": 0.0,
            "risk_level": "OK",
        }

    composites = [s.get("scores", {}).get("composite", 0.0) for s in _sessions.values()]
    avg = sum(composites) / len(composites)
    anomalous = sum(1 for c in composites if c > cfg.WARN_THRESHOLD)
    critical = sum(1 for c in composites if c > cfg.ABORT_THRESHOLD)

    if critical > 0:
        risk_level = "CRITICAL"
    elif anomalous > 0:
        risk_level = "WARNING"
    else:
        risk_level = "OK"

    return {
        "risk_level":          risk_level,
        "total_sessions":      len(_sessions),
        "active_sessions":     sum(1 for s in _sessions.values() if s["status"] == "active"),
        "paused_sessions":     sum(1 for s in _sessions.values() if s["status"] == "paused"),
        "aborted_sessions":    sum(1 for s in _sessions.values() if s["status"] == "aborted"),
        "anomalous_sessions":  anomalous,
        "critical_sessions":   critical,
        "avg_composite_score": round(avg, 3),
        "total_alerts":        len(_anomaly_log),
    }


def _get_session_status(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        # Try Splunk if configured
        splunk_result = _query_splunk_for_session(session_id)
        if splunk_result:
            return splunk_result
        return {"error": f"Session '{session_id}' not found. Check session ID or start an agent."}

    return {
        "session_id":    session["session_id"],
        "agent_id":      session["agent_id"],
        "status":        session["status"],
        "started_at":    session["started_at"],
        "last_seen_at":  session["last_seen_at"],
        "span_count":    session["span_count"],
        "scores": {
            "hallucination":   session.get("scores", {}).get("hallucination", 0.0),
            "tool_loop":       session.get("scores", {}).get("tool_loop", 0.0),
            "reasoning_drift": session.get("scores", {}).get("reasoning_drift", 0.0),
            "cascade_risk":    session.get("scores", {}).get("cascade_risk", 0.0),
            "composite":       session.get("scores", {}).get("composite", 0.0),
        },
        "alerts":    session.get("alerts", []),
        "alert_count": len(session.get("alerts", [])),
    }


def _get_recent_anomalies(limit: int = 20, min_score: float = 0.0) -> dict:
    filtered = [
        a for a in _anomaly_log
        if a.get("scores", {}).get("composite", 0) >= min_score
    ]
    filtered.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return {
        "count":    len(filtered[:limit]),
        "anomalies": filtered[:limit],
    }


def _resume_session(session_id: str, operator: str, notes: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}
    if session["status"] != "paused":
        return {"error": f"Session is '{session['status']}', not 'paused'. Cannot resume."}

    _handler.resume(session_id)
    session["status"] = "active"

    audit_entry = {
        "action":     "RESUMED",
        "operator":   operator,
        "notes":      notes,
        "timestamp":  time.time(),
    }
    session.setdefault("alerts", []).append(audit_entry)

    return {
        "status":     "ok",
        "session_id": session_id,
        "action":     "RESUMED",
        "operator":   operator,
        "message":    f"Session {session_id} resumed. Agent will continue its workflow.",
    }


def _abort_session(session_id: str, reason: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}
    if session["status"] in ("aborted", "completed"):
        return {"error": f"Session is already '{session['status']}'."}

    session["status"] = "aborted"
    audit_entry = {
        "action":    "MANUAL_ABORT",
        "reason":    reason,
        "timestamp": time.time(),
    }
    session.setdefault("alerts", []).append(audit_entry)

    # Emit an abort span to Splunk for the audit trail.
    abort_span = Span(
        span_id=str(uuid.uuid4()),
        session_id=session_id,
        agent_id=session["agent_id"],
        span_type=SpanType.REMEDIATION,
        metadata={
            "action":  "ABORT",
            "trigger": "manual_operator",
            "reason":  reason,
        },
    )
    try:
        _writer.write(abort_span)
    except Exception:
        pass

    return {
        "status":     "ok",
        "session_id": session_id,
        "action":     "ABORTED",
        "reason":     reason,
        "message":    f"Session {session_id} force-aborted. Audit span emitted to Splunk.",
    }


def _score_span(args: dict) -> dict:
    span_type_map = {
        "llm_call":       SpanType.LLM_CALL,
        "tool_call":      SpanType.TOOL_CALL,
        "reasoning_step": SpanType.REASONING_STEP,
    }
    span_type_str = args.get("span_type", "llm_call")
    span_type = span_type_map.get(span_type_str, SpanType.LLM_CALL)

    span = Span(
        span_id=str(uuid.uuid4()),
        session_id=args.get("session_id", "mcp-test-session"),
        agent_id=args.get("agent_id", "test-agent"),
        span_type=span_type,
        metadata=args.get("metadata", {}),
    )

    scores = _scorer.score(span)

    interpretation = []
    if scores["hallucination"] > 0.5:
        interpretation.append("HIGH hallucination risk — LLM may be asserting ungrounded facts.")
    if scores["tool_loop"] > 0.5:
        interpretation.append("HIGH tool loop risk — agent may be stuck retrying a failing tool.")
    if scores["reasoning_drift"] > 0.5:
        interpretation.append("HIGH reasoning drift — agent goal may have shifted (prompt injection risk).")
    if scores["cascade_risk"] > 0.5:
        interpretation.append("HIGH cascade risk — prior errors may be corrupting downstream steps.")
    if not interpretation:
        interpretation.append("No significant anomalies detected.")

    return {
        "scores":          scores,
        "interpretation":  interpretation,
        "action_needed":   scores["composite"] > cfg.WARN_THRESHOLD,
        "recommended_action": (
            "ABORT"  if scores["composite"] > cfg.ABORT_THRESHOLD else
            "PAUSE"  if scores["composite"] > cfg.PAUSE_THRESHOLD else
            "WARN"   if scores["composite"] > cfg.WARN_THRESHOLD  else
            "NONE"
        ),
    }


def _query_splunk_for_session(session_id: str) -> Optional[dict]:
    """
    Fallback: query Splunk directly for session status when the session
    is not in the local in-process registry (e.g. watcher restarted).
    """
    if not (os.getenv("SPLUNK_HOST") and os.getenv("SPLUNK_USERNAME")):
        return None
    try:
        import splunklib.client as client
        import splunklib.results as results_module

        service = client.connect(
            host=cfg.SPLUNK_HOST,
            port=cfg.SPLUNK_PORT,
            username=cfg.SPLUNK_USERNAME,
            password=cfg.SPLUNK_PASSWORD,
        )
        spl = (
            f'search index=agent_telemetry sourcetype=agent_sentinel '
            f'session_id="{session_id}" '
            f'| stats count AS span_count, max(composite) AS peak_composite, '
            f'  values(span_type) AS span_types BY session_id agent_id'
        )
        job = service.jobs.create(spl, exec_mode="blocking", count=1)
        rows = []
        for r in results_module.JSONResultsReader(job.results(output_mode="json", count=1)):
            if isinstance(r, dict):
                rows.append(r)
        if rows:
            r = rows[0]
            return {
                "session_id":        session_id,
                "agent_id":          r.get("agent_id", "unknown"),
                "status":            "completed",
                "source":            "splunk",
                "span_count":        int(r.get("span_count", 0)),
                "peak_composite":    float(r.get("peak_composite", 0)),
                "span_types_seen":   r.get("span_types", []),
            }
    except Exception:
        pass
    return None


# ─── Public helper: register a session from an external tracer ───────────────
# AgentTracer instances call this so the MCP server's in-process registry
# stays current without waiting for a Splunk poll cycle.

def register_session(session_id: str, agent_id: str) -> None:
    """Called by AgentTracer.start_session() to register with the MCP server."""
    _sessions[session_id] = {
        "session_id":  session_id,
        "agent_id":    agent_id,
        "status":      "active",
        "started_at":  time.time(),
        "last_seen_at": time.time(),
        "span_count":  0,
        "scores":      {},
        "alerts":      [],
    }


def update_session_scores(session_id: str, scores: dict, action: Optional[str] = None) -> None:
    """Called by RemediationHandler when new scores are computed."""
    if session_id not in _sessions:
        return
    session = _sessions[session_id]
    session["scores"]      = scores
    session["last_seen_at"] = time.time()
    session["span_count"]  += 1

    if action and action != "NONE":
        alert = {
            "action":    action,
            "scores":    scores,
            "timestamp": time.time(),
        }
        session.setdefault("alerts", []).append(alert)
        _anomaly_log.append({
            "session_id": session_id,
            "agent_id":   session["agent_id"],
            "action":     action,
            "scores":     scores,
            "timestamp":  time.time(),
        })

        if action == "PAUSED":
            session["status"] = "paused"
        elif action == "ABORTED":
            session["status"] = "aborted"


# ─── Entry point ──────────────────────────────────────────────────────────────

async def _run_stdio():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main():
    parser = argparse.ArgumentParser(description="AgentSentinel MCP Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"], default="stdio",
        help="Transport: 'stdio' for Claude Desktop/CLI (default), 'sse' for HTTP."
    )
    parser.add_argument("--port", type=int, default=8765, help="Port for SSE transport.")
    args = parser.parse_args()

    if args.transport == "sse":
        try:
            from mcp.server.sse import SseServerTransport
            from starlette.applications import Starlette
            from starlette.routing import Route
            import uvicorn

            sse = SseServerTransport("/messages/")

            async def handle_sse(request):
                async with sse.connect_sse(
                    request.scope, request.receive, request._send
                ) as streams:
                    await app.run(streams[0], streams[1], app.create_initialization_options())

            starlette_app = Starlette(routes=[Route("/sse", endpoint=handle_sse)])
            print(f"[AgentSentinel MCP] SSE server starting on port {args.port}")
            uvicorn.run(starlette_app, host="0.0.0.0", port=args.port)
        except ImportError:
            print("SSE transport requires: pip install uvicorn starlette")
            sys.exit(1)
    else:
        import asyncio
        print("[AgentSentinel MCP] Starting stdio server...", file=sys.stderr)
        asyncio.run(_run_stdio())


if __name__ == "__main__":
    main()
