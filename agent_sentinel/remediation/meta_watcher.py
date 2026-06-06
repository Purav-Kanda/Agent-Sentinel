# agent_sentinel/remediation/meta_watcher.py
# ─────────────────────────────────────────────────────────────────────────────
# MetaAgentWatcher
# ----------------
# The "agent that watches agents."
#
# Architecture:
#   ┌─────────────────────┐       spans       ┌──────────────────┐
#   │   Primary Agent(s)  │ ───────────────▶  │  Splunk Index    │
#   │  (SOC triage, etc.) │                   │  agent_telemetry │
#   └─────────────────────┘                   └────────┬─────────┘
#                                                      │ poll via SDK
#                                             ┌────────▼─────────┐
#                                             │  MetaAgentWatcher │
#                                             │  - AnomalyScorer  │
#                                             │  - Remediation    │
#                                             └──────────────────┘
#
# The watcher runs as a background thread.  Every POLL_INTERVAL_S seconds
# it queries Splunk for spans produced since its last poll, scores them,
# and fires remediation if thresholds are breached.
#
# MCP Integration:
# The watcher also exposes a simple MCP-compatible tool interface so an
# external AI assistant (e.g. Claude via Splunk MCP Server) can query
# the current state of all active sessions in natural language.
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from agent_sentinel.detection.scorer import AnomalyScorer
from agent_sentinel.detection.spl_queries import get_query
from agent_sentinel.remediation.handler import RemediationHandler, AgentAbortError
from agent_sentinel.telemetry.splunk_writer import SplunkWriter

logger = logging.getLogger(__name__)


class MetaAgentWatcher:
    """
    Background thread that continuously monitors all active agent sessions.

    Parameters
    ----------
    splunk_client    : An initialised splunklib.client.Service object
                       (from the Splunk Python SDK).  Pass None to run in
                       dry-run mode (reads from a file or stdin instead).
    writer           : SplunkWriter used to emit anomaly/remediation spans.
    poll_interval_s  : How often (seconds) to query Splunk for new spans.
    """

    POLL_INTERVAL_S = 10   # check for new spans every 10 seconds

    def __init__(
        self,
        splunk_client,                      # splunklib.client.Service | None
        writer:          SplunkWriter,
        poll_interval_s: int = POLL_INTERVAL_S,
    ):
        self.splunk_client    = splunk_client
        self.writer           = writer
        self.poll_interval_s  = poll_interval_s

        self.scorer  = AnomalyScorer()
        self.handler = RemediationHandler(writer=writer)

        # Track the last event time we processed per session so we don't
        # re-score the same spans on the next poll.
        self._last_event_time: Dict[str, float] = {}

        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._watch_loop,
            name="meta-agent-watcher",
            daemon=True,
        )

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background watcher thread."""
        logger.info("MetaAgentWatcher starting – polling every %ds", self.poll_interval_s)
        self._thread.start()

    def stop(self) -> None:
        """Signal the watcher thread to stop and wait for it to exit."""
        self._stop_event.set()
        self._thread.join(timeout=30)
        logger.info("MetaAgentWatcher stopped")

    # ─── Main loop ───────────────────────────────────────────────────────────

    def _watch_loop(self) -> None:
        """
        Poll Splunk for new telemetry spans, score them, and react.
        Runs until stop() is called.
        """
        while not self._stop_event.is_set():
            try:
                self._poll_and_score()
            except Exception as exc:
                # Never crash the watcher – log and keep going.
                logger.error("Watcher poll error: %s", exc, exc_info=True)

            # Sleep in 1-second increments so stop() responds quickly.
            for _ in range(self.poll_interval_s):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def _poll_and_score(self) -> None:
        """
        One poll cycle:
          1. Fetch recent spans from Splunk.
          2. Score each span.
          3. If composite score breaches threshold, call remediation.
        """
        if self.splunk_client is None:
            # Dry-run mode: nothing to poll.
            return

        # Build a time-bounded SPL query to fetch only new events.
        earliest = "-{}s".format(self.poll_interval_s + 5)  # small overlap
        spl = (
            f"search index=agent_telemetry sourcetype=agent_sentinel "
            f"earliest={earliest} | sort _time | table *"
        )

        try:
            results = self._run_spl(spl)
        except Exception as exc:
            logger.error("SPL poll failed: %s", exc)
            return

        for row in results:
            self._process_row(row)

    def _process_row(self, row: Dict[str, Any]) -> None:
        """Convert a raw Splunk result row back into something scoreable."""
        from agent_sentinel.telemetry.span import Span, SpanType

        span_type_str = row.get("span_type", "")
        try:
            span_type = SpanType(span_type_str)
        except ValueError:
            return  # unknown span type – skip

        span = Span(
            span_id=row.get("span_id", ""),
            session_id=row.get("session_id"),
            agent_id=row.get("agent_id", ""),
            span_type=span_type,
            metadata={k: v for k, v in row.items()
                      if k not in ("span_id", "session_id", "agent_id", "span_type")},
        )

        scores = self.scorer.score(span)

        if scores["composite"] > self.scorer.threshold:
            try:
                self.handler.evaluate_and_act(
                    session_id=span.session_id or "unknown",
                    agent_id=span.agent_id,
                    scores=scores,
                    span=span,
                )
            except AgentAbortError as e:
                logger.critical("ABORT issued: %s", e)

    # ─── MCP Tool Interface ──────────────────────────────────────────────────

    def get_session_status(self, session_id: Optional[str] = None) -> str:
        """
        MCP-compatible tool: returns a JSON summary of active sessions.

        When connected via Splunk MCP Server, an AI assistant can call this
        to answer natural-language questions like:
            "Which agent sessions are currently anomalous?"

        Returns JSON string (so it works as a tool output in any MCP client).
        """
        if self.splunk_client is None:
            return json.dumps({"error": "No Splunk client configured"})

        spl = get_query("SESSION_HEALTH_OVERVIEW")
        try:
            results = self._run_spl(spl)
            if session_id:
                results = [r for r in results if r.get("session_id") == session_id]
            return json.dumps(results, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    def get_recent_anomalies(self, limit: int = 20) -> str:
        """
        MCP-compatible tool: returns the most recent anomaly alerts.
        """
        spl = get_query("ANOMALY_ALERT_FEED") + f"\n| head {limit}"
        try:
            results = self._run_spl(spl)
            return json.dumps(results, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    def resume_session(self, session_id: str, operator: str = "human") -> str:
        """
        MCP-compatible tool: resumes a paused session after human review.
        Call this from the Splunk AI Assistant or any MCP client.
        """
        self.handler.resume(session_id)
        return json.dumps({
            "status":     "resumed",
            "session_id": session_id,
            "operator":   operator,
        })

    # ─── Splunk SDK helper ───────────────────────────────────────────────────

    def _run_spl(self, spl: str) -> List[Dict[str, Any]]:
        """
        Execute a blocking SPL search via the Splunk Python SDK and
        return results as a list of dicts.
        """
        import splunklib.results as results_module

        job = self.splunk_client.jobs.create(
            spl,
            exec_mode="blocking",
            count=500,
        )
        reader = results_module.JSONResultsReader(
            job.results(output_mode="json", count=500)
        )
        rows = []
        for result in reader:
            if isinstance(result, dict):
                rows.append(result)
        return rows
