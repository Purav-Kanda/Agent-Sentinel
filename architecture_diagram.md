# AgentSentinel – Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        PRIMARY AGENT(S)                         │
│          (SOC Triage / ITOps / Threat Hunting agents)           │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              AgentSentinel Instrumentation              │   │
│   │                                                         │   │
│   │   @tracer.trace_llm_call()    ← wraps every LLM call   │   │
│   │   @tracer.trace_tool_call()   ← wraps every tool call  │   │
│   │   tracer.log_reasoning_step() ← captures reasoning     │   │
│   └───────────────────────┬─────────────────────────────────┘   │
└───────────────────────────│─────────────────────────────────────┘
                            │ Span events (JSON)
                            │ Non-blocking queue → background flusher
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              SPLUNK HTTP EVENT COLLECTOR (HEC)                  │
│                       Port 8088                                 │
│         Batched POST, Authorization: Splunk <token>             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│           SPLUNK INDEX: agent_telemetry                         │
│           sourcetype: agent_sentinel  (JSON, KV_MODE=json)      │
│                                                                 │
│   Span types stored:                                            │
│   • session_start / session_end                                 │
│   • llm_call      (prompt, response, latency_ms, tokens)        │
│   • tool_call     (tool_name, inputs, output, retry_count)      │
│   • reasoning_step (text, step_index, confidence)               │
│   • anomaly_alert  (scores, anomaly_type, recommended_action)   │
│   • remediation    (action_taken, outcome, audit trail)         │
└──────────┬──────────────────────────────────┬───────────────────┘
           │                                  │
           │ Poll via Splunk Python SDK        │ SPL queries from
           │ (port 8089, blocking search)      │ saved searches /
           ▼                                  │ dashboard panels
┌──────────────────────────┐                  ▼
│   META-AGENT WATCHER     │    ┌─────────────────────────────────┐
│   (background thread)    │    │   AGENTSENTINEL DASHBOARD       │
│                          │    │                                 │
│  ┌────────────────────┐  │    │  • Session Health table         │
│  │  AnomalyScorer     │  │    │  • Real-time Anomaly Alert feed │
│  │                    │  │    │  • Tool Loop heatmap            │
│  │  hallucination ────┼──┼───▶│  • Hallucination Risk chart     │
│  │  tool_loop     ────┼──┼───▶│  • Remediation Audit trail      │
│  │  reasoning_drift───┼──┼───▶│  • Token Cost by Agent          │
│  │  cascade_risk  ────┼──┼───▶│  • Error Rate timeline          │
│  │                    │  │    └─────────────────────────────────┘
│  │  composite score   │  │
│  └────────┬───────────┘  │
│           │              │
│           ▼              │
│  ┌────────────────────┐  │
│  │ RemediationHandler │  │
│  │                    │  │
│  │ >0.40 → WARN       │  │  ← emit ANOMALY_ALERT span to Splunk
│  │ >0.65 → PAUSE      │  │  ← set pause flag, call webhook
│  │ >0.90 → ABORT      │  │  ← raise AgentAbortError
│  └────────────────────┘  │
└──────────────────────────┘
           │
           │ MCP Tool Interface
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   SPLUNK MCP SERVER                              │
│                                                                  │
│   Tools exposed to AI assistants (Claude, etc.):                │
│   • get_session_status(session_id)  → JSON health summary        │
│   • get_recent_anomalies(limit)     → JSON alert feed            │
│   • resume_session(session_id)      → human-in-the-loop gate     │
│                                                                  │
│   Enables natural-language ops:                                  │
│   "Which agents are currently anomalous?"                        │
│   "Resume session abc after I reviewed it"                       │
└──────────────────────────────────────────────────────────────────┘
```

---

## How the Application Interacts with Splunk

| Direction | Method | Port | Purpose |
|---|---|---|---|
| Agent → Splunk | HTTP POST to HEC | 8088 | Write telemetry spans in real time |
| MetaWatcher → Splunk | Splunk Python SDK search | 8089 | Read spans via SPL for anomaly detection |
| Dashboard → Splunk | SPL saved searches | 8089 | Power all dashboard panels |
| MCP Server → Splunk | Splunk MCP Server app | 8089 | Natural-language queries from AI assistants |

---

## How AI Models and Agents Are Integrated

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI INTEGRATION LAYERS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1 – Splunk Python SDK (AI Custom App)                    │
│  ├── AgentTracer decorators instrument any LLM/tool function    │
│  └── Works with any LLM: Claude, GPT, Gemini, local models      │
│                                                                 │
│  Layer 2 – Heuristic Anomaly Scorer (local, zero-latency)       │
│  ├── Hallucination: linguistic pattern matching + speed ratio   │
│  ├── Tool Loop: identical-input retry counting per session       │
│  ├── Reasoning Drift: Jaccard similarity between steps          │
│  └── Cascade Risk: error_rate × log(workflow_depth)             │
│                                                                 │
│  Layer 3 – Splunk AI Toolkit (production upgrade path)          │
│  ├── Cisco Deep Time Series Model → latency anomaly detection   │
│  └── Foundation-Sec-1.1-8B → security-specific classification   │
│                                                                 │
│  Layer 4 – Splunk MCP Server                                    │
│  ├── MetaAgentWatcher exposes MCP-compatible tool interface      │
│  └── AI assistants can query/control sessions in natural lang.  │
│                                                                 │
│  Layer 5 – Splunk AI Assistant (SAIA)                           │
│  └── All SPL queries in spl_queries.py generated with SAIA      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Between Services, APIs, and Components

```
[Security Alert Arrives]
        │
        ▼
[SOC Triage Agent starts]
        │
        ├──(1)──▶ AgentTracer.start_session()
        │              └──▶ SESSION_START span → HEC → Splunk
        │
        ├──(2)──▶ @trace_tool_call: Splunk Search
        │              └──▶ TOOL_CALL span → HEC → Splunk
        │
        ├──(3)──▶ tracer.log_reasoning_step()
        │              └──▶ REASONING_STEP span → HEC → Splunk
        │
        ├──(4)──▶ @trace_llm_call: LLM reasoning
        │              └──▶ LLM_CALL span → HEC → Splunk
        │
        │         ┌─ Meanwhile, every 10 seconds ──────────────┐
        │         │  MetaAgentWatcher polls Splunk via SDK      │
        │         │  AnomalyScorer.score(each_span)             │
        │         │  if composite > threshold:                  │
        │         │    → ANOMALY_ALERT span → HEC → Splunk      │
        │         │    → RemediationHandler.evaluate_and_act()  │
        │         │      → WARN / PAUSE / ABORT                 │
        │         └────────────────────────────────────────────┘
        │
        ├──(5)──▶ @trace_tool_call: Threat Intel Lookup
        │              └──▶ TOOL_CALL span → HEC → Splunk
        │
        └──(6)──▶ AgentTracer.end_session()
                       └──▶ SESSION_END span → HEC → Splunk

[All spans visible in AgentSentinel Dashboard in real time]
[Saved searches fire alerts if thresholds breached]
[MCP Server allows AI assistant to query session state]
```

---

## Hackathon Track

**Primary: Security** — AgentSentinel protects SOC triage integrity by detecting when AI agents hallucinate threat intelligence, loop on failing searches, or drift from their original investigation goal.

**Bonus prizes targeted:**
- Best Use of Splunk MCP Server (MetaAgentWatcher MCP tool interface)
- Best Use of Splunk Developer Tools (Python SDK + App Inspect compliant structure)
