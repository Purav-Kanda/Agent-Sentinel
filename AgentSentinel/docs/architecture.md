# AgentSentinel – Architecture Deep Dive

## Data Flow

```
Agent code
  │
  │  @tracer.trace_llm_call / @tracer.trace_tool_call
  ▼
AgentTracer._emit(span)
  │
  │  queue.put_nowait(span)   ← non-blocking, O(1)
  ▼
in-memory queue (thread-safe, max 10,000 items)
  │
  │  background flusher wakes every 2s or when 50 items accumulate
  ▼
SplunkWriter._post_to_hec(batch)
  │
  │  HTTP POST with Authorization: Splunk <token>
  │  payload = newline-delimited JSON event objects
  ▼
Splunk HEC endpoint :8088
  │
  │  Splunk parses JSON, extracts fields (KV_MODE=json in props.conf)
  ▼
index=agent_telemetry  sourcetype=agent_sentinel
  │
  │  MetaAgentWatcher polls every 10s via SPL
  ▼
AnomalyScorer.score(span) → scores dict
  │
  │  if composite > threshold
  ▼
RemediationHandler.evaluate_and_act()
  │
  ├── WARN:  emit ANOMALY_ALERT span → back to Splunk
  ├── PAUSE: set session flag + optional webhook
  └── ABORT: raise AgentAbortError
```

## Thread Model

- **Main thread**: runs the agent's workflow
- **Flusher thread**: daemon, drains HEC queue every 2s
- **Watcher thread**: daemon, polls Splunk every 10s

All communication between threads uses thread-safe primitives:
- `queue.Queue` for span buffering
- `threading.Event` for stop signals
- `threading.local` for per-thread retry counters

## Why HEC (not SDK search)?

Writing spans: HEC (port 8088) is used for *ingest* because:
- Single HTTP POST can carry 50 events (batching)
- No authentication overhead per event
- Designed for high-throughput streaming

Reading spans: SDK search API (port 8089) is used for *retrieval* because:
- SPL is the right abstraction for aggregation queries
- The meta-watcher needs computed stats (avg, dc, streamstats) not raw events

## Span Schema

Every event stored in Splunk has this structure:

```json
{
  "time":       1715350800.123,
  "sourcetype": "agent_sentinel",
  "index":      "agent_telemetry",
  "event": {
    "span_id":    "uuid4",
    "session_id": "uuid4",
    "agent_id":   "soc-triage-v1",
    "span_type":  "llm_call",
    "prompt":     "...",
    "response":   "...",
    "latency_ms": 823.4,
    "tokens_in":  220,
    "tokens_out": 180,
    "model":      "claude-sonnet-4-6",
    "status":     "success"
  }
}
```

SPL can access all event fields directly:
```
index=agent_telemetry span_type=llm_call latency_ms>1000
```

## MCP Integration

`MetaAgentWatcher` exposes three MCP-compatible tools:

```python
watcher.get_session_status(session_id=None)  → JSON str
watcher.get_recent_anomalies(limit=20)       → JSON str
watcher.resume_session(session_id, operator) → JSON str
```

When connected via Splunk MCP Server, an operator can ask Claude:
> "Which agent sessions are currently anomalous?"
> "Resume session sess-abc after I reviewed it"

Claude calls these tools and returns a natural-language answer.

## Extending AgentSentinel

### Add a new detector

1. Add a new method `_score_<name>(span, sid) -> float` to `AnomalyScorer`
2. Update the composite score weights in `score()`
3. Add a new `SpanType` value if needed
4. Add a corresponding SPL query to `spl_queries.py`
5. Add a panel to the dashboard XML

### Replace heuristic scorer with AITK model

For production, the `_score_hallucination` heuristic can be replaced with
the Foundation-Sec-1.1-8B-Instruct model via Splunk AI Toolkit:

```python
# In scorer.py, replace _score_hallucination with:
def _score_hallucination_aitk(self, span, sid):
    response = span.metadata.get("response", "")
    # Call AITK model via SPL: | makeresults | eval text=response
    # | sendalert foundation_sec_classify
    ...
```

The time-series anomaly detection (latency drift over time) maps directly
to Splunk's Cisco Deep Time Series Model in AITK.
