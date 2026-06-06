# agent_sentinel/detection/spl_queries.py
# ─────────────────────────────────────────────────────────────────────────────
# SPL Query Library
# -----------------
# All Splunk Search Processing Language (SPL) queries used by AgentSentinel.
#
# These queries are executed by the Splunk Python SDK against the
# "agent_telemetry" index populated by SplunkWriter.
#
# They are stored here as Python constants (not inside XML/conf files) so:
#   1. They can be unit-tested against a local Splunk dev instance.
#   2. They are version-controlled alongside the Python code.
#   3. They can be parameterised at runtime (f-strings / .format()).
#
# All queries assume sourcetype=agent_sentinel and index=agent_telemetry.
# ─────────────────────────────────────────────────────────────────────────────


# ─── 1. Tool Loop Detection ───────────────────────────────────────────────────
# Finds sessions where the same tool was called with identical inputs
# more than N times.  High retry counts indicate stuck loops.
TOOL_LOOP_DETECTION = """
index=agent_telemetry sourcetype=agent_sentinel span_type=tool_call
| stats
    count         AS total_calls,
    dc(inputs)    AS unique_inputs,
    values(status) AS statuses
    BY session_id, agent_id, tool_name
| eval loop_ratio = round((total_calls - unique_inputs) / total_calls, 3)
| where total_calls > 3 AND loop_ratio > 0.5
| eval severity = case(
    loop_ratio > 0.8, "critical",
    loop_ratio > 0.6, "high",
    true(),           "medium"
  )
| sort -loop_ratio
| table _time, session_id, agent_id, tool_name,
        total_calls, unique_inputs, loop_ratio, severity, statuses
"""

# ─── 2. Hallucination Latency Anomaly ────────────────────────────────────────
# LLM calls where response time is suspiciously fast given token count.
# Fast responses on large outputs often mean the model is reciting from
# weights (hallucinating) rather than actually reasoning over tool outputs.
HALLUCINATION_LATENCY_ANOMALY = """
index=agent_telemetry sourcetype=agent_sentinel span_type=llm_call
    status=success
| eval tokens_per_ms = round(tokens_out / latency_ms, 4)
| stats
    avg(tokens_per_ms) AS avg_speed,
    stdev(tokens_per_ms) AS sd_speed,
    count AS n
    BY agent_id
| join agent_id [
    search index=agent_telemetry sourcetype=agent_sentinel span_type=llm_call
    | eval tokens_per_ms = round(tokens_out / latency_ms, 4)
    | table session_id, agent_id, span_id, latency_ms, tokens_out, tokens_per_ms, response
  ]
| eval z_score = round((tokens_per_ms - avg_speed) / sd_speed, 2)
| where z_score > 2.5
| eval hallucination_risk = "high"
| sort -z_score
| table _time, session_id, agent_id, span_id, latency_ms,
        tokens_out, tokens_per_ms, z_score, hallucination_risk
"""

# ─── 3. Reasoning Drift Over Time ────────────────────────────────────────────
# Looks at sessions where the agent's reasoning steps diverge significantly.
# Uses the pre-computed drift_score that the Python scorer writes back.
REASONING_DRIFT_TIMELINE = """
index=agent_telemetry sourcetype=agent_sentinel span_type=reasoning_step
| eval step_time = strftime(_time, "%H:%M:%S")
| sort session_id, step_index
| streamstats
    window=2
    current=true
    last(reasoning_text) AS prev_reasoning
    BY session_id
| eval
    curr_words = split(lower(reasoning_text), " "),
    prev_words = split(lower(prev_reasoning), " ")
| eval
    intersection = mvcount(mvcombine(curr_words, prev_words))
| eventstats
    max(step_index) AS max_step
    BY session_id
| where step_index > 0
| table _time, session_id, agent_id, step_index,
        step_time, confidence, reasoning_text
"""

# ─── 4. Error Cascade Risk ───────────────────────────────────────────────────
# Sessions where error rate within a workflow exceeds a threshold,
# indicating that a bad early decision is cascading downstream.
ERROR_CASCADE_RISK = """
index=agent_telemetry sourcetype=agent_sentinel
    (span_type=llm_call OR span_type=tool_call)
| eval is_error = if(status="error", 1, 0)
| stats
    sum(is_error) AS errors,
    count         AS total_events,
    min(_time)    AS start_time,
    max(_time)    AS last_event
    BY session_id, agent_id
| eval error_rate = round(errors / total_events, 3)
| eval duration_s = last_event - start_time
| where errors > 0
| eval cascade_risk = case(
    error_rate > 0.4 AND total_events > 5, "critical",
    error_rate > 0.2,                       "high",
    error_rate > 0.1,                       "medium",
    true(),                                 "low"
  )
| sort -error_rate
| table session_id, agent_id, errors, total_events,
        error_rate, duration_s, cascade_risk
"""

# ─── 5. Session Health Overview ──────────────────────────────────────────────
# Full summary of every agent session: call counts, latency, anomaly flags.
SESSION_HEALTH_OVERVIEW = """
index=agent_telemetry sourcetype=agent_sentinel
| stats
    count                          AS total_spans,
    sum(eval(span_type="llm_call")) AS llm_calls,
    sum(eval(span_type="tool_call")) AS tool_calls,
    avg(latency_ms)                AS avg_latency_ms,
    max(latency_ms)                AS max_latency_ms,
    sum(tokens_in)                 AS total_tokens_in,
    sum(tokens_out)                AS total_tokens_out,
    sum(eval(status="error"))      AS total_errors,
    min(_time)                     AS session_start,
    max(_time)                     AS session_end
    BY session_id, agent_id
| eval
    duration_s      = round(session_end - session_start, 1),
    error_rate      = round(total_errors / total_spans, 3),
    health_status   = case(
        error_rate > 0.3, "critical",
        error_rate > 0.1, "degraded",
        true(),           "healthy"
    )
| sort -session_start
| table session_id, agent_id, health_status, total_spans,
        llm_calls, tool_calls, avg_latency_ms, total_errors,
        error_rate, duration_s, total_tokens_in, total_tokens_out
"""

# ─── 6. Anomaly Alert Feed ───────────────────────────────────────────────────
# Real-time feed of ANOMALY_ALERT spans emitted by the meta-agent watcher.
ANOMALY_ALERT_FEED = """
index=agent_telemetry sourcetype=agent_sentinel span_type=anomaly_alert
| eval fired_at = strftime(_time, "%Y-%m-%d %H:%M:%S")
| sort -_time
| table fired_at, session_id, agent_id,
        hallucination_score, tool_loop_score,
        reasoning_drift_score, cascade_risk_score,
        composite_score, anomaly_type, recommended_action
"""

# ─── 7. Remediation Audit Trail ──────────────────────────────────────────────
# All remediation actions taken by the meta-agent (pause, escalate, etc.)
REMEDIATION_AUDIT_TRAIL = """
index=agent_telemetry sourcetype=agent_sentinel span_type=remediation
| eval actioned_at = strftime(_time, "%Y-%m-%d %H:%M:%S")
| sort -_time
| table actioned_at, session_id, agent_id,
        action_taken, triggered_by_score, outcome, notes
"""

# ─── 8. Cost & Token Usage ───────────────────────────────────────────────────
# Tracks token burn by agent, useful for detecting runaway loops that also
# waste money.
TOKEN_COST_BY_AGENT = """
index=agent_telemetry sourcetype=agent_sentinel span_type=llm_call
| stats
    sum(tokens_in)   AS total_tokens_in,
    sum(tokens_out)  AS total_tokens_out,
    count            AS call_count,
    avg(latency_ms)  AS avg_latency
    BY agent_id, model
| eval total_tokens = total_tokens_in + total_tokens_out
| sort -total_tokens
| table agent_id, model, call_count, total_tokens,
        total_tokens_in, total_tokens_out, avg_latency
"""


# ─── Helper function ─────────────────────────────────────────────────────────

def get_query(name: str, **params) -> str:
    """
    Retrieve a query by name and optionally substitute parameters.

    Usage:
        spl = get_query("TOOL_LOOP_DETECTION")
        spl_custom = get_query("ERROR_CASCADE_RISK", min_errors=3)
    """
    queries = {
        "TOOL_LOOP_DETECTION":         TOOL_LOOP_DETECTION,
        "HALLUCINATION_LATENCY_ANOMALY": HALLUCINATION_LATENCY_ANOMALY,
        "REASONING_DRIFT_TIMELINE":    REASONING_DRIFT_TIMELINE,
        "ERROR_CASCADE_RISK":          ERROR_CASCADE_RISK,
        "SESSION_HEALTH_OVERVIEW":     SESSION_HEALTH_OVERVIEW,
        "ANOMALY_ALERT_FEED":          ANOMALY_ALERT_FEED,
        "REMEDIATION_AUDIT_TRAIL":     REMEDIATION_AUDIT_TRAIL,
        "TOKEN_COST_BY_AGENT":         TOKEN_COST_BY_AGENT,
    }
    q = queries.get(name)
    if q is None:
        raise KeyError(f"Unknown query: {name}. Available: {list(queries)}")
    return q.format(**params) if params else q
