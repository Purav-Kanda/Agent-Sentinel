# agent_sentinel/telemetry/span.py
# ─────────────────────────────────────────────────────────────────────────────
# Span – the atomic unit of telemetry in AgentSentinel.
#
# Every event (LLM call, tool invocation, reasoning step, session boundary)
# is modelled as a Span.  Spans are serialised to JSON and sent to the
# Splunk HTTP Event Collector (HEC) as individual events.
#
# The sourcetype "agent_sentinel" lets Splunk extract fields automatically
# from the JSON payload so every key becomes searchable without manual
# field extractions.
# ─────────────────────────────────────────────────────────────────────────────

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional


class SpanType(str, Enum):
    """
    All event types that AgentSentinel can produce.
    Using an Enum (not plain strings) means a typo causes a compile-time
    error rather than a silent wrong value in Splunk.
    """
    SESSION_START   = "session_start"    # workflow run begins
    SESSION_END     = "session_end"      # workflow run ends
    LLM_CALL        = "llm_call"         # call to any LLM
    TOOL_CALL       = "tool_call"        # call to a tool (Splunk search, API…)
    REASONING_STEP  = "reasoning_step"   # one step of chain-of-thought
    ANOMALY_ALERT   = "anomaly_alert"    # meta-agent detected a problem
    REMEDIATION     = "remediation"      # remediation action was taken


@dataclass
class Span:
    """
    A single telemetry event.

    Fields
    ------
    span_id    : Globally unique ID for this event (UUID4).
    session_id : Groups all spans from one agent run together.
    agent_id   : Which agent produced this span.
    span_type  : One of SpanType values – used as the primary Splunk filter.
    metadata   : Arbitrary dict of extra fields.  Everything here lands as
                 top-level JSON keys so SPL can reach them with
                 `| spath metadata.latency_ms`.
    timestamp  : Unix epoch seconds (float).  Set automatically on creation.
    """
    span_id:    str
    session_id: Optional[str]
    agent_id:   str
    span_type:  SpanType
    metadata:   Dict[str, Any] = field(default_factory=dict)
    timestamp:  float          = field(default_factory=time.time)

    def to_hec_payload(self) -> dict:
        """
        Serialise to the HEC JSON format that Splunk expects:

            {
                "time":       <unix timestamp>,
                "sourcetype": "agent_sentinel",
                "index":      "agent_telemetry",
                "event": {
                    "span_id":    "...",
                    "session_id": "...",
                    "agent_id":   "...",
                    "span_type":  "llm_call",
                    ...metadata fields flattened in...
                }
            }

        We flatten metadata directly into the event object (rather than
        nesting it) so SPL queries are simpler:
            index=agent_telemetry span_type=llm_call latency_ms>500
        instead of:
            index=agent_telemetry span_type=llm_call metadata.latency_ms>500
        """
        event = {
            "span_id":    self.span_id,
            "session_id": self.session_id,
            "agent_id":   self.agent_id,
            "span_type":  self.span_type.value,
        }
        # Flatten metadata keys into the top-level event dict.
        event.update(self.metadata)

        return {
            "time":       self.timestamp,
            "sourcetype": "agent_sentinel",
            "index":      "agent_telemetry",
            "event":      event,
        }
