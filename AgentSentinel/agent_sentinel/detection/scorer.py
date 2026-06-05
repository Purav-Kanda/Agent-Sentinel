# agent_sentinel/detection/scorer.py
# ─────────────────────────────────────────────────────────────────────────────
# AnomalyScorer
# -------------
# The intelligence layer of AgentSentinel.  It reads raw telemetry spans
# (streamed in or pulled from Splunk) and produces anomaly scores across
# four failure dimensions:
#
#   1. Hallucination Score   – is the LLM asserting things that aren't
#                              grounded in its context / retrieved data?
#   2. Tool Loop Score       – is the agent calling the same tool with the
#                              same (failing) args repeatedly?
#   3. Reasoning Drift Score – is the agent's stated goal shifting between
#                              reasoning steps (goal hijacking / confusion)?
#   4. Cascade Risk Score    – given an early error, how likely is it to
#                              propagate through the remaining workflow?
#
# Each scorer returns a float in [0.0, 1.0].  A composite score > THRESHOLD
# triggers a RemediationHandler action.
#
# Implementation note:
# For the hackathon demo we use lightweight heuristic scorers that run
# locally (no external ML service needed).  In production you would swap
# in the Splunk AI Toolkit / AITK Deep Time Series model for time-series
# anomaly detection, and the Foundation-Sec-1.1 model for security-specific
# classification.
# ─────────────────────────────────────────────────────────────────────────────

import re
import math
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

from agent_sentinel.telemetry.span import Span, SpanType

logger = logging.getLogger(__name__)


# ─── Constants ────────────────────────────────────────────────────────────────

# Composite score above this → trigger remediation
ANOMALY_THRESHOLD = 0.65

# How many recent spans to keep in memory per session for drift analysis
REASONING_WINDOW = 10

# Tool call retry count that starts raising the loop score
TOOL_LOOP_WARN_THRESHOLD  = 3
TOOL_LOOP_ALERT_THRESHOLD = 5

# Phrases that often appear when an LLM is hallucinating confidently
HALLUCINATION_MARKERS = [
    r"\bI (know|confirm|verified|checked)\b",
    r"\bthe (logs?|data|records?) (show|indicate|confirm)\b",
    r"\baccording to (the )?(Splunk )?(data|logs?|results?)\b",
    r"\bI (found|can see|observed)\b",
    r"\bstatus (is|was) (definitely|clearly|certainly)\b",
]

# Compile all patterns once at import time for speed
_HALLUCINATION_RE = [re.compile(p, re.IGNORECASE) for p in HALLUCINATION_MARKERS]


class AnomalyScorer:
    """
    Stateful scorer that maintains a sliding window of spans per session
    and computes anomaly scores in real time.

    Typical usage (in the meta-agent watcher loop):
        scorer = AnomalyScorer()
        for span in incoming_spans:
            scores = scorer.score(span)
            if scores["composite"] > ANOMALY_THRESHOLD:
                handler.escalate(span.session_id, scores)
    """

    def __init__(self, threshold: float = ANOMALY_THRESHOLD):
        self.threshold = threshold

        # Per-session state.  Using defaultdict so new sessions are
        # initialised automatically.
        self._tool_call_history:  Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self._reasoning_history:  Dict[str, deque]                 = defaultdict(lambda: deque(maxlen=REASONING_WINDOW))
        self._llm_call_count:     Dict[str, int]                   = defaultdict(int)
        self._error_count:        Dict[str, int]                   = defaultdict(int)

    # ─── Main entry point ────────────────────────────────────────────────────

    def score(self, span: Span) -> Dict[str, float]:
        """
        Score a single incoming span.

        Returns a dict:
        {
            "hallucination": 0.0–1.0,
            "tool_loop":     0.0–1.0,
            "reasoning_drift": 0.0–1.0,
            "cascade_risk":  0.0–1.0,
            "composite":     0.0–1.0,   ← weighted average
        }
        """
        sid = span.session_id or "unknown"

        # Update internal state before scoring so the score reflects the
        # current span.
        self._update_state(span)

        hallucination   = self._score_hallucination(span, sid)
        tool_loop       = self._score_tool_loop(span, sid)
        reasoning_drift = self._score_reasoning_drift(span, sid)
        cascade_risk    = self._score_cascade_risk(span, sid)

        # Composite: weighted average biased toward hallucination and loops
        # because those are the highest-impact failures in a SOC context.
        composite = (
            0.35 * hallucination   +
            0.30 * tool_loop       +
            0.20 * reasoning_drift +
            0.15 * cascade_risk
        )

        scores = {
            "hallucination":   round(hallucination,   3),
            "tool_loop":       round(tool_loop,       3),
            "reasoning_drift": round(reasoning_drift, 3),
            "cascade_risk":    round(cascade_risk,    3),
            "composite":       round(composite,       3),
        }

        if composite > self.threshold:
            logger.warning(
                "ANOMALY DETECTED session=%s agent=%s composite=%.2f scores=%s",
                sid, span.agent_id, composite, scores
            )

        return scores

    # ─── State updater ───────────────────────────────────────────────────────

    def _update_state(self, span: Span) -> None:
        """Update rolling state buffers from an incoming span."""
        sid = span.session_id or "unknown"

        if span.span_type == SpanType.TOOL_CALL:
            tool_name = span.metadata.get("tool_name", "unknown")
            inputs_str = str(span.metadata.get("inputs", ""))
            # Store (tool_name, inputs) pairs to detect exact-repeat calls.
            self._tool_call_history[sid][tool_name].append(inputs_str)
            if span.metadata.get("status") == "error":
                self._error_count[sid] += 1

        elif span.span_type == SpanType.LLM_CALL:
            self._llm_call_count[sid] += 1
            if span.metadata.get("status") == "error":
                self._error_count[sid] += 1

        elif span.span_type == SpanType.REASONING_STEP:
            self._reasoning_history[sid].append(
                span.metadata.get("reasoning_text", "")
            )

    # ─── Individual scorers ──────────────────────────────────────────────────

    def _score_hallucination(self, span: Span, sid: str) -> float:
        """
        Heuristic hallucination detector.

        Logic:
          - Only LLM_CALL spans can contain hallucinations.
          - We look for linguistic patterns that indicate the model is asserting
            things it cannot actually know (e.g. "I confirmed in the logs").
          - We also penalise very low latency on a high-token response, which
            can indicate the model retrieved from weights rather than reasoning
            over actual tool outputs.
          - Score range: 0.0 (clean) → 1.0 (strong hallucination signal).
        """
        if span.span_type != SpanType.LLM_CALL:
            return 0.0

        response = span.metadata.get("response", "")
        if not response:
            return 0.0

        # Count how many hallucination-marker patterns match.
        match_count = sum(1 for pat in _HALLUCINATION_RE if pat.search(response))
        pattern_score = min(match_count / 3.0, 1.0)  # saturates at 3 matches

        # Latency heuristic: genuine retrieval-augmented reasoning takes time.
        # A response > 200 tokens arriving in < 300ms is suspicious.
        tokens_out  = span.metadata.get("tokens_out", 0)
        latency_ms  = span.metadata.get("latency_ms", 9999)
        speed_score = 0.0
        if tokens_out > 200 and latency_ms < 300:
            speed_score = 0.4   # suspicious but not conclusive

        return min(pattern_score + speed_score, 1.0)

    def _score_tool_loop(self, span: Span, sid: str) -> float:
        """
        Detects tool-call loops: the agent calling the same tool with the
        same arguments multiple times (stuck in a retry loop).

        Score logic:
          - 0.0 if fewer than WARN_THRESHOLD identical calls.
          - Rises linearly from warn to alert threshold.
          - Caps at 1.0 at ALERT_THRESHOLD.
        """
        if span.span_type != SpanType.TOOL_CALL:
            return 0.0

        tool_name  = span.metadata.get("tool_name", "unknown")
        call_list  = self._tool_call_history[sid][tool_name]

        if len(call_list) < 2:
            return 0.0

        # Count how many recent calls had identical inputs to the latest one.
        latest_input = call_list[-1]
        identical    = sum(1 for c in call_list[:-1] if c == latest_input)

        if identical < TOOL_LOOP_WARN_THRESHOLD:
            return 0.0

        # Linear ramp between warn and alert thresholds.
        ramp = (identical - TOOL_LOOP_WARN_THRESHOLD) / (
            TOOL_LOOP_ALERT_THRESHOLD - TOOL_LOOP_WARN_THRESHOLD
        )
        return min(ramp, 1.0)

    def _score_reasoning_drift(self, span: Span, sid: str) -> float:
        """
        Detects goal/reasoning drift across reasoning steps.

        We compute a simple lexical overlap (Jaccard similarity) between
        consecutive reasoning texts.  A sudden drop in similarity signals
        that the agent's context has shifted – possibly due to a prompt
        injection in retrieved data or an accumulation of hallucinated facts.

        Score: 0.0 (stable reasoning) → 1.0 (severe drift).
        """
        if span.span_type != SpanType.REASONING_STEP:
            return 0.0

        history = list(self._reasoning_history[sid])
        if len(history) < 2:
            return 0.0

        # Compare the two most recent reasoning texts.
        prev_text = history[-2]
        curr_text = history[-1]

        similarity = _jaccard_similarity(prev_text, curr_text)

        # Low similarity = high drift score.
        # We use a threshold of 0.3 – below that the texts are very different.
        drift = max(0.0, 1.0 - (similarity / 0.3))
        return min(drift, 1.0)

    def _score_cascade_risk(self, span: Span, sid: str) -> float:
        """
        Estimates the risk that earlier errors will cascade through the rest
        of the workflow.

        Logic: error rate so far × log(steps completed).
        More steps completed with errors = higher cascade risk because
        each downstream step consumed potentially corrupt context.
        """
        total_calls = self._llm_call_count[sid] + sum(
            len(v) for v in self._tool_call_history[sid].values()
        )
        if total_calls == 0:
            return 0.0

        error_rate  = self._error_count[sid] / total_calls
        # log factor: risk grows with workflow depth (more steps = more
        # opportunity for error to propagate).
        depth_factor = math.log1p(total_calls) / math.log1p(20)  # normalised to 20 steps
        return min(error_rate * depth_factor, 1.0)

    # ─── Utility ─────────────────────────────────────────────────────────────

    def clear_session(self, session_id: str) -> None:
        """Free memory for a completed session."""
        self._tool_call_history.pop(session_id, None)
        self._reasoning_history.pop(session_id, None)
        self._llm_call_count.pop(session_id, None)
        self._error_count.pop(session_id, None)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _jaccard_similarity(text_a: str, text_b: str) -> float:
    """
    Jaccard similarity between the word-sets of two strings.
    Returns 0.0 if either string is empty.
    """
    if not text_a or not text_b:
        return 0.0
    set_a = set(text_a.lower().split())
    set_b = set(text_b.lower().split())
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)
