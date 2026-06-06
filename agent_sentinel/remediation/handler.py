# agent_sentinel/remediation/handler.py
import logging
import threading
import uuid
from enum import Enum
from typing import Callable, Dict, Optional

from agent_sentinel.telemetry.span import Span, SpanType
from agent_sentinel.telemetry.splunk_writer import SplunkWriter

logger = logging.getLogger(__name__)


class RemediationAction(str, Enum):
    WARN  = "warn"
    PAUSE = "pause"
    ABORT = "abort"


class AgentAbortError(RuntimeError):
    pass


class RemediationHandler:
    """
    Executes remediation actions and records them in Splunk.

    Decision logic (first match wins):
      1. composite >= abort_threshold              -> ABORT
      2. composite >= pause_threshold              -> PAUSE
      3. any individual score >= 0.85              -> PAUSE  (single detector critical)
      4. composite >= warn_threshold               -> WARN
      5. any individual score >= 0.65              -> WARN   (single detector high)
      6. otherwise                                 -> no action
    """

    # Per-detector thresholds (supplement the composite thresholds)
    _INDIVIDUAL_WARN_THRESHOLD  = 0.65
    _INDIVIDUAL_PAUSE_THRESHOLD = 0.85

    def __init__(
        self,
        writer,
        warn_threshold:    float = 0.50,
        pause_threshold:   float = 0.65,
        abort_threshold:   float = 0.90,
        on_pause_callback: Optional[Callable[[str, dict], None]] = None,
    ):
        self.writer            = writer
        self.warn_threshold    = warn_threshold
        self.pause_threshold   = pause_threshold
        self.abort_threshold   = abort_threshold
        self.on_pause_callback = on_pause_callback
        self._paused_sessions: set = set()
        self._lock = threading.Lock()

    def evaluate_and_act(self, session_id, agent_id, scores, span=None):
        composite = scores.get("composite", 0.0)
        max_individual = max(
            scores.get("hallucination",   0.0),
            scores.get("tool_loop",       0.0),
            scores.get("reasoning_drift", 0.0),
            scores.get("cascade_risk",    0.0),
        )

        if composite >= self.abort_threshold:
            action = RemediationAction.ABORT
        elif composite >= self.pause_threshold:
            action = RemediationAction.PAUSE
        elif max_individual >= self._INDIVIDUAL_PAUSE_THRESHOLD:
            action = RemediationAction.PAUSE
        elif composite >= self.warn_threshold:
            action = RemediationAction.WARN
        elif max_individual >= self._INDIVIDUAL_WARN_THRESHOLD:
            action = RemediationAction.WARN
        else:
            return RemediationAction.WARN  # no-op

        self._execute(action, session_id, agent_id, scores)
        return action

    def _execute(self, action, session_id, agent_id, scores):
        composite = scores.get("composite", 0.0)
        logger.warning(
            "REMEDIATION action=%s session=%s agent=%s composite=%.2f",
            action.value, session_id, agent_id, composite
        )
        self._emit_anomaly_alert(session_id, agent_id, scores, action)

        if action == RemediationAction.PAUSE:
            with self._lock:
                self._paused_sessions.add(session_id)
            if self.on_pause_callback:
                try:
                    self.on_pause_callback(session_id, scores)
                except Exception as exc:
                    logger.error("Pause callback failed: %s", exc)
            self._emit_remediation_span(
                session_id, agent_id, action, scores,
                outcome="session_paused_awaiting_human"
            )
        elif action == RemediationAction.ABORT:
            self._emit_remediation_span(
                session_id, agent_id, action, scores,
                outcome="session_aborted_by_sentinel"
            )
            raise AgentAbortError(
                f"AgentSentinel aborted session {session_id} "
                f"(composite_score={composite:.2f})"
            )
        else:  # WARN
            self._emit_remediation_span(
                session_id, agent_id, action, scores,
                outcome="warning_logged_agent_continues"
            )

    def is_paused(self, session_id):
        with self._lock:
            return session_id in self._paused_sessions

    def resume(self, session_id):
        with self._lock:
            self._paused_sessions.discard(session_id)
        logger.info("Session %s resumed by operator", session_id)

    def _emit_anomaly_alert(self, session_id, agent_id, scores, action):
        span = Span(
            span_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id=agent_id,
            span_type=SpanType.ANOMALY_ALERT,
            metadata={
                "hallucination_score":   scores.get("hallucination", 0),
                "tool_loop_score":       scores.get("tool_loop", 0),
                "reasoning_drift_score": scores.get("reasoning_drift", 0),
                "cascade_risk_score":    scores.get("cascade_risk", 0),
                "composite_score":       scores.get("composite", 0),
                "anomaly_type":          self._classify_anomaly(scores),
                "recommended_action":    action.value,
            },
        )
        self._safe_write(span)

    def _emit_remediation_span(self, session_id, agent_id, action, scores, outcome, notes=""):
        span = Span(
            span_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id=agent_id,
            span_type=SpanType.REMEDIATION,
            metadata={
                "action_taken":       action.value,
                "triggered_by_score": scores.get("composite", 0),
                "outcome":            outcome,
                "notes":              notes,
            },
        )
        self._safe_write(span)

    def _safe_write(self, span):
        try:
            self.writer.write(span)
        except Exception:
            pass

    @staticmethod
    def _classify_anomaly(scores):
        ranked = sorted(
            [("hallucination",   scores.get("hallucination", 0)),
             ("tool_loop",       scores.get("tool_loop", 0)),
             ("reasoning_drift", scores.get("reasoning_drift", 0)),
             ("cascade_risk",    scores.get("cascade_risk", 0))],
            key=lambda x: x[1], reverse=True,
        )
        top_name, top_score = ranked[0]
        return "low_risk" if top_score < 0.2 else top_name
