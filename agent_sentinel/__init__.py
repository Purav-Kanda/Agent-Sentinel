# agent_sentinel/__init__.py
# ─────────────────────────────────────────────────────────────────────────────
# AgentSentinel - Agentic AI Observability for Splunk
# Entry point that exposes the public API of the package.
# ─────────────────────────────────────────────────────────────────────────────

from agent_sentinel.telemetry.tracer import AgentTracer
from agent_sentinel.telemetry.splunk_writer import SplunkWriter
from agent_sentinel.detection.scorer import AnomalyScorer
from agent_sentinel.remediation.handler import RemediationHandler

__version__ = "1.0.0"
__all__ = ["AgentTracer", "SplunkWriter", "AnomalyScorer", "RemediationHandler"]
