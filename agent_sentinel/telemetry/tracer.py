# agent_sentinel/telemetry/tracer.py
# ─────────────────────────────────────────────────────────────────────────────
# AgentTracer
# -----------
# The heart of AgentSentinel's data collection layer.
#
# It works as a Python decorator / context manager that wraps any function
# that calls an LLM or a Splunk tool.  Every call is captured as a structured
# "span" (similar to OpenTelemetry) and forwarded to SplunkWriter.
#
# Key design decisions:
#   1. Non-intrusive  – add @tracer.trace_llm_call on any function; zero
#      change to the underlying logic.
#   2. Thread-safe    – uses a threading.local stack so nested / concurrent
#      agent calls don't bleed into each other.
#   3. Failure-safe   – if telemetry itself fails, the original call still
#      completes; we never break the agent we're monitoring.
# ─────────────────────────────────────────────────────────────────────────────

import time
import uuid
import threading
import traceback
import functools
from typing import Any, Callable, Dict, Optional

from agent_sentinel.telemetry.splunk_writer import SplunkWriter
from agent_sentinel.telemetry.span import Span, SpanType


class AgentTracer:
    """
    Instruments agentic workflows and ships structured telemetry to Splunk.

    Usage
    -----
    tracer = AgentTracer(agent_id="soc-triage-v1", writer=SplunkWriter(...))

    @tracer.trace_llm_call
    def call_llm(prompt: str) -> str:
        ...

    @tracer.trace_tool_call(tool_name="splunk_search")
    def run_search(query: str) -> dict:
        ...
    """

    # Thread-local storage keeps the active workflow stack per thread,
    # which is essential when running multiple agents concurrently.
    _local = threading.local()

    def __init__(self, agent_id: str, writer: SplunkWriter):
        """
        Parameters
        ----------
        agent_id : str
            Unique identifier for this agent instance (e.g. "soc-triage-v1").
            Shows up as a dimension in every Splunk event so you can filter
            dashboards by agent.
        writer : SplunkWriter
            Configured SplunkWriter that knows how to POST events to HEC.
        """
        self.agent_id = agent_id
        self.writer = writer

        # Each new workflow gets a fresh session_id so all spans from one
        # "run" of the agent can be grouped together in Splunk.
        self.session_id: Optional[str] = None

    # ─── Session management ──────────────────────────────────────────────────

    def start_session(self, session_id: Optional[str] = None) -> str:
        """
        Call this at the beginning of a new agentic workflow run.
        Returns the session_id so the caller can log it externally too.
        """
        self.session_id = session_id or str(uuid.uuid4())

        # Record a SESSION_START span so Splunk knows when the run began.
        span = Span(
            span_id=str(uuid.uuid4()),
            session_id=self.session_id,
            agent_id=self.agent_id,
            span_type=SpanType.SESSION_START,
            metadata={"event": "session_start"},
        )
        self._emit(span)
        return self.session_id

    def end_session(self, outcome: str = "completed") -> None:
        """
        Call this at the end of a workflow run.
        outcome: "completed" | "failed" | "paused_by_sentinel"
        """
        span = Span(
            span_id=str(uuid.uuid4()),
            session_id=self.session_id,
            agent_id=self.agent_id,
            span_type=SpanType.SESSION_END,
            metadata={"event": "session_end", "outcome": outcome},
        )
        self._emit(span)
        self.session_id = None

    # ─── Decorators ──────────────────────────────────────────────────────────

    def trace_llm_call(self, func: Callable) -> Callable:
        """
        Decorator for any function that calls an LLM.

        Captures:
          - The full prompt sent to the model
          - The raw response text
          - Latency in milliseconds
          - Token counts (if the wrapped function returns them)
          - Whether the call raised an exception

        The wrapped function may optionally return a dict with keys:
            {"response": str, "tokens_in": int, "tokens_out": int,
             "model": str, "reasoning": str}
        or just a plain string response.
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            span_id = str(uuid.uuid4())
            start_ms = time.time() * 1000

            # Extract prompt from first positional arg or 'prompt' kwarg.
            prompt = kwargs.get("prompt") or (args[0] if args else "")

            try:
                result = func(*args, **kwargs)
                latency_ms = time.time() * 1000 - start_ms

                # Support both plain-string and dict return types.
                if isinstance(result, dict):
                    response_text = result.get("response", "")
                    tokens_in     = result.get("tokens_in", 0)
                    tokens_out    = result.get("tokens_out", 0)
                    model         = result.get("model", "unknown")
                    reasoning     = result.get("reasoning", "")
                else:
                    response_text = str(result)
                    tokens_in = tokens_out = 0
                    model = "unknown"
                    reasoning = ""

                span = Span(
                    span_id=span_id,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    span_type=SpanType.LLM_CALL,
                    metadata={
                        "prompt": prompt,
                        "response": response_text,
                        "reasoning": reasoning,
                        "latency_ms": round(latency_ms, 2),
                        "tokens_in": tokens_in,
                        "tokens_out": tokens_out,
                        "model": model,
                        "status": "success",
                    },
                )
                self._emit(span)
                return result

            except Exception as exc:
                latency_ms = time.time() * 1000 - start_ms
                span = Span(
                    span_id=span_id,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    span_type=SpanType.LLM_CALL,
                    metadata={
                        "prompt": prompt,
                        "latency_ms": round(latency_ms, 2),
                        "status": "error",
                        "error": str(exc),
                        "traceback": traceback.format_exc(),
                    },
                )
                self._emit(span)
                raise  # re-raise so the agent's own error handling fires

        return wrapper

    def trace_tool_call(self, tool_name: str):
        """
        Decorator factory for functions that invoke an external tool
        (Splunk search, REST API call, file read, etc.).

        Usage:
            @tracer.trace_tool_call(tool_name="splunk_search")
            def run_search(query: str) -> dict: ...

        Captures: tool name, inputs, outputs, latency, retry count, errors.
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                span_id = str(uuid.uuid4())
                start_ms = time.time() * 1000

                # Capture all inputs for the tool call.
                inputs = {"args": [str(a) for a in args],
                          "kwargs": {k: str(v) for k, v in kwargs.items()}}

                # Track retry count – the agent might call us from a loop.
                retry_count = getattr(self._local, "tool_retry_counts", {})
                retry_count[tool_name] = retry_count.get(tool_name, 0) + 1
                self._local.tool_retry_counts = retry_count
                current_retry = retry_count[tool_name]

                try:
                    result = func(*args, **kwargs)
                    latency_ms = time.time() * 1000 - start_ms

                    span = Span(
                        span_id=span_id,
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        span_type=SpanType.TOOL_CALL,
                        metadata={
                            "tool_name": tool_name,
                            "inputs": inputs,
                            "output": str(result)[:2000],  # cap at 2 KB
                            "latency_ms": round(latency_ms, 2),
                            "retry_count": current_retry,
                            "status": "success",
                        },
                    )
                    self._emit(span)
                    return result

                except Exception as exc:
                    latency_ms = time.time() * 1000 - start_ms
                    span = Span(
                        span_id=span_id,
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        span_type=SpanType.TOOL_CALL,
                        metadata={
                            "tool_name": tool_name,
                            "inputs": inputs,
                            "latency_ms": round(latency_ms, 2),
                            "retry_count": current_retry,
                            "status": "error",
                            "error": str(exc),
                        },
                    )
                    self._emit(span)
                    raise

            return wrapper
        return decorator

    def log_reasoning_step(self, step_index: int, reasoning_text: str,
                           confidence: Optional[float] = None) -> None:
        """
        Manually log a reasoning/chain-of-thought step.

        Call this inside your agent's planning loop after each reasoning
        iteration.  AgentSentinel uses these events to detect "reasoning
        drift" – when the agent's stated goal shifts between steps.

        Parameters
        ----------
        step_index  : 0-based step counter within the current session.
        reasoning_text : The raw reasoning/scratchpad text from the LLM.
        confidence  : Optional self-reported confidence score (0.0–1.0).
        """
        span = Span(
            span_id=str(uuid.uuid4()),
            session_id=self.session_id,
            agent_id=self.agent_id,
            span_type=SpanType.REASONING_STEP,
            metadata={
                "step_index": step_index,
                "reasoning_text": reasoning_text[:3000],
                "confidence": confidence,
            },
        )
        self._emit(span)

    def reset_tool_retry_counts(self) -> None:
        """Reset per-tool retry counters at the start of a new reasoning loop."""
        self._local.tool_retry_counts = {}

    # ─── Internal helpers ────────────────────────────────────────────────────

    def _emit(self, span: "Span") -> None:
        """
        Ship a span to Splunk. Wrapped in try/except so telemetry failures
        never crash the monitored agent.
        """
        try:
            self.writer.write(span)
        except Exception:
            # Silently swallow – monitoring must never break the monitored code.
            pass
