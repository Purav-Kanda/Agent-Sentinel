# tests/test_tracer.py
# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for AgentTracer – verifies that the decorator layer captures
# spans correctly without breaking the underlying function.
# Run with: pytest tests/test_tracer.py -v
# ─────────────────────────────────────────────────────────────────────────────

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from agent_sentinel.telemetry.tracer import AgentTracer
from agent_sentinel.telemetry.span import SpanType


# ── Spy writer – records spans in memory so tests can inspect them ────────────

class SpyWriter:
    def __init__(self):
        self.spans = []

    def write(self, span):
        self.spans.append(span)

    def flush(self): pass
    def close(self): pass


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tracer_and_writer():
    writer = SpyWriter()
    tracer = AgentTracer(agent_id="test-agent", writer=writer)
    tracer.start_session(session_id="sess-test")
    yield tracer, writer
    tracer.end_session()


# ── Session lifecycle tests ───────────────────────────────────────────────────

def test_start_session_emits_span():
    writer = SpyWriter()
    tracer = AgentTracer(agent_id="a1", writer=writer)
    sid = tracer.start_session("my-session")
    assert sid == "my-session"
    assert len(writer.spans) == 1
    assert writer.spans[0].span_type == SpanType.SESSION_START

def test_end_session_emits_span(tracer_and_writer):
    tracer, writer = tracer_and_writer
    initial_count = len(writer.spans)
    tracer.end_session(outcome="completed")
    assert len(writer.spans) == initial_count + 1
    last = writer.spans[-1]
    assert last.span_type == SpanType.SESSION_END
    assert last.metadata["outcome"] == "completed"


# ── LLM call decorator tests ──────────────────────────────────────────────────

def test_trace_llm_call_captures_span(tracer_and_writer):
    tracer, writer = tracer_and_writer
    initial = len(writer.spans)

    @tracer.trace_llm_call
    def my_llm(prompt: str) -> dict:
        return {"response": "hello", "tokens_in": 10, "tokens_out": 5,
                "model": "test-model", "reasoning": "thinking"}

    result = my_llm(prompt="test prompt")
    assert result["response"] == "hello"

    new_spans = writer.spans[initial:]
    llm_spans = [s for s in new_spans if s.span_type == SpanType.LLM_CALL]
    assert len(llm_spans) == 1

    meta = llm_spans[0].metadata
    assert meta["status"] == "success"
    assert meta["tokens_in"] == 10
    assert meta["model"] == "test-model"
    assert meta["latency_ms"] >= 0

def test_trace_llm_call_captures_error(tracer_and_writer):
    tracer, writer = tracer_and_writer

    @tracer.trace_llm_call
    def failing_llm(prompt: str):
        raise ValueError("LLM timeout")

    with pytest.raises(ValueError):
        failing_llm(prompt="oops")

    llm_spans = [s for s in writer.spans if s.span_type == SpanType.LLM_CALL]
    assert len(llm_spans) == 1
    assert llm_spans[0].metadata["status"] == "error"
    assert "LLM timeout" in llm_spans[0].metadata["error"]

def test_trace_llm_call_plain_string_return(tracer_and_writer):
    tracer, writer = tracer_and_writer

    @tracer.trace_llm_call
    def simple_llm(prompt: str) -> str:
        return "just a string"

    result = simple_llm(prompt="hello")
    assert result == "just a string"
    llm_spans = [s for s in writer.spans if s.span_type == SpanType.LLM_CALL]
    assert llm_spans[-1].metadata["response"] == "just a string"


# ── Tool call decorator tests ─────────────────────────────────────────────────

def test_trace_tool_call_captures_span(tracer_and_writer):
    tracer, writer = tracer_and_writer

    @tracer.trace_tool_call(tool_name="splunk_search")
    def search(query: str) -> dict:
        return {"results": [1, 2, 3]}

    result = search(query="index=main")
    assert result == {"results": [1, 2, 3]}

    tool_spans = [s for s in writer.spans if s.span_type == SpanType.TOOL_CALL]
    assert len(tool_spans) == 1
    assert tool_spans[0].metadata["tool_name"] == "splunk_search"
    assert tool_spans[0].metadata["status"] == "success"

def test_trace_tool_call_retry_count_increments(tracer_and_writer):
    tracer, writer = tracer_and_writer

    @tracer.trace_tool_call(tool_name="flaky_tool")
    def flaky(query: str) -> dict:
        return {}

    for _ in range(3):
        flaky(query="same_query")

    tool_spans = [s for s in writer.spans if s.span_type == SpanType.TOOL_CALL]
    retry_counts = [s.metadata["retry_count"] for s in tool_spans]
    assert retry_counts == [1, 2, 3]

def test_trace_tool_call_captures_error(tracer_and_writer):
    tracer, writer = tracer_and_writer

    @tracer.trace_tool_call(tool_name="broken_tool")
    def broken():
        raise RuntimeError("connection refused")

    with pytest.raises(RuntimeError):
        broken()

    tool_spans = [s for s in writer.spans if s.span_type == SpanType.TOOL_CALL]
    assert tool_spans[-1].metadata["status"] == "error"


# ── Reasoning step tests ──────────────────────────────────────────────────────

def test_log_reasoning_step_emits_span(tracer_and_writer):
    tracer, writer = tracer_and_writer
    tracer.log_reasoning_step(
        step_index=0,
        reasoning_text="Thinking about the alert...",
        confidence=0.9,
    )
    reasoning_spans = [s for s in writer.spans
                       if s.span_type == SpanType.REASONING_STEP]
    assert len(reasoning_spans) == 1
    meta = reasoning_spans[0].metadata
    assert meta["step_index"] == 0
    assert meta["confidence"] == 0.9


# ── Failure-safety tests ──────────────────────────────────────────────────────

def test_writer_failure_does_not_crash_agent():
    """If Splunk is down, the agent must keep running."""

    class BrokenWriter:
        def write(self, span):
            raise ConnectionError("Splunk HEC unreachable")
        def flush(self): pass
        def close(self): pass

    tracer = AgentTracer(agent_id="resilient-agent", writer=BrokenWriter())
    tracer.start_session("sess-resilient")

    @tracer.trace_llm_call
    def llm(prompt: str) -> str:
        return "response"

    # This should NOT raise even though the writer is broken.
    result = llm(prompt="hello")
    assert result == "response"
