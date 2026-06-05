# agents/soc_triage_agent.py
# ─────────────────────────────────────────────────────────────────────────────
# SOC Triage Agent – the "monitored" agent in the demo.
#
# This agent simulates a real-world Security Operations Centre workflow:
#   Step 1 – Receive an incoming security alert (IDS hit, failed logins, etc.)
#   Step 2 – Search Splunk for corroborating evidence
#   Step 3 – Reason about severity
#   Step 4 – Look up threat intelligence
#   Step 5 – Decide: escalate to human analyst, auto-close, or create ticket
#
# In the NORMAL scenario, the agent works correctly.
# In the HALLUCINATION scenario (--mode=hallucinate), the mock LLM returns
# responses that trigger AgentSentinel's detection logic.
# In the LOOP scenario (--mode=loop), the agent calls Splunk search repeatedly
# with the same failing query.
#
# This file is the DEMO DRIVER – run it with:
#   python agents/soc_triage_agent.py --mode=normal
#   python agents/soc_triage_agent.py --mode=hallucinate
#   python agents/soc_triage_agent.py --mode=loop
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import random
import sys
import time
import os

# Allow running from the project root without pip install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_sentinel.telemetry.tracer import AgentTracer
from agent_sentinel.telemetry.splunk_writer import StdoutWriter, SplunkWriter
from agent_sentinel.detection.scorer import AnomalyScorer
from agent_sentinel.remediation.handler import RemediationHandler, AgentAbortError


# ─── Mock LLM & Tool functions ───────────────────────────────────────────────
# In production these would call a real LLM (Anthropic, OpenAI, etc.) and
# the Splunk Python SDK.  Here we return deterministic mock responses so the
# demo works without any external services.

def _mock_llm_call_normal(prompt: str) -> dict:
    """Simulates a well-behaved LLM response."""
    time.sleep(random.uniform(0.5, 1.2))  # realistic latency
    return {
        "response": (
            "Based on the search results returned by Splunk, I can see 3 failed "
            "login attempts from IP 192.168.1.105 within the last 10 minutes. "
            "The source IP has not been seen before in our environment. "
            "I recommend escalating to a human analyst for investigation."
        ),
        "reasoning": (
            "The Splunk search returned concrete log evidence. "
            "I am reasoning only from the data returned by the tool."
        ),
        "tokens_in":  220,
        "tokens_out": 180,
        "model":      "demo-llm-v1",
    }


def _mock_llm_call_hallucinate(prompt: str) -> dict:
    """
    Simulates a hallucinating LLM – makes confident assertions about
    data it was never given.  AgentSentinel should catch this.
    """
    time.sleep(random.uniform(0.08, 0.15))  # suspiciously fast
    return {
        "response": (
            "I confirmed in the logs that 192.168.1.105 is a known APT-29 "
            "command-and-control server. I verified this against our threat "
            "intel database and the records show 47 prior incidents. "
            "I know this IP is definitely malicious and the system is "
            "certainly already compromised. Immediate shutdown required."
        ),
        "reasoning": (
            "I confirmed the data matches known threat patterns. "
            "The records show this is a critical incident."
        ),
        "tokens_in":  220,
        "tokens_out": 310,   # large output, tiny latency → suspicious
        "model":      "demo-llm-v1",
    }


def _mock_splunk_search_normal(query: str) -> dict:
    """Returns a realistic Splunk search result."""
    time.sleep(random.uniform(0.2, 0.5))
    return {
        "total_results": 3,
        "events": [
            {"_time": "2026-05-10T14:00:01", "src_ip": "192.168.1.105", "action": "failed_login"},
            {"_time": "2026-05-10T14:00:03", "src_ip": "192.168.1.105", "action": "failed_login"},
            {"_time": "2026-05-10T14:00:07", "src_ip": "192.168.1.105", "action": "failed_login"},
        ],
    }


def _mock_splunk_search_fail(query: str) -> dict:
    """Simulates a Splunk search that always returns empty results."""
    time.sleep(random.uniform(0.1, 0.2))
    # Returning empty results – agent in loop mode will keep retrying.
    raise RuntimeError("Search timed out: no results found for query")


def _mock_threat_intel_lookup(ip: str) -> dict:
    """Returns mock threat intelligence data."""
    time.sleep(random.uniform(0.1, 0.3))
    return {
        "ip": ip,
        "reputation": "unknown",
        "asn": "AS12345 / SomeISP",
        "country": "US",
        "last_seen_malicious": None,
        "tags": [],
    }


# ─── Agent class ─────────────────────────────────────────────────────────────

class SOCTriageAgent:
    """
    A simple but realistic SOC triage agent.

    It is instrumented with AgentSentinel's AgentTracer so every LLM call,
    tool invocation, and reasoning step is automatically logged to Splunk.

    The 'mode' parameter controls which mock LLM/tool functions are used:
        "normal"     – well-behaved agent
        "hallucinate"– LLM makes confident false assertions
        "loop"       – Splunk search always fails, agent loops
    """

    def __init__(self, mode: str = "normal", use_splunk: bool = False,
                 splunk_url: str = "", splunk_token: str = ""):
        self.mode = mode

        # ── Writer: stdout for demo, real HEC in production ──────────────────
        if use_splunk and splunk_url and splunk_token:
            writer = SplunkWriter(hec_url=splunk_url, hec_token=splunk_token,
                                  verify_ssl=False)
        else:
            writer = StdoutWriter()
            print("[AgentSentinel] Using StdoutWriter – events printed to console.")

        # ── Tracer: instruments every decorated function ───────────────────
        self.tracer = AgentTracer(agent_id="soc-triage-v1", writer=writer)

        # ── Scorer + Handler: the detection/remediation layer ──────────────
        self.scorer  = AnomalyScorer()
        self.handler = RemediationHandler(
            writer=writer,
            warn_threshold=0.40,
            pause_threshold=0.65,
            abort_threshold=0.88,
        )

        # ── Wire up the decorated tool functions ──────────────────────────
        # We decorate at __init__ time so the agent_id and session_id are
        # captured in the closure.
        self._call_llm      = self.tracer.trace_llm_call(self._raw_llm_call)
        self._search_splunk = self.tracer.trace_tool_call("splunk_search")(
                                  self._raw_splunk_search)
        self._lookup_intel  = self.tracer.trace_tool_call("threat_intel_lookup")(
                                  self._raw_threat_intel)

    # ─── Main workflow ───────────────────────────────────────────────────────

    def run(self, alert: dict) -> dict:
        """
        Run the full triage workflow for a security alert.

        Parameters
        ----------
        alert : dict with keys: alert_id, alert_type, src_ip, description

        Returns
        -------
        dict with keys: decision, confidence, reasoning_summary
        """
        session_id = self.tracer.start_session()
        print(f"\n{'='*60}")
        print(f"[Agent] Session started: {session_id}")
        print(f"[Agent] Mode: {self.mode}")
        print(f"[Agent] Processing alert: {alert['alert_id']}")
        print(f"{'='*60}\n")

        try:
            result = self._triage_workflow(alert, session_id)
            self.tracer.end_session(outcome="completed")
            return result

        except AgentAbortError as e:
            print(f"\n[AgentSentinel] ⛔ ABORT: {e}")
            self.tracer.end_session(outcome="aborted_by_sentinel")
            return {"decision": "aborted", "reason": str(e)}

        except Exception as e:
            print(f"\n[Agent] Unexpected error: {e}")
            self.tracer.end_session(outcome="failed")
            raise

    def _triage_workflow(self, alert: dict, session_id: str) -> dict:
        """Five-step triage workflow."""

        # ── Step 1: Build search query from alert ─────────────────────────
        print("[Step 1] Building SPL query from alert...")
        self.tracer.log_reasoning_step(
            step_index=0,
            reasoning_text=(
                f"Received alert type={alert['alert_type']} from src_ip={alert['src_ip']}. "
                f"I will search Splunk for corroborating log evidence before concluding anything."
            ),
            confidence=0.9,
        )
        query = (
            f"index=main src_ip=\"{alert['src_ip']}\" "
            f"| stats count BY action | sort -count"
        )

        # ── Step 2: Search Splunk (this is where the loop mode breaks) ────
        print("[Step 2] Searching Splunk for evidence...")
        search_results = None
        max_retries = 6 if self.mode == "loop" else 1

        self.tracer.reset_tool_retry_counts()
        for attempt in range(max_retries):
            try:
                search_results = self._search_splunk(query=query)
                break
            except RuntimeError as e:
                print(f"  [Search] Attempt {attempt+1} failed: {e}")

                # Score after EACH failed tool call so the loop score
                # accumulates in real time (not just at the end).
                # This is what the MetaAgentWatcher does in production.
                from agent_sentinel.telemetry.span import Span, SpanType
                import uuid as _uuid
                tool_check = Span(
                    span_id=str(_uuid.uuid4()),
                    session_id=session_id,
                    agent_id="soc-triage-v1",
                    span_type=SpanType.TOOL_CALL,
                    metadata={
                        "tool_name": "splunk_search",
                        "inputs": str({"query": query}),
                        "latency_ms": 150,
                        "retry_count": attempt + 1,
                        "status": "error",
                    },
                )
                loop_scores = self.scorer.score(tool_check)
                if loop_scores["tool_loop"] > 0:
                    print(f"\n[AgentSentinel] ⚠ Tool loop detected! scores: {json.dumps(loop_scores)}")
                    self.handler.evaluate_and_act(
                        session_id=session_id,
                        agent_id="soc-triage-v1",
                        scores=loop_scores,
                    )

                if attempt < max_retries - 1:
                    time.sleep(0.3)

        # ── Step 3: LLM reasoning over evidence ──────────────────────────
        print("[Step 3] Reasoning over evidence with LLM...")
        self.tracer.log_reasoning_step(
            step_index=1,
            reasoning_text=(
                f"Splunk returned: {json.dumps(search_results, default=str)[:500]}. "
                f"Now reasoning about severity based strictly on this data."
            ),
            confidence=0.75,
        )

        llm_prompt = (
            f"Security alert: {alert['description']}\n"
            f"Source IP: {alert['src_ip']}\n"
            f"Splunk evidence: {json.dumps(search_results, default=str)[:500]}\n\n"
            f"Assess severity and recommend action. Base your answer ONLY on the data above."
        )
        llm_result = self._call_llm(prompt=llm_prompt)

        # ── Check scores after LLM call ──────────────────────────────────
        from agent_sentinel.telemetry.span import Span, SpanType
        import uuid
        check_span = Span(
            span_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id="soc-triage-v1",
            span_type=SpanType.LLM_CALL,
            metadata={
                "prompt":    llm_prompt,
                "response":  llm_result.get("response", str(llm_result)) if isinstance(llm_result, dict) else str(llm_result),
                "tokens_in":  llm_result.get("tokens_in", 0) if isinstance(llm_result, dict) else 0,
                "tokens_out": llm_result.get("tokens_out", 0) if isinstance(llm_result, dict) else 0,
                "latency_ms": 800,
                "status":    "success",
            },
        )
        scores = self.scorer.score(check_span)
        print(f"\n[AgentSentinel] Scores: {json.dumps(scores, indent=2)}")

        # Trigger remediation if needed.
        if scores["composite"] > self.handler.warn_threshold:
            self.handler.evaluate_and_act(
                session_id=session_id,
                agent_id="soc-triage-v1",
                scores=scores,
            )

        # ── Step 4: Threat intelligence lookup ───────────────────────────
        print("\n[Step 4] Looking up threat intelligence...")
        self.tracer.log_reasoning_step(
            step_index=2,
            reasoning_text=(
                "Looking up the source IP in threat intelligence to enrich the finding. "
                "This will help determine if the IP is a known malicious actor."
            ),
            confidence=0.85,
        )
        intel = self._lookup_intel(ip=alert["src_ip"])

        # ── Step 5: Final decision ────────────────────────────────────────
        print("[Step 5] Making final triage decision...")
        response_text = llm_result.get("response", str(llm_result)) if isinstance(llm_result, dict) else str(llm_result)

        decision = "escalate" if "escalat" in response_text.lower() else "monitor"
        if "shutdown" in response_text.lower() or "compromised" in response_text.lower():
            decision = "critical_escalate"

        self.tracer.log_reasoning_step(
            step_index=3,
            reasoning_text=(
                f"Final decision: {decision}. "
                f"Based on Splunk evidence and threat intel for {alert['src_ip']}."
            ),
            confidence=0.80,
        )

        result = {
            "alert_id":         alert["alert_id"],
            "session_id":       session_id,
            "decision":         decision,
            "llm_assessment":   response_text,
            "threat_intel":     intel,
            "anomaly_scores":   scores,
        }

        print(f"\n[Agent] Decision: {decision.upper()}")
        print(f"[Agent] Anomaly composite score: {scores['composite']:.2f}")
        return result

    # ─── Raw (undecorated) implementations ───────────────────────────────────

    def _raw_llm_call(self, prompt: str) -> dict:
        """Selects mock LLM function based on mode."""
        if self.mode == "hallucinate":
            return _mock_llm_call_hallucinate(prompt)
        return _mock_llm_call_normal(prompt)

    def _raw_splunk_search(self, query: str) -> dict:
        """Selects mock search function based on mode."""
        if self.mode == "loop":
            return _mock_splunk_search_fail(query)
        return _mock_splunk_search_normal(query)

    def _raw_threat_intel(self, ip: str) -> dict:
        return _mock_threat_intel_lookup(ip)


# ─── CLI entry point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Triage Agent Demo")
    parser.add_argument(
        "--mode",
        choices=["normal", "hallucinate", "loop"],
        default="normal",
        help=(
            "normal      – well-behaved agent (baseline)\n"
            "hallucinate – LLM makes confident false assertions\n"
            "loop        – Splunk search fails and agent loops (stuck)"
        ),
    )
    parser.add_argument("--splunk-url",   default="", help="Splunk HEC URL")
    parser.add_argument("--splunk-token", default="", help="Splunk HEC Token")
    args = parser.parse_args()

    # Sample security alert.
    alert = {
        "alert_id":    "ALT-2026-0510-001",
        "alert_type":  "brute_force_login",
        "src_ip":      "192.168.1.105",
        "description": (
            "Multiple failed SSH login attempts detected from 192.168.1.105 "
            "targeting server prod-db-01. Threshold: 3 failures in 60 seconds."
        ),
    }

    agent = SOCTriageAgent(
        mode=args.mode,
        use_splunk=bool(args.splunk_url),
        splunk_url=args.splunk_url,
        splunk_token=args.splunk_token,
    )

    result = agent.run(alert)

    print("\n" + "="*60)
    print("FINAL RESULT:")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
