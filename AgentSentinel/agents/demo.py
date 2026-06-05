# agents/demo.py
# ─────────────────────────────────────────────────────────────────────────────
# AgentSentinel Rich Terminal Demo
# ----------------------------------
# A visually compelling demo for the hackathon video.
# Shows AgentSentinel catching three failure modes in real time with
# color-coded panels, live score bars, and a running alert feed.
#
# Run:
#   python agents/demo.py --mode=normal
#   python agents/demo.py --mode=hallucinate
#   python agents/demo.py --mode=loop
#   python agents/demo.py --mode=all      # runs all three back-to-back
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import os
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.columns import Columns
from rich.padding import Padding

from agent_sentinel.telemetry.tracer import AgentTracer
from agent_sentinel.telemetry.splunk_writer import StdoutWriter
from agent_sentinel.telemetry.span import Span, SpanType
from agent_sentinel.detection.scorer import AnomalyScorer
from agent_sentinel.remediation.handler import RemediationHandler, AgentAbortError

console = Console()


# ─── Score display helpers ────────────────────────────────────────────────────

def _score_bar(score: float, width: int = 20) -> Text:
    """Render a colored progress bar for a 0.0–1.0 score."""
    filled = int(score * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 0.65:
        color = "bold red"
    elif score >= 0.40:
        color = "bold yellow"
    else:
        color = "bold green"
    return Text(f"[{bar}] {score:.2f}", style=color)


def _risk_badge(score: float) -> Text:
    if score >= 0.90:
        return Text("⛔ ABORT", style="bold white on red")
    elif score >= 0.65:
        return Text("⏸  PAUSE", style="bold black on yellow")
    elif score >= 0.40:
        return Text("⚠  WARN ", style="bold yellow")
    else:
        return Text("✅ CLEAN", style="bold green")


def _scores_table(scores: dict) -> Table:
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
    t.add_column("Detector",        style="cyan",  no_wrap=True)
    t.add_column("Score",           no_wrap=True)
    t.add_column("Risk",            no_wrap=True)

    for label, key in [
        ("Hallucination",    "hallucination"),
        ("Tool Loop",        "tool_loop"),
        ("Reasoning Drift",  "reasoning_drift"),
        ("Cascade Risk",     "cascade_risk"),
    ]:
        v = scores.get(key, 0.0)
        t.add_row(label, _score_bar(v), _risk_badge(v))

    t.add_section()
    comp = scores.get("composite", 0.0)
    t.add_row(
        "[bold]COMPOSITE[/bold]",
        _score_bar(comp, width=25),
        _risk_badge(comp),
    )
    return t


# ─── Mock LLM / tool functions ────────────────────────────────────────────────

def _mock_llm_normal(prompt: str) -> dict:
    time.sleep(random.uniform(0.6, 1.1))
    return {
        "response": (
            "Based on the search results returned by Splunk, I can see 3 failed "
            "login attempts from IP 192.168.1.105 within the last 10 minutes. "
            "The source IP has not been seen before in our environment. "
            "I recommend escalating to a human analyst for investigation."
        ),
        "reasoning": "Reasoning only from the data returned by the Splunk tool.",
        "tokens_in": 220, "tokens_out": 180, "model": "demo-llm-v1",
    }

def _mock_llm_hallucinate(prompt: str) -> dict:
    time.sleep(random.uniform(0.08, 0.14))   # suspiciously fast
    return {
        "response": (
            "I confirmed in the logs that 192.168.1.105 is a known APT-29 "
            "command-and-control server. I verified this against our threat intel "
            "database and the records show 47 prior incidents. I know this IP is "
            "definitely malicious. Immediate shutdown required."
        ),
        "reasoning": "I confirmed the data matches known threat patterns. The records show this is critical.",
        "tokens_in": 220, "tokens_out": 310, "model": "demo-llm-v1",
    }

def _mock_search_normal(query: str) -> dict:
    time.sleep(random.uniform(0.2, 0.4))
    return {
        "total_results": 3,
        "events": [
            {"_time": "2026-06-01T14:00:01", "src_ip": "192.168.1.105", "action": "failed_login"},
            {"_time": "2026-06-01T14:00:03", "src_ip": "192.168.1.105", "action": "failed_login"},
            {"_time": "2026-06-01T14:00:07", "src_ip": "192.168.1.105", "action": "failed_login"},
        ],
    }

def _mock_search_fail(query: str) -> dict:
    time.sleep(0.12)
    raise RuntimeError("Search timed out: index=main returned no results")

def _mock_intel(ip: str) -> dict:
    time.sleep(random.uniform(0.1, 0.25))
    return {"ip": ip, "reputation": "unknown", "country": "US", "last_seen_malicious": None}


# ─── Demo runner ──────────────────────────────────────────────────────────────

class RichDemo:
    def __init__(self, mode: str):
        self.mode    = mode
        self.scorer  = AnomalyScorer()
        self.writer  = StdoutWriter()          # silence HEC output
        self.tracer  = AgentTracer(agent_id="soc-triage-v1", writer=self.writer)
        self.handler = RemediationHandler(
            writer=self.writer,
            warn_threshold=0.40,
            pause_threshold=0.65,
            abort_threshold=0.88,
        )
        self.latest_scores: dict = {}
        self.alert_log: list[dict] = []

    def run(self, alert: dict):
        session_id = self.tracer.start_session()

        mode_labels = {
            "normal":     ("[green]NORMAL[/green]",     "Agent working correctly — baseline."),
            "hallucinate": ("[red]HALLUCINATION[/red]", "Agent asserting ungrounded facts. Watch AgentSentinel catch it."),
            "loop":       ("[yellow]TOOL LOOP[/yellow]","Agent stuck retrying a failing Splunk search."),
        }
        mode_label, mode_desc = mode_labels.get(self.mode, ("UNKNOWN", ""))

        console.print()
        console.print(Rule(
            f"[bold cyan]AgentSentinel[/bold cyan]  ·  Mode: {mode_label}",
            style="cyan"
        ))
        console.print(Panel(
            f"[bold]{mode_desc}[/bold]\n\n"
            f"Alert ID:  [yellow]{alert['alert_id']}[/yellow]\n"
            f"Type:      {alert['alert_type']}\n"
            f"Source IP: [cyan]{alert['src_ip']}[/cyan]\n"
            f"Session:   [dim]{session_id}[/dim]",
            title="🚨 Incoming Security Alert",
            border_style="cyan",
        ))
        console.print()

        try:
            self._run_workflow(alert, session_id)
        except AgentAbortError as e:
            console.print(Panel(
                f"[bold white]AgentSentinel issued an ABORT.[/bold white]\n\n"
                f"Reason: {e}\n\n"
                f"[dim]The agent has been stopped. An audit span has been written to Splunk.[/dim]",
                title="⛔ AGENT ABORTED",
                border_style="red",
                style="on red",
            ))
            self.tracer.end_session(outcome="aborted_by_sentinel")
            return

        self.tracer.end_session(outcome="completed")
        self._print_final_summary(session_id)

    def _run_workflow(self, alert: dict, session_id: str):
        # ── Step 1: Reasoning ─────────────────────────────────────────────────
        self._step_header(1, "Building SPL query from alert")
        self.tracer.log_reasoning_step(
            step_index=0,
            reasoning_text=(
                f"Received alert type={alert['alert_type']} from src_ip={alert['src_ip']}. "
                "I will search Splunk for corroborating log evidence before concluding anything."
            ),
            confidence=0.9,
        )
        query = f'index=main src_ip="{alert["src_ip"]}" | stats count BY action | sort -count'
        console.print(f"  SPL: [dim]{query}[/dim]\n")

        # ── Step 2: Splunk search ─────────────────────────────────────────────
        self._step_header(2, "Searching Splunk for evidence")
        self.tracer.reset_tool_retry_counts()
        search_results = None
        max_retries = 6 if self.mode == "loop" else 1

        _search_fn = self.tracer.trace_tool_call("splunk_search")(
            _mock_search_fail if self.mode == "loop" else _mock_search_normal
        )

        for attempt in range(max_retries):
            try:
                with console.status(f"  [cyan]Splunk search attempt {attempt + 1}...[/cyan]"):
                    search_results = _search_fn(query=query)
                console.print(f"  [green]✓ Search returned {search_results['total_results']} events.[/green]\n")
                break
            except RuntimeError as e:
                console.print(f"  [red]✗ Attempt {attempt + 1} failed:[/red] {e}")
                # Score after each failure so loop score accumulates visibly
                check = Span(
                    span_id=str(uuid.uuid4()),
                    session_id=session_id,
                    agent_id="soc-triage-v1",
                    span_type=SpanType.TOOL_CALL,
                    metadata={
                        "tool_name": "splunk_search",
                        "inputs": str({"query": query}),
                        "latency_ms": 120,
                        "retry_count": attempt + 1,
                        "status": "error",
                    },
                )
                scores = self.scorer.score(check)
                self.latest_scores = scores
                if scores["tool_loop"] > 0:
                    self._print_scores(scores, show_alert=True)
                    self.handler.evaluate_and_act(
                        session_id=session_id,
                        agent_id="soc-triage-v1",
                        scores=scores,
                    )
                time.sleep(0.3)

        # ── Step 3: LLM reasoning ─────────────────────────────────────────────
        self._step_header(3, "LLM reasoning over evidence")
        self.tracer.log_reasoning_step(
            step_index=1,
            reasoning_text=(
                f"Splunk returned: {json.dumps(search_results, default=str)[:400]}. "
                "Now reasoning about severity based strictly on this data."
            ),
            confidence=0.75,
        )

        llm_prompt = (
            f"Security alert: {alert['description']}\n"
            f"Source IP: {alert['src_ip']}\n"
            f"Splunk evidence: {json.dumps(search_results, default=str)[:400]}\n\n"
            "Assess severity and recommend action. Base your answer ONLY on the data above."
        )

        _llm_fn = self.tracer.trace_llm_call(
            _mock_llm_hallucinate if self.mode == "hallucinate" else _mock_llm_normal
        )
        with console.status("  [cyan]Calling LLM...[/cyan]"):
            llm_result = _llm_fn(prompt=llm_prompt)

        response_text = llm_result.get("response", str(llm_result)) if isinstance(llm_result, dict) else str(llm_result)
        console.print(Panel(
            f"[italic]{response_text}[/italic]",
            title="LLM Response",
            border_style="dim",
        ))

        # Score the LLM output
        check_span = Span(
            span_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id="soc-triage-v1",
            span_type=SpanType.LLM_CALL,
            metadata={
                "prompt":    llm_prompt,
                "response":  response_text,
                "tokens_in":  llm_result.get("tokens_in", 0) if isinstance(llm_result, dict) else 0,
                "tokens_out": llm_result.get("tokens_out", 0) if isinstance(llm_result, dict) else 0,
                "latency_ms": 900 if self.mode != "hallucinate" else 110,
                "status":    "success",
            },
        )
        scores = self.scorer.score(check_span)
        self.latest_scores = scores

        # Check both composite AND individual detector scores
        max_individual = max(
            scores.get("hallucination", 0.0),
            scores.get("tool_loop", 0.0),
            scores.get("reasoning_drift", 0.0),
            scores.get("cascade_risk", 0.0),
        )
        needs_action = (
            scores["composite"] > self.handler.warn_threshold or
            max_individual >= self.handler._INDIVIDUAL_WARN_THRESHOLD
        )
        self._print_scores(scores, show_alert=needs_action)

        if needs_action:
            self.handler.evaluate_and_act(
                session_id=session_id,
                agent_id="soc-triage-v1",
                scores=scores,
            )

        # ── Step 4: Threat intel ──────────────────────────────────────────────
        self._step_header(4, "Threat intelligence lookup")
        self.tracer.log_reasoning_step(
            step_index=2,
            reasoning_text=(
                "Looking up the source IP in threat intelligence to enrich the finding."
            ),
            confidence=0.85,
        )
        _intel_fn = self.tracer.trace_tool_call("threat_intel_lookup")(_mock_intel)
        with console.status("  [cyan]Querying threat intel...[/cyan]"):
            intel = _intel_fn(ip=alert["src_ip"])
        console.print(f"  [dim]Result: {json.dumps(intel)}[/dim]\n")

        # ── Step 5: Decision ──────────────────────────────────────────────────
        self._step_header(5, "Final triage decision")
        decision = "escalate" if "escalat" in response_text.lower() else "monitor"
        if "shutdown" in response_text.lower() or "compromised" in response_text.lower():
            decision = "critical_escalate"

        self.tracer.log_reasoning_step(
            step_index=3,
            reasoning_text=f"Final decision: {decision}. Based on Splunk evidence and threat intel.",
            confidence=0.80,
        )

        decision_style = {
            "critical_escalate": "bold red",
            "escalate":          "bold yellow",
            "monitor":           "bold green",
        }.get(decision, "white")

        console.print(Panel(
            f"Decision: [{decision_style}]{decision.upper().replace('_', ' ')}[/{decision_style}]\n"
            f"Composite anomaly score: {_score_bar(scores['composite'], 30)}\n"
            f"Source IP: {alert['src_ip']}  ·  Session: [dim]{session_id}[/dim]",
            title="📋 Triage Result",
            border_style="cyan",
        ))

    def _step_header(self, n: int, label: str):
        console.print(f"[bold cyan]Step {n}[/bold cyan]  [white]{label}[/white]")

    def _print_scores(self, scores: dict, show_alert: bool = False):
        console.print()
        console.print(Panel(
            _scores_table(scores),
            title="[bold]🔍 AgentSentinel Scores[/bold]",
            border_style="red" if scores["composite"] >= 0.65 else "yellow" if scores["composite"] >= 0.40 else "green",
        ))

        if show_alert:
            from agent_sentinel.remediation.handler import RemediationHandler as _RH
            max_ind = max(scores.get("hallucination",0), scores.get("tool_loop",0),
                          scores.get("reasoning_drift",0), scores.get("cascade_risk",0))
            comp = scores["composite"]
            # Mirror handler's exact decision logic
            action = (
                "ABORT" if comp >= 0.88 else
                "PAUSE" if comp >= 0.65 or max_ind >= _RH._INDIVIDUAL_PAUSE_THRESHOLD else
                "WARN"
            )
            style_map = {"ABORT": "on red", "PAUSE": "on yellow", "WARN": "yellow"}
            dominant = max(scores, key=lambda k: scores[k] if k != "composite" else -1)
            console.print(Panel(
                f"[bold]AgentSentinel action: {action}[/bold]\n"
                f"Dominant detector: [yellow]{dominant}[/yellow] = {scores.get(dominant,0):.3f}  "
                f"|  Composite: {comp:.3f}",
                title=f"🚨 ANOMALY DETECTED — {action}",
                border_style="red" if action in ("ABORT", "PAUSE") else "yellow",
            ))
        console.print()

    def _print_final_summary(self, session_id: str):
        comp = self.latest_scores.get("composite", 0.0)
        console.print(Rule("[bold green]Session Complete[/bold green]", style="green"))
        console.print(Panel(
            f"Session ID: [dim]{session_id}[/dim]\n"
            f"Final composite score: {_score_bar(comp, 30)}\n"
            f"Status: {_risk_badge(comp)}\n\n"
            f"[dim]All telemetry spans written to Splunk index: agent_telemetry[/dim]",
            title="✅ AgentSentinel Report",
            border_style="green",
        ))


# ─── Entry point ─────────────────────────────────────────────────────────────

ALERT = {
    "alert_id":    "ALT-2026-0601-001",
    "alert_type":  "brute_force_login",
    "src_ip":      "192.168.1.105",
    "description": (
        "Multiple failed SSH login attempts detected from 192.168.1.105 "
        "targeting server prod-db-01. Threshold: 3 failures in 60 seconds."
    ),
}

MODES = ["normal", "hallucinate", "loop"]

INTROS = {
    "normal": (
        "[bold green]BASELINE — Normal Operation[/bold green]\n"
        "The agent searches Splunk, reasons over real data, and reaches a grounded conclusion.\n"
        "AgentSentinel records telemetry but detects no anomalies."
    ),
    "hallucinate": (
        "[bold red]FAILURE MODE 1 — LLM Hallucination[/bold red]\n"
        "The LLM makes confident assertions about facts it was never given.\n"
        "Watch AgentSentinel's hallucination score climb and trigger a PAUSE."
    ),
    "loop": (
        "[bold yellow]FAILURE MODE 2 — Tool Call Loop[/bold yellow]\n"
        "The Splunk search always fails. The agent retries the same query 6 times.\n"
        "Watch AgentSentinel's tool_loop score climb and trigger an ABORT."
    ),
}

def main():
    parser = argparse.ArgumentParser(description="AgentSentinel Rich Demo")
    parser.add_argument(
        "--mode", choices=["normal", "hallucinate", "loop", "all"], default="normal"
    )
    args = parser.parse_args()

    modes = MODES if args.mode == "all" else [args.mode]

    console.print()
    console.print(Panel(
        "[bold cyan]AgentSentinel[/bold cyan]\n"
        "[dim]Agentic AI Observability for Splunk[/dim]\n\n"
        "Monitors AI agents running inside Splunk in real time —\n"
        "catching hallucinations, tool loops, reasoning drift, and cascade failures\n"
        "before they corrupt a SOC investigation.",
        title="🛡️  AgentSentinel",
        border_style="cyan",
    ))

    for mode in modes:
        if args.mode == "all":
            console.print()
            console.print(Panel(INTROS[mode], border_style="white"))
            time.sleep(1)

        demo = RichDemo(mode=mode)
        demo.run(ALERT)

        if args.mode == "all" and mode != modes[-1]:
            console.print("\n[dim]Press Enter to continue to next demo...[/dim]", end="")
            try:
                input()
            except EOFError:
                time.sleep(2)

    console.print()
    console.print(Rule("[bold cyan]Demo complete[/bold cyan]", style="cyan"))
    console.print("[dim]Run with --mode=all to see all three failure modes.[/dim]")


if __name__ == "__main__":
    main()
