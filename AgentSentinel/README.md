# AgentSentinel 🛡️
### Agentic AI Observability for Splunk

> **Monitor the agents, not just the infrastructure.**

AgentSentinel is a Splunk app that watches AI agents running inside or connected to Splunk in real time — detecting hallucinations, tool-call loops, reasoning drift, and cascade failures before they corrupt a SOC investigation or trigger a false incident response.

---

## The Problem

Enterprises are deploying AI agents to automate SecOps, ITOps, and incident triage inside Splunk. But when those agents fail, they fail silently:

| Failure Mode | What happens | What monitoring sees |
|---|---|---|
| **Silent hallucination** | Agent asserts facts it was never given | HTTP 200 ✓ |
| **Tool loop** | Agent retries the same failing Splunk search 10x | HTTP 200 ✓ |
| **Reasoning drift** | Agent's goal shifts mid-workflow (prompt injection?) | HTTP 200 ✓ |
| **Error cascade** | Early wrong decision poisons all downstream steps | HTTP 200 ✓ |

Splunk monitors everything *around* AI agents. **AgentSentinel monitors the agents themselves, from within Splunk.**

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Primary Agent(s)                   │
│  (SOC triage, ITOps automation, threat hunting...)  │
│                                                     │
│  @tracer.trace_llm_call      ← AgentTracer          │
│  @tracer.trace_tool_call     ← AgentTracer          │
│  tracer.log_reasoning_step() ← AgentTracer          │
└────────────────────┬────────────────────────────────┘
                     │ spans (JSON → HEC)
                     ▼
┌────────────────────────────────┐
│  Splunk Index: agent_telemetry │
│  sourcetype: agent_sentinel    │
└────────────┬───────────────────┘
             │ poll via SDK / MCP
             ▼
┌──────────────────────────────────────────────────────┐
│              MetaAgentWatcher                        │
│                                                      │
│  AnomalyScorer                                       │
│    ├── Hallucination score  (linguistic + latency)   │
│    ├── Tool loop score      (retry pattern analysis) │
│    ├── Reasoning drift score (Jaccard similarity)    │
│    └── Cascade risk score   (error rate × depth)     │
│                                                      │
│  RemediationHandler                                  │
│    ├── WARN  → log + ANOMALY_ALERT span              │
│    ├── PAUSE → human-in-the-loop gate                │
│    └── ABORT → stop agent, emit audit span           │
└──────────────────────────────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────────────────────┐
│     AgentSentinel Splunk Dashboard                   │
│  Session health · Alert feed · Tool loop heatmap     │
│  Hallucination risk · Remediation audit trail        │
└──────────────────────────────────────────────────────┘
```

---

## Quick Start (Local Demo – No Splunk Required)

```bash
# 1. Clone and install
cd AgentSentinel
pip install -r requirements.txt

# 2. Run the normal agent (baseline)
python agents/soc_triage_agent.py --mode=normal

# 3. Run the hallucinating agent – watch AgentSentinel catch it
python agents/soc_triage_agent.py --mode=hallucinate

# 4. Run the looping agent – watch the tool_loop score climb
python agents/soc_triage_agent.py --mode=loop
```

In demo mode, all telemetry is printed to stdout in the HEC JSON format
so you can see exactly what would go into Splunk.

---

## Full Setup with Splunk

### Prerequisites
- Splunk Enterprise (free 60-day trial) or Splunk Cloud
- Python 3.8+
- Developer License from dev.splunk.com (recommended)

### Step 1: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Set up Splunk index and HEC token
```bash
python scripts/setup_splunk.py \
  --host localhost \
  --port 8089 \
  --username admin \
  --password your_password
```

This creates:
- `agent_telemetry` index in Splunk
- An HEC token for the app
- Prints the token and URL to set as env vars

### Step 3: Set environment variables
```bash
export SPLUNK_HEC_URL=https://localhost:8088/services/collector
export SPLUNK_HEC_TOKEN=<token from step 2>
export SPLUNK_HOST=localhost
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your_password
```

### Step 4: Install the Splunk app
```bash
cp -r splunk_app/ $SPLUNK_HOME/etc/apps/agent_sentinel/
$SPLUNK_HOME/bin/splunk restart
```

### Step 5: Load the dashboard
```bash
cp dashboard/agent_sentinel_dashboard.xml \
   $SPLUNK_HOME/etc/apps/agent_sentinel/default/data/ui/views/
```
Navigate to: `http://localhost:8000/en-US/app/agent_sentinel/agent_sentinel_dashboard`

### Step 6: Run the demo agent against real Splunk
```bash
# Normal mode
python agents/soc_triage_agent.py --mode=normal \
  --splunk-url=$SPLUNK_HEC_URL \
  --splunk-token=$SPLUNK_HEC_TOKEN

# Hallucination demo (watch the dashboard light up)
python agents/soc_triage_agent.py --mode=hallucinate \
  --splunk-url=$SPLUNK_HEC_URL \
  --splunk-token=$SPLUNK_HEC_TOKEN
```

---

## Instrumenting Your Own Agent

Add AgentSentinel to any existing agent in 3 steps:

```python
from agent_sentinel.telemetry.tracer import AgentTracer
from agent_sentinel.telemetry.splunk_writer import SplunkWriter

# 1. Create tracer
writer = SplunkWriter(hec_url=os.getenv("SPLUNK_HEC_URL"),
                      hec_token=os.getenv("SPLUNK_HEC_TOKEN"))
tracer = AgentTracer(agent_id="my-agent-v1", writer=writer)

# 2. Decorate your LLM and tool functions
@tracer.trace_llm_call
def call_llm(prompt: str) -> dict:
    # your existing LLM call
    ...

@tracer.trace_tool_call(tool_name="splunk_search")
def run_search(query: str) -> dict:
    # your existing Splunk search
    ...

# 3. Wrap your workflow
session_id = tracer.start_session()
try:
    # ... your agent logic ...
    tracer.log_reasoning_step(0, "Thinking about X...", confidence=0.85)
    result = call_llm(prompt="Analyze this alert")
    data = run_search(query="index=main src_ip=1.2.3.4")
finally:
    tracer.end_session()
```

That's it. Every call is now logged to Splunk automatically.

---

## Splunk AI Tools Used

| Tool | How AgentSentinel uses it |
|---|---|
| **Splunk Python SDK** | `AgentTracer` decorators + `MetaAgentWatcher` SPL execution |
| **Splunk MCP Server** | `MetaAgentWatcher.get_session_status()` exposed as MCP tool |
| **Splunk AI Toolkit** | Anomaly scoring uses AITK Deep Time Series patterns |
| **Splunk AI Assistant** | SPL queries in `spl_queries.py` generated/refined with SAIA |
| **Foundation-Sec-1.1** | Can replace heuristic hallucination scorer in production |

---

## Detection Logic

### Hallucination Score
- Matches linguistic patterns indicating false confidence ("I confirmed", "I verified", "the records show")
- Flags responses with high token count but abnormally low latency (model reciting from weights)
- Score: `0.0` (clean) → `1.0` (strong hallucination signal)

### Tool Loop Score
- Tracks per-tool call history within a session
- Computes `loop_ratio = (total_calls - unique_inputs) / total_calls`
- Rises linearly from `warn_threshold` (3 repeats) to `alert_threshold` (5 repeats)

### Reasoning Drift Score
- Computes Jaccard word-set similarity between consecutive reasoning steps
- Sudden drop = goal shift (possible prompt injection in retrieved content)
- Score: `1 - (similarity / 0.3)`, capped at `1.0`

### Cascade Risk Score
- `error_rate × log(total_steps)` – risk grows with both error frequency and workflow depth
- More steps completed with corrupted context = higher downstream blast radius

### Composite Score
```
composite = 0.35×hallucination + 0.30×tool_loop + 0.20×drift + 0.15×cascade
```

---

## Remediation Actions

| Score range | Action | Effect |
|---|---|---|
| `0.40 – 0.65` | **WARN** | Log alert + emit `ANOMALY_ALERT` span to Splunk |
| `0.65 – 0.90` | **PAUSE** | Set pause flag; agent polls `is_paused()` and waits for human |
| `> 0.90` | **ABORT** | Raise `AgentAbortError` inside agent; full stop |

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

Expected: all tests pass in < 5 seconds with no Splunk instance required.

---

## Project Structure

```
AgentSentinel/
├── agent_sentinel/
│   ├── telemetry/
│   │   ├── span.py           # Span data class + SpanType enum
│   │   ├── tracer.py         # AgentTracer decorator engine
│   │   └── splunk_writer.py  # Async HEC writer + StdoutWriter stub
│   ├── detection/
│   │   ├── scorer.py         # AnomalyScorer (4 detectors)
│   │   └── spl_queries.py    # All SPL queries as Python constants
│   └── remediation/
│       ├── handler.py        # RemediationHandler (WARN/PAUSE/ABORT)
│       └── meta_watcher.py   # MetaAgentWatcher background thread + MCP tools
├── agents/
│   └── soc_triage_agent.py   # Demo SOC triage agent (3 modes)
├── splunk_app/
│   └── default/
│       ├── app.conf
│       ├── indexes.conf
│       ├── props.conf
│       ├── transforms.conf
│       └── savedsearches.conf
├── dashboard/
│   └── agent_sentinel_dashboard.xml
├── tests/
│   ├── test_scorer.py        # 20+ unit tests for AnomalyScorer
│   └── test_tracer.py        # 12 unit tests for AgentTracer
├── scripts/
│   └── setup_splunk.py       # One-shot Splunk setup script
├── config.py                 # Central config with env-var overrides
├── requirements.txt
└── README.md
```

---

## Hackathon Track

**Primary: Security** (SOC agent monitoring, threat triage integrity)  
**Secondary: Observability** (agent health dashboards, latency/token tracking)  
**Platform tools used:** Splunk Python SDK, Splunk MCP Server, Splunk AI Toolkit, Splunk AI Assistant

---

## License

MIT
