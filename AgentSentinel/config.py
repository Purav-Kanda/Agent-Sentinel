# config.py
# ─────────────────────────────────────────────────────────────────────────────
# Central configuration for AgentSentinel.
# Override any value via environment variables for production deployments.
#
# Usage:
#   from config import cfg
#   writer = SplunkWriter(hec_url=cfg.HEC_URL, hec_token=cfg.HEC_TOKEN)
# ─────────────────────────────────────────────────────────────────────────────

import os


class Config:
    # ── Splunk HEC connection ─────────────────────────────────────────────────
    # Set these as environment variables in production:
    #   export SPLUNK_HEC_URL=https://your-splunk:8088/services/collector
    #   export SPLUNK_HEC_TOKEN=your-hec-token
    HEC_URL   = os.getenv("SPLUNK_HEC_URL",   "https://localhost:8088/services/collector")
    HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "YOUR_HEC_TOKEN_HERE")

    # ── Splunk search API (for the MetaAgentWatcher) ──────────────────────────
    SPLUNK_HOST     = os.getenv("SPLUNK_HOST",     "localhost")
    SPLUNK_PORT     = int(os.getenv("SPLUNK_PORT", "8089"))
    SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
    SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "YOUR_PASSWORD_HERE")

    # ── Splunk index ──────────────────────────────────────────────────────────
    SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "agent_telemetry")

    # ── TLS ───────────────────────────────────────────────────────────────────
    # Set to "true" in production with valid certs
    VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    # ── Anomaly thresholds ────────────────────────────────────────────────────
    WARN_THRESHOLD  = float(os.getenv("SENTINEL_WARN_THRESHOLD",  "0.40"))
    PAUSE_THRESHOLD = float(os.getenv("SENTINEL_PAUSE_THRESHOLD", "0.65"))
    ABORT_THRESHOLD = float(os.getenv("SENTINEL_ABORT_THRESHOLD", "0.90"))

    # ── MetaAgentWatcher polling ──────────────────────────────────────────────
    POLL_INTERVAL_S = int(os.getenv("SENTINEL_POLL_INTERVAL", "10"))

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL = os.getenv("SENTINEL_LOG_LEVEL", "INFO")


cfg = Config()
