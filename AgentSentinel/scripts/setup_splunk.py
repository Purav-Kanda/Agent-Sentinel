# scripts/setup_splunk.py
# ─────────────────────────────────────────────────────────────────────────────
# One-shot setup script: creates the Splunk index and HEC token needed
# by AgentSentinel.  Run once before starting the demo.
#
# Usage:
#   python scripts/setup_splunk.py --host localhost --port 8089 \
#          --username admin --password changeme
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def setup(host: str, port: int, username: str, password: str) -> None:
    try:
        import splunklib.client as client
    except ImportError:
        print("ERROR: splunk-sdk not installed. Run: pip install splunk-sdk")
        sys.exit(1)

    print(f"Connecting to Splunk at {host}:{port} as {username}...")
    service = client.connect(
        host=host, port=port,
        username=username, password=password,
        scheme="https",
    )

    # ── Create index ─────────────────────────────────────────────────────────
    if "agent_telemetry" not in service.indexes:
        print("Creating index: agent_telemetry")
        service.indexes.create(
            "agent_telemetry",
            **{
                "maxDataSize":          "5000",
                "maxTotalDataSizeMB":   "5000",
                "frozenTimePeriodInSecs": "7776000",  # 90 days
            }
        )
        print("  ✓ Index created")
    else:
        print("  ✓ Index already exists")

    # ── Create HEC token ──────────────────────────────────────────────────────
    print("Creating HEC token: agent_sentinel_token")
    try:
        inputs = service.inputs
        hec_input = inputs.create(
            name="agent_sentinel_token",
            kind="http",
            index="agent_telemetry",
            sourcetype="agent_sentinel",
        )
        token = hec_input["token"]
        print(f"  ✓ HEC token created: {token}")
        print(f"\n  Set this in your environment:")
        print(f"  export SPLUNK_HEC_TOKEN={token}")
        print(f"  export SPLUNK_HEC_URL=https://{host}:8088/services/collector")
    except Exception as e:
        print(f"  HEC token creation: {e}")
        print("  (Token may already exist – check Splunk Settings → Data Inputs → HTTP)")

    print("\nSetup complete. You can now run the demo:")
    print("  python agents/soc_triage_agent.py --mode=normal \\")
    print(f"    --splunk-url=https://{host}:8088/services/collector \\")
    print("    --splunk-token=<token-from-above>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentSentinel Splunk Setup")
    parser.add_argument("--host",     default="localhost")
    parser.add_argument("--port",     type=int, default=8089)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    setup(args.host, args.port, args.username, args.password)
