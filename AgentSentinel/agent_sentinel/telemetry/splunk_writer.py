# agent_sentinel/telemetry/splunk_writer.py
# ─────────────────────────────────────────────────────────────────────────────
# SplunkWriter
# ------------
# Responsible for POSTing span events to the Splunk HTTP Event Collector (HEC).
#
# HEC is Splunk's recommended high-throughput ingest API.  A single POST can
# carry many events (batching), which keeps network overhead low.
#
# Architecture:
#   1. Spans are pushed into an in-memory queue (thread-safe).
#   2. A background daemon thread flushes the queue every FLUSH_INTERVAL_MS ms
#      OR whenever the queue reaches BATCH_SIZE events.
#   3. On shutdown (or explicit flush()) remaining events are drained.
#
# This means the agent's hot path (the LLM call itself) is never blocked
# waiting for a network round-trip to Splunk.
# ─────────────────────────────────────────────────────────────────────────────

import json
import queue
import threading
import time
import logging
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from agent_sentinel.telemetry.span import Span

logger = logging.getLogger(__name__)


class SplunkWriter:
    """
    Async, batching writer for Splunk HEC.

    Parameters
    ----------
    hec_url   : Full HEC endpoint, e.g. "https://localhost:8088/services/collector"
    hec_token : HEC token created in Splunk Settings → Data Inputs → HTTP Event Collector
    index     : Target Splunk index (must exist and be allowed by the token).
    verify_ssl: Set False only for local dev with self-signed certs.
    batch_size: Max events per HTTP POST (Splunk recommends ≤ 100).
    flush_interval_ms: How often the background thread wakes to flush.
    """

    BATCH_SIZE         = 50
    FLUSH_INTERVAL_MS  = 2000   # flush at least every 2 seconds
    QUEUE_MAX          = 10_000 # drop if backpressure > 10k events

    def __init__(
        self,
        hec_url:          str,
        hec_token:        str,
        index:            str  = "agent_telemetry",
        verify_ssl:       bool = True,
        batch_size:       int  = BATCH_SIZE,
        flush_interval_ms: int = FLUSH_INTERVAL_MS,
    ):
        self.hec_url           = hec_url
        self.hec_token         = hec_token
        self.index             = index
        self.verify_ssl        = verify_ssl
        self.batch_size        = batch_size
        self.flush_interval_s  = flush_interval_ms / 1000.0

        # Thread-safe queue between the instrumented code and the flusher.
        self._queue: queue.Queue = queue.Queue(maxsize=self.QUEUE_MAX)
        self._stop_event         = threading.Event()

        # Build an HTTP session with automatic retries on transient errors.
        self._session = self._build_session()

        # Start the background flusher daemon thread.
        self._flusher = threading.Thread(
            target=self._flush_loop,
            name="agent-sentinel-flusher",
            daemon=True,   # dies with the main process – no zombie threads
        )
        self._flusher.start()

    # ─── Public API ──────────────────────────────────────────────────────────

    def write(self, span: Span) -> None:
        """
        Enqueue a span for async delivery to Splunk.
        This call returns immediately (non-blocking).
        Drops silently if queue is full (backpressure protection).
        """
        try:
            self._queue.put_nowait(span)
        except queue.Full:
            logger.warning("AgentSentinel queue full – dropping span %s", span.span_id)

    def flush(self) -> None:
        """Force-drain the queue right now (call before process exit)."""
        self._drain()

    def close(self) -> None:
        """Flush remaining events and stop the background thread."""
        self._stop_event.set()
        self.flush()
        self._flusher.join(timeout=5)
        self._session.close()

    # ─── Background flusher ──────────────────────────────────────────────────

    def _flush_loop(self) -> None:
        """
        Background thread: wakes every FLUSH_INTERVAL_S seconds and drains
        the queue.  Also wakes early if BATCH_SIZE events are waiting.
        """
        while not self._stop_event.is_set():
            # Sleep in small increments so we can respond to stop_event quickly.
            deadline = time.time() + self.flush_interval_s
            while time.time() < deadline and not self._stop_event.is_set():
                if self._queue.qsize() >= self.batch_size:
                    break
                time.sleep(0.05)

            self._drain()

    def _drain(self) -> None:
        """Pull up to BATCH_SIZE events from the queue and POST them."""
        batch = []
        try:
            while len(batch) < self.batch_size:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        if not batch:
            return

        self._post_to_hec(batch)

    def _post_to_hec(self, spans: list) -> None:
        """
        Serialise a list of Spans and POST to HEC.

        HEC accepts multiple events in one request when each event JSON
        object is newline-delimited (not a JSON array).
        """
        # Build a newline-separated string of JSON event objects.
        payload = "\n".join(
            json.dumps(span.to_hec_payload()) for span in spans
        )

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type":  "application/json",
        }

        try:
            resp = self._session.post(
                self.hec_url,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=5,
            )
            if resp.status_code != 200:
                logger.error(
                    "HEC returned %s: %s", resp.status_code, resp.text[:200]
                )
        except requests.RequestException as exc:
            logger.error("Failed to POST to HEC: %s", exc)

    # ─── HTTP session with retries ────────────────────────────────────────────

    @staticmethod
    def _build_session() -> requests.Session:
        """
        Build a requests.Session with exponential-backoff retries for
        transient network errors and 5xx responses from Splunk.
        """
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        return session


# ─── Dev / test stub ─────────────────────────────────────────────────────────

class StdoutWriter:
    """
    Drop-in replacement for SplunkWriter that prints events to stdout.
    Use this in local development when you don't have Splunk running.

    Usage:
        writer = StdoutWriter()
        tracer = AgentTracer(agent_id="test", writer=writer)
    """

    def write(self, span: Span) -> None:
        print(json.dumps(span.to_hec_payload(), indent=2))

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
