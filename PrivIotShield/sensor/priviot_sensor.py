"""
PrivIoT Lightweight Standalone Edge Sensor (Phase 2)
Captures local traffic metadata, buffers with backpressure, and streams authenticated batches to PrivIoT Control Plane.
"""

import os
import sys
import time
import json
import socket
import logging
import signal
import urllib.request
import urllib.error
from queue import Queue, Full

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("priviot_sensor")

API_URL = os.environ.get("PRIVIOT_API_URL", "http://localhost:5000/api/v2/telemetry/ingest")
SENSOR_TOKEN = os.environ.get("PRIVIOT_SENSOR_TOKEN", "")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
FLUSH_INTERVAL = float(os.environ.get("FLUSH_INTERVAL", "5.0"))
QUEUE_MAX_SIZE = int(os.environ.get("QUEUE_MAX_SIZE", "5000"))

telemetry_queue: Queue = Queue(maxsize=QUEUE_MAX_SIZE)
running = True


def handle_shutdown(signum, frame):
    global running
    logger.info("Received termination signal. Shutting down PrivIoT Sensor gracefully...")
    running = False


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


def push_event(event_dict):
    """Enqueue event with non-blocking backpressure drop if buffer full."""
    try:
        telemetry_queue.put_nowait(event_dict)
    except Full:
        logger.warning("Telemetry buffer full! Dropping event due to backpressure.")


def transmit_batch(events):
    """Post event batch to PrivIoT API over authenticated HTTP/TLS."""
    if not events or not SENSOR_TOKEN:
        return False

    payload = json.dumps(events).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Sensor-Token": SENSOR_TOKEN
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in (200, 201):
                logger.info(f"Successfully transmitted {len(events)} telemetry events.")
                return True
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error transmitting telemetry: {e.code} - {e.read().decode('utf-8')}")
    except Exception as e:
        logger.error(f"Failed to connect to PrivIoT Control Plane: {e}")

    return False


def run_sensor_loop():
    logger.info("PrivIoT Lightweight Sensor started.")
    last_flush = time.time()
    batch = []

    while running:
        try:
            # Drain queue up to BATCH_SIZE
            while len(batch) < BATCH_SIZE and not telemetry_queue.empty():
                batch.append(telemetry_queue.get_nowait())

            now = time.time()
            if batch and (len(batch) >= BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL):
                success = transmit_batch(batch)
                if success:
                    batch.clear()
                    last_flush = now
                else:
                    # Retry backoff
                    time.sleep(2.0)

            time.sleep(0.1)
        except Exception as e:
            logger.error(f"Unexpected sensor loop error: {e}")
            time.sleep(1.0)

    # Flush remaining on shutdown
    if batch:
        transmit_batch(batch)
    logger.info("PrivIoT Sensor stopped.")


if __name__ == "__main__":
    run_sensor_loop()
