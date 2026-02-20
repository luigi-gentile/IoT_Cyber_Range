#!/usr/bin/env python3
"""
IoT Backend — Insecure Architecture

Aggregates sensor data from all MQTT devices and exposes it via a REST API.
Also passively observes command traffic, making injected commands visible
in the /api/events endpoint — useful for thesis attack documentation.

Demonstrated vulnerabilities:
    - No authentication on any REST endpoint
    - All device data accessible to anyone who can reach the server
    - Command injection events logged but not prevented
"""

import os
import json
import time
import threading
import logging
from collections import defaultdict, deque
from flask import Flask, jsonify
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("backend")

BROKER_HOST = os.getenv("BROKER_HOST", "localhost")
BROKER_PORT = int(os.getenv("BROKER_PORT", 1883))

app = Flask(__name__)

# In-memory store: device_id -> last 100 readings
device_data:   dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
device_status: dict[str, dict]  = {}
attack_log:    list[dict]        = []   # passive log of observed commands


# ---------------------------------------------------------------------------
# MQTT Callbacks
# ---------------------------------------------------------------------------

def on_connect(client, userdata, flags, rc):
    """Subscribe to all IoT topics with a wildcard on successful connection."""
    log.info(f"Backend connected to broker (rc={rc})")
    client.subscribe("iot/#")


def on_message(client, userdata, msg):
    """
    Process incoming MQTT messages.
    Routes messages to the appropriate store based on topic type.
    Also records observed commands as attack evidence.
    """
    try:
        payload = json.loads(msg.payload.decode())
        parts   = msg.topic.split("/")

        if len(parts) >= 3:
            device_id = parts[1]
            msg_type  = parts[2]

            if msg_type == "data":
                device_data[device_id].append({**payload, "_received_at": time.time()})

            elif msg_type == "status":
                device_status[device_id] = payload

            elif msg_type == "cmd":
                # Passively log injected commands for the /api/events endpoint
                entry = {
                    "timestamp": time.time(),
                    "device":    device_id,
                    "payload":   payload
                }
                attack_log.append(entry)
                log.warning(f"[PASSIVE OBSERVATION] Command on {msg.topic}: {payload}")

    except Exception as e:
        log.error(f"Message parsing error: {e}")


# ---------------------------------------------------------------------------
# REST API Endpoints
# VULNERABILITY: no authentication decorator on any route
# ---------------------------------------------------------------------------

@app.route("/api/devices")
def get_devices():
    """List all known devices and their current status."""
    return jsonify({"devices": list(device_data.keys()), "status": device_status})


@app.route("/api/devices/<device_id>/data")
def get_device_data(device_id: str):
    """Return the last 100 readings for a specific device."""
    return jsonify({
        "device_id": device_id,
        "readings":  list(device_data.get(device_id, []))
    })


@app.route("/api/devices/all")
def get_all_data():
    """Return all sensor data for all devices — full data exfiltration endpoint."""
    return jsonify({dev: list(readings) for dev, readings in device_data.items()})


@app.route("/api/events")
def get_events():
    """Return the log of all observed commands, including injected ones."""
    return jsonify({"events": attack_log})


@app.route("/health")
def health():
    """Health check endpoint for Docker and monitoring."""
    return jsonify({"status": "ok", "broker": f"{BROKER_HOST}:{BROKER_PORT}"})


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

def start_mqtt():
    """Start the MQTT client in a background thread."""
    client = mqtt.Client(client_id="backend-collector")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    threading.Thread(target=start_mqtt, daemon=True).start()
    log.info("Backend started on :5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
