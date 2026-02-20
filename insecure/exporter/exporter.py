#!/usr/bin/env python3
"""
Prometheus Metrics Exporter — Insecure IoT Architecture

Subscribes to all MQTT topics and derives security-relevant metrics
that are exposed via an HTTP endpoint for Prometheus to scrape.

Metrics exposed:
    iot_sensor_value              - current sensor reading per device
    iot_device_online             - device availability (0/1)
    iot_messages_total            - total MQTT messages per topic
    iot_messages_per_device       - total messages per device
    iot_attack_commands_total     - unauthorized commands received per device
    iot_attack_unlock_total       - unauthorized unlock events per device
    iot_attack_poison_total       - data poisoning events per device
    iot_attack_connections_total  - total unauthorized command attempts
    iot_last_attack_timestamp     - Unix timestamp of the last attack event

Endpoint: http://localhost:8000/metrics
"""

import os
import time
import json
import threading
import logging
from collections import defaultdict, deque
from flask import Flask, Response
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("exporter")

BROKER_HOST = os.getenv("BROKER_HOST", "10.10.0.10")
BROKER_PORT = int(os.getenv("BROKER_PORT", 1883))

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Internal metrics state — protected by a threading lock
# ---------------------------------------------------------------------------
_lock = threading.Lock()

state = {
    "sensor_values":       {},                      # device_id -> {value, sensor, unit, timestamp}
    "device_online":       {},                      # device_id -> 0 or 1
    "messages_total":      defaultdict(int),        # topic -> count
    "messages_per_device": defaultdict(int),        # device_id -> count
    "attack_commands":     defaultdict(int),        # device_id -> count
    "unlock_events":       defaultdict(int),        # device_id -> count
    "attack_poison":       defaultdict(int),        # device_id -> count
    "attack_connections":  0,                       # total unauthorized commands
    "attack_timeline":     deque(maxlen=100),       # last 100 attack events
}


# ---------------------------------------------------------------------------
# MQTT Message Processing
# ---------------------------------------------------------------------------

def on_connect(client, userdata, flags, rc):
    """Subscribe to all topics on successful broker connection."""
    log.info(f"Exporter connected to broker (rc={rc})")
    client.subscribe("#")


def on_message(client, userdata, msg):
    """
    Parse each MQTT message and update the corresponding metrics.
    Anomaly detection (data poisoning) is performed here in real time.
    """
    with _lock:
        topic = msg.topic
        parts = topic.split("/")
        now   = time.time()

        state["messages_total"][topic] += 1

        # Only process IoT device topics
        if len(parts) < 3 or parts[0] != "iot":
            return

        device_id = parts[1]
        msg_type  = parts[2]
        state["messages_per_device"][device_id] += 1

        try:
            payload = json.loads(msg.payload.decode())
        except Exception:
            return

        # ── Device status ──────────────────────────────────────────────────
        if msg_type == "status":
            state["device_online"][device_id] = (
                1 if payload.get("status") == "online" else 0
            )

        # ── Sensor data ────────────────────────────────────────────────────
        elif msg_type == "data":
            value  = payload.get("value")
            sensor = payload.get("sensor", "unknown")

            if isinstance(value, (int, float)):
                # Anomaly detection: values outside physical range indicate poisoning
                if value < -50 or value > 200:
                    state["attack_poison"][device_id] += 1
                    state["attack_timeline"].append({
                        "ts": now, "type": "data_poison",
                        "device": device_id, "value": value
                    })
                    log.warning(f"[ANOMALY] Data poisoning detected on {device_id}: {value}")
                else:
                    state["sensor_values"][device_id] = {
                        "value":     float(value),
                        "sensor":    sensor,
                        "unit":      payload.get("unit", ""),
                        "timestamp": now
                    }
            elif isinstance(value, str):
                # Map door lock state to numeric: locked=1, unlocked=0
                numeric = 1 if value == "locked" else 0
                state["sensor_values"][device_id] = {
                    "value":     numeric,
                    "sensor":    sensor,
                    "unit":      "state",
                    "timestamp": now
                }

        # ── Command events ─────────────────────────────────────────────────
        elif msg_type == "cmd":
            cmd = payload.get("cmd", "unknown")
            state["attack_commands"][device_id] += 1
            state["attack_connections"] += 1

            if cmd == "unlock":
                state["unlock_events"][device_id] += 1
                state["attack_timeline"].append(
                    {"ts": now, "type": "unlock", "device": device_id}
                )
            elif cmd == "set_interval":
                state["attack_timeline"].append(
                    {"ts": now, "type": "dos", "device": device_id,
                     "value": payload.get("value")}
                )
            elif cmd == "reboot":
                state["attack_timeline"].append(
                    {"ts": now, "type": "reboot", "device": device_id}
                )


# ---------------------------------------------------------------------------
# Prometheus Exposition Format
# ---------------------------------------------------------------------------

def generate_metrics() -> str:
    """
    Render all metrics in Prometheus text exposition format (version 0.0.4).
    Each metric includes a HELP comment and TYPE declaration.
    """
    lines = []

    with _lock:
        # Sensor values
        lines += [
            "# HELP iot_sensor_value Current sensor reading for each IoT device",
            "# TYPE iot_sensor_value gauge"
        ]
        for dev, data in state["sensor_values"].items():
            labels = f'device="{dev}",sensor="{data["sensor"]}",unit="{data["unit"]}"'
            lines.append(f"iot_sensor_value{{{labels}}} {data['value']}")

        # Device availability
        lines += [
            "# HELP iot_device_online 1 if the device is online, 0 otherwise",
            "# TYPE iot_device_online gauge"
        ]
        for dev, status in state["device_online"].items():
            lines.append(f'iot_device_online{{device="{dev}"}} {status}')

        # Total messages per topic
        lines += [
            "# HELP iot_messages_total Total MQTT messages observed per topic",
            "# TYPE iot_messages_total counter"
        ]
        for topic, count in state["messages_total"].items():
            safe = topic.replace('"', '\\"')
            lines.append(f'iot_messages_total{{topic="{safe}"}} {count}')

        # Messages per device
        lines += [
            "# HELP iot_messages_per_device Total MQTT messages per device",
            "# TYPE iot_messages_per_device counter"
        ]
        for dev, count in state["messages_per_device"].items():
            lines.append(f'iot_messages_per_device{{device="{dev}"}} {count}')

        # Unauthorized commands
        lines += [
            "# HELP iot_attack_commands_total Unauthorized commands injected per device",
            "# TYPE iot_attack_commands_total counter"
        ]
        for dev, count in state["attack_commands"].items():
            lines.append(f'iot_attack_commands_total{{device="{dev}"}} {count}')

        # Unlock events
        lines += [
            "# HELP iot_attack_unlock_total Unauthorized physical unlock events per device",
            "# TYPE iot_attack_unlock_total counter"
        ]
        for dev, count in state["unlock_events"].items():
            lines.append(f'iot_attack_unlock_total{{device="{dev}"}} {count}')

        # Data poisoning
        lines += [
            "# HELP iot_attack_poison_total Data poisoning events detected per device",
            "# TYPE iot_attack_poison_total counter"
        ]
        for dev, count in state["attack_poison"].items():
            lines.append(f'iot_attack_poison_total{{device="{dev}"}} {count}')

        # Total attack connections
        lines += [
            "# HELP iot_attack_connections_total Total unauthorized command attempts",
            "# TYPE iot_attack_connections_total counter"
        ]
        lines.append(f'iot_attack_connections_total {state["attack_connections"]}')

        # Timestamp of last attack
        lines += [
            "# HELP iot_last_attack_timestamp Unix timestamp of the most recent attack event",
            "# TYPE iot_last_attack_timestamp gauge"
        ]
        if state["attack_timeline"]:
            lines.append(f'iot_last_attack_timestamp {state["attack_timeline"][-1]["ts"]}')

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTTP Endpoints
# ---------------------------------------------------------------------------

@app.route("/metrics")
def metrics_endpoint():
    """Prometheus scrape endpoint — returns metrics in text exposition format."""
    return Response(generate_metrics(), mimetype="text/plain; version=0.0.4")


@app.route("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "tracked_devices": len(state["sensor_values"])}


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

def start_mqtt():
    """Connect to the MQTT broker and start the message processing loop."""
    client = mqtt.Client(client_id="prometheus-exporter")
    client.on_connect = on_connect
    client.on_message = on_message
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            client.loop_forever()
        except Exception as e:
            log.error(f"MQTT connection error: {e}. Retrying in 5s...")
            time.sleep(5)


if __name__ == "__main__":
    threading.Thread(target=start_mqtt, daemon=True).start()
    log.info("Prometheus exporter started on :8000")
    app.run(host="0.0.0.0", port=8000, debug=False)
