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
