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
