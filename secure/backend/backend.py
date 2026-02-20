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
