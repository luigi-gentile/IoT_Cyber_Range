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
