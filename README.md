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
