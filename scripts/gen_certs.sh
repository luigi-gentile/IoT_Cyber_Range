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
