#!/usr/bin/env bash
#
# Export the CA certificates of a TLS-inspecting proxy so the scanner image can
# be built behind it. Linux/macOS counterpart of export-proxy-ca.ps1.
#
# Corporate proxies (Netskope, Zscaler, Palo Alto, Fortinet deep inspection, …)
# re-sign every HTTPS connection with a private CA that the python:3.12-slim
# build container does not trust, so `pip install` fails with
# CERTIFICATE_VERIFY_FAILED.
#
#   ./scripts/export-proxy-ca.sh
#   docker compose build scanner
#
set -euo pipefail

TARGET_HOST="${1:-pypi.org}"
PORT="${2:-443}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${OUT_FILE:-$ROOT/certs/proxy-ca.crt}"

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}

echo "Probing https://${TARGET_HOST}:${PORT} ..."

chain="$(echo | openssl s_client -showcerts -servername "$TARGET_HOST" \
    -connect "${TARGET_HOST}:${PORT}" 2>/dev/null)"

if [ -z "$chain" ]; then
    echo "Could not reach ${TARGET_HOST}:${PORT}" >&2
    exit 1
fi

# Keep every certificate except the leaf (the first one presented).
authorities="$(printf '%s\n' "$chain" \
    | awk '/-----BEGIN CERTIFICATE-----/{n++} n>1' \
    | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/')"

if [ -z "$authorities" ]; then
    echo "No intermediate/root CA returned. Nothing written."
    exit 0
fi

echo
printf '%s\n' "$authorities" \
    | openssl storeutl -noout -text /dev/stdin 2>/dev/null \
    | grep -E '^\s+Subject:' || true

if printf '%s\n' "$authorities" | grep -qiE \
    'DigiCert|Let.s Encrypt|ISRG|Baltimore|GlobalSign|Sectigo|USERTrust|Amazon|Google Trust'; then
    echo
    echo "The chain looks like a public one - this connection is probably NOT"
    echo "being intercepted. Inspect the output above before using the file."
fi

mkdir -p "$(dirname "$OUT_FILE")"
printf '%s\n' "$authorities" > "$OUT_FILE"

echo
echo "Wrote CA certificate(s) to: $OUT_FILE"
echo "Now run:  docker compose build scanner"
