#!/usr/bin/env bash
# Sign a webhook payload with the demo HMAC secret and POST it to /secure/webhook.
# Usage: bash scripts/sign-webhook.sh '{"event":"payment.received"}'
set -euo pipefail

PAYLOAD="${1:-{\"event\":\"payment.received\"}}"
BASE="${BASE_URL:-http://localhost:5050}"
SECRET="demo-secret"

SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')

echo "Payload:   $PAYLOAD"
echo "Signature: $SIG"
echo
curl -s -X POST "$BASE/secure/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Signature: $SIG" \
  -d "$PAYLOAD"
echo
