#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

API_BIND="127.0.0.1:19091"
PROXY_BIND="127.0.0.1:19090"
DATA_DIR="$(mktemp -d)"
LOG_FILE="$DATA_DIR/roxy.log"

cleanup() {
  if [[ -n "${APP_PID:-}" ]] && kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" || true
    wait "$APP_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

cd "$REPO_ROOT"
ROXY_API_BIND="$API_BIND" \
ROXY_PROXY_BIND="$PROXY_BIND" \
ROXY_DATA_DIR="$DATA_DIR" \
cargo run -p roxy >"$LOG_FILE" 2>&1 &
APP_PID=$!

for _ in $(seq 1 240); do
  if curl -fsS "http://$API_BIND/api/v1/health" >/dev/null; then
    break
  fi
  sleep 0.25
done

curl -fsS "http://$API_BIND/api/v1/health" | grep -q '"status":"ok"'

curl -fsS -X PUT "http://$API_BIND/api/v1/proxy/intercept" \
  -H 'content-type: application/json' \
  -d '{"enabled":true}' | grep -q '"enabled":true'

curl -fsS "http://$API_BIND/api/v1/proxy/intercept" | grep -q '"enabled":true'

curl -fsS "http://$API_BIND/api/v1/proxy/settings/ca.der" >/dev/null
