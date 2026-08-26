#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

for command in caddy curl; do
  if ! command -v "$command" >/dev/null; then
    echo "$command is required for the public web gateway." >&2
    exit 1
  fi
done
UV_BIN=${UV_BIN:-}
if [[ -z "$UV_BIN" ]]; then
  if command -v uv >/dev/null; then
    UV_BIN=$(command -v uv)
  elif [[ -x "$HOME/.local/bin/uv" ]]; then
    UV_BIN="$HOME/.local/bin/uv"
  elif [[ -x "$HOME/.hermes/bin/uv" ]]; then
    UV_BIN="$HOME/.hermes/bin/uv"
  else
    echo "uv is required; set UV_BIN to its absolute path." >&2
    exit 1
  fi
fi
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created public .env. Replace every placeholder before starting." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

required=(SECRET_KEY BOOTSTRAP_ADMIN_PASSWORD IDENGRID_APP_DOMAIN PUBLIC_ORIGIN)
for name in "${required[@]}"; do
  value=${!name:-}
  if [[ -z "$value" || "$value" == replace-* ]]; then
    echo "$name must be configured in .env." >&2
    exit 1
  fi
done
if [[ "$PUBLIC_ORIGIN" != "https://${IDENGRID_APP_DOMAIN}" ]]; then
  echo "PUBLIC_ORIGIN must equal https://${IDENGRID_APP_DOMAIN}." >&2
  exit 1
fi
if [[ "${COOKIE_SECURE:-}" != "true" ]]; then
  echo "COOKIE_SECURE must be true for the public gateway." >&2
  exit 1
fi
if [[ "${HOST:-127.0.0.1}" != "127.0.0.1" ]]; then
  echo "HOST must remain 127.0.0.1; only Caddy may be public." >&2
  exit 1
fi

mkdir -p "${DATA_DIR:-/data/runtime-web}"
"$UV_BIN" sync --dev
if [[ "${CLOUD_VIDEO_ENABLED:-false}" != "false" ]]; then
  echo "CLOUD_VIDEO_ENABLED must remain false; cloud video is not part of IdenGrid." >&2
  exit 1
fi
caddy validate --config deploy/Caddyfile --adapter caddyfile

cleanup() {
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true
  [[ -n "${CADDY_PID:-}" ]] && kill "$CADDY_PID" 2>/dev/null || true
  wait "${API_PID:-}" "${CADDY_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$UV_BIN" run uvicorn cloudbrowser.main:app \
  --host 127.0.0.1 --port "${PORT:-8000}" --proxy-headers --no-access-log \
  >"${DATA_DIR:-/data/runtime-web}/api.log" 2>&1 &
API_PID=$!
for _ in {1..60}; do
  if curl -fsS "http://127.0.0.1:${PORT:-8000}/healthz" >/dev/null; then
    break
  fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "API exited during startup; see ${DATA_DIR:-/data/runtime-web}/api.log" >&2
    exit 1
  fi
  sleep 0.25
done
curl -fsS "http://127.0.0.1:${PORT:-8000}/healthz" >/dev/null

caddy run --config deploy/Caddyfile --adapter caddyfile &
CADDY_PID=$!
echo "Public IdenGrid gateway: https://${IDENGRID_APP_DOMAIN}"
wait -n "$API_PID" "$CADDY_PID"
