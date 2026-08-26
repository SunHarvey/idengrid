#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if ! command -v podman >/dev/null; then
  echo "Podman is required (Docker compatibility is planned)." >&2
  exit 1
fi
if ! command -v slirp4netns >/dev/null; then
  echo "slirp4netns is required." >&2
  exit 1
fi
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
  cp .env.development.example .env
  echo "Created development .env. Set SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD before starting." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a
if [[ ${SECRET_KEY:-} == replace-* || ${BOOTSTRAP_ADMIN_PASSWORD:-} == replace-* ]]; then
  echo "Replace placeholder secrets in .env before starting." >&2
  exit 1
fi

"$UV_BIN" sync --dev
podman build -t localhost/cloud-browser-webrtc:latest -f browser-webrtc/Containerfile .
exec "$UV_BIN" run uvicorn cloudbrowser.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
