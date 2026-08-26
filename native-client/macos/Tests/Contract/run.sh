#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

swiftc \
  -warnings-as-errors \
  "$ROOT/Sources/IdenGridApp/Models.swift" \
  "$ROOT/Sources/IdenGridApp/ClientConfiguration.swift" \
  "$ROOT/Sources/IdenGridApp/StoreVisualIdentity.swift" \
  "$ROOT/Sources/IdenGridApp/StorePaths.swift" \
  "$ROOT/Sources/IdenGridApp/BrandContract.swift" \
  "$ROOT/Tests/Contract/main.swift" \
  -o "$TMP/idengrid-contract-tests"

"$TMP/idengrid-contract-tests"

SOCKET="$TMP/agent.sock"
python3 "$ROOT/Tests/Contract/unix_socket_server.py" "$SOCKET" &
SERVER_PID=$!
for _ in $(seq 1 100); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.01
done
[[ -S "$SOCKET" ]] || { echo "Unix Socket test server failed to start" >&2; exit 1; }

swiftc \
  -warnings-as-errors \
  "$ROOT/Sources/IdenGridApp/UnixSocketClient.swift" \
  "$ROOT/Tests/Contract/unix_socket_main.swift" \
  -o "$TMP/idengrid-unix-socket-tests"

"$TMP/idengrid-unix-socket-tests" "$SOCKET"
wait "$SERVER_PID"
SERVER_PID=""
