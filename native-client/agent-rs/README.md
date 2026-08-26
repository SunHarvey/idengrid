# IdenGrid native agent (Rust)

A fail-closed local SOCKS5-to-IdenGrid Edge bridge. The agent performs Central preflight and lease connect, binds an OS-selected port on `127.0.0.1`, obtains exactly one target-scoped ticket for every accepted SOCKS `CONNECT`, and relays binary WebSocket frames through the immutable Edge endpoint.

## Security contract

- Configuration is accepted **only** from stdin, or from `--config` pointing to a regular, non-symlink Unix file with mode exactly `0600` (opened with `O_NOFOLLOW`).
- Production Central and Edge origins require TLS. Plain HTTP/WS is accepted only on loopback for integration tests.
- `local_port` must be `0`; the listener is always `127.0.0.1:<ephemeral>`.
- SOCKS5 supports unauthenticated `CONNECT` to valid hostnames/IPv4/IPv6 on ports 80 and 443 only. Central remains the authoritative public-target policy.
- The Edge endpoint returned by preflight is immutable for the process lifetime. A different connect or ticket endpoint fails closed.
- Tickets are held as secrets, sent only as the Edge WebSocket bearer capability, and never logged.
- Structured JSON logs include only operational identifiers; known bearer and named-secret forms are redacted from errors.
- The Unix control socket is created mode `0600`, requires a constant-time checked capability, and is removed during graceful shutdown.

## Configuration

```json
{
  "central_url": "https://central.example",
  "native_access_token": "short-lived-native-token",
  "store_id": 42,
  "device_id": "mac-01",
  "control_socket_path": "/Users/me/Library/Caches/idengrid-agent.sock",
  "control_capability": "random-secret-with-at-least-32-characters",
  "local_port": 0
}
```

Run from stdin:

```sh
cargo run --release < config.json
```

Or from a protected file:

```sh
chmod 600 config.json
cargo run --release -- --config config.json
```

The agent calls the backend's current routes: `GET /api/stores`, then `POST /api/stores/{id}/connect`; while connected it uses `POST /api/stores/{id}/tickets`, `/heartbeat`, and `/disconnect`. Response DTOs tolerate backend extension fields such as `capabilities`, `recovered`, and health metadata, while validating every security-relevant field used by the agent.

## Control IPC

Send one newline-terminated JSON object per Unix-domain connection:

```json
{"capability":"random-secret-with-at-least-32-characters","command":"status"}
```

or:

```json
{"capability":"random-secret-with-at-least-32-characters","command":"shutdown"}
```

Status returns `status`, `socks_host`, `socks_port`, `store_id`, and `device_id`. `SIGTERM`, Ctrl-C, or authorized IPC shutdown stop accepting connections, close active relays, call Central disconnect, and remove the socket.

## Protocol artifacts and verification

Schemas and backend-shaped fixtures are under `protocol/`. The mock Central+WebSocket integration test verifies per-connection tickets, binary relay, endpoint-change fail-closed behavior, heartbeat, disconnect, loopback/ephemeral binding, and control-socket permissions and commands.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo check --target aarch64-apple-darwin
```
