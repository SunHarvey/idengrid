# IdenGrid native agent (Rust)

A fail-closed local SOCKS5-to-IdenGrid Edge bridge. The agent performs Central preflight and lease connect, binds an OS-selected port on `127.0.0.1`, obtains exactly one target-scoped ticket for every accepted SOCKS `CONNECT`, and relays binary WebSocket frames through the immutable Edge endpoint.

## Security contract

- Configuration is accepted from stdin on both platforms. Only Unix permits `--config` pointing to a regular, non-symlink file with mode exactly `0600` (opened with `O_NOFOLLOW`); Windows rejects `--config` files and requires stdin. Never put tokens/capabilities in arguments, environment variables, logs or an ordinary persistent file.
- Production Central and Edge origins require TLS. Plain HTTP/WS is accepted only on loopback for integration tests.
- `local_port` must be `0`; the listener is always `127.0.0.1:<ephemeral>`.
- SOCKS5 supports unauthenticated `CONNECT` to valid hostnames/IPv4/IPv6 on ports 80 and 443 only. Central remains the authoritative public-target policy.
- The Edge endpoint returned by preflight is immutable for the process lifetime. A different connect or ticket endpoint fails closed.
- Tickets are held as secrets, sent only as the Edge WebSocket bearer capability, and never logged.
- Structured JSON logs include only operational identifiers; known bearer and named-secret forms are redacted from errors.
- On Unix the control socket is mode `0600`; on Windows the control channel is a per-store local Named Pipe with an explicit current-user/SYSTEM DACL. Both require capability authentication. Native Windows ACL and cross-user denial must be tested on Windows; source-string tests alone are not runtime evidence.

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

For a local **non-production fixture** on Unix, stdin can be used:

```sh
cargo run --release < config.json
```

On Unix only, a protected regular file with exact mode `0600` is also supported:

```sh
chmod 600 config.json
cargo run --release -- --config config.json
```

These examples contain credential-bearing fields; use ephemeral test credentials and delete fixture files securely according to the test environment's policy. **Windows does not support `--config`.** The WPF manager (`windows-client/src/IdenGrid.Windows.Wpf/WindowsStoreProcessManager.cs`) starts the bundled `Components/idengrid-agent.exe` with redirected stdin, writes its short-lived JSON configuration there and closes stdin. Reuse that path rather than putting real credentials in a PowerShell command, environment variable or persistent `config.json`. `control_socket_path` is an absolute Unix socket path on macOS or an absolute `\\.\pipe\...` path on Windows; `local_port: 0` selects the loopback SOCKS port.

The agent calls the backend's current routes: `GET /api/stores`, then `POST /api/stores/{id}/connect`; while connected it uses `POST /api/stores/{id}/tickets`, `/heartbeat`, and `/disconnect`. Response DTOs tolerate backend extension fields such as `capabilities`, `recovered`, and health metadata, while validating every security-relevant field used by the agent.

## Control IPC

Send one newline-terminated JSON object per authenticated control connection (Unix socket on macOS, local Named Pipe on Windows):

```json
{"capability":"random-secret-with-at-least-32-characters","command":"status"}
```

or:

```json
{"capability":"random-secret-with-at-least-32-characters","command":"shutdown"}
```

Status returns `status`, `socks_host`, `socks_port`, `store_id`, `device_id`, and optional `edge_latency`. `update_token` requires the new short-lived `native_access_token` in the authenticated IPC payload; never log it. Ctrl-C or authorized IPC shutdown stops accepting connections, closes active relays and calls Central disconnect; Unix also supports SIGTERM and removes its socket on graceful shutdown. Windows pipe behavior must be verified on Windows, not inferred from Unix tests.

The Python static check at `windows-client/tests/Static/test_windows_agent_packaging.py` only checks source text/CRT configuration. It does **not** prove Windows Named Pipe DACL enforcement, correct-SID access, a second user's denial, or Fail Closed in a real client session. Run those as separate native Windows acceptance gates on the exact bundled Agent.

## Protocol artifacts and verification

Schemas and backend-shaped fixtures are under `protocol/`. The mock Central+WebSocket integration test verifies per-connection tickets, binary relay, endpoint-change fail-closed behavior, heartbeat, disconnect, loopback/ephemeral binding, and control-socket permissions and commands.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo check --target aarch64-apple-darwin
```
