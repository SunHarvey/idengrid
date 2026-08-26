# IdenGrid · 澜序

**Cross-platform browser workspaces with isolated profiles and managed fixed egress.**
**环境独立，协作从容。**

IdenGrid is a source-available platform for managing isolated browser workspaces across macOS and Windows. Each workspace keeps an independent browser profile, local agent, lease, and authorized Edge route.

## Architecture

```text
macOS / Windows client
  → local Chromium profile
  → loopback SOCKS
  → per-workspace Rust Agent
  → authenticated WSS
  → authorized Edge
  → fixed egress
```

The control plane manages users, devices, workspace authorization, leases, one-time tickets, audits, and Edge health. Browser profiles and cookies remain on each device.

## Components

- `cloudbrowser/` — FastAPI control plane
- `edge-tunnel/` — authenticated Python/aiohttp Edge relay
- `native-client/agent-rs/` — cross-platform Rust Agent
- `native-client/macos/` — Apple Silicon SwiftUI client
- `windows-client/` — Windows 11 x86-64 .NET/WPF client
- `config/` — public configuration templates
- `tests/` — control-plane and contract tests

## Configuration

Production infrastructure is never hard-coded in source. Start from:

```text
config/control.env.example
config/caddy.env.example
config/bootstrap.example.json
config/local-environment.example.json
config/client.example.json
```

Critical production values must be supplied through protected deployment configuration. Client API origins are injected at build time into signed application resources.

## Development

### Control plane

```bash
uv sync --dev
uv run ruff check cloudbrowser scripts tests
uv run pytest -q
```

### Rust Agent

```bash
cd native-client/agent-rs
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

### macOS static contracts

```bash
pytest -q native-client/macos/Tests/Static
```

Apple Silicon builds require macOS Command Line Tools and the release scripts under `native-client/release/scripts/`. Set `IDENGRID_API_BASE_URL` (and, for signed updates, `IDENGRID_UPDATE_FEED_URL`) before running the build script; the values are embedded into signed application resources.

### Windows static contracts

```bash
pytest -q windows-client/tests/Static
```

A full WPF build requires Windows and .NET 10:

```powershell
$env:IDENGRID_API_BASE_URL = "https://api.example.com/"
.\windows-client\Build-IdenGrid-Windows.ps1
```

The build script validates the HTTPS origin and embeds a temporary configuration resource without modifying the repository template.

## Security Principles

- Fail closed when route, identity, capacity, ticket, or egress validation fails.
- Never place tokens or credentials in command-line arguments or logs.
- Keep profiles, cookies, agents, control channels, and leases isolated per device and workspace.
- Allow users to connect only to administrator-authorized Edge nodes.
- Do not persist page content, cookies, passwords, or HTTPS URL paths in audits.

See [SECURITY.md](SECURITY.md) for reporting guidance.

## License

Source Available · Free for Non-Commercial Use.

Non-commercial use is permitted under the [IdenGrid Community License](LICENSE). Commercial use requires a separate written license; see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). Brand assets are governed by [TRADEMARKS.md](TRADEMARKS.md).

This license is not represented as OSI-approved open source.
