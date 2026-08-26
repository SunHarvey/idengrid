# IdenGrid · 澜序

[中文](README.md) | [English](README_EN.md)

**Cross-platform browser workspaces with isolated environments and managed fixed egress.**

**Independent environments, effortless collaboration.**

IdenGrid is a source-available platform for managing isolated browser workspaces across macOS and Windows. Each workspace has its own browser profile, local Agent, connection lease, and authorized Edge route.

## Architecture

```text
macOS / Windows client
  → local Chromium profile
  → loopback SOCKS
  → dedicated Rust Agent per workspace
  → authenticated WSS tunnel
  → administrator-authorized Edge node
  → fixed public egress
```

The control plane manages users, devices, workspace authorization, connection leases, one-time tickets, audits, and Edge health. Browser profiles, cookies, and local browser data remain on each device. The same profile directory is never shared between devices.

## Components

- `cloudbrowser/` — FastAPI control plane
- `edge-tunnel/` — authenticated Python/aiohttp Edge relay
- `native-client/agent-rs/` — cross-platform Rust Agent
- `native-client/macos/` — Apple Silicon SwiftUI client
- `windows-client/` — Windows 11 x86-64 .NET/WPF client
- `config/` — public configuration templates
- `tests/` — control-plane and client contract tests

## Configuration

Production domains, database connections, node endpoints, and credentials are never hard-coded in source. Create deployment configuration from these examples:

```text
config/control.env.example
config/caddy.env.example
config/bootstrap.example.json
config/local-environment.example.json
config/client.example.json
```

Real production values must be stored in protected deployment files. The control-plane origin used by the macOS and Windows clients is injected into application resources at build time. There is no production-origin fallback in source.

## Local Development and Verification

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

### macOS client

Static contract tests:

```bash
pytest -q native-client/macos/Tests/Static
```

Apple Silicon builds require macOS Command Line Tools and the scripts under `native-client/release/scripts/`. Set the control-plane origin before building:

```bash
export IDENGRID_API_BASE_URL="https://api.example.com/"
```

Signed updates also require `IDENGRID_UPDATE_FEED_URL`. These values are written into application resources during the build.

### Windows client

Static contract tests:

```bash
pytest -q windows-client/tests/Static
```

A full WPF build requires Windows and .NET 10:

```powershell
$env:IDENGRID_API_BASE_URL = "https://api.example.com/"
.\windows-client\Build-IdenGrid-Windows.ps1
```

The build script validates the HTTPS origin and injects it through a temporary configuration resource without modifying the repository template.

## Security Principles

- Fail closed when route, identity, capacity, ticket, or egress validation fails
- Never place tokens or credentials in command-line arguments or logs
- Isolate profiles, cookies, Agents, control channels, and leases per device and workspace
- Allow users to connect only to administrator-authorized Edge nodes
- Never persist page content, cookies, passwords, or HTTPS URL paths in audits
- Never fall back to the local public network or an unauthorized egress when a node fails

See [SECURITY.md](SECURITY.md) for security reporting guidance.

## License

This project uses a source-available, non-commercial licensing model:

- Non-commercial use is free
- Modified versions distributed to others or provided as a network service must disclose the corresponding source code
- Any commercial use requires separate written permission from the copyright holder
- The IdenGrid and 澜序 names, logos, and other brand assets are not included in the code license

See:

- [IdenGrid Community License](LICENSE)
- [Commercial licensing](COMMERCIAL-LICENSE.md)
- [Trademarks](TRADEMARKS.md)

This license is not an OSI-approved open-source license.
