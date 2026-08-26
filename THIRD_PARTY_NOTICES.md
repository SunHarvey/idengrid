# Third-Party Notices

IdenGrid depends on third-party software. Those components remain governed by their own licenses; the IdenGrid Community License does not replace them.

Key components include:

- Chromium — BSD-style license and bundled third-party notices
- Sparkle — MIT License
- Python packages listed in `pyproject.toml` and `uv.lock`
- Rust crates listed in `native-client/agent-rs/Cargo.toml` and `Cargo.lock`
- .NET packages listed in the Windows project files

The repository does not vendor Chromium or release binaries. Build and release processes must preserve the license and notice files supplied by each third-party component. Generated distributions must include the complete notices corresponding to the exact dependency and Chromium versions shipped.

The macOS distribution-specific notice file is maintained at `native-client/macos/Resources/THIRD_PARTY_NOTICES.txt`.
