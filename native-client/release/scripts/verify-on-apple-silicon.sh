#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[[ "$(uname -s)" == Darwin ]] || { echo "需要 macOS" >&2; exit 2; }
[[ "$(uname -m)" == arm64 ]] || { echo "需要 Apple Silicon Mac" >&2; exit 2; }
command -v swift >/dev/null || { echo "缺少 Swift 工具链" >&2; exit 2; }
command -v xcrun >/dev/null || { echo "缺少 Apple Command Line Tools" >&2; exit 2; }
command -v cargo >/dev/null || { echo "缺少 Rust：请先安装 https://rustup.rs" >&2; exit 2; }
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
[[ -d "$SDK_PATH" ]] || { echo "缺少可用的 macOS SDK" >&2; exit 2; }

echo "== Host =="
sw_vers
uname -m
swift --version
xcrun --sdk macosx --show-sdk-path
cargo --version

echo "== Rust Agent =="
cd "$ROOT/agent-rs"
rustup target add aarch64-apple-darwin
rustup component add rustfmt clippy
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --target aarch64-apple-darwin
AGENT="$PWD/target/aarch64-apple-darwin/release/idengrid-agent"
test "$(lipo -archs "$AGENT")" = arm64

echo "== SwiftUI =="
cd "$ROOT/macos"
swift build -c release --arch arm64 -Xswiftc -warnings-as-errors
bash Tests/Contract/run.sh
MAIN="$PWD/.build/arm64-apple-macosx/release/IdenGrid"
test "$(lipo -archs "$MAIN")" = arm64

echo "Apple Silicon source compile verification passed."
echo "Agent: $AGENT"
echo "SwiftUI: $MAIN"
