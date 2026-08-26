#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; RELEASE="$(cd "$ROOT/../release" && pwd)"
for script in "$RELEASE"/scripts/*.sh "$0"; do bash -n "$script"; done
! grep -RniE 'tkinter|/Applications/(Google Chrome|Chromium)|usr/bin/python|python3' "$ROOT/Sources" "$RELEASE/scripts"
grep -q 'WindowGroup' "$ROOT/Sources/IdenGridApp/IdenGridApp.swift"
! grep -q 'MenuBarExtra' "$ROOT/Sources/IdenGridApp/IdenGridApp.swift"
grep -q 'chmod(paths.config.path, 0o600)' "$ROOT/Sources/IdenGridApp/StoreProcessManager.swift"
grep -q 'ARCHS=arm64' "$RELEASE/scripts/build-arm64.sh"
grep -q 'LSMinimumSystemVersion' "$ROOT/Resources/Info.plist"
[[ ! -e "$RELEASE/build/IdenGrid.dmg" ]]
echo "static shell contracts passed"
