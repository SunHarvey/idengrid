#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
command -v node >/dev/null || { echo "node is required for extension tests" >&2; exit 1; }
node "$ROOT/Tests/Extension/extension.test.cjs"
