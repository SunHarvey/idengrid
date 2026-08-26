#!/bin/bash
set -euo pipefail
APP="${1:?usage: check-licenses-sbom.sh IdenGrid.app [output-dir]}"; OUT="${2:-$(dirname "$APP")/compliance}"
command -v syft >/dev/null || { echo "syft is required for SBOM generation" >&2; exit 1; }
[[ -f "$APP/Contents/Frameworks/IdenGrid Browser.app/Contents/Resources/LICENSE" ]] || { echo "Chromium LICENSE missing" >&2; exit 1; }
[[ -f "$APP/Contents/Resources/THIRD_PARTY_NOTICES.txt" ]] || { echo "THIRD_PARTY_NOTICES missing" >&2; exit 1; }
mkdir -p "$OUT"
syft "dir:$APP" -o spdx-json="$OUT/IdenGrid.spdx.json"
[[ -s "$OUT/IdenGrid.spdx.json" ]] || { echo "SBOM generation failed" >&2; exit 1; }
