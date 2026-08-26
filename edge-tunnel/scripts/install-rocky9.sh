#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run as root on Rocky Linux 9.\n' >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ ${ID:-} != "rocky" || ${VERSION_ID%%.*} != "9" ]]; then
  printf 'This installer supports Rocky Linux 9 only.\n' >&2
  exit 1
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_DIR=/opt/edge-tunnel

dnf install -y python3.11 python3.11-pip

install -d -m 0755 "$INSTALL_DIR" /etc/edge-tunnel
rm -rf "$INSTALL_DIR/edge_tunnel" "$INSTALL_DIR/venv"
cp -a "$SOURCE_DIR/edge_tunnel" "$INSTALL_DIR/edge_tunnel"
install -m 0644 "$SOURCE_DIR/pyproject.toml" "$INSTALL_DIR/pyproject.toml"
install -m 0644 "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

python3.11 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install --no-cache-dir "$INSTALL_DIR"

install -m 0644 "$SOURCE_DIR/systemd/edge-tunnel@.service" \
  /etc/systemd/system/edge-tunnel@.service
install -m 0600 "$SOURCE_DIR/config/edge-tunnel.env.example" \
  /etc/edge-tunnel/edge-sg01.env.example
systemctl daemon-reload

if [[ ${INSTALL_CADDY:-0} == "1" ]]; then
  dnf install -y 'dnf-command(copr)'
  dnf copr enable -y @caddy/caddy
  dnf install -y caddy
fi

printf '%s\n' \
  'Installed but NOT enabled or started.' \
  'Create /etc/edge-tunnel/<node>.env (mode 0600), configure Caddy,' \
  'then explicitly enable edge-tunnel@<node>.service and caddy.'
