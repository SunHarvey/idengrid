#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SERVER="" NODE_NAME="" TOKEN="" PUBLIC_IP="" DRY_RUN=0 PHASE=installing
while (($#)); do
  case "$1" in
    --server) SERVER=${2:-}; shift 2 ;;
    --node-name) NODE_NAME=${2:-}; shift 2 ;;
    --token) TOKEN=${2:-}; shift 2 ;;
    --public-ip) PUBLIC_IP=${2:-}; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) printf 'Unknown option\n' >&2; exit 2 ;;
  esac
done
[[ $SERVER == https://* && -n $NODE_NAME && -n $TOKEN ]] || { printf 'Required arguments missing\n' >&2; exit 2; }
SERVER=${SERVER%/}

if ((DRY_RUN)); then
  printf 'Dry-run: validated enrollment installer inputs; no changes made.\n'
  exit 0
fi
[[ $EUID -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == rocky && ${VERSION_ID%%.*} == 9 ]] || { printf 'Rocky Linux 9 required.\n' >&2; exit 1; }
WORK=$(mktemp -d)
CLAIM="$WORK/claim.json" REPORT_CONFIG="$WORK/report.curl" CLAIM_CONFIG="$WORK/claim.curl"
cleanup() { rm -rf -- "$WORK"; TOKEN=""; }
report() {
  local phase=$1 error=${2:-} payload
  [[ -s $CLAIM ]] || return 0
  payload=$(python3 - "$phase" "$error" <<'PY'
import json,sys
print(json.dumps({"phase":sys.argv[1], "error":sys.argv[2][:500] or None}, separators=(",",":")))
PY
)
  curl --config "$REPORT_CONFIG" --data-binary "$payload" \
    "$SERVER/api/edge-enrollments/report" >/dev/null 2>&1 || true
}
on_error() { local code=$1; trap - ERR; report failed "installer failed during $PHASE"; exit "$code"; }
trap 'on_error $? $LINENO' ERR
trap cleanup EXIT

if [[ -z $PUBLIC_IP ]]; then
  PUBLIC_IP=$(curl --proto '=https' --tlsv1.2 -fsS --max-time 10 https://api.ipify.org)
fi
TOKEN_FILE="$WORK/enrollment-token"
printf '%s' "$TOKEN" > "$TOKEN_FILE"
chmod 0600 "$TOKEN_FILE"
python3 - "$CLAIM_CONFIG" "$TOKEN_FILE" <<'PY'
import os,sys
path,token_path=sys.argv[1:]
token=open(token_path).read()
with open(path,"w") as f:
    f.write('silent\nshow-error\nfail\nproto = "=https"\ntlsv1.2\n')
    f.write('header = "Authorization: Enrollment '+token.replace('"','')+'"\n')
os.chmod(path,0o600)
PY
rm -f "$TOKEN_FILE"; TOKEN=""
CLAIM_BODY=$(python3 - "$NODE_NAME" "$PUBLIC_IP" <<'PY'
import json,sys
print(json.dumps({"node_name":sys.argv[1],"public_ipv4":sys.argv[2],"agent_version":"1.0.0"},separators=(",",":")))
PY
)
curl --config "$CLAIM_CONFIG" -H 'Content-Type: application/json' \
  --data-binary "$CLAIM_BODY" "$SERVER/api/edge-enrollments/claim" -o "$CLAIM"
rm -f "$CLAIM_CONFIG"
python3 - "$REPORT_CONFIG" "$CLAIM" <<'PY'
import json,os,sys
out,claim=sys.argv[1:]
token=json.load(open(claim))["report_token"]
with open(out,"w") as f:
    f.write('silent\nshow-error\nfail\nproto = "=https"\ntlsv1.2\n')
    f.write('header = "Authorization: Report '+token.replace('"','')+'"\n')
    f.write('header = "Content-Type: application/json"\n')
os.chmod(out,0o600)
PY
# report URL is supplied separately, never carrying a token.
report installing
PHASE=dependencies; report dependencies
dnf install -y python3.11 python3.11-pip firewalld curl tar openssh-server 'dnf-command(copr)'
dnf copr enable -y @caddy/caddy
dnf install -y caddy

PHASE=configuring; report configuring
PACKAGE="$WORK/edge-tunnel.tar.gz"
readarray -t META < <(python3 - "$CLAIM" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); print(x["package_url"]); print(x["package_sha256"]); print(x["domain"])
PY
)
curl --proto '=https' --tlsv1.2 -fsS "${META[0]}" -o "$PACKAGE"
printf '%s  %s\n' "${META[1]}" "$PACKAGE" | sha256sum -c -
install -d -m 0755 /opt/edge-tunnel /etc/edge-tunnel
rm -rf /opt/edge-tunnel/*
tar -xzf "$PACKAGE" -C /opt/edge-tunnel --strip-components=1
python3.11 -m venv /opt/edge-tunnel/venv
/opt/edge-tunnel/venv/bin/python -m pip install --no-cache-dir /opt/edge-tunnel
install -m 0644 /opt/edge-tunnel/systemd/edge-tunnel@.service /etc/systemd/system/edge-tunnel@.service
python3 - "$CLAIM" "/etc/edge-tunnel/$NODE_NAME.env" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1])); r=x["resources"]
lines={"EDGE_NODE_ID":x["node_name"],"EDGE_TICKET_SECRET":x["edge_ticket_secret"],
"EDGE_MAX_CONNECTIONS":r["max_connections"],"EDGE_MAX_FRAME_BYTES":r["max_frame_bytes"],
"EDGE_MAX_BYTES":r["max_bytes"],"EDGE_IDLE_TIMEOUT":r["idle_timeout"],
"EDGE_MAX_DURATION":r["max_duration"],"EDGE_CONNECT_TIMEOUT":r["connect_timeout"],
"EDGE_TICKET_MAX_TTL":r["ticket_max_ttl"]}
fd=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w") as f:
    for k,v in lines.items(): f.write(f"{k}={v}\n")
os.chmod(sys.argv[2],0o600)
PY
chmod 0600 "/etc/edge-tunnel/$NODE_NAME.env"

PHASE=caddy; report caddy
python3 - "${META[2]}" > /etc/caddy/Caddyfile <<'PY'
import sys
host=sys.argv[1]
print(f'''{host} {{
 encode zstd gzip
 header {{
  Strict-Transport-Security "max-age=31536000; includeSubDomains"
  X-Content-Type-Options "nosniff"
  Referrer-Policy "no-referrer"
  -Server
 }}
 reverse_proxy 127.0.0.1:8787 {{
  stream_timeout 9h
 }}
}}''')
PY
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now firewalld
firewall-cmd --permanent --remove-service=cockpit || true
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
install -d -m 0755 /etc/ssh/sshd_config.d /etc/systemd/journald.conf.d
printf '%s\n' \
  'PasswordAuthentication no' \
  'KbdInteractiveAuthentication no' \
  'PermitRootLogin prohibit-password' \
  'X11Forwarding no' \
  'AllowAgentForwarding no' \
  > /etc/ssh/sshd_config.d/60-edge-hardening.conf
chmod 0644 /etc/ssh/sshd_config.d/60-edge-hardening.conf
sshd -t
systemctl reload sshd
printf '%s\n' \
  '[Journal]' \
  'SystemMaxUse=100M' \
  'RuntimeMaxUse=50M' \
  'MaxRetentionSec=14day' \
  > /etc/systemd/journald.conf.d/60-edge-limits.conf
chmod 0644 /etc/systemd/journald.conf.d/60-edge-limits.conf
systemctl restart systemd-journald
if ! swapon --show --noheadings | grep -q .; then
  fallocate -l 2G /swapfile; chmod 0600 /swapfile; mkswap /swapfile; swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
fi

PHASE=starting; report starting
systemctl daemon-reload
systemctl enable --now "edge-tunnel@$NODE_NAME.service" caddy
systemctl is-active --quiet "edge-tunnel@$NODE_NAME.service"
systemctl is-active --quiet caddy
PHASE=ready; report ready
printf 'IdenGrid Edge enrollment completed. Monitor confirmation is pending.\n'
