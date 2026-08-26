#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SERVER="" DRY_RUN=0 INSTALL_ADMIN_SSH_KEY=0
POLL_TIMEOUT_SECONDS=${POLL_TIMEOUT_SECONDS:-7200}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS:-15}
while (($#)); do
  case "$1" in
    --server) SERVER=${2:-}; shift 2 ;;
    --install-admin-ssh-key) INSTALL_ADMIN_SSH_KEY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) printf 'Unknown option\n' >&2; exit 2 ;;
  esac
done
[[ $SERVER == https://* ]] || { printf 'A valid HTTPS --server is required.\n' >&2; exit 2; }
SERVER=${SERVER%/}
[[ $POLL_TIMEOUT_SECONDS =~ ^[0-9]+$ && $POLL_TIMEOUT_SECONDS -ge 1800 ]] || {
  printf 'POLL_TIMEOUT_SECONDS must be at least 1800.\n' >&2; exit 2;
}
if ((DRY_RUN)); then
  printf 'Dry-run: validated generic node installer; no files, keys, network calls, or system settings changed.\n'
  exit 0
fi
[[ $EUID -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == rocky && ${VERSION_ID%%.*} == 9 ]] || { printf 'Rocky Linux 9 required.\n' >&2; exit 1; }

dnf install -y curl openssl python3 firewalld tar openssh-server 'dnf-command(copr)'
WORK=$(mktemp -d)
IDENTITY_DIR=/etc/hermes-edge-registration
PRIVATE_KEY="$IDENTITY_DIR/identity.key"
PUBLIC_KEY="$IDENTITY_DIR/identity.pub.pem"
REGISTRATION_JSON="$WORK/registration.json"
CLAIM_JSON="$WORK/claim.json"
AUTH_CONFIG="$WORK/registration.curl"
REPORT_CONFIG="$WORK/report.curl"
PHASE=installing
cleanup() { rm -rf -- "$WORK"; }
report() {
  local phase=$1 error=${2:-} payload
  [[ -s $REPORT_CONFIG ]] || return 0
  payload=$(python3 - "$phase" "$error" <<'PY'
import json,sys
print(json.dumps({"phase":sys.argv[1],"error":" ".join(sys.argv[2].split())[:500] or None},separators=(",",":")))
PY
)
  curl --config "$REPORT_CONFIG" --data-binary "$payload" \
    "$SERVER/api/edge-enrollments/report" >/dev/null 2>&1 || true
}
on_error() { local code=$1; trap - ERR; report failed "installer failed during $PHASE"; exit "$code"; }
trap 'on_error $?' ERR
trap cleanup EXIT

install -d -m 0700 "$IDENTITY_DIR"
if [[ ! -s $PRIVATE_KEY ]]; then
  openssl genpkey -algorithm ED25519 -out "$PRIVATE_KEY"
fi
chmod 0600 "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
chmod 0644 "$PUBLIC_KEY"
MACHINE_FINGERPRINT=$(sha256sum /etc/machine-id | cut -d' ' -f1)
PUBLIC_IP=$(curl --proto '=https' --tlsv1.2 -fsS --max-time 15 https://api.ipify.org)
HOSTNAME_REPORTED=$(hostname -f 2>/dev/null || hostname)
CPU_COUNT=$(getconf _NPROCESSORS_ONLN)
MEMORY_TOTAL=$(python3 - <<'PY'
with open('/proc/meminfo') as f:
    values=dict(line.split(':',1) for line in f)
print(int(values['MemTotal'].split()[0])*1024)
PY
)
DISK_TOTAL=$(df -B1 --output=size / | tail -n 1 | tr -d ' ')
OS_NAME=${PRETTY_NAME:-Rocky Linux 9}
REGISTER_BODY=$(python3 - "$PUBLIC_KEY" "$MACHINE_FINGERPRINT" "$HOSTNAME_REPORTED" \
  "$PUBLIC_IP" "$OS_NAME" "$CPU_COUNT" "$MEMORY_TOTAL" "$DISK_TOTAL" <<'PY'
import json,sys
key,machine,hostname,ip,os_name,cpu,memory,disk=sys.argv[1:]
print(json.dumps({"public_key_pem":open(key).read(),"platform":"linux","machine_fingerprint":machine,
 "reported_hostname":hostname,"public_ipv4":ip,"os_name":os_name,"cpu_count":int(cpu),
 "memory_total_bytes":int(memory),"disk_total_bytes":int(disk),"agent_version":"1.0.0"},
 separators=(",",":")))
PY
)
curl --proto '=https' --tlsv1.2 -fsS -H 'Content-Type: application/json' \
  --data-binary "$REGISTER_BODY" "$SERVER/api/node-registration-requests" -o "$REGISTRATION_JSON"
chmod 0600 "$REGISTRATION_JSON"
readarray -t REGISTRATION < <(python3 - "$REGISTRATION_JSON" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); print(x['request_id']); print(x['challenge']); print(x['registration_token'])
PY
)
REQUEST_ID=${REGISTRATION[0]}; CHALLENGE=${REGISTRATION[1]}; REGISTRATION_TOKEN=${REGISTRATION[2]}
[[ $REQUEST_ID =~ ^[0-9a-f]{32}$ ]] || { printf 'Invalid registration response.\n' >&2; exit 1; }
printf 'Node registration request ID: %s\n' "$REQUEST_ID"
python3 - "$AUTH_CONFIG" "$REQUEST_ID" "$REGISTRATION_TOKEN" <<'PY'
import os,sys
path,request_id,token=sys.argv[1:]
with open(path,'w') as f:
    f.write('silent\nshow-error\nfail\nproto = "=https"\ntlsv1.2\n')
    f.write(f'header = "Authorization: Registration {request_id}.{token}"\n')
os.chmod(path,0o600)
PY
REGISTRATION_TOKEN=""
MESSAGE="$WORK/proof-message"
SIGNATURE="$WORK/proof.sig"
printf 'hermes-node-registration-v1\n%s\n%s\n%s\n%s\n' \
  "$REQUEST_ID" "$CHALLENGE" "$PUBLIC_IP" "$MACHINE_FINGERPRINT" > "$MESSAGE"
openssl pkeyutl -sign -rawin -inkey "$PRIVATE_KEY" -in "$MESSAGE" -out "$SIGNATURE"
PROOF_BODY=$(python3 - "$CHALLENGE" "$SIGNATURE" <<'PY'
import base64,json,sys
print(json.dumps({"challenge":sys.argv[1],"signature":base64.b64encode(open(sys.argv[2],'rb').read()).decode()},separators=(",",":")))
PY
)
curl --config "$AUTH_CONFIG" -H 'Content-Type: application/json' --data-binary "$PROOF_BODY" \
  "$SERVER/api/node-registration-requests/$REQUEST_ID/proof" >/dev/null
CHALLENGE=""; PROOF_BODY=""; rm -f "$MESSAGE" "$SIGNATURE" "$REGISTRATION_JSON"

started=$SECONDS
while :; do
  STATUS_JSON=$(curl --config "$AUTH_CONFIG" \
    "$SERVER/api/node-registration-requests/$REQUEST_ID/status")
  STATE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$STATUS_JSON")
  case "$STATE" in
    approved) break ;;
    rejected|expired|failed)
      printf 'Registration ended with status: %s\n' "$STATE" >&2; exit 1 ;;
    pending_approval|pending_proof) ;;
    *) printf 'Unexpected registration status.\n' >&2; exit 1 ;;
  esac
  (( SECONDS - started < POLL_TIMEOUT_SECONDS )) || {
    printf 'Timed out waiting for administrator approval. Request ID: %s\n' "$REQUEST_ID" >&2; exit 1;
  }
  sleep "$POLL_INTERVAL_SECONDS"
done
CLAIM_CHALLENGE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["claim_challenge"])' <<<"$STATUS_JSON")
[[ ${#CLAIM_CHALLENGE} -ge 32 ]] || { printf 'Invalid claim challenge.\n' >&2; exit 1; }
CLAIM_MESSAGE="$WORK/claim-message"
CLAIM_SIGNATURE="$WORK/claim.sig"
printf 'hermes-node-claim-v1\n%s\n%s\n%s\n%s\n' \
  "$REQUEST_ID" "$CLAIM_CHALLENGE" "$PUBLIC_IP" "$MACHINE_FINGERPRINT" > "$CLAIM_MESSAGE"
openssl pkeyutl -sign -rawin -inkey "$PRIVATE_KEY" -in "$CLAIM_MESSAGE" -out "$CLAIM_SIGNATURE"
CLAIM_BODY=$(python3 - "$CLAIM_CHALLENGE" "$CLAIM_SIGNATURE" <<'PY'
import base64,json,sys
print(json.dumps({"challenge":sys.argv[1],"signature":base64.b64encode(open(sys.argv[2],'rb').read()).decode()},separators=(",",":")))
PY
)
curl --config "$AUTH_CONFIG" -H 'Content-Type: application/json' --data-binary "$CLAIM_BODY" \
  "$SERVER/api/node-registration-requests/$REQUEST_ID/claim-approved" -o "$CLAIM_JSON"
CLAIM_CHALLENGE=""; CLAIM_BODY=""; chmod 0600 "$CLAIM_JSON"; rm -f "$AUTH_CONFIG" "$CLAIM_MESSAGE" "$CLAIM_SIGNATURE"
readarray -t CLAIM < <(python3 - "$CLAIM_JSON" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));
for k in ('node_name','domain','package_url','package_sha256','report_token'):
 print(x[k])
print('1' if x.get('install_admin_ssh_key') else '0')
PY
)
NODE_NAME=${CLAIM[0]}; DOMAIN=${CLAIM[1]}; PACKAGE_URL=${CLAIM[2]}; PACKAGE_SHA=${CLAIM[3]}
REPORT_TOKEN=${CLAIM[4]}; APPROVED_SSH=${CLAIM[5]}
python3 - "$REPORT_CONFIG" "$REPORT_TOKEN" <<'PY'
import os,sys
path,token=sys.argv[1:]
with open(path,'w') as f:
 f.write('silent\nshow-error\nfail\nproto = "=https"\ntlsv1.2\n')
 f.write(f'header = "Authorization: Report {token}"\nheader = "Content-Type: application/json"\n')
os.chmod(path,0o600)
PY
REPORT_TOKEN=""
report installing

PHASE=dependencies; report dependencies
dnf install -y python3.11 python3.11-pip
dnf copr enable -y @caddy/caddy
dnf install -y caddy
PHASE=configuring; report configuring
PACKAGE="$WORK/edge-tunnel.tar.gz"
curl --proto '=https' --tlsv1.2 -fsS "$PACKAGE_URL" -o "$PACKAGE"
printf '%s  %s\n' "$PACKAGE_SHA" "$PACKAGE" | sha256sum -c -
install -d -m 0755 /opt/edge-tunnel /etc/edge-tunnel
rm -rf /opt/edge-tunnel/*
tar -xzf "$PACKAGE" -C /opt/edge-tunnel --strip-components=1
python3.11 -m venv /opt/edge-tunnel/venv
/opt/edge-tunnel/venv/bin/python -m pip install --no-cache-dir /opt/edge-tunnel
install -m 0644 /opt/edge-tunnel/systemd/edge-tunnel@.service /etc/systemd/system/edge-tunnel@.service
python3 - "$CLAIM_JSON" "/etc/edge-tunnel/$NODE_NAME.env" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1])); r=x['resources']
lines={'EDGE_NODE_ID':x['node_name'],'EDGE_TICKET_SECRET':x['edge_ticket_secret'],
'EDGE_MAX_CONNECTIONS':r['max_connections'],'EDGE_MAX_FRAME_BYTES':r['max_frame_bytes'],
'EDGE_MAX_BYTES':r['max_bytes'],'EDGE_IDLE_TIMEOUT':r['idle_timeout'],
'EDGE_MAX_DURATION':r['max_duration'],'EDGE_CONNECT_TIMEOUT':r['connect_timeout'],
'EDGE_TICKET_MAX_TTL':r['ticket_max_ttl']}
fd=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as f:
 for k,v in lines.items(): f.write(f'{k}={v}\n')
os.chmod(sys.argv[2],0o600)
PY
chmod 0600 "/etc/edge-tunnel/$NODE_NAME.env"

if ((INSTALL_ADMIN_SSH_KEY)) && [[ $APPROVED_SSH == 1 ]]; then
  ADMIN_KEY="$WORK/admin-ssh.pub"
  curl --proto '=https' --tlsv1.2 -fsS "$SERVER/bootstrap/admin-ssh.pub" -o "$ADMIN_KEY"
  ssh-keygen -l -f "$ADMIN_KEY" >/dev/null
  install -d -m 0700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 0600 /root/.ssh/authorized_keys
  KEY_LINE=$(tr -d '\r\n' < "$ADMIN_KEY")
  grep -qxF -- "$KEY_LINE" /root/.ssh/authorized_keys || printf '%s\n' "$KEY_LINE" >> /root/.ssh/authorized_keys
fi

PHASE=caddy; report caddy
python3 - "$DOMAIN" > /etc/caddy/Caddyfile <<'PY'
import sys
print(f'''{sys.argv[1]} {{
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
printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' \
  'PermitRootLogin prohibit-password' 'X11Forwarding no' 'AllowAgentForwarding no' \
  > /etc/ssh/sshd_config.d/60-edge-hardening.conf
chmod 0644 /etc/ssh/sshd_config.d/60-edge-hardening.conf
sshd -t; systemctl reload sshd
printf '%s\n' '[Journal]' 'SystemMaxUse=100M' 'RuntimeMaxUse=50M' 'MaxRetentionSec=14day' \
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
printf 'IdenGrid Edge installation completed. Monitor confirmation is pending.\n'
