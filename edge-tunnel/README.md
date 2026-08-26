# Edge WSS Tunnel

A small, standalone edge service for Rocky Linux 9. It accepts a signed,
short-lived capability over WSS and relays **binary WebSocket frames** to one
DNS-vetted public TCP destination. It has no central-user password, SSH, SOCKS,
CONNECT, arbitrary-port, or client-supplied destination fallback.

## Security model

* The service listens only on `127.0.0.1`; Caddy is the TLS boundary.
* Send the capability only as `Authorization: Bearer <ticket>` (never in a URL).
* Every node has a unique secret and `EDGE_NODE_ID`. A ticket signed for one node
  cannot be used on another.
* The signed payload fixes `store`, `node`, `host`, and `port`; `store` is a
  non-empty central store identifier. Tickets are one-use per process (`jti`).
* Only destination ports 80 and 443 are accepted.
* DNS runs on the edge. **Every** A/AAAA answer must be globally routable and
  non-multicast. One private, loopback, link-local, unspecified, reserved,
  documentation, or otherwise non-global answer rejects the entire target.
* The socket receives the already-vetted numeric address and address family, so
  no second DNS lookup can rebind it.
* Concurrent connections, inbound frame size, aggregate bidirectional bytes,
  connect time, idle time, and total duration are bounded.
* Caddy terminates TLS, strips server disclosure, and redacts authorization and
  query data from its JSON access log. The Python process disables access logs.

The in-memory one-use cache is an extra replay barrier, not a distributed
revocation system. Keep tickets at 60 seconds or less (the hard configuration
ceiling is 300 seconds). Restarting a node clears this cache; expiry and HMAC
validation still apply.

## Ticket wire format

`base64url(payload-json-without-padding).base64url(HMAC-SHA256-without-padding)`

HMAC input is the ASCII payload segment exactly as transmitted. Required claims:

```json
{"v":1,"node":"edge-sg01","store":"store-42","host":"example.com","port":443,"iat":1700000000,"exp":1700000030,"jti":"128-bit-random-id"}
```

`iat` and `exp` are integer Unix seconds. Lifetime must not exceed
`EDGE_TICKET_MAX_TTL`; `exp` must be in the future. Generate `jti` with a CSPRNG.
The central issuer must select the secret by node and must authorize the store's
target before signing. The edge independently repeats destination validation.

## HTTP/WSS API

* `GET /healthz` → `{"status":"ok","node":"..."}`
* `GET /status` → non-secret counters plus validated `public_ipv4`, 1-minute
  load, memory/disk byte totals and availability, uptime, and agent version
* `GET /v1/tunnel` + WebSocket upgrade + Bearer ticket → binary TCP relay

Text frames are rejected. Close code `1008` indicates a relay limit; oversized
frames are rejected by the WebSocket parser.

`public_ipv4` is discovered server-side over bounded HTTPS (3 seconds), must be
a globally routable IPv4 address, and is cached for 60 seconds. A refresh
failure after expiry makes `/status` return 503; stale values are not accepted
without limit. Resource metrics come from `/proc/loadavg`, `/proc/meminfo`,
`/proc/uptime`, and `statvfs("/")`. No ticket secret is returned.

## Rocky Linux 9 installation (does not deploy automatically)

Review files first. On the target node:

```bash
sudo ./scripts/install-rocky9.sh
# Add INSTALL_CADDY=1 only if Caddy is not already installed:
sudo INSTALL_CADDY=1 ./scripts/install-rocky9.sh
sudo install -m 0600 config/edge-tunnel.env.example /etc/edge-tunnel/edge-sg01.env
sudoedit /etc/edge-tunnel/edge-sg01.env   # replace [REDACTED]
sudo install -m 0644 caddy/Caddyfile.template /etc/caddy/Caddyfile
sudoedit /etc/caddy/Caddyfile             # set edge-sg01 or edge-hk01 hostname
caddy validate --config /etc/caddy/Caddyfile
sudo systemctl enable --now edge-tunnel@edge-sg01.service caddy
```

Use a different 32+ byte random secret in each node environment file. Keep the
file root-owned mode `0600`. Permit inbound 80/443 to Caddy; do not expose 8787.
For the current nodes, use `edge-sg.example.com` and
`edge-hk.example.com`; point DNS at each node before Caddy obtains a certificate.
The central domain `api.example.com` is not used as an edge secret or login.

## Development and tests

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/pip install -e .
.venv/bin/pytest -q
```
