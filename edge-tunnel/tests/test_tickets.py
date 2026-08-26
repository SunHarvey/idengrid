import base64
import hashlib
import hmac
import json
import time

import pytest
from edge_tunnel.tickets import TicketError, TicketVerifier


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_ticket(secret: bytes, payload: dict) -> str:
    encoded = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = _b64(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def valid_payload(now: int) -> dict:
    return {
        "v": 1,
        "node": "edge-sg01",
        "store": "store-42",
        "host": "example.com",
        "port": 443,
        "iat": now,
        "exp": now + 30,
        "jti": "unique-ticket-id",
    }


def test_verifies_valid_node_and_store_scoped_ticket():
    now = int(time.time())
    verifier = TicketVerifier(b"a" * 32, "edge-sg01", max_ttl=60, clock=lambda: now)

    ticket = verifier.verify(make_ticket(b"a" * 32, valid_payload(now)))

    assert ticket.node == "edge-sg01"
    assert ticket.store == "store-42"
    assert ticket.host == "example.com"
    assert ticket.port == 443


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"node": "edge-hk01"}, "wrong node"),
        ({"store": ""}, "store"),
        ({"exp": 99}, "expired"),
        ({"iat": 101, "exp": 200}, "future"),
        ({"iat": 100, "exp": 161}, "lifetime"),
        ({"port": 22}, "port"),
        ({"jti": ""}, "jti"),
    ],
)
def test_rejects_invalid_ticket_claims(change, message):
    now = 100
    payload = valid_payload(now)
    payload.update(change)
    verifier = TicketVerifier(b"a" * 32, "edge-sg01", max_ttl=60, clock=lambda: now, future_skew=0)

    with pytest.raises(TicketError, match=message):
        verifier.verify(make_ticket(b"a" * 32, payload))


def test_rejects_modified_signature():
    now = 100
    verifier = TicketVerifier(b"a" * 32, "edge-sg01", clock=lambda: now)
    token = make_ticket(b"b" * 32, valid_payload(now))

    with pytest.raises(TicketError, match="signature"):
        verifier.verify(token)


def test_rejects_malformed_ticket_without_leaking_parser_errors():
    verifier = TicketVerifier(b"a" * 32, "edge-sg01")

    with pytest.raises(TicketError, match="malformed"):
        verifier.verify("not-a-ticket")
