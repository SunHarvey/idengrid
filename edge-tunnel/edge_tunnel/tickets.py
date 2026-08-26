from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass


class TicketError(ValueError):
    """A capability ticket is invalid or unusable."""


@dataclass(frozen=True)
class Ticket:
    node: str
    store: str
    host: str
    port: int
    issued_at: int
    expires_at: int
    jti: str


class TicketVerifier:
    def __init__(
        self,
        secret: bytes,
        node_id: str,
        *,
        max_ttl: int = 60,
        clock: Callable[[], float] = time.time,
        future_skew: int = 5,
    ) -> None:
        self.secret = secret
        self.node_id = node_id
        self.max_ttl = max_ttl
        self.clock = clock
        self.future_skew = future_skew

    @staticmethod
    def _decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)

    def verify(self, token: str) -> Ticket:
        try:
            encoded, supplied_signature = token.split(".")
            raw = self._decode(encoded)
            signature = self._decode(supplied_signature)
            payload = json.loads(raw)
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise TicketError("malformed ticket") from exc

        expected = hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise TicketError("invalid ticket signature")
        if not isinstance(payload, dict):
            raise TicketError("malformed ticket claims")

        required = {"v", "node", "store", "host", "port", "iat", "exp", "jti"}
        if not required.issubset(payload):
            raise TicketError("malformed ticket claims")
        if payload["v"] != 1:
            raise TicketError("unsupported ticket version")
        for name in ("node", "store", "host", "jti"):
            if not isinstance(payload[name], str) or not payload[name]:
                raise TicketError(f"invalid ticket {name}")
        for name in ("port", "iat", "exp"):
            if isinstance(payload[name], bool) or not isinstance(payload[name], int):
                raise TicketError(f"invalid ticket {name}")
        if payload["node"] != self.node_id:
            raise TicketError("ticket is for wrong node")
        if payload["port"] not in (80, 443):
            raise TicketError("invalid ticket port")

        now = int(self.clock())
        if payload["exp"] <= now:
            raise TicketError("ticket expired")
        if payload["iat"] > now + self.future_skew:
            raise TicketError("ticket issued in future")
        lifetime = payload["exp"] - payload["iat"]
        if lifetime <= 0 or lifetime > self.max_ttl:
            raise TicketError("ticket lifetime exceeds limit")

        return Ticket(
            node=payload["node"],
            store=payload["store"],
            host=payload["host"],
            port=payload["port"],
            issued_at=payload["iat"],
            expires_at=payload["exp"],
            jti=payload["jti"],
        )
