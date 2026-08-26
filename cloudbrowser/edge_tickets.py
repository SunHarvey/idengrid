from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable


class EdgeTicketIssuer:
    """Issue node- and store-scoped capability tickets understood by Edge."""

    def __init__(
        self,
        secret: str | bytes,
        node_id: str,
        *,
        max_ttl: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 0 < max_ttl <= 60:
            raise ValueError("ticket lifetime must be between 1 and 60 seconds")
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.node_id = node_id
        self.max_ttl = max_ttl
        self.clock = clock

    @staticmethod
    def _encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def issue(self, *, store: str, host: str, port: int, ttl: int | None = None) -> str:
        lifetime = self.max_ttl if ttl is None else min(ttl, self.max_ttl)
        if lifetime <= 0:
            raise ValueError("ticket lifetime must be positive")
        issued_at = int(self.clock())
        payload = {
            "v": 1,
            "node": self.node_id,
            "store": store,
            "host": host,
            "port": port,
            "iat": issued_at,
            "exp": issued_at + lifetime,
            "jti": secrets.token_urlsafe(18),
        }
        encoded = self._encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signature = self._encode(
            hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{encoded}.{signature}"
