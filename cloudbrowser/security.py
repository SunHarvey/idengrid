from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlparse

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class NetworkPolicy:
    """Application-side mirror of the browser's deny policy."""

    def is_url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return True
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )


class SessionTicketSigner:
    def __init__(
        self,
        secret_key: str,
        ttl_seconds: int = 60,
        salt: str = "browser-session-ticket",
    ):
        self.serializer = URLSafeTimedSerializer(secret_key, salt=salt)
        self.ttl_seconds = ttl_seconds

    def issue(self, user_id: int, session_id: str) -> str:
        return self.serializer.dumps(
            {
                "user_id": user_id,
                "session_id": session_id,
                "expires_at": time.time() + self.ttl_seconds,
            }
        )

    def verify(self, token: str, user_id: int, session_id: str) -> bool:
        try:
            payload = self.serializer.loads(token)
        except (BadSignature, SignatureExpired):
            return False
        return (
            payload.get("user_id") == user_id
            and payload.get("session_id") == session_id
            and float(payload.get("expires_at", 0)) > time.time()
        )
