from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from typing import NamedTuple


class TargetDenied(ValueError):
    """A requested destination violates the outbound policy."""


class ResolvedTarget(NamedTuple):
    host: str
    port: int
    address: str
    family: int


Resolver = Callable[[str, int], Iterable[tuple]]
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)


class PublicTargetPolicy:
    def __init__(self, resolver: Resolver | None = None) -> None:
        self.resolver = resolver or self._resolve

    @staticmethod
    def _resolve(host: str, port: int) -> list[tuple]:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    @staticmethod
    def _public(address: str) -> bool:
        value = ipaddress.ip_address(address)
        return value.is_global and not value.is_multicast

    def resolve(self, host: str, port: int) -> ResolvedTarget:
        if isinstance(port, bool) or port not in (80, 443):
            raise TargetDenied("only target ports 80 and 443 are allowed")
        if not isinstance(host, str):
            raise TargetDenied("invalid target hostname")
        normalized = host.rstrip(".").lower()
        if not normalized or normalized == "localhost" or normalized.endswith(".localhost"):
            raise TargetDenied("local target hostname is blocked")
        try:
            ascii_host = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetDenied("invalid target hostname") from exc
        if not _HOST_RE.fullmatch(ascii_host):
            # Plain IPv6 literals are valid resolver inputs but not hostnames; permit
            # only syntactically valid literals and subject them to the same policy.
            try:
                ipaddress.IPv6Address(ascii_host)
            except ValueError as exc:
                raise TargetDenied("invalid target hostname") from exc

        try:
            answers = list(self.resolver(ascii_host, port))
        except OSError as exc:
            raise TargetDenied("target DNS resolution failed") from exc
        if not answers:
            raise TargetDenied("target DNS resolution returned no addresses")

        vetted: list[tuple[int, str]] = []
        for entry in answers:
            try:
                family = int(entry[0])
                address = str(entry[4][0])
                parsed = ipaddress.ip_address(address)
            except (IndexError, TypeError, ValueError) as exc:
                raise TargetDenied("target DNS returned an invalid address") from exc
            expected_family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
            if family != expected_family or not self._public(address):
                raise TargetDenied("target resolves to a blocked network")
            pair = (family, parsed.compressed)
            if pair not in vetted:
                vetted.append(pair)

        family, address = vetted[0]
        return ResolvedTarget(ascii_host, port, address, family)
