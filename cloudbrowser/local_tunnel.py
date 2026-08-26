from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from typing import NamedTuple


class TunnelTargetDenied(ValueError):
    pass


class ResolvedTarget(NamedTuple):
    host: str
    port: int
    address: str
    family: int


Resolver = Callable[[str, int], Iterable[tuple]]


class PublicTargetPolicy:
    def __init__(self, resolver: Resolver | None = None, allowed_ports: set[int] | None = None):
        self.resolver = resolver or self._resolve
        self.allowed_ports = allowed_ports or {80, 443}

    @staticmethod
    def _resolve(host: str, port: int) -> list[tuple]:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    @staticmethod
    def _is_public(address: str) -> bool:
        value = ipaddress.ip_address(address)
        return not (
            value.is_private
            or value.is_loopback
            or value.is_link_local
            or value.is_multicast
            or value.is_reserved
            or value.is_unspecified
        )

    def resolve(self, host: str, port: int) -> ResolvedTarget:
        if port not in self.allowed_ports:
            raise TunnelTargetDenied("only HTTP and HTTPS target ports are allowed")
        host = host.rstrip(".").lower()
        if not host or host == "localhost" or host.endswith(".localhost"):
            raise TunnelTargetDenied("local targets are blocked")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TunnelTargetDenied("invalid target hostname") from exc
        try:
            answers = list(self.resolver(ascii_host, port))
        except OSError as exc:
            raise TunnelTargetDenied("target DNS resolution failed") from exc
        if not answers:
            raise TunnelTargetDenied("target DNS resolution returned no addresses")

        resolved: list[tuple[int, str]] = []
        for answer in answers:
            family = int(answer[0])
            sockaddr = answer[4]
            address = str(sockaddr[0])
            if family not in {socket.AF_INET, socket.AF_INET6} or not self._is_public(address):
                raise TunnelTargetDenied("target resolves to a blocked network")
            if (family, address) not in resolved:
                resolved.append((family, address))
        family, address = resolved[0]
        return ResolvedTarget(ascii_host, port, address, family)
