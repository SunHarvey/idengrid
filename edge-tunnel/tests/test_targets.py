import socket

import pytest
from edge_tunnel.targets import PublicTargetPolicy, TargetDenied


def answer(address: str, family: int = socket.AF_INET):
    sockaddr = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def test_resolves_hostname_server_side_and_returns_vetted_numeric_ip():
    calls = []

    def resolver(host, port):
        calls.append((host, port))
        return [answer("93.184.216.34")]

    result = PublicTargetPolicy(resolver).resolve("Example.COM.", 443)

    assert calls == [("example.com", 443)]
    assert result.host == "example.com"
    assert result.address == "93.184.216.34"
    assert result.family == socket.AF_INET


@pytest.mark.parametrize("port", [0, 22, 81, 8080, 65535])
def test_rejects_every_port_except_http_and_https(port):
    with pytest.raises(TargetDenied, match="ports"):
        PublicTargetPolicy(lambda *_: []).resolve("example.com", port)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.2",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_rejects_non_public_dns_answers(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    policy = PublicTargetPolicy(lambda *_: [answer(address, family)])

    with pytest.raises(TargetDenied, match="blocked network"):
        policy.resolve("example.com", 80)


def test_rejects_entire_target_when_dns_answers_are_mixed_public_and_private():
    policy = PublicTargetPolicy(lambda *_: [answer("93.184.216.34"), answer("127.0.0.1")])

    with pytest.raises(TargetDenied, match="blocked network"):
        policy.resolve("example.com", 443)


@pytest.mark.parametrize("host", ["", ".", "localhost", "x.localhost", "bad host", "a" * 254])
def test_rejects_invalid_or_local_hostnames_before_connect(host):
    with pytest.raises(TargetDenied, match="target"):
        PublicTargetPolicy(lambda *_: []).resolve(host, 443)


def test_rejects_dns_failure_and_empty_answers():
    with pytest.raises(TargetDenied, match="no addresses"):
        PublicTargetPolicy(lambda *_: []).resolve("example.com", 443)

    def failed(*_):
        raise socket.gaierror("nope")

    with pytest.raises(TargetDenied, match="resolution failed"):
        PublicTargetPolicy(failed).resolve("example.com", 443)
