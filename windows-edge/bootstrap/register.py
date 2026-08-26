"""In-memory Windows Edge registration and claim bootstrap."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class BootstrapError(RuntimeError):
    """A deliberately sanitized bootstrap failure."""


class JsonTransport:
    def __init__(self, server: str, timeout: int = 30) -> None:
        if not server.startswith("https://") or server.endswith("/"):
            raise BootstrapError("server must be an HTTPS origin without a trailing slash")
        self.server = server
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request_headers = {"Accept": "application/json"}
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.server + path, data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise BootstrapError("registration service rejected the request")
                payload = response.read(1_048_577)
                if len(payload) > 1_048_576:
                    raise BootstrapError("registration response is too large")
                result = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise BootstrapError("registration service request failed") from exc
        if not isinstance(result, dict):
            raise BootstrapError("registration service returned invalid data")
        return result


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _machine_guid() -> str:
    import winreg

    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, access
    ) as key:
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
    if not isinstance(value, str) or not value.strip():
        raise BootstrapError("Windows machine identity is unavailable")
    return value.strip()


def _os_name() -> str:
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            product, _ = winreg.QueryValueEx(key, "ProductName")
            build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
        return f"{product} build {build}"
    except OSError:
        return platform.platform()


def _memory_bytes() -> int:
    status = _MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise BootstrapError("Windows memory inventory is unavailable")
    return int(status.ullTotalPhys)


def _disk_bytes() -> int:
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    return int(shutil.disk_usage(drive).total)


def collect_inventory(
    *,
    hostname: Callable[[], str] = socket.gethostname,
    machine_guid: Callable[[], str] = _machine_guid,
    os_name: Callable[[], str] = _os_name,
    cpu_count: Callable[[], int | None] = os.cpu_count,
    memory_bytes: Callable[[], int] = _memory_bytes,
    disk_bytes: Callable[[], int] = _disk_bytes,
) -> dict[str, Any]:
    raw_guid = machine_guid()
    inventory = {
        "machine_fingerprint": hashlib.sha256(raw_guid.encode("utf-8")).hexdigest(),
        "reported_hostname": hostname(),
        "os_name": os_name(),
        "cpu_count": cpu_count(),
        "memory_total_bytes": memory_bytes(),
        "disk_total_bytes": disk_bytes(),
        "agent_version": "windows-bootstrap/1",
    }
    raw_guid = ""  # best-effort reduction of sensitive lifetime
    if not inventory["reported_hostname"] or not isinstance(inventory["cpu_count"], int):
        raise BootstrapError("Windows host inventory is incomplete")
    if min(
        inventory["cpu_count"],
        inventory["memory_total_bytes"],
        inventory["disk_total_bytes"],
    ) < 1:
        raise BootstrapError("Windows host inventory is incomplete")
    return inventory


def enroll(
    transport: Any,
    inventory: dict[str, Any],
    *,
    poll_seconds: float = 5,
    max_polls: int = 720,
) -> dict[str, Any]:
    if "Windows Server 2025" not in str(inventory.get("os_name", "")):
        raise BootstrapError("unsupported Windows host")
    source = transport.request("GET", "/api/node-registration-source")
    public_ipv4 = source.get("public_ipv4")
    if not isinstance(public_ipv4, str):
        raise BootstrapError("public IPv4 is unavailable")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    create_body = {
        **inventory,
        "platform": "windows",
        "public_ipv4": public_ipv4,
        "public_key_pem": public_pem,
    }
    created = transport.request("POST", "/api/node-registration-requests", create_body)
    request_id = created.get("request_id")
    challenge = created.get("challenge")
    token_secret = created.get("registration_token")
    if not all(isinstance(value, str) and value for value in (request_id, challenge, token_secret)):
        raise BootstrapError("registration service returned invalid data")
    print(f"Registration request: {request_id}", file=sys.stderr, flush=True)

    authorization = f"Registration {request_id}.{token_secret}"
    auth_headers = {"Authorization": authorization}
    message = (
        f"hermes-node-registration-v1\n{request_id}\n{challenge}\n{public_ipv4}\n"
        f"{inventory['machine_fingerprint']}\n"
    ).encode()
    signature = base64.b64encode(private_key.sign(message)).decode("ascii")
    transport.request(
        "POST",
        f"/api/node-registration-requests/{request_id}/proof",
        {"challenge": challenge, "signature": signature},
        auth_headers,
    )
    challenge = signature = ""

    for _ in range(max_polls):
        status = transport.request(
            "GET", f"/api/node-registration-requests/{request_id}/status", headers=auth_headers
        )
        state = status.get("status")
        if state == "approved":
            claim_challenge = status.get("claim_challenge")
            if not isinstance(claim_challenge, str) or len(claim_challenge) < 32:
                raise BootstrapError("registration service returned invalid state")
            claim_message = (
                f"hermes-node-claim-v1\n{request_id}\n{claim_challenge}\n{public_ipv4}\n"
                f"{inventory['machine_fingerprint']}\n"
            ).encode()
            claim_signature = base64.b64encode(private_key.sign(claim_message)).decode("ascii")
            claim = transport.request(
                "POST",
                f"/api/node-registration-requests/{request_id}/claim-approved",
                {"challenge": claim_challenge, "signature": claim_signature},
                auth_headers,
            )
            private_key = None
            authorization = token_secret = claim_challenge = claim_signature = ""
            return claim
        if state in {"rejected", "expired", "failed"}:
            raise BootstrapError(f"registration {state}")
        if state not in {"pending_approval", "pending_proof"}:
            raise BootstrapError("registration service returned invalid state")
        time.sleep(poll_seconds)
    raise BootstrapError("registration approval timed out")


def main() -> int:
    parser = argparse.ArgumentParser(description="Register and claim this Windows Edge host")
    parser.add_argument("--server", required=True)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument("--max-polls", type=int, default=720)
    args = parser.parse_args()
    try:
        claim = enroll(
            JsonTransport(args.server),
            collect_inventory(),
            poll_seconds=args.poll_seconds,
            max_polls=args.max_polls,
        )
        json.dump(claim, sys.stdout, separators=(",", ":"), ensure_ascii=True)
        sys.stdout.write("\n")
        return 0
    except BootstrapError as exc:
        print(f"Windows Edge bootstrap failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
