from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "bootstrap" / "register.py"
SPEC = importlib.util.spec_from_file_location("windows_edge_register", MODULE_PATH)
register = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(register)


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None, dict[str, str]]] = []
        self.statuses = iter(
            [
                {"status": "pending_approval"},
                {"status": "approved", "claim_challenge": "d" * 32},
            ]
        )

    def request(self, method, path, body=None, headers=None):
        headers = headers or {}
        self.calls.append((method, path, body, headers))
        if path == "/api/node-registration-source":
            return {"public_ipv4": "8.8.8.8"}
        if path == "/api/node-registration-requests":
            return {"request_id": "req1", "challenge": "c" * 32, "registration_token": "secret"}
        if path == "/api/node-registration-requests/req1/proof":
            public_key = register.serialization.load_pem_public_key(
                self.calls[1][2]["public_key_pem"].encode("ascii")
            )
            message = b"hermes-node-registration-v1\nreq1\n" + b"c" * 32 + b"\n8.8.8.8\n" + b"a" * 64 + b"\n"
            public_key.verify(base64.b64decode(body["signature"]), message)
            return {"status": "pending_approval"}
        if path.endswith("/status"):
            return next(self.statuses)
        if path.endswith("/claim-approved"):
            public_key = register.serialization.load_pem_public_key(
                self.calls[1][2]["public_key_pem"].encode("ascii")
            )
            message = (
                b"hermes-node-claim-v1\nreq1\n"
                + b"d" * 32
                + b"\n8.8.8.8\n"
                + b"a" * 64
                + b"\n"
            )
            public_key.verify(base64.b64decode(body["signature"]), message)
            assert body["challenge"] == "d" * 32
            return {"node_id": 7, "package_sha256": "b" * 64, "edge_ticket_secret": "claim-secret"}
        raise AssertionError(path)


def test_enroll_posts_windows_inventory_signs_proof_polls_and_claims(monkeypatch):
    transport = FakeTransport()
    inventory = {
        "machine_fingerprint": "a" * 64,
        "reported_hostname": "WIN-EDGE",
        "os_name": "Windows Server 2025",
        "cpu_count": 8,
        "memory_total_bytes": 16 * 1024**3,
        "disk_total_bytes": 100 * 1024**3,
        "agent_version": "windows-bootstrap/1",
    }
    monkeypatch.setattr(register.time, "sleep", lambda _: None)

    claim = register.enroll(transport, inventory, poll_seconds=0, max_polls=3)

    assert claim["node_id"] == 7
    create = transport.calls[1]
    assert create[2]["platform"] == "windows"
    assert create[2]["public_ipv4"] == "8.8.8.8"
    assert set(create[2]) >= {"public_key_pem", *inventory}
    sensitive_headers = [call[3]["Authorization"] for call in transport.calls if "Authorization" in call[3]]
    assert sensitive_headers == ["Registration req1.secret"] * 4


def test_collect_inventory_hashes_machine_guid_without_returning_raw_value():
    inventory = register.collect_inventory(
        hostname=lambda: "WIN-EDGE",
        machine_guid=lambda: "raw-machine-guid",
        os_name=lambda: "Windows Server 2025 Datacenter",
        cpu_count=lambda: 4,
        memory_bytes=lambda: 1024,
        disk_bytes=lambda: 2048,
    )

    assert inventory["machine_fingerprint"] == register.hashlib.sha256(b"raw-machine-guid").hexdigest()
    assert "raw-machine-guid" not in json.dumps(inventory)


def test_enroll_rejects_non_windows_server_2025_inventory():
    inventory = {
        "machine_fingerprint": "a" * 64,
        "reported_hostname": "WIN-EDGE",
        "os_name": "Windows Server 2022",
        "cpu_count": 8,
        "memory_total_bytes": 1024,
        "disk_total_bytes": 2048,
        "agent_version": "windows-bootstrap/1",
    }
    try:
        register.enroll(FakeTransport(), inventory, poll_seconds=0, max_polls=1)
    except register.BootstrapError as exc:
        assert str(exc) == "unsupported Windows host"
    else:
        raise AssertionError("expected fail closed")