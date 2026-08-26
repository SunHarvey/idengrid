import json
import math
import os
from types import SimpleNamespace

import pytest
from edge_tunnel.app import Settings
from edge_tunnel.config import (
    Win32ConfigAPI,
    WindowsObjectInfo,
    _read_limited,
    _windows_directory_sddl_is_restricted,
    _windows_sddl_is_restricted,
    _windows_settings_from_file,
)

VALID_CONFIG = {
    "schema_version": 1,
    "node_id": "edge-windows-01",
    "ticket_secret": "s" * 32,
    "max_connections": 256,
    "max_frame_bytes": 1_048_576,
    "max_bytes_per_connection": 2_147_483_648,
    "idle_timeout": 300,
    "max_connection_seconds": 28_800,
    "connect_timeout": 10,
    "ticket_max_ttl": 60,
}


def write_config(tmp_path, data=VALID_CONFIG):
    path = tmp_path / "edge.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_settings_load_required_identity_and_limits_from_environment(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv("EDGE_MAX_CONNECTIONS", "12")

    settings = Settings.from_env()

    assert settings.node_id == "edge-sg01"
    assert settings.ticket_secret == b"x" * 32
    assert settings.max_connections == 12


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EDGE_MAX_CONNECTIONS", "0"),
        ("EDGE_MAX_FRAME_BYTES", "0"),
        ("EDGE_MAX_BYTES", "0"),
        ("EDGE_IDLE_TIMEOUT", "0"),
        ("EDGE_MAX_DURATION", "0"),
        ("EDGE_CONNECT_TIMEOUT", "0"),
        ("EDGE_TICKET_MAX_TTL", "0"),
        ("EDGE_MAX_CONNECTIONS", "not-an-int"),
    ],
)
def test_settings_fail_closed_on_invalid_limits(monkeypatch, name, value):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="invalid edge configuration"):
        Settings.from_env()


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
@pytest.mark.parametrize("name", ["EDGE_IDLE_TIMEOUT", "EDGE_MAX_DURATION", "EDGE_CONNECT_TIMEOUT"])
def test_settings_environment_rejects_non_finite_floats(monkeypatch, name, value):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="invalid edge configuration"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EDGE_MAX_CONNECTIONS", "65536"),
        ("EDGE_MAX_FRAME_BYTES", str(64 * 1024 * 1024 + 1)),
        ("EDGE_MAX_BYTES", str(1024**4 + 1)),
        ("EDGE_TICKET_MAX_TTL", "301"),
    ],
)
def test_settings_environment_rejects_integer_values_above_safe_bounds(monkeypatch, name, value):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="invalid edge configuration"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("node", "secret"), [("", "x" * 32), ("edge-sg01", "short"), ("bad/node", "x" * 32)]
)
def test_settings_reject_missing_or_unsafe_identity(monkeypatch, node, secret):
    monkeypatch.setenv("EDGE_NODE_ID", node)
    monkeypatch.setenv("EDGE_TICKET_SECRET", secret)

    with pytest.raises(RuntimeError):
        Settings.from_env()


def test_settings_load_complete_strict_json_file(tmp_path):
    settings = Settings.from_file(write_config(tmp_path))

    assert settings.node_id == "edge-windows-01"
    assert settings.ticket_secret == b"s" * 32
    assert settings.max_connections == 256
    assert settings.max_bytes_per_connection == 2_147_483_648


def test_settings_loads_powershell_51_utf8_bom_config(tmp_path):
    path = tmp_path / "edge.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(VALID_CONFIG).encode("utf-8"))
    path.chmod(0o600)

    settings = Settings.from_file(path)

    assert settings.node_id == "edge-windows-01"
    assert settings.ticket_secret == b"s" * 32


@pytest.mark.parametrize(
    "change,field",
    [
        ({"unexpected": 1}, "unexpected"),
        ({"schema_version": 2}, "schema_version"),
        ({"node_id": "bad/node"}, "node_id"),
        ({"ticket_secret": "short"}, "ticket_secret"),
        ({"max_connections": 0}, "max_connections"),
        ({"idle_timeout": True}, "idle_timeout"),
        ({"ticket_max_ttl": 301}, "ticket_max_ttl"),
    ],
)
def test_settings_file_rejects_unknown_or_invalid_fields_without_values(tmp_path, change, field):
    data = {**VALID_CONFIG, **change}
    secret = data["ticket_secret"]

    with pytest.raises(RuntimeError) as error:
        Settings.from_file(write_config(tmp_path, data))

    assert field in str(error.value)
    assert secret not in str(error.value)


def test_settings_file_rejects_missing_field(tmp_path):
    data = dict(VALID_CONFIG)
    del data["connect_timeout"]

    with pytest.raises(RuntimeError, match="connect_timeout"):
        Settings.from_file(write_config(tmp_path, data))


@pytest.mark.parametrize("field", ["idle_timeout", "max_connection_seconds", "connect_timeout"])
@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 1e309])
def test_settings_file_rejects_non_finite_floats(tmp_path, field, value):
    data = {**VALID_CONFIG, field: value}

    with pytest.raises(RuntimeError):
        Settings.from_file(write_config(tmp_path, data))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_connections", 65_536),
        ("max_frame_bytes", 64 * 1024 * 1024 + 1),
        ("max_bytes_per_connection", 1024**4 + 1),
    ],
)
def test_settings_file_rejects_integer_values_above_safe_bounds(tmp_path, field, value):
    with pytest.raises(RuntimeError, match=field):
        Settings.from_file(write_config(tmp_path, {**VALID_CONFIG, field: value}))


def test_read_limited_rejects_large_regular_file_before_read(monkeypatch):
    monkeypatch.setattr(
        "edge_tunnel.config.os.fstat", lambda descriptor: SimpleNamespace(st_size=65_537)
    )
    monkeypatch.setattr(
        "edge_tunnel.config.os.read",
        lambda descriptor, count: pytest.fail("oversize file must not be read"),
    )

    with pytest.raises(RuntimeError, match="too large"):
        _read_limited(123)


def test_read_limited_loops_until_eof_when_reads_are_short(monkeypatch):
    chunks = iter((b'{"schema_', b'version":1}', b""))
    monkeypatch.setattr(
        "edge_tunnel.config.os.fstat", lambda descriptor: SimpleNamespace(st_size=20)
    )
    monkeypatch.setattr("edge_tunnel.config.os.read", lambda descriptor, count: next(chunks))

    assert _read_limited(123) == b'{"schema_version":1}'


def test_settings_file_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "edge.json"
    body = json.dumps(VALID_CONFIG)
    body = body[:-1] + ', "node_id": "second-node"}'
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(RuntimeError, match="node_id"):
        Settings.from_file(path)


def test_settings_file_rejects_symlink(tmp_path):
    target = write_config(tmp_path)
    link = tmp_path / "edge-link.json"
    link.symlink_to(target)

    with pytest.raises(RuntimeError, match="unsafe config path"):
        Settings.from_file(link)


def test_settings_file_rejects_group_or_world_permissions(tmp_path):
    path = write_config(tmp_path)
    path.chmod(0o640)

    with pytest.raises(RuntimeError, match="permissions"):
        Settings.from_file(path)


def test_settings_file_rejects_reparse_attribute(tmp_path, monkeypatch):
    path = write_config(tmp_path)
    real_lstat = os.lstat

    def reparse_lstat(candidate):
        result = real_lstat(candidate)
        if os.fspath(candidate) == os.fspath(path):

            class ReparseStat:
                st_mode = result.st_mode
                st_file_attributes = 0x400

            return ReparseStat()
        return result

    monkeypatch.setattr("edge_tunnel.config.os.lstat", reparse_lstat)

    with pytest.raises(RuntimeError, match="unsafe config path"):
        Settings.from_file(path)


@pytest.mark.parametrize(
    "sddl",
    [
        "D:AI(A;;FA;;;SY)(A;;FRFX;;;LS)",
        "D:P(A;;FA;;;SY)(A;;FRFX;;;WD)",
        "D:P(A;;FA;;;SY)(A;;FW;;;LS)",
        "D:P(A;;FA;;;SY)(A;;0x12019f;;;LS)",
        "D:P(A;;FR;;;SY)(A;;FR;;;LS)",
        "D:P(A;;FA;;;SY)",
        "D:P(A;IO;FA;;;SY)(A;;FR;;;LS)",
    ],
)
def test_windows_acl_rejects_inherited_broad_or_writable_dacls(sddl):
    assert not _windows_sddl_is_restricted(sddl)


def test_windows_acl_accepts_only_system_full_and_local_service_read():
    assert _windows_sddl_is_restricted("D:P(A;;FA;;;SY)(A;;FR;;;LS)")


class FakeWindowsConfigAPI:
    def __init__(self, objects, payload=None):
        self.objects = objects
        self.payload = payload or json.dumps(VALID_CONFIG).encode()
        self.opened = []
        self.closed = []

    def open(self, path, *, directory):
        key = str(path).casefold()
        self.opened.append((key, directory))
        if key not in self.objects:
            raise OSError("missing fake object")
        return key

    def inspect(self, handle):
        return self.objects[handle]

    def read_limited(self, handle, limit):
        if len(self.payload) > limit:
            raise RuntimeError("config file is too large")
        return self.payload

    def close(self, handle):
        self.closed.append(handle)


def windows_object(path, *, directory, sddl, identity=None, reparse=False):
    return WindowsObjectInfo(
        final_path=path,
        identity=identity or (7, hash(path)),
        is_directory=directory,
        is_reparse_point=reparse,
        owner_sid="S-1-5-18" if not directory else "S-1-5-32-544",
        sddl=sddl,
    )


def safe_windows_objects():
    directory_acl = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
    return {
        "c:\\programdata\\idengrid\\edge.json": windows_object(
            r"C:\ProgramData\IdenGrid\edge.json",
            directory=False,
            sddl="O:SYD:P(A;;0x1f01ff;;;S-1-5-18)(A;;0x120089;;;S-1-5-19)",
        ),
        "c:\\programdata\\idengrid": windows_object(
            r"C:\ProgramData\IdenGrid", directory=True, sddl=directory_acl
        ),
        "c:\\programdata": windows_object(r"C:\ProgramData", directory=True, sddl=directory_acl),
        "c:\\": windows_object("C:\\", directory=True, sddl=directory_acl),
    }


def test_windows_loader_validates_and_reads_the_same_open_leaf_handle():
    api = FakeWindowsConfigAPI(safe_windows_objects())

    settings = _windows_settings_from_file(r"C:\ProgramData\IdenGrid\edge.json", api=api)

    assert settings.node_id == VALID_CONFIG["node_id"]
    assert api.opened == [
        (r"c:\programdata\idengrid\edge.json", False),
        (r"c:\programdata\idengrid", True),
        (r"c:\programdata", True),
        ("c:\\", True),
    ]
    assert api.closed == [item[0] for item in api.opened]


def test_windows_loader_rejects_path_swap_exposed_by_handle_final_path():
    objects = safe_windows_objects()
    objects[r"c:\programdata\idengrid\edge.json"] = windows_object(
        r"C:\Attacker\edge.json",
        directory=False,
        sddl="O:SYD:P(A;;FA;;;SY)(A;;FR;;;LS)",
    )
    api = FakeWindowsConfigAPI(objects)

    with pytest.raises(RuntimeError, match="unsafe config path"):
        _windows_settings_from_file(r"C:\ProgramData\IdenGrid\edge.json", api=api)

    assert api.closed == [r"c:\programdata\idengrid\edge.json"]


def test_windows_loader_rejects_reparse_point_reported_by_open_handle():
    objects = safe_windows_objects()
    objects[r"c:\programdata\idengrid\edge.json"] = windows_object(
        r"C:\ProgramData\IdenGrid\edge.json",
        directory=False,
        reparse=True,
        sddl="O:SYD:P(A;;FA;;;SY)(A;;FR;;;LS)",
    )

    with pytest.raises(RuntimeError, match="unsafe config path"):
        _windows_settings_from_file(
            r"C:\ProgramData\IdenGrid\edge.json", api=FakeWindowsConfigAPI(objects)
        )


def test_windows_loader_rejects_reparse_parent_reported_by_open_handle():
    objects = safe_windows_objects()
    parent = objects[r"c:\programdata\idengrid"]
    objects[r"c:\programdata\idengrid"] = WindowsObjectInfo(
        final_path=parent.final_path,
        identity=parent.identity,
        is_directory=True,
        is_reparse_point=True,
        owner_sid=parent.owner_sid,
        sddl=parent.sddl,
    )

    with pytest.raises(RuntimeError, match="unsafe config path"):
        _windows_settings_from_file(
            r"C:\ProgramData\IdenGrid\edge.json", api=FakeWindowsConfigAPI(objects)
        )


def test_windows_loader_requires_system_to_own_leaf():
    objects = safe_windows_objects()
    leaf = objects[r"c:\programdata\idengrid\edge.json"]
    objects[r"c:\programdata\idengrid\edge.json"] = WindowsObjectInfo(
        final_path=leaf.final_path,
        identity=leaf.identity,
        is_directory=False,
        is_reparse_point=False,
        owner_sid="S-1-5-32-544",
        sddl=leaf.sddl,
    )

    with pytest.raises(RuntimeError, match="config permissions"):
        _windows_settings_from_file(
            r"C:\ProgramData\IdenGrid\edge.json", api=FakeWindowsConfigAPI(objects)
        )


def test_windows_loader_rejects_parent_writable_by_non_admin_identity():
    objects = safe_windows_objects()
    objects[r"c:\programdata\idengrid"] = windows_object(
        r"C:\ProgramData\IdenGrid",
        directory=True,
        sddl="O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;BU)",
    )

    with pytest.raises(RuntimeError, match="parent directory permissions"):
        _windows_settings_from_file(
            r"C:\ProgramData\IdenGrid\edge.json", api=FakeWindowsConfigAPI(objects)
        )


def test_windows_loader_rejects_untrusted_parent_owner_even_with_read_only_acl():
    objects = safe_windows_objects()
    unsafe = objects[r"c:\programdata\idengrid"]
    objects[r"c:\programdata\idengrid"] = WindowsObjectInfo(
        final_path=unsafe.final_path,
        identity=unsafe.identity,
        is_directory=True,
        is_reparse_point=False,
        owner_sid="S-1-5-21-1-2-3-1001",
        sddl=unsafe.sddl,
    )

    with pytest.raises(RuntimeError, match="parent directory permissions"):
        _windows_settings_from_file(
            r"C:\ProgramData\IdenGrid\edge.json", api=FakeWindowsConfigAPI(objects)
        )


def test_windows_directory_acl_hex_masks_allow_read_but_reject_write():
    assert _windows_directory_sddl_is_restricted(
        "D:P(A;;0x1f01ff;;;SY)(A;;0x1f01ff;;;BA)(A;;0x1200a9;;;BU)"
    )
    assert _windows_directory_sddl_is_restricted(
        "D:P(A;;FA;;;SY)(A;OICIIO;0x1f01ff;;;CO)(A;;0x1200a9;;;BU)"
    )
    assert not _windows_directory_sddl_is_restricted(
        "D:P(A;;0x1f01ff;;;SY)(A;;0x1f01ff;;;BA)(A;;0x120116;;;BU)"
    )


def test_windows_leaf_acl_hex_masks_require_exact_system_full_and_localservice_read():
    assert _windows_sddl_is_restricted("D:P(A;;0x1f01ff;;;S-1-5-18)(A;;0x120089;;;S-1-5-19)")
    assert not _windows_sddl_is_restricted("D:P(A;;0x1f01ff;;;SY)(A;;0x1200a9;;;LS)")


def test_win32_api_opens_non_reparse_handles_without_write_or_delete_sharing():
    class Bindings:
        def __init__(self):
            self.calls = []

        def create_file(self, path, access, share, creation, flags):
            self.calls.append((path, access, share, creation, flags))
            return 42

    bindings = Bindings()
    api = Win32ConfigAPI(bindings=bindings)

    assert api.open(r"C:\ProgramData\IdenGrid\edge.json", directory=False) == 42
    assert api.open(r"C:\ProgramData\IdenGrid", directory=True) == 42
    leaf, directory = bindings.calls
    assert leaf[2] == directory[2] == 0x1  # FILE_SHARE_READ only
    assert leaf[3] == directory[3] == 3  # OPEN_EXISTING
    assert leaf[4] & directory[4] & 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    assert leaf[4] & directory[4] & 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
    assert leaf[1] & 0x80000000  # GENERIC_READ for the leaf
    assert not directory[1] & 0x80000000
