import ctypes
import json
import math
from types import SimpleNamespace

import pytest
from edge_tunnel.app import Settings
from edge_tunnel.config import (
    Win32ConfigAPI,
    WindowsObjectInfo,
    _CtypesWin32Bindings,
    _parse_json,
    _settings_from_mapping,
    _windows_ancestor_sddl_is_restricted,
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


def settings_from_json(data):
    return _settings_from_mapping(_parse_json(json.dumps(data).encode()))


def test_settings_load_required_identity_and_limits_from_environment(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv("EDGE_MAX_CONNECTIONS", "12")

    settings = Settings.from_env()

    assert settings.node_id == "edge-sg01"
    assert settings.ticket_secret == b"x" * 32
    assert settings.max_connections == 12


def test_settings_file_loader_is_unavailable_on_linux(tmp_path, monkeypatch):
    path = write_config(tmp_path)
    monkeypatch.setattr("edge_tunnel.config.os.name", "posix")

    with pytest.raises(RuntimeError, match="Windows"):
        Settings.from_file(path)


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
    ("name", "maximum"),
    [
        ("EDGE_IDLE_TIMEOUT", 3_600),
        ("EDGE_MAX_DURATION", 32_400),
        ("EDGE_CONNECT_TIMEOUT", 120),
    ],
)
def test_settings_environment_accepts_timeout_safe_upper_bound(monkeypatch, name, maximum):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, str(maximum))

    Settings.from_env()


@pytest.mark.parametrize(
    ("name", "maximum"),
    [
        ("EDGE_IDLE_TIMEOUT", 3_600),
        ("EDGE_MAX_DURATION", 32_400),
        ("EDGE_CONNECT_TIMEOUT", 120),
    ],
)
def test_settings_environment_rejects_timeout_above_safe_upper_bound(
    monkeypatch, name, maximum
):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, str(maximum + 0.001))

    with pytest.raises(RuntimeError, match="invalid edge configuration"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("idle_timeout", 3_600),
        ("max_connection_seconds", 32_400),
        ("connect_timeout", 120),
    ],
)
def test_settings_json_accepts_timeout_safe_upper_bound(field, maximum):
    settings = settings_from_json({**VALID_CONFIG, field: maximum})

    assert getattr(settings, field) == maximum


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("idle_timeout", 3_600),
        ("max_connection_seconds", 32_400),
        ("connect_timeout", 120),
    ],
)
def test_settings_json_rejects_timeout_above_safe_upper_bound(field, maximum):
    with pytest.raises(RuntimeError, match=field):
        settings_from_json({**VALID_CONFIG, field: maximum + 0.001})


@pytest.mark.parametrize(
    ("node", "secret"), [("", "x" * 32), ("edge-sg01", "short"), ("bad/node", "x" * 32)]
)
def test_settings_reject_missing_or_unsafe_identity(monkeypatch, node, secret):
    monkeypatch.setenv("EDGE_NODE_ID", node)
    monkeypatch.setenv("EDGE_TICKET_SECRET", secret)

    with pytest.raises(RuntimeError):
        Settings.from_env()


def test_settings_load_complete_strict_json():
    settings = settings_from_json(VALID_CONFIG)

    assert settings.node_id == "edge-windows-01"
    assert settings.ticket_secret == b"s" * 32
    assert settings.max_connections == 256
    assert settings.max_bytes_per_connection == 2_147_483_648


def test_settings_loads_powershell_51_utf8_bom_config():
    raw = b"\xef\xbb\xbf" + json.dumps(VALID_CONFIG).encode("utf-8")

    settings = _settings_from_mapping(_parse_json(raw))

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
def test_settings_json_rejects_unknown_or_invalid_fields_without_values(change, field):
    data = {**VALID_CONFIG, **change}
    secret = data["ticket_secret"]

    with pytest.raises(RuntimeError) as error:
        settings_from_json(data)

    assert field in str(error.value)
    assert secret not in str(error.value)


def test_settings_json_rejects_missing_field():
    data = dict(VALID_CONFIG)
    del data["connect_timeout"]

    with pytest.raises(RuntimeError, match="connect_timeout"):
        settings_from_json(data)


@pytest.mark.parametrize("field", ["idle_timeout", "max_connection_seconds", "connect_timeout"])
@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 1e309])
def test_settings_json_rejects_non_finite_floats(field, value):
    data = {**VALID_CONFIG, field: value}

    with pytest.raises(RuntimeError):
        settings_from_json(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_connections", 65_536),
        ("max_frame_bytes", 64 * 1024 * 1024 + 1),
        ("max_bytes_per_connection", 1024**4 + 1),
    ],
)
def test_settings_json_rejects_integer_values_above_safe_bounds(field, value):
    with pytest.raises(RuntimeError, match=field):
        settings_from_json({**VALID_CONFIG, field: value})


class FakeReadKernel:
    def __init__(self, payload, *, reported_size=None, size_result=True, read_results=None):
        self.payload = payload
        self.reported_size = len(payload) if reported_size is None else reported_size
        self.size_result = size_result
        self.read_results = iter(read_results) if read_results is not None else None
        self.offset = 0

    def GetFileSizeEx(self, handle, size):
        size._obj.value = self.reported_size
        return self.size_result

    def ReadFile(self, handle, buffer, capacity, count, overlapped):
        result = True if self.read_results is None else next(self.read_results)
        if not result:
            return False
        chunk = self.payload[self.offset : self.offset + capacity]
        ctypes.memmove(buffer, chunk, len(chunk))
        count._obj.value = len(chunk)
        self.offset += len(chunk)
        return True


def fake_ctypes_windows_bindings(kernel):
    bindings = object.__new__(_CtypesWin32Bindings)
    bindings.ctypes = SimpleNamespace(
        c_longlong=ctypes.c_longlong,
        byref=ctypes.byref,
        create_string_buffer=ctypes.create_string_buffer,
        get_last_error=lambda: 5,
        FormatError=lambda code: "injected error",
    )
    bindings.wintypes = SimpleNamespace(DWORD=ctypes.c_uint32)
    bindings.kernel = kernel
    return bindings


def test_windows_read_limited_loops_after_short_reads():
    class ShortReadKernel(FakeReadKernel):
        def ReadFile(self, handle, buffer, capacity, count, overlapped):
            return super().ReadFile(handle, buffer, min(capacity, 3), count, overlapped)

    payload = b"short reads must be joined"
    bindings = fake_ctypes_windows_bindings(ShortReadKernel(payload))

    assert bindings.read_limited(42, 65_536) == payload


def test_windows_read_limited_accepts_exactly_65536_bytes():
    payload = b"x" * 65_536
    bindings = fake_ctypes_windows_bindings(FakeReadKernel(payload))

    assert bindings.read_limited(42, 65_536) == payload


def test_windows_read_limited_rejects_file_reported_as_65537_bytes_before_read():
    kernel = FakeReadKernel(b"x" * 65_537)
    bindings = fake_ctypes_windows_bindings(kernel)

    with pytest.raises(RuntimeError, match="too large"):
        bindings.read_limited(42, 65_536)

    assert kernel.offset == 0


def test_windows_read_limited_rejects_file_that_grows_to_65537_bytes():
    kernel = FakeReadKernel(b"x" * 65_537, reported_size=65_536)
    bindings = fake_ctypes_windows_bindings(kernel)

    with pytest.raises(RuntimeError, match="too large"):
        bindings.read_limited(42, 65_536)

    assert kernel.offset == 65_537


def test_windows_read_limited_reports_get_file_size_error():
    bindings = fake_ctypes_windows_bindings(FakeReadKernel(b"", size_result=False))

    with pytest.raises(OSError, match="GetFileSizeEx failed"):
        bindings.read_limited(42, 65_536)


def test_windows_read_limited_reports_read_file_error():
    bindings = fake_ctypes_windows_bindings(FakeReadKernel(b"x", read_results=[False]))

    with pytest.raises(OSError, match="ReadFile failed"):
        bindings.read_limited(42, 65_536)


def test_settings_json_rejects_duplicate_keys():
    body = json.dumps(VALID_CONFIG)
    body = body[:-1] + ', "node_id": "second-node"}'

    with pytest.raises(RuntimeError, match="node_id"):
        _parse_json(body.encode())


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


def windows_object(path, *, directory, sddl, identity=None, reparse=False, owner_sid=None):
    return WindowsObjectInfo(
        final_path=path,
        identity=identity or (7, hash(path)),
        is_directory=directory,
        is_reparse_point=reparse,
        owner_sid=owner_sid or ("S-1-5-18" if not directory else "S-1-5-32-544"),
        sddl=sddl,
    )


def safe_windows_objects():
    directory_acl = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
    ancestor_acl = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;BU)"
    return {
        "c:\\programdata\\idengrid\\edge.json": windows_object(
            r"C:\ProgramData\IdenGrid\edge.json",
            directory=False,
            sddl="O:SYD:P(A;;0x1f01ff;;;S-1-5-18)(A;;0x120089;;;S-1-5-19)",
        ),
        "c:\\programdata\\idengrid": windows_object(
            r"C:\ProgramData\IdenGrid", directory=True, sddl=directory_acl
        ),
        "c:\\programdata": windows_object(r"C:\ProgramData", directory=True, sddl=ancestor_acl),
        "c:\\": windows_object(
            "C:\\",
            directory=True,
            sddl=ancestor_acl,
            owner_sid="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        ),
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


def test_windows_ancestor_acl_allows_create_but_rejects_path_replacement():
    standard_create = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;BU)"
    delete_child = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120156;;;BU)"
    assert _windows_ancestor_sddl_is_restricted(standard_create)
    assert not _windows_ancestor_sddl_is_restricted(delete_child)
    assert not _windows_directory_sddl_is_restricted(standard_create)


def test_windows_ancestor_acl_accepts_standard_server_2025_sddl():
    program_data = "O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)"
    system_root = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;CIIO;DC;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1)"
    assert _windows_ancestor_sddl_is_restricted(program_data)
    assert _windows_ancestor_sddl_is_restricted(system_root)


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
