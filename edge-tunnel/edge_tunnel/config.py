from __future__ import annotations

import json
import math
import ntpath
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

_NODE_ID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_FIELDS = {
    "schema_version",
    "node_id",
    "ticket_secret",
    "max_connections",
    "max_frame_bytes",
    "max_bytes_per_connection",
    "idle_timeout",
    "max_connection_seconds",
    "connect_timeout",
    "ticket_max_ttl",
}
_REPARSE_POINT = 0x400
_MAX_CONFIG_BYTES = 65_536
_INTEGER_LIMITS = {
    "max_connections": 65_535,
    "max_frame_bytes": 64 * 1024 * 1024,
    "max_bytes_per_connection": 1024**4,
    "ticket_max_ttl": 300,
}


@dataclass(frozen=True)
class Settings:
    node_id: str
    ticket_secret: bytes
    max_connections: int = 64
    max_frame_bytes: int = 1_048_576
    max_bytes_per_connection: int = 67_108_864
    idle_timeout: float = 60.0
    max_connection_seconds: float = 600.0
    connect_timeout: float = 10.0
    ticket_max_ttl: int = 60

    @classmethod
    def from_env(cls) -> Settings:
        secret = os.environ.get("EDGE_TICKET_SECRET", "").encode()
        node = os.environ.get("EDGE_NODE_ID", "")
        _validate_identity(node, secret, env=True)
        try:
            settings = cls(
                node_id=node,
                ticket_secret=secret,
                max_connections=int(os.getenv("EDGE_MAX_CONNECTIONS", "64")),
                max_frame_bytes=int(os.getenv("EDGE_MAX_FRAME_BYTES", "1048576")),
                max_bytes_per_connection=int(os.getenv("EDGE_MAX_BYTES", "67108864")),
                idle_timeout=float(os.getenv("EDGE_IDLE_TIMEOUT", "60")),
                max_connection_seconds=float(os.getenv("EDGE_MAX_DURATION", "600")),
                connect_timeout=float(os.getenv("EDGE_CONNECT_TIMEOUT", "10")),
                ticket_max_ttl=int(os.getenv("EDGE_TICKET_MAX_TTL", "60")),
            )
        except ValueError as exc:
            raise RuntimeError("invalid edge configuration value") from exc
        _validate_limits(settings)
        return settings

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Settings:
        if os.name == "nt":
            return _windows_settings_from_file(os.path.abspath(path), api=Win32ConfigAPI())
        config_path = Path(path).absolute()
        _validate_safe_path(config_path)
        descriptor = _open_config(config_path)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise RuntimeError("unsafe config path")
            if not _permissions_are_restricted(config_path, file_stat.st_mode):
                raise RuntimeError("unsafe config permissions")
            raw = _read_limited(descriptor)
        finally:
            os.close(descriptor)
        data = _parse_json(raw)
        return _settings_from_mapping(data)


def _validate_identity(node: Any, secret: bytes, *, env: bool = False) -> None:
    if not isinstance(node, str) or _NODE_ID.fullmatch(node) is None:
        message = "EDGE_NODE_ID is missing or unsafe" if env else "invalid config field: node_id"
        raise RuntimeError(message)
    if len(secret) < 32:
        message = (
            "EDGE_TICKET_SECRET must be at least 32 bytes"
            if env
            else "invalid config field: ticket_secret"
        )
        raise RuntimeError(message)


def _validate_limits(settings: Settings) -> None:
    integer_values = {
        "max_connections": settings.max_connections,
        "max_frame_bytes": settings.max_frame_bytes,
        "max_bytes_per_connection": settings.max_bytes_per_connection,
        "ticket_max_ttl": settings.ticket_max_ttl,
    }
    floats = (
        settings.idle_timeout,
        settings.max_connection_seconds,
        settings.connect_timeout,
    )
    if any(
        value <= 0 or value > _INTEGER_LIMITS[name] for name, value in integer_values.items()
    ) or any(not math.isfinite(value) or value <= 0 for value in floats):
        raise RuntimeError("invalid edge configuration limit")


def _settings_from_mapping(data: dict[str, Any]) -> Settings:
    unknown = data.keys() - _FIELDS
    missing = _FIELDS - data.keys()
    if unknown:
        raise RuntimeError(f"unknown config field: {min(unknown)}")
    if missing:
        raise RuntimeError(f"missing config field: {min(missing)}")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RuntimeError("invalid config field: schema_version")
    for field in (
        "max_connections",
        "max_frame_bytes",
        "max_bytes_per_connection",
        "ticket_max_ttl",
    ):
        if type(data[field]) is not int or data[field] <= 0 or data[field] > _INTEGER_LIMITS[field]:
            raise RuntimeError(f"invalid config field: {field}")
    for field in ("idle_timeout", "max_connection_seconds", "connect_timeout"):
        if (
            type(data[field]) not in (int, float)
            or not math.isfinite(data[field])
            or data[field] <= 0
        ):
            raise RuntimeError(f"invalid config field: {field}")
    if not isinstance(data["ticket_secret"], str):
        raise RuntimeError("invalid config field: ticket_secret")  # noqa: TRY004
    try:
        secret = data["ticket_secret"].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RuntimeError("invalid config field: ticket_secret") from exc
    _validate_identity(data["node_id"], secret)
    return Settings(
        node_id=data["node_id"],
        ticket_secret=secret,
        max_connections=data["max_connections"],
        max_frame_bytes=data["max_frame_bytes"],
        max_bytes_per_connection=data["max_bytes_per_connection"],
        idle_timeout=float(data["idle_timeout"]),
        max_connection_seconds=float(data["max_connection_seconds"]),
        connect_timeout=float(data["connect_timeout"]),
        ticket_max_ttl=data["ticket_max_ttl"],
    )


def _validate_safe_path(path: Path) -> None:
    current = path
    while current != current.parent:
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            if current == path:
                raise RuntimeError("config file is unavailable") from None
            current = current.parent
            continue
        if stat.S_ISLNK(details.st_mode) or (
            getattr(details, "st_file_attributes", 0) & _REPARSE_POINT
        ):
            raise RuntimeError("unsafe config path")
        current = current.parent


def _open_config(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("config file is unavailable") from exc


def _read_limited(descriptor: int) -> bytes:
    if os.fstat(descriptor).st_size > _MAX_CONFIG_BYTES:
        raise RuntimeError("config file is too large")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, _MAX_CONFIG_BYTES + 1 - total)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_CONFIG_BYTES:
            raise RuntimeError("config file is too large")


def _parse_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RuntimeError(f"duplicate config field: {key}")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise ValueError

    try:
        data = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=invalid_constant
        )
    except RuntimeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("invalid JSON config") from exc
    if not isinstance(data, dict):
        raise RuntimeError("config root must be an object")  # noqa: TRY004
    return data


def _permissions_are_restricted(path: Path, mode: int) -> bool:
    return mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


@dataclass(frozen=True)
class WindowsObjectInfo:
    """Security and identity facts captured from one already-open Windows handle."""

    final_path: str
    identity: tuple[int, int]
    is_directory: bool
    is_reparse_point: bool
    owner_sid: str
    sddl: str


class Win32ConfigAPI:
    """Handle-only adapter used by the Windows configuration loader."""

    def __init__(self, *, bindings: Any | None = None) -> None:
        self._bindings = bindings if bindings is not None else _CtypesWin32Bindings()

    def open(self, path: str, *, directory: bool) -> Any:
        access = 0x00020000 | (0x00000080 if directory else 0x80000000)
        return self._bindings.create_file(
            path,
            access,
            0x00000001,
            3,
            0x00200000 | 0x02000000,
        )

    def inspect(self, handle: Any) -> WindowsObjectInfo:
        return self._bindings.inspect(handle)

    def read_limited(self, handle: Any, limit: int) -> bytes:
        return self._bindings.read_limited(handle, limit)

    def close(self, handle: Any) -> None:
        self._bindings.close(handle)


class _CtypesWin32Bindings:
    """Thin ctypes bindings; construction intentionally requires real Windows.

    Linux CI covers the loader with injected handle objects, but cannot validate
    Windows ABI, filesystem redirectors, or domain/inherited ACL behavior. Those
    remain explicit real-Windows integration-test responsibilities.
    """

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)

        class FileTime(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        class ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("creation_time", FileTime),
                ("last_access_time", FileTime),
                ("last_write_time", FileTime),
                ("volume_serial", wintypes.DWORD),
                ("file_size_high", wintypes.DWORD),
                ("file_size_low", wintypes.DWORD),
                ("number_of_links", wintypes.DWORD),
                ("file_index_high", wintypes.DWORD),
                ("file_index_low", wintypes.DWORD),
            ]

        self.file_information = ByHandleFileInformation
        self.kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.GetFileType.argtypes = [wintypes.HANDLE]
        self.kernel.GetFileType.restype = wintypes.DWORD
        self.kernel.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ByHandleFileInformation),
        ]
        self.kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self.kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        self.kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
        self.kernel.GetFileSizeEx.restype = wintypes.BOOL
        self.kernel.ReadFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        self.kernel.ReadFile.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p
        self.security.GetSecurityInfo.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.security.GetSecurityInfo.restype = wintypes.DWORD
        self.security.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self.security.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.ULONG),
        ]
        self.security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL

    def _error(self, message: str) -> OSError:
        code = self.ctypes.get_last_error()
        return OSError(code, f"{message}: {self.ctypes.FormatError(code)}")

    def create_file(self, path: str, access: int, share: int, creation: int, flags: int) -> Any:
        handle = self.kernel.CreateFileW(path, access, share, None, creation, flags, None)
        if handle == self.ctypes.c_void_p(-1).value:
            raise self._error("CreateFileW failed")
        return handle

    def _final_path(self, handle: Any) -> str:
        capacity = 512
        while True:
            buffer = self.ctypes.create_unicode_buffer(capacity)
            length = self.kernel.GetFinalPathNameByHandleW(handle, buffer, capacity, 0)
            if not length:
                raise self._error("GetFinalPathNameByHandleW failed")
            if length < capacity:
                return buffer.value
            capacity = length + 1

    def _security(self, handle: Any) -> tuple[str, str]:
        owner = self.ctypes.c_void_p()
        descriptor = self.ctypes.c_void_p()
        result = self.security.GetSecurityInfo(
            handle,
            1,
            0x00000005,
            self.ctypes.byref(owner),
            None,
            None,
            None,
            self.ctypes.byref(descriptor),
        )
        if result:
            raise OSError(result, "GetSecurityInfo failed")
        owner_text = self.wintypes.LPWSTR()
        sddl_text = self.wintypes.LPWSTR()
        try:
            if not self.security.ConvertSidToStringSidW(owner, self.ctypes.byref(owner_text)):
                raise self._error("ConvertSidToStringSidW failed")
            if not self.security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 0x00000005, self.ctypes.byref(sddl_text), None
            ):
                raise self._error("security descriptor conversion failed")
            return owner_text.value, sddl_text.value
        finally:
            if owner_text:
                self.kernel.LocalFree(owner_text)
            if sddl_text:
                self.kernel.LocalFree(sddl_text)
            if descriptor:
                self.kernel.LocalFree(descriptor)

    def inspect(self, handle: Any) -> WindowsObjectInfo:
        if self.kernel.GetFileType(handle) != 0x0001:
            raise OSError("handle is not a disk file")
        details = self.file_information()
        if not self.kernel.GetFileInformationByHandle(handle, self.ctypes.byref(details)):
            raise self._error("GetFileInformationByHandle failed")
        owner_sid, sddl = self._security(handle)
        return WindowsObjectInfo(
            final_path=self._final_path(handle),
            identity=(
                int(details.volume_serial),
                (int(details.file_index_high) << 32) | int(details.file_index_low),
            ),
            is_directory=bool(details.attributes & 0x10),
            is_reparse_point=bool(details.attributes & _REPARSE_POINT),
            owner_sid=owner_sid,
            sddl=sddl,
        )

    def read_limited(self, handle: Any, limit: int) -> bytes:
        size = self.ctypes.c_longlong()
        if not self.kernel.GetFileSizeEx(handle, self.ctypes.byref(size)):
            raise self._error("GetFileSizeEx failed")
        if size.value > limit:
            raise RuntimeError("config file is too large")
        chunks: list[bytes] = []
        total = 0
        while True:
            capacity = min(8192, limit + 1 - total)
            buffer = self.ctypes.create_string_buffer(capacity)
            count = self.wintypes.DWORD()
            if not self.kernel.ReadFile(handle, buffer, capacity, self.ctypes.byref(count), None):
                raise self._error("ReadFile failed")
            if not count.value:
                return b"".join(chunks)
            chunks.append(buffer.raw[: count.value])
            total += count.value
            if total > limit:
                raise RuntimeError("config file is too large")

    def close(self, handle: Any) -> None:
        if not self.kernel.CloseHandle(handle):
            raise self._error("CloseHandle failed")


_SYSTEM_SIDS = {"SY", "S-1-5-18"}
_ADMIN_SIDS = {"BA", "S-1-5-32-544"}
_LOCAL_SERVICE_SIDS = {"LS", "S-1-5-19"}
_WRITE_MASK = 0x10000000 | 0x40000000 | 0x000D0156
_REPLACE_MASK = 0x10000000 | 0x40000000 | 0x000D0040


def _windows_path_key(path: str | os.PathLike[str]) -> str:
    value = ntpath.normpath(os.fspath(path))
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return value.casefold()


def _dacl(sddl: str) -> str | None:
    start = sddl.find("D:")
    if start < 0:
        return None
    end = sddl.find("S:", start + 2)
    return sddl[start:] if end < 0 else sddl[start:end]


def _aces(sddl: str) -> list[list[str]] | None:
    dacl = _dacl(sddl)
    if dacl is None:
        return None
    raw = re.findall(r"\(([^()]*)\)", dacl)
    fields = [ace.split(";") for ace in raw]
    return fields if raw and all(len(item) == 6 for item in fields) else None


def _rights_mask(rights: str) -> int | None:
    lowered = rights.lower()
    if lowered.startswith("0x"):
        try:
            return int(lowered, 16)
        except ValueError:
            return None
    values = {
        "GA": 0x10000000,
        "GW": 0x40000000,
        "GR": 0x80000000,
        "GX": 0x20000000,
        "FA": 0x001F01FF,
        "FW": 0x00120116,
        "FR": 0x00120089,
        "FX": 0x001200A0,
    }
    if len(rights) % 2:
        return None
    result = 0
    for offset in range(0, len(rights), 2):
        value = values.get(rights[offset : offset + 2].upper())
        if value is None:
            return None
        result |= value
    return result


def _windows_settings_from_file(path: str, *, api: Any) -> Settings:
    """Load after validating leaf and every parent through held handles.

    The injected API makes race and ACL policy testable on non-Windows hosts. The
    production API below is still exercised only by a real Windows test lane.
    """
    requested = _windows_path_key(path)
    handles: list[Any] = []
    identities: set[tuple[int, int]] = set()
    try:
        leaf = api.open(path, directory=False)
        handles.append(leaf)
        leaf_info = api.inspect(leaf)
        if (
            leaf_info.is_directory
            or leaf_info.is_reparse_point
            or not leaf_info.identity
            or _windows_path_key(leaf_info.final_path) != requested
        ):
            raise RuntimeError("unsafe config path")
        if leaf_info.owner_sid not in _SYSTEM_SIDS or not _windows_sddl_is_restricted(
            leaf_info.sddl
        ):
            raise RuntimeError("unsafe config permissions")
        identities.add(leaf_info.identity)

        current = PureWindowsPath(leaf_info.final_path).parent
        immediate_parent = True
        while current != current.parent:
            parent = api.open(str(current), directory=True)
            handles.append(parent)
            info = api.inspect(parent)
            if (
                not info.is_directory
                or info.is_reparse_point
                or not info.identity
                or info.identity in identities
                or _windows_path_key(info.final_path) != _windows_path_key(str(current))
            ):
                raise RuntimeError("unsafe config path")
            directory_acl_ok = (
                _windows_directory_sddl_is_restricted(info.sddl)
                if immediate_parent
                else _windows_ancestor_sddl_is_restricted(info.sddl)
            )
            if info.owner_sid not in (_SYSTEM_SIDS | _ADMIN_SIDS) or not directory_acl_ok:
                raise RuntimeError("unsafe parent directory permissions")
            identities.add(info.identity)
            current = current.parent
            immediate_parent = False
        root = api.open(str(current), directory=True)
        handles.append(root)
        root_info = api.inspect(root)
        if (
            not root_info.is_directory
            or root_info.is_reparse_point
            or not root_info.identity
            or root_info.identity in identities
            or _windows_path_key(root_info.final_path) != _windows_path_key(str(current))
        ):
            raise RuntimeError("unsafe config path")
        if root_info.owner_sid not in (_SYSTEM_SIDS | _ADMIN_SIDS) or not (
            _windows_ancestor_sddl_is_restricted(root_info.sddl)
        ):
            raise RuntimeError("unsafe parent directory permissions")
        raw = api.read_limited(leaf, _MAX_CONFIG_BYTES)
    except OSError as exc:
        raise RuntimeError("config file is unavailable") from exc
    finally:
        for handle in handles:
            api.close(handle)
    return _settings_from_mapping(_parse_json(raw))


def _windows_sddl_is_restricted(sddl: str) -> bool:
    dacl = _dacl(sddl)
    aces = _aces(sddl)
    if dacl is None or not dacl.startswith("D:P") or aces is None or len(aces) != 2:
        return False
    system_present = False
    local_service_present = False
    for fields in aces:
        if fields[0] != "A" or any(fields[index] for index in (1, 3, 4)):
            return False
        rights, trustee = fields[2], fields[5]
        mask = _rights_mask(rights)
        if trustee in _SYSTEM_SIDS:
            if rights.upper() not in {"FA", "GA"} and mask != 0x001F01FF:
                return False
            system_present = True
        elif trustee in _LOCAL_SERVICE_SIDS:
            if rights.upper() not in {"FR", "GR"} and mask != 0x00120089:
                return False
            local_service_present = True
        else:
            return False
    return system_present and local_service_present


def _windows_directory_sddl_is_restricted(sddl: str) -> bool:
    return _windows_directory_sddl_respects_mask(sddl, _WRITE_MASK)


def _windows_ancestor_sddl_is_restricted(sddl: str) -> bool:
    return _windows_directory_sddl_respects_mask(sddl, _REPLACE_MASK)


def _windows_directory_sddl_respects_mask(sddl: str, unsafe_mask: int) -> bool:
    aces = _aces(sddl)
    if aces is None:
        return False
    for fields in aces:
        ace_type, flags, rights, trustee = fields[0], fields[1], fields[2], fields[5]
        mask = _rights_mask(rights)
        flag_parts = {flags[index : index + 2] for index in range(0, len(flags), 2)}
        if (
            ace_type not in {"A", "D"}
            or mask is None
            or len(flags) % 2
            or not flag_parts <= {"CI", "OI", "NP", "IO", "ID", "SA", "FA"}
        ):
            return False
        if (
            ace_type == "A"
            and "IO" not in flag_parts
            and trustee not in (_SYSTEM_SIDS | _ADMIN_SIDS)
            and mask & unsafe_mask
        ):
            return False
    return True
