#!/usr/bin/env python3
"""Create a reproducible public Windows Edge ZIP from a strict staging allowlist."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_FILES = {
    "manifest.json",
    "runtime-manifest.json",
    "THIRD_PARTY_NOTICES.txt",
    "app/edge_tunnel/__init__.py",
    "app/edge_tunnel/__main__.py",
    "app/edge_tunnel/app.py",
    "app/edge_tunnel/config.py",
    "app/edge_tunnel/resources.py",
    "app/edge_tunnel/targets.py",
    "app/edge_tunnel/tickets.py",
    "bootstrap/register.py",
    "gateway/caddy.exe",
    "service/IdenGridEdgeGateway.exe",
    "service/IdenGridEdgeGateway.xml",
    "service/IdenGridEdgeService.exe",
    "service/IdenGridEdgeService.xml",
    "scripts/Build-WindowsEdge.ps1",
    "scripts/Get-IdenGridEdgeStatus.ps1",
    "scripts/Install-IdenGridEdge.ps1",
    "scripts/Uninstall-IdenGridEdge.ps1",
    "scripts/Upgrade-IdenGridEdge.ps1",
    "templates/Caddyfile.template",
    "templates/edge.json.example",
}
ALLOWED_RUNTIME_ROOTS = {
    "LICENSE.txt",
    "_asyncio.pyd",
    "_bz2.pyd",
    "_ctypes.pyd",
    "_decimal.pyd",
    "_elementtree.pyd",
    "_hashlib.pyd",
    "_lzma.pyd",
    "_msi.pyd",
    "_multiprocessing.pyd",
    "_overlapped.pyd",
    "_queue.pyd",
    "_socket.pyd",
    "_sqlite3.pyd",
    "_ssl.pyd",
    "_uuid.pyd",
    "_zoneinfo.pyd",
    "libcrypto-3.dll",
    "libffi-8.dll",
    "libssl-3.dll",
    "pyexpat.pyd",
    "python.exe",
    "python.cat",
    "pythonw.exe",
    "python3.dll",
    "python311.dll",
    "python311._pth",
    "python311.zip",
    "select.pyd",
    "sqlite3.dll",
    "unicodedata.pyd",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "winsound.pyd",
}
ALLOWED_RUNTIME_SUFFIXES = {
    ".cfg",
    ".dll",
    ".h",
    ".pxd",
    ".pxi",
    ".py",
    ".pyc",
    ".pyd",
    ".pyi",
    ".pyx",
}
ALLOWED_RUNTIME_METADATA = {
    "COPYING",
    "INSTALLER",
    "LICENSE",
    "LICENSE.txt",
    "METADATA",
    "NOTICE",
    "py.typed",
    "RECORD",
    "WHEEL",
    "entry_points.txt",
    "top_level.txt",
}
ALLOWED_SITE_PACKAGE_ROOTS = {
    "aiohappyeyeballs",
    "aiohttp",
    "aiosignal",
    "attr",
    "attrs",
    "cffi",
    "cryptography",
    "cryptography.libs",
    "frozenlist",
    "idna",
    "multidict",
    "propcache",
    "psutil",
    "pycparser",
    "typing_extensions.py",
    "yarl",
}
ALLOWED_SITE_PACKAGE_PREFIXES = (
    "_cffi_backend.",
    "aiohappyeyeballs-2.6.1.dist-info",
    "aiohttp-3.14.3.dist-info",
    "aiosignal-1.4.0.dist-info",
    "attrs-25.3.0.dist-info",
    "cffi-1.17.1.dist-info",
    "cryptography-45.0.5.dist-info",
    "frozenlist-1.7.0.dist-info",
    "idna-3.10.dist-info",
    "multidict-6.6.4.dist-info",
    "propcache-0.3.2.dist-info",
    "psutil-7.0.0.dist-info",
    "pycparser-2.22.dist-info",
    "typing_extensions-4.14.1.dist-info",
    "yarl-1.20.1.dist-info",
)
FORBIDDEN_NAMES = {
    ".env",
    "edge.json",
    "install-state.json",
    "registration-token",
    "node-secret",
}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".pfx", ".p12"}
FORBIDDEN_CONTENT = (
    b"-----BEGIN " + b"PRIVATE KEY-----\n",
    b"-----BEGIN " + b"PRIVATE KEY-----\r\n",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\r\n",
    b"EDGE_TICKET_SECRET=",
    b'"ticket_secret":"',
    b'"node_secret":"',
    b'"registration_token":"',
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class PackageBuildError(RuntimeError):
    """A sanitized package validation failure."""


def _allowed(relative: PurePosixPath) -> bool:
    rendered = relative.as_posix()
    if rendered in ALLOWED_FILES:
        return True
    if relative.parts[0] != "runtime":
        return False
    if len(relative.parts) == 2:
        return relative.name in ALLOWED_RUNTIME_ROOTS
    if relative.parts[1] == "DLLs":
        return len(relative.parts) == 3 and relative.suffix.lower() in {".dll", ".pyd"}
    if relative.parts[1:3] != ("Lib", "site-packages"):
        return False
    site_root = relative.parts[3]
    if site_root not in ALLOWED_SITE_PACKAGE_ROOTS and not site_root.startswith(
        ALLOWED_SITE_PACKAGE_PREFIXES
    ):
        return False
    return (
        relative.suffix.lower() in ALLOWED_RUNTIME_SUFFIXES
        or relative.name in ALLOWED_RUNTIME_METADATA
        or relative.name.startswith(("LICENSE.", "COPYING."))
    )


def collect_files(source: Path) -> list[tuple[PurePosixPath, bytes]]:
    if not source.is_dir() or source.is_symlink():
        raise PackageBuildError("unsafe package input")
    collected: list[tuple[PurePosixPath, bytes]] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            if path.is_symlink():
                raise PackageBuildError("unsafe package input")
            continue
        if path.is_symlink() or not path.is_file():
            raise PackageBuildError("unsafe package input")
        relative = PurePosixPath(path.relative_to(source).as_posix())
        lowered = {part.lower() for part in relative.parts}
        if (
            not _allowed(relative)
            or lowered & FORBIDDEN_NAMES
            or relative.suffix.lower() in FORBIDDEN_SUFFIXES
            or "__pycache__" in lowered
        ):
            raise PackageBuildError("unsafe package input")
        data = path.read_bytes()
        if any(marker in data for marker in FORBIDDEN_CONTENT):
            raise PackageBuildError("unsafe package input")
        collected.append((relative, data))
    if not collected:
        raise PackageBuildError("empty package input")
    return collected


def build(source: Path, output: Path) -> str:
    files = collect_files(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True
        ) as archive:
            for relative, data in files:
                info = zipfile.ZipInfo(relative.as_posix(), ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n", encoding="ascii", newline="\n"
    )
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/IdenGrid-Edge-Windows-Server-2025-x64.zip"),
    )
    args = parser.parse_args()
    try:
        print(build(args.source, args.output))
    except (OSError, PackageBuildError):
        print("error: unsafe Windows Edge package input", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
