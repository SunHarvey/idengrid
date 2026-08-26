#!/usr/bin/env python3
"""Create a reproducible public Windows Edge ZIP from an exact staging manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
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
DEFAULT_RUNTIME_EXPECTED_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "windows-edge"
    / "manifests"
    / "windows-x64-runtime-expected.json"
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


def load_expected_runtime(manifest_path: Path) -> dict[str, str]:
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageBuildError("invalid runtime expected manifest") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "files"}:
        raise PackageBuildError("invalid runtime expected manifest")
    if document["schema_version"] != 1 or not isinstance(document["files"], list):
        raise PackageBuildError("invalid runtime expected manifest")

    expected: dict[str, str] = {}
    for entry in document["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise PackageBuildError("invalid runtime expected manifest")
        path = entry["path"]
        digest = entry["sha256"]
        if (
            not isinstance(path, str)
            or not path.startswith("runtime/")
            or PurePosixPath(path).as_posix() != path
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or path in expected
        ):
            raise PackageBuildError("invalid runtime expected manifest")
        expected[path] = digest
    return expected


def collect_files(
    source: Path,
    expected_runtime_manifest: Path = DEFAULT_RUNTIME_EXPECTED_MANIFEST,
) -> list[tuple[PurePosixPath, bytes]]:
    if not source.is_dir() or source.is_symlink():
        raise PackageBuildError("unsafe package input")
    expected_runtime = load_expected_runtime(expected_runtime_manifest)
    expected_paths = ALLOWED_FILES | set(expected_runtime)
    actual_paths: set[str] = set()
    collected: list[tuple[PurePosixPath, bytes]] = []

    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            if path.is_symlink():
                raise PackageBuildError("unsafe package input")
            continue
        if path.is_symlink() or not path.is_file():
            raise PackageBuildError("unsafe package input")
        relative = PurePosixPath(path.relative_to(source).as_posix())
        rendered = relative.as_posix()
        lowered = {part.lower() for part in relative.parts}
        if (
            (not rendered.startswith("runtime/") and rendered not in ALLOWED_FILES)
            or lowered & FORBIDDEN_NAMES
            or relative.suffix.lower() in FORBIDDEN_SUFFIXES
            or "__pycache__" in lowered
        ):
            raise PackageBuildError("unsafe package input")
        data = path.read_bytes()
        if rendered in expected_runtime and hashlib.sha256(data).hexdigest() != expected_runtime[rendered]:
            raise PackageBuildError("runtime file hash does not match expected manifest")
        if any(marker in data for marker in FORBIDDEN_CONTENT):
            raise PackageBuildError("unsafe package input")
        actual_paths.add(rendered)
        collected.append((relative, data))

    actual_runtime = {path for path in actual_paths if path.startswith("runtime/")}
    if actual_runtime != set(expected_runtime):
        raise PackageBuildError("runtime file set does not match expected manifest")
    if actual_paths != expected_paths:
        raise PackageBuildError("package file set does not match exact allowlist")
    return collected


def build(source: Path, output: Path, expected_runtime_manifest: Path) -> str:
    files = collect_files(source, expected_runtime_manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for relative, data in files:
                info = zipfile.ZipInfo(relative.as_posix(), ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(
                    info,
                    data,
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
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
    parser.add_argument(
        "--expected-runtime-manifest",
        type=Path,
        default=DEFAULT_RUNTIME_EXPECTED_MANIFEST,
    )
    args = parser.parse_args()
    try:
        print(build(args.source, args.output, args.expected_runtime_manifest))
    except (OSError, PackageBuildError):
        print("error: unsafe Windows Edge package input", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
