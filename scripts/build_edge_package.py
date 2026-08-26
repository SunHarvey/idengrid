#!/usr/bin/env python3
"""Build the public Edge bundle reproducibly from an allowlist."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "edge-tunnel"
ALLOWLIST = [
    "pyproject.toml",
    "requirements.txt",
    "edge_tunnel/__init__.py",
    "edge_tunnel/__main__.py",
    "edge_tunnel/app.py",
    "edge_tunnel/targets.py",
    "edge_tunnel/tickets.py",
    "systemd/edge-tunnel@.service",
    "caddy/Caddyfile.template",
]


def build(output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative in sorted(ALLOWLIST):
            source = EDGE / relative
            data = source.read_bytes()
            info = tarfile.TarInfo(f"edge-tunnel/{relative}")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            archive.addfile(info, io.BytesIO(data))
    with (
        output.open("wb") as target,
        gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0, compresslevel=9) as zipped,
    ):
        zipped.write(buffer.getvalue())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}  {output.name}\n")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist/edge-tunnel.tar.gz")
    args = parser.parse_args()
    print(build(args.output))


if __name__ == "__main__":
    main()
