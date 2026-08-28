#!/usr/bin/env python3
"""Create or verify detached Ed25519 Windows release manifests."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
FILE_RE = re.compile(r"^IdenGrid-Edge-Windows-Server-2025-x64-v[0-9A-Za-z.-]+\.zip$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def b64(value: str, size: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid base64") from exc
    if len(decoded) != size:
        raise ValueError(f"{label} must decode to {size} bytes")
    return decoded


def read_private_key(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("private key path is unsafe")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("private key path is unsafe")
    if os.name != "nt" and details.st_mode & 0o077:
        raise ValueError("private key permissions are too broad")
    value = path.read_bytes()
    if len(value) != 32:
        raise ValueError("private key must contain exactly 32 bytes")
    return value


def validate_manifest(raw: bytes) -> dict:
    if len(raw) > 4096:
        raise ValueError("release manifest is too large")
    try:
        doc = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release manifest must be ASCII JSON") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "package"} or doc["schema_version"] != 1:
        raise ValueError("release manifest top-level shape is invalid")
    package = doc["package"]
    if not isinstance(package, dict) or set(package) != {"filename", "sha256", "size", "version"}:
        raise ValueError("release manifest package shape is invalid")
    if not isinstance(package["filename"], str) or not FILE_RE.fullmatch(package["filename"]):
        raise ValueError("release filename is invalid")
    if not isinstance(package["sha256"], str) or not SHA_RE.fullmatch(package["sha256"]):
        raise ValueError("release SHA256 is invalid")
    if type(package["size"]) is not int or not 0 < package["size"] <= 8 * 1024**3:
        raise ValueError("release size is invalid")
    if not isinstance(package["version"], str) or not VERSION_RE.fullmatch(package["version"]):
        raise ValueError("release version is invalid")
    expected = f"IdenGrid-Edge-Windows-Server-2025-x64-v{package['version']}.zip"
    if package["filename"] != expected:
        raise ValueError("release filename/version mismatch")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--public-key-base64")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.verify:
            raw = args.manifest.read_bytes()
            validate_manifest(raw)
            signature = b64(args.signature.read_text("ascii").strip(), 64, "signature")
            public = Ed25519PublicKey.from_public_bytes(b64(args.public_key_base64 or "", 32, "public key"))
            public.verify(signature, raw)
            return 0
        if not args.package or not args.version or not args.private_key_file:
            parser.error("signing requires --package, --version, and --private-key-file")
        if not VERSION_RE.fullmatch(args.version):
            raise ValueError("version is invalid")
        expected = f"IdenGrid-Edge-Windows-Server-2025-x64-v{args.version}.zip"
        if args.package.name != expected or not args.package.is_file():
            raise ValueError("package basename/version is invalid")
        package_bytes = args.package.read_bytes()
        doc = {"schema_version": 1, "package": {"filename": expected, "sha256": hashlib.sha256(package_bytes).hexdigest(), "size": len(package_bytes), "version": args.version}}
        raw = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        validate_manifest(raw)
        private = Ed25519PrivateKey.from_private_bytes(read_private_key(args.private_key_file))
        args.manifest.write_bytes(raw)
        args.signature.write_text(base64.b64encode(private.sign(raw)).decode("ascii") + "\n", encoding="ascii")
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print(base64.b64encode(public).decode("ascii"))
        return 0
    except (OSError, ValueError, InvalidSignature) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
