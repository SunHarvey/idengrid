from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import re
import secrets
import shlex
import uuid
from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, JSONResponse
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, Field
from sqlalchemy import inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .browser_control import (
    BrowserControlError,
    BrowserTargetNotFound,
    LastTabError,
    normalize_address_input,
)
from .database import create_database_engine as create_engine
from .edge_health import migrate_edge_health_schema
from .edge_tickets import EdgeTicketIssuer
from .local_tunnel import PublicTargetPolicy, TunnelTargetDenied
from .models import (
    AuditEvent,
    Base,
    BrowserSession,
    DeviceSession,
    EdgeCapability,
    EdgeNode,
    EgressProfile,
    LocalHistoryEntry,
    LocalTabSnapshot,
    ManagedStore,
    NodeEnrollment,
    NodeRegistrationRequest,
    StoreConnectionLease,
    SystemSetting,
    User,
    UserEdgeNodeGrant,
    Workspace,
)
from .runner import BrowserRunner
from .schema import (
    migrate_edge_platform_schema,
    migrate_mysql_active_uniqueness,
    migrate_mysql_device_platform_constraint,
)
from .security import NetworkPolicy, SessionTicketSigner

passwords = PasswordHasher()

BRAND_ASSET_TYPES = {
    "design-tokens.css": "text/css",
    "favicon.svg": "image/svg+xml",
    "idengrid-32.png": "image/png",
    "idengrid-64.png": "image/png",
    "idengrid-lockup-cn-primary.svg": "image/svg+xml",
    "idengrid-symbol.svg": "image/svg+xml",
    "site.webmanifest": "application/manifest+json",
}
BRAND_ASSET_HEADERS = {
    "Cache-Control": "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
}
LINUX_EDGE_PACKAGE_PATH = Path("/data/dist/edge-tunnel.tar.gz")
WINDOWS_EDGE_INSTALLER_PATH = Path("/data/windows-edge/scripts/Install-IdenGridEdge.ps1")
WINDOWS_EDGE_RELEASE_MANIFEST_PATH = Path("/data/dist/release-manifest.json")
WINDOWS_EDGE_RELEASE_SIGNATURE_PATH = Path("/data/dist/release-manifest.json.sig")
WINDOWS_EDGE_RELEASE_PUBLIC_KEY_BASE64 = "Wf/s6zRs0+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk="
LINUX_EDGE_PACKAGE_ROUTE = "/edge-package/edge-tunnel.tar.gz"


def verified_windows_release() -> tuple[Path, str, str]:
    try:
        manifest_raw = WINDOWS_EDGE_RELEASE_MANIFEST_PATH.read_bytes()
        if len(manifest_raw) > 4096:
            raise ValueError("invalid release manifest")
        signature_text = WINDOWS_EDGE_RELEASE_SIGNATURE_PATH.read_text(encoding="ascii").strip()
        signature = base64.b64decode(signature_text, validate=True)
        public_key_raw = base64.b64decode(
            WINDOWS_EDGE_RELEASE_PUBLIC_KEY_BASE64, validate=True
        )
        if len(signature) != 64 or len(public_key_raw) != 32:
            raise ValueError("invalid release signature")
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, manifest_raw)
        document = json.loads(manifest_raw.decode("ascii"))
        package = document["package"]
        if (
            set(document) != {"schema_version", "package"}
            or document["schema_version"] != 1
            or set(package) != {"filename", "sha256", "size", "version"}
            or not isinstance(package["filename"], str)
            or not package["filename"].startswith("IdenGrid-Edge-Windows-Server-2025-x64-v")
            or not package["filename"].endswith(".zip")
            or Path(package["filename"]).name != package["filename"]
            or not isinstance(package["sha256"], str)
            or len(package["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in package["sha256"])
            or type(package["size"]) is not int
            or not 0 < package["size"] <= 8 * 1024**3
            or not isinstance(package["version"], str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", package["version"])
            is None
            or package["filename"]
            != f"IdenGrid-Edge-Windows-Server-2025-x64-v{package['version']}.zip"
        ):
            raise ValueError("invalid release manifest")
        package_path = WINDOWS_EDGE_RELEASE_MANIFEST_PATH.parent / package["filename"]
        data = package_path.read_bytes()
    except (
        InvalidSignature,
        OSError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Edge package unavailable")
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != package["size"] or not hmac.compare_digest(actual, package["sha256"]):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Edge package unavailable")
    return package_path, actual, f"/edge-package/{package['filename']}"


def verified_edge_package(platform: str) -> tuple[str, str]:
    if platform == "windows":
        _, checksum, route = verified_windows_release()
        return checksum, route
    if platform != "linux":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Edge package unavailable")
    checksum_path = LINUX_EDGE_PACKAGE_PATH.with_suffix(LINUX_EDGE_PACKAGE_PATH.suffix + ".sha256")
    try:
        expected, filename = checksum_path.read_text(encoding="ascii").split()
        actual = hashlib.sha256(LINUX_EDGE_PACKAGE_PATH.read_bytes()).hexdigest()
    except (OSError, UnicodeError, ValueError):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Edge package unavailable")
    if (
        len(expected) != 64
        or filename != LINUX_EDGE_PACKAGE_PATH.name
        or not hmac.compare_digest(expected, actual)
    ):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Edge package unavailable")
    return actual, LINUX_EDGE_PACKAGE_ROUTE


class LoginBody(BaseModel):
    username: str
    password: str


class NativeLoginBody(LoginBody):
    device_id: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    device_name: str = Field(min_length=1, max_length=200)
    platform: str = Field(pattern=r"^(macos|windows)$")


class CreateUserBody(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=16, max_length=128)


class ChangeUserPasswordBody(BaseModel):
    password: str = Field(min_length=16, max_length=128)


class SetUserEnabledBody(BaseModel):
    enabled: bool


class ViewerTicketBody(BaseModel):
    ticket: str


class AddressInputBody(BaseModel):
    input: str = Field(min_length=1, max_length=2048)


class LocalHistoryItem(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(default="", max_length=500)
    last_visit_ms: int = Field(ge=0)
    visit_count: int = Field(ge=0)


class LocalTabItem(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(default="", max_length=500)


class LocalSyncBody(BaseModel):
    device_id: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    history: list[LocalHistoryItem] = Field(max_length=1000)
    tabs: list[LocalTabItem] = Field(max_length=100)


class EdgeNodeCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    endpoint: str = Field(min_length=8, max_length=255)
    shared_secret: str = Field(min_length=16, max_length=255)
    expected_public_ipv4: str | None = Field(default=None, max_length=15)
    enabled: bool = True
    maintenance_mode: bool = False


class EdgeNodeUpdateBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    endpoint: str | None = Field(default=None, min_length=8, max_length=255)
    shared_secret: str | None = Field(default=None, min_length=16, max_length=255)
    expected_public_ipv4: str | None = Field(default=None, max_length=15)
    enabled: bool | None = None
    maintenance_mode: bool | None = None


class EdgeCapabilityBody(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    config: dict = Field(default_factory=dict)


class ManagedStoreCreateBody(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    owner_user_id: int | None = None
    edge_node_id: int
    enabled: bool = True


class ManagedStoreUpdateBody(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=100)
    owner_user_id: int | None = None
    edge_node_id: int | None = None
    enabled: bool | None = None


class EdgeTargetTicketBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int
    lease_id: str | None = Field(default=None, min_length=32, max_length=64)
    device_id: str | None = Field(
        default=None, min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$"
    )


class StoreDisconnectBody(BaseModel):
    lease_id: str | None = Field(default=None, min_length=32, max_length=64)
    device_id: str | None = Field(
        default=None, min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$"
    )


class StoreConnectBody(BaseModel):
    device_id: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")


class StoreHeartbeatBody(StoreConnectBody):
    lease_id: str = Field(min_length=32, max_length=64)


class UserEdgeNodeGrantsBody(BaseModel):
    node_ids: list[int] = Field(max_length=1000)


class EdgeEnrollmentCreateBody(BaseModel):
    node_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    endpoint: str = Field(min_length=8, max_length=255)
    expected_public_ipv4: str = Field(min_length=7, max_length=15)


class EdgeEnrollmentClaimBody(BaseModel):
    node_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    public_ipv4: str = Field(min_length=7, max_length=15)
    agent_version: str = Field(min_length=1, max_length=100)


class EdgeEnrollmentReportBody(BaseModel):
    phase: str = Field(
        pattern=(
            r"^(installing|dependencies|configuring|caddy|gateway|service|starting|ready|failed)$"
        )
    )
    error: str | None = Field(default=None, max_length=500)


class NodeRegistrationCreateBody(BaseModel):
    public_key_pem: str = Field(min_length=80, max_length=1000)
    platform: str = Field(pattern=r"^(linux|windows)$")
    machine_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    reported_hostname: str = Field(min_length=1, max_length=255)
    public_ipv4: str = Field(min_length=7, max_length=15)
    os_name: str = Field(min_length=1, max_length=100)
    cpu_count: int = Field(ge=1, le=4096)
    memory_total_bytes: int = Field(ge=1, le=2**63 - 1)
    disk_total_bytes: int = Field(ge=1, le=2**63 - 1)
    agent_version: str = Field(min_length=1, max_length=100)


class NodeRegistrationProofBody(BaseModel):
    challenge: str = Field(min_length=32, max_length=200)
    signature: str = Field(min_length=80, max_length=200)


class NodeRegistrationClaimBody(BaseModel):
    challenge: str = Field(min_length=32, max_length=200)
    signature: str = Field(min_length=80, max_length=200)


class NodeRegistrationAcceptBody(BaseModel):
    node_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._-]+$")
    endpoint: str = Field(min_length=8, max_length=255)
    expected_public_ipv4: str = Field(min_length=7, max_length=15)
    install_admin_ssh_key: bool = False


class NodeRegistrationRejectBody(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def create_app(
    database_url: str,
    secret_key: str,
    runner: BrowserRunner,
    bootstrap_admin: tuple[str, str] | None = None,
    secure_cookies: bool = False,
    public_origin: str | None = None,
    local_environment: dict | None = None,
    cloud_video_enabled: bool = False,
    enrollment_source_ip: Callable[[Request], str | None] | None = None,
    admin_ssh_public_key_file: str = "/data/dist/hermes-admin-ssh.pub",
    bootstrap_topology: dict | None = None,
) -> FastAPI:
    app = FastAPI(title="IdenGrid 澜序", version="0.1.0")
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(engine, expire_on_commit=False)
    token_signer = URLSafeSerializer(secret_key, salt="api-access-token")
    native_token_signer = URLSafeSerializer(secret_key, salt="native-access-token")
    ticket_signer = SessionTicketSigner(secret_key, ttl_seconds=60)
    viewer_signer = SessionTicketSigner(
        secret_key, ttl_seconds=8 * 60 * 60, salt="browser-viewer-grant"
    )
    local_environment_policy = local_environment or {
        "environment_id": "default-v1",
        "timezone": "UTC",
        "locale": "en-US",
        "accept_languages": ["en-US", "en"],
        "expected_egress_ips": [],
        "geolocation": "block",
        "quic": "disable",
    }
    app.state.runner = runner
    app.state.db = SessionLocal
    app.state.cloud_video_enabled = cloud_video_enabled
    app.state.enrollment_source_ip = enrollment_source_ip
    app.state.enrollment_rate = {}
    app.state.registration_rate = {}

    @app.middleware("http")
    async def disable_cloud_video(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/node-registration-requests"):
            try:
                content_length = int(request.headers.get("content-length", "0"))
            except ValueError:
                content_length = 8193
            if content_length > 8192:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            if request.method in {"POST", "PUT", "PATCH"}:
                body_bytes = await request.body()
                if len(body_bytes) > 8192:
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body too large"}
                    )
            if path == "/api/node-registration-requests" and request.method == "POST":
                candidate = (
                    enrollment_source_ip(request)
                    if enrollment_source_ip
                    else (request.client.host if request.client else "unknown")
                )
                rate_key = str(candidate)
                now_seconds = datetime.now(UTC).timestamp()
                recent = [
                    seen
                    for seen in app.state.registration_rate.get(rate_key, [])
                    if seen > now_seconds - 3600
                ]
                if len(recent) >= 3:
                    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
                recent.append(now_seconds)
                app.state.registration_rate[rate_key] = recent
        if path in {"/api/edge-enrollments/claim", "/api/edge-enrollments/report"}:
            try:
                content_length = int(request.headers.get("content-length", "0"))
            except ValueError:
                content_length = 4097
            if content_length > 4096:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            rate_key = (path, request.client.host if request.client else "unknown")
            now_seconds = datetime.now(UTC).timestamp()
            recent = [
                seen
                for seen in app.state.enrollment_rate.get(rate_key, [])
                if seen > now_seconds - 60
            ]
            limit = 20 if path.endswith("/claim") else 120
            if len(recent) >= limit:
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
            recent.append(now_seconds)
            app.state.enrollment_rate[rate_key] = recent
        video_path = path.startswith(
            ("/api/sessions/", "/api/admin/sessions/", "/viewer/")
        ) or path in {"/api/sessions", "/api/admin/sessions", "/api/diagnostics/egress"}
        if not cloud_video_enabled and video_path:
            return JSONResponse(status_code=410, content={"detail": "Cloud video is disabled"})
        return await call_next(request)

    Base.metadata.create_all(engine)
    migrate_edge_platform_schema(engine)
    migrate_mysql_active_uniqueness(engine)
    migrate_mysql_device_platform_constraint(engine)
    migrate_edge_health_schema(engine)
    lease_columns = {
        column["name"] for column in inspect(engine).get_columns("store_connection_leases")
    }
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "device_id" not in lease_columns:
            connection.execute(
                text("ALTER TABLE store_connection_leases ADD COLUMN device_id VARCHAR(100)")
            )
        if "last_heartbeat_at" not in lease_columns:
            connection.execute(
                text("ALTER TABLE store_connection_leases ADD COLUMN last_heartbeat_at DATETIME")
            )
        if "deleted_at" not in user_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN deleted_at DATETIME"))
    with SessionLocal() as db:
        egress = db.scalar(select(EgressProfile).where(EgressProfile.name == "local-host-egress"))
        if not egress:
            egress = EgressProfile(name="local-host-egress", kind="host", config_json="{}")
            db.add(egress)
            db.flush()
        workspace = db.scalar(select(Workspace).where(Workspace.name == "default-store"))
        if not workspace:
            workspace = Workspace(name="default-store", egress_profile_id=egress.id)
            db.add(workspace)
            db.flush()
        if bootstrap_admin:
            username, password = bootstrap_admin
            if not db.scalar(select(User).where(User.username == username)):
                db.add(
                    User(
                        username=username,
                        password_hash=passwords.hash(password),
                        role="admin",
                        workspace_id=workspace.id,
                    )
                )
                db.flush()
        bootstrap_key = "bootstrap_topology_applied_v1"
        if bootstrap_topology and db.get(SystemSetting, bootstrap_key) is None:
            nodes_by_name: dict[str, EdgeNode] = {}
            for item in bootstrap_topology.get("nodes", []):
                node = db.scalar(select(EdgeNode).where(EdgeNode.name == item["name"]))
                if node is None:
                    node = EdgeNode(
                        name=item["name"],
                        endpoint=item["endpoint"],
                        shared_secret=secrets.token_urlsafe(32),
                        expected_public_ipv4=item["expected_public_ipv4"],
                        enabled=bool(item.get("enabled", False)),
                    )
                    db.add(node)
                    db.flush()
                nodes_by_name[node.name] = node
            for item in bootstrap_topology.get("stores", []):
                node = nodes_by_name[item["node"]]
                if not db.scalar(select(ManagedStore.id).where(ManagedStore.label == item["name"])):
                    db.add(
                        ManagedStore(
                            label=item["name"],
                            owner_user_id=pilot_owner.id if (pilot_owner := db.scalar(
                                select(User).where(User.role == "admin").order_by(User.id)
                            )) else None,
                            edge_node_id=node.id,
                            enabled=bool(item.get("enabled", False)),
                        )
                    )
            db.add(SystemSetting(key=bootstrap_key, value="complete"))
        db.commit()

    def get_db() -> Generator[Session, None, None]:
        with SessionLocal() as db:
            yield db

    def issue_access(user: User) -> str:
        return token_signer.dumps({"uid": user.id, "ver": user.token_version})

    def refresh_hash(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def issue_native_access(user: User, item: DeviceSession) -> str:
        return native_token_signer.dumps(
            {
                "uid": user.id,
                "ver": user.token_version,
                "dsid": item.id,
                "gen": item.token_generation,
                "exp": int((datetime.now(UTC) + timedelta(minutes=15)).timestamp()),
            }
        )

    def native_access_identity(raw: str, db: Session) -> tuple[User, DeviceSession] | None:
        try:
            payload = native_token_signer.loads(raw)
        except BadSignature:
            return None
        now = datetime.now(UTC)
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(now.timestamp()):
            return None
        item = db.get(DeviceSession, payload.get("dsid"))
        user = db.get(User, payload.get("uid"))
        if item is None or user is None:
            return None
        expires_at = (
            item.expires_at.replace(tzinfo=UTC)
            if item.expires_at.tzinfo is None
            else item.expires_at
        )
        if (
            item.user_id != user.id
            or item.token_generation != payload.get("gen")
            or item.revoked_at is not None
            or expires_at <= now
            or not user.enabled
            or user.deleted_at is not None
            or user.token_version != payload.get("ver")
        ):
            return None
        return user, item

    def bearer_user(authorization: str | None, db: Session) -> User | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        raw = authorization[7:]
        try:
            payload = token_signer.loads(raw)
        except BadSignature:
            native = native_access_identity(raw, db)
            return native[0] if native else None
        user = db.get(User, payload.get("uid"))
        if (
            not user
            or not user.enabled
            or user.deleted_at is not None
            or user.token_version != payload.get("ver")
        ):
            return None
        return user

    def current_user(
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(get_db),
    ) -> User:
        user = bearer_user(authorization, db)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked token")
        return user

    def current_native_identity(
        request: Request,
        db: Session = Depends(get_db),
    ) -> tuple[User, DeviceSession]:
        authorization = request.headers.get("authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked native token")
        identity = native_access_identity(authorization[7:], db)
        if identity is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked native token")
        return identity

    def revoke_device_sessions(db: Session, user_id: int, revoked_at: datetime) -> int:
        result = db.execute(
            update(DeviceSession)
            .where(DeviceSession.user_id == user_id, DeviceSession.revoked_at.is_(None))
            .values(
                revoked_at=revoked_at,
                updated_at=revoked_at,
                token_generation=DeviceSession.token_generation + 1,
            )
        )
        return result.rowcount

    def access_user_from_header(authorization: str | None, db: Session) -> User | None:
        return bearer_user(authorization, db)

    def admin(user: User = Depends(current_user)) -> User:
        if user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator required")
        return user

    def audit(
        db: Session,
        event_type: str,
        actor: int | None,
        target_type: str | None = None,
        target_id: str | None = None,
        details: dict | None = None,
    ) -> None:
        payload = dict(details or {})
        if actor is not None:
            actor_user = db.get(User, actor)
            if actor_user is not None:
                payload.setdefault("_actor_username", actor_user.username)
        if target_id is not None:
            target_name = target_id
            try:
                numeric_target_id = int(target_id)
            except ValueError:
                numeric_target_id = None
            if target_type == "user" and numeric_target_id is not None:
                target = db.get(User, numeric_target_id)
                target_name = target.username if target else target_id
            elif target_type == "managed_store" and numeric_target_id is not None:
                target = db.get(ManagedStore, numeric_target_id)
                target_name = target.label if target else target_id
            elif target_type == "edge_node" and numeric_target_id is not None:
                target = db.get(EdgeNode, numeric_target_id)
                target_name = target.name if target else target_id
            payload.setdefault("_target_name", target_name)
        db.add(
            AuditEvent(
                event_type=event_type,
                actor_user_id=actor,
                target_type=target_type,
                target_id=target_id,
                details_json=json.dumps(payload, separators=(",", ":")),
            )
        )

    def request_audit_details(request: Request) -> dict[str, str]:
        return {
            "source_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown")[:300],
        }

    def owned_session(db: Session, session_id: str, user: User) -> BrowserSession:
        item = db.scalar(
            select(BrowserSession).where(
                BrowserSession.id == session_id, BrowserSession.user_id == user.id
            )
        )
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
        return item

    def running_browser_session(db: Session, session_id: str, user: User) -> str:
        item = owned_session(db, session_id, user)
        if item.status != "running":
            raise HTTPException(status.HTTP_409_CONFLICT, "Session is not running")
        return item.id

    def browser_result(operation):
        try:
            return operation()
        except BrowserTargetNotFound as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        except LastTabError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except BrowserControlError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "Browser control channel unavailable"
            ) from exc

    def serialize_session(item: BrowserSession) -> dict:
        return {
            "id": item.id,
            "status": item.status,
            "profile_key": item.profile_key,
            "viewer_url": f"/viewer/{item.id}",
            "created_at": item.created_at.isoformat(),
        }

    @app.get("/")
    def workspace_page():
        return FileResponse(Path(__file__).parent / "templates" / "index.html")

    @app.get("/static/brand/{asset_path:path}", include_in_schema=False)
    def brand_asset(asset_path: str):
        media_type = BRAND_ASSET_TYPES.get(asset_path)
        if media_type is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Brand asset not found")
        return FileResponse(
            Path(__file__).parent / "static" / "brand" / asset_path,
            media_type=media_type,
            headers=BRAND_ASSET_HEADERS,
        )

    @app.get("/install-edge.sh")
    def edge_installer():
        return FileResponse(
            "/data/scripts/install-edge.sh",
            media_type="text/x-shellscript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/bootstrap/edge-install.sh")
    def generic_edge_installer():
        return FileResponse(
            "/data/scripts/edge-install.sh",
            media_type="text/x-shellscript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/bootstrap/admin-ssh.pub")
    def admin_ssh_public_key():
        try:
            key = Path(admin_ssh_public_key_file).read_bytes()
            if len(key) > 16_384 or b"\x00" in key or b"PRIVATE" in key:
                raise ValueError
            serialization.load_ssh_public_key(key.strip())
        except (OSError, TypeError, ValueError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Public key unavailable")
        return Response(
            content=key.strip() + b"\n",
            media_type="text/plain",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/edge-package/edge-tunnel.tar.gz")
    def edge_package():
        verified_edge_package("linux")
        return FileResponse(
            LINUX_EDGE_PACKAGE_PATH,
            media_type="application/gzip",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/bootstrap/Install-IdenGridEdge.ps1")
    def windows_edge_installer():
        return FileResponse(
            WINDOWS_EDGE_INSTALLER_PATH,
            media_type="text/plain",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/edge-package/release-manifest.json")
    def windows_edge_release_manifest():
        verified_windows_release()
        return FileResponse(
            WINDOWS_EDGE_RELEASE_MANIFEST_PATH,
            media_type="application/json",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/edge-package/release-manifest.json.sig")
    def windows_edge_release_signature():
        verified_windows_release()
        return FileResponse(
            WINDOWS_EDGE_RELEASE_SIGNATURE_PATH,
            media_type="application/octet-stream",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/edge-package/{filename}")
    def windows_edge_versioned_package(filename: str):
        package_path, _, route = verified_windows_release()
        if route != f"/edge-package/{filename}":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Release package not found")
        return FileResponse(
            package_path,
            media_type="application/zip",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, db: Session = Depends(get_db)):
        user = db.scalar(select(User).where(User.username == body.username))
        valid = False
        if user and user.enabled:
            try:
                valid = passwords.verify(user.password_hash, body.password)
            except VerifyMismatchError:
                valid = False
        if not valid or not user:
            audit(
                db,
                "login.failed",
                None,
                "user",
                body.username,
                {"username": body.username, **request_audit_details(request)},
            )
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
        audit(
            db,
            "login.succeeded",
            user.id,
            "user",
            str(user.id),
            {"username": user.username, "role": user.role, **request_audit_details(request)},
        )
        db.commit()
        return {"access_token": issue_access(user), "token_type": "bearer", "role": user.role}

    @app.post("/api/native/login")
    def native_login(body: NativeLoginBody, request: Request, db: Session = Depends(get_db)):
        user = db.scalar(select(User).where(User.username == body.username))
        valid = False
        if user and user.enabled and user.deleted_at is None:
            try:
                valid = passwords.verify(user.password_hash, body.password)
            except VerifyMismatchError:
                valid = False
        if not valid or not user:
            audit(
                db,
                "native.login_failed",
                None,
                "user",
                body.username,
                {"username": body.username, **request_audit_details(request)},
            )
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
        now = datetime.now(UTC)
        item = db.scalar(
            select(DeviceSession).where(
                DeviceSession.user_id == user.id, DeviceSession.device_id == body.device_id
            )
        )
        if item is None:
            item = DeviceSession(
                id=uuid.uuid4().hex,
                user_id=user.id,
                device_id=body.device_id,
                device_name=body.device_name,
                platform=body.platform,
                refresh_token_hash="0" * 64,
                expires_at=now + timedelta(days=30),
            )
            db.add(item)
        else:
            item.device_name = body.device_name
            item.platform = body.platform
            item.token_generation += 1
            item.revoked_at = None
            item.updated_at = now
            item.last_seen_at = now
            item.expires_at = now + timedelta(days=30)
        raw = f"{item.id}.{secrets.token_urlsafe(32)}"
        item.refresh_token_hash = refresh_hash(raw)
        db.flush()
        audit(db, "native.login_succeeded", user.id, "device_session", item.id)
        db.commit()
        return {
            "access_token": issue_native_access(user, item),
            "refresh_token": raw,
            "device_session_id": item.id,
            "access_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
            "refresh_expires_at": item.expires_at.isoformat(),
            "token_type": "bearer",
            "expires_in": 15 * 60,
            "refresh_expires_in": 30 * 24 * 60 * 60,
            "role": user.role,
        }

    def invalid_refresh() -> HTTPException:
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or replayed refresh token")

    @app.post("/api/native/refresh")
    def native_refresh(request: Request, db: Session = Depends(get_db)):
        authorization = request.headers.get("authorization")
        if not authorization or not authorization.startswith("Refresh "):
            raise invalid_refresh()
        raw = authorization[8:]
        session_id, separator, secret = raw.partition(".")
        if not separator or not session_id or not secret:
            raise invalid_refresh()
        item = db.get(DeviceSession, session_id)
        if item is None:
            raise invalid_refresh()
        now = datetime.now(UTC)
        current_hash = refresh_hash(raw)
        expires_at = (
            item.expires_at.replace(tzinfo=UTC)
            if item.expires_at.tzinfo is None
            else item.expires_at
        )
        if not hmac.compare_digest(item.refresh_token_hash, current_hash):
            if item.revoked_at is None:
                item.revoked_at = now
                item.updated_at = now
                item.token_generation += 1
                audit(db, "native.refresh_replayed", item.user_id, "device_session", item.id)
                db.commit()
            raise invalid_refresh()
        user = db.get(User, item.user_id)
        if (
            item.revoked_at is not None
            or expires_at <= now
            or user is None
            or not user.enabled
            or user.deleted_at is not None
        ):
            raise invalid_refresh()

        new_raw = f"{item.id}.{secrets.token_urlsafe(32)}"
        generation = item.token_generation + 1
        rotated = db.execute(
            update(DeviceSession)
            .where(
                DeviceSession.id == item.id,
                DeviceSession.refresh_token_hash == current_hash,
                DeviceSession.token_generation == item.token_generation,
                DeviceSession.revoked_at.is_(None),
            )
            .values(
                refresh_token_hash=refresh_hash(new_raw),
                token_generation=generation,
                updated_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(days=30),
            )
        )
        if rotated.rowcount != 1:
            db.rollback()
            replayed = db.get(DeviceSession, session_id)
            if replayed is not None and replayed.revoked_at is None:
                replayed.revoked_at = now
                replayed.updated_at = now
                replayed.token_generation += 1
                audit(
                    db,
                    "native.refresh_replayed",
                    replayed.user_id,
                    "device_session",
                    replayed.id,
                )
                db.commit()
            raise invalid_refresh()
        db.commit()
        rotated_item = db.get(DeviceSession, session_id)
        return {
            "access_token": issue_native_access(user, rotated_item),
            "refresh_token": new_raw,
            "device_session_id": rotated_item.id,
            "access_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
            "refresh_expires_at": rotated_item.expires_at.isoformat(),
            "token_type": "bearer",
            "expires_in": 15 * 60,
            "refresh_expires_in": 30 * 24 * 60 * 60,
            "role": user.role,
        }

    @app.get("/api/native/devices")
    def native_devices(
        identity: tuple[User, DeviceSession] = Depends(current_native_identity),
        db: Session = Depends(get_db),
    ):
        user, current = identity
        items = db.scalars(
            select(DeviceSession)
            .where(DeviceSession.user_id == user.id)
            .order_by(DeviceSession.created_at, DeviceSession.id)
        ).all()
        return {
            "devices": [
                {
                    "id": item.id,
                    "device_id": item.device_id,
                    "device_name": item.device_name,
                    "platform": item.platform,
                    "current": item.id == current.id,
                    "created_at": item.created_at.isoformat(),
                    "last_seen_at": item.last_seen_at.isoformat(),
                    "expires_at": item.expires_at.isoformat(),
                    "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
                }
                for item in items
            ]
        }

    @app.delete("/api/native/devices/{device_session_id}", status_code=204)
    def revoke_native_device(
        device_session_id: str,
        identity: tuple[User, DeviceSession] = Depends(current_native_identity),
        db: Session = Depends(get_db),
    ):
        user, _ = identity
        item = db.scalar(
            select(DeviceSession).where(
                DeviceSession.id == device_session_id,
                DeviceSession.user_id == user.id,
            )
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
        if item.revoked_at is None:
            now = datetime.now(UTC)
            item.revoked_at = now
            item.updated_at = now
            item.token_generation += 1
            audit(db, "native.device_revoked", user.id, "device_session", item.id)
            db.commit()
        return Response(status_code=204)

    @app.post("/api/native/logout")
    def native_logout(
        identity: tuple[User, DeviceSession] = Depends(current_native_identity),
        db: Session = Depends(get_db),
    ):
        user, item = identity
        now = datetime.now(UTC)
        item.revoked_at = now
        item.updated_at = now
        item.token_generation += 1
        audit(db, "native.logout", user.id, "device_session", item.id)
        db.commit()
        return {"ok": True}

    @app.get("/api/native/stores")
    def native_stores(
        identity: tuple[User, DeviceSession] = Depends(current_native_identity),
        db: Session = Depends(get_db),
    ):
        user, _ = identity
        query = select(ManagedStore).join(EdgeNode, EdgeNode.id == ManagedStore.edge_node_id)
        if user.role != "admin":
            query = query.join(
                UserEdgeNodeGrant,
                UserEdgeNodeGrant.edge_node_id == ManagedStore.edge_node_id,
            ).where(UserEdgeNodeGrant.user_id == user.id)
        stores = db.scalars(query.order_by(ManagedStore.id)).all()
        rows = []
        for store in stores:
            node = db.get(EdgeNode, store.edge_node_id)
            rows.append(
                {
                    "id": str(store.id),
                    "name": store.label,
                    "node_name": node.name,
                    "status": "available" if store.enabled else "disabled",
                    "health_status": node.health_status,
                    "maintenance_mode": node.maintenance_mode,
                    "enabled": store.enabled,
                    "expected_public_ipv4": node.expected_public_ipv4,
                    "actual_public_ipv4": node.actual_public_ipv4,
                    "latency_ms": node.latency_ms,
                    "active_connections": node.active_connections,
                    "max_connections": node.max_connections,
                    "legacy_profile_path": None,
                }
            )
        return {"stores": rows}

    @app.post("/api/native/stores/{store_id}/preflight")
    def native_store_preflight(
        store_id: int,
        identity: tuple[User, DeviceSession] = Depends(current_native_identity),
        db: Session = Depends(get_db),
    ):
        user, device_session = identity
        store = accessible_store(db, store_id, user)
        node = db.get(EdgeNode, store.edge_node_id)
        if not store.enabled or not node.enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store or edge node is disabled")
        require_online_edge(node)
        lease = active_store_lease(db, store.id, user.id, device_session.device_id)
        now = datetime.now(UTC)
        recovered = lease is not None
        if lease is not None:
            lease.last_heartbeat_at = now
            lease.expires_at = now + timedelta(hours=8)
        else:
            lease = StoreConnectionLease(
                id=uuid.uuid4().hex,
                store_id=store.id,
                owner_user_id=user.id,
                device_id=device_session.device_id,
                status="active",
                expires_at=now + timedelta(hours=8),
                last_heartbeat_at=now,
            )
            db.add(lease)
            try:
                db.flush()
            except IntegrityError as exc:
                db.rollback()
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "Store already has an active connection"
                ) from exc
        lease_expires_at = (
            lease.expires_at.replace(tzinfo=UTC)
            if lease.expires_at.tzinfo is None
            else lease.expires_at
        )
        audit(
            db,
            "native.store_preflighted",
            user.id,
            "managed_store",
            str(store.id),
            {"device_id": device_session.device_id, "recovered": recovered},
        )
        db.commit()
        return {
            "ready": True,
            "store_id": str(store.id),
            "lease_id": lease.id,
            "expires_at": lease_expires_at.isoformat(),
            "recovered": recovered,
        }

    @app.get("/api/me")
    def me(user: User = Depends(current_user)):
        return {"id": user.id, "username": user.username, "role": user.role}

    @app.get("/api/local-browser/environment")
    def local_browser_environment(user: User = Depends(current_user)):
        del user
        return local_environment_policy

    @app.post("/api/local-browser/sync")
    def local_browser_sync(
        body: LocalSyncBody,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        policy = NetworkPolicy()
        for item in [*body.history, *body.tabs]:
            if not policy.is_url_allowed(item.url):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsafe URL in sync payload")

        for item in body.history:
            entry = db.scalar(
                select(LocalHistoryEntry).where(
                    LocalHistoryEntry.user_id == user.id,
                    LocalHistoryEntry.url == item.url,
                )
            )
            if entry is None:
                db.add(
                    LocalHistoryEntry(
                        user_id=user.id,
                        url=item.url,
                        title=item.title,
                        last_visit_ms=item.last_visit_ms,
                        visit_count=item.visit_count,
                    )
                )
            else:
                if item.last_visit_ms >= entry.last_visit_ms:
                    entry.title = item.title
                    entry.last_visit_ms = item.last_visit_ms
                entry.visit_count = max(entry.visit_count, item.visit_count)

        tabs = [item.model_dump() for item in body.tabs]
        snapshot = db.scalar(
            select(LocalTabSnapshot).where(
                LocalTabSnapshot.user_id == user.id,
                LocalTabSnapshot.device_id == body.device_id,
            )
        )
        if snapshot is None:
            db.add(
                LocalTabSnapshot(
                    user_id=user.id,
                    device_id=body.device_id,
                    tabs_json=json.dumps(tabs, separators=(",", ":")),
                    updated_at=datetime.now(UTC),
                )
            )
        else:
            snapshot.tabs_json = json.dumps(tabs, separators=(",", ":"))
            snapshot.updated_at = datetime.now(UTC)
        audit(db, "local_browser.synced", user.id, "device", body.device_id)
        db.commit()

        history_rows = db.scalars(
            select(LocalHistoryEntry)
            .where(LocalHistoryEntry.user_id == user.id)
            .order_by(LocalHistoryEntry.last_visit_ms.desc())
            .limit(1000)
        ).all()
        tab_rows = db.scalars(
            select(LocalTabSnapshot)
            .where(LocalTabSnapshot.user_id == user.id)
            .order_by(LocalTabSnapshot.device_id)
        ).all()
        return {
            "history": [
                {
                    "url": item.url,
                    "title": item.title,
                    "last_visit_ms": item.last_visit_ms,
                    "visit_count": item.visit_count,
                }
                for item in history_rows
            ],
            "tabs_by_device": {item.device_id: json.loads(item.tabs_json) for item in tab_rows},
        }

    @app.post("/api/logout")
    def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
        user.token_version += 1
        audit(db, "logout", user.id, "user", str(user.id), request_audit_details(request))
        db.commit()
        return {"ok": True}

    @app.post("/api/admin/users", status_code=201)
    def create_user(
        body: CreateUserBody, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        if db.scalar(select(User).where(User.username == body.username)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
        user = User(
            username=body.username,
            password_hash=passwords.hash(body.password),
            role="member",
            workspace_id=actor.workspace_id,
        )
        db.add(user)
        db.flush()
        audit(db, "workspace.user_assigned", actor.id, "user", str(user.id))
        db.commit()
        return {"id": user.id, "username": user.username, "enabled": user.enabled}

    @app.get("/api/admin/users")
    def list_users(actor: User = Depends(admin), db: Session = Depends(get_db)):
        del actor
        users = db.scalars(
            select(User).where(User.role != "admin", User.deleted_at.is_(None)).order_by(User.id)
        ).all()
        return [
            {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "enabled": user.enabled,
            }
            for user in users
        ]

    def member_user(db: Session, user_id: int) -> User:
        target = db.get(User, user_id)
        if target is None or target.role == "admin" or target.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
        return target

    def granted_node_ids(db: Session, user_id: int) -> list[int]:
        return list(
            db.scalars(
                select(UserEdgeNodeGrant.edge_node_id)
                .where(UserEdgeNodeGrant.user_id == user_id)
                .order_by(UserEdgeNodeGrant.edge_node_id)
            ).all()
        )

    @app.get("/api/admin/users/{user_id}/edge-nodes")
    def list_user_edge_nodes(
        user_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        del actor
        member_user(db, user_id)
        return {"node_ids": granted_node_ids(db, user_id)}

    @app.put("/api/admin/users/{user_id}/edge-nodes")
    def replace_user_edge_nodes(
        user_id: int,
        body: UserEdgeNodeGrantsBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        member_user(db, user_id)
        node_ids = sorted(set(body.node_ids))
        if node_ids:
            existing = set(db.scalars(select(EdgeNode.id).where(EdgeNode.id.in_(node_ids))).all())
            if existing != set(node_ids):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY, "Valid edge nodes required"
                )
        for grant in db.scalars(
            select(UserEdgeNodeGrant).where(UserEdgeNodeGrant.user_id == user_id)
        ).all():
            db.delete(grant)
        db.flush()
        db.add_all(
            [UserEdgeNodeGrant(user_id=user_id, edge_node_id=node_id) for node_id in node_ids]
        )
        audit(
            db,
            "user.edge_nodes_replaced",
            actor.id,
            "user",
            str(user_id),
            {"node_ids": node_ids},
        )
        db.commit()
        return {"node_ids": node_ids}

    @app.put("/api/admin/users/{user_id}/password")
    def change_user_password(
        user_id: int,
        body: ChangeUserPasswordBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        target = member_user(db, user_id)
        now = datetime.now(UTC)
        target.password_hash = passwords.hash(body.password)
        target.token_version += 1
        revoke_device_sessions(db, target.id, now)
        for lease in db.scalars(
            select(StoreConnectionLease).where(
                StoreConnectionLease.owner_user_id == target.id,
                StoreConnectionLease.status == "active",
            )
        ).all():
            lease.status = "disconnected"
            lease.disconnected_at = now
        audit(
            db,
            "user.password_changed",
            actor.id,
            "user",
            str(target.id),
            {"tokens_revoked": True},
        )
        db.commit()
        return {"id": target.id, "password_changed": True}

    @app.put("/api/admin/users/{user_id}/enabled")
    def set_user_enabled(
        user_id: int,
        body: SetUserEnabledBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        target = member_user(db, user_id)
        revoked_devices = 0
        if target.enabled and not body.enabled:
            now = datetime.now(UTC)
            target.token_version += 1
            revoked_devices = revoke_device_sessions(db, target.id, now)
        target.enabled = body.enabled
        audit(
            db,
            "user.enabled_changed",
            actor.id,
            "user",
            str(target.id),
            {"enabled": target.enabled, "revoked_device_sessions": revoked_devices},
        )
        db.commit()
        return {"id": target.id, "enabled": target.enabled}

    @app.delete("/api/admin/users/{user_id}", status_code=204)
    def delete_user(user_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)):
        target = member_user(db, user_id)
        username = target.username
        now = datetime.now(UTC)
        grants = db.scalars(
            select(UserEdgeNodeGrant).where(UserEdgeNodeGrant.user_id == target.id)
        ).all()
        for grant in grants:
            db.delete(grant)
        leases = db.scalars(
            select(StoreConnectionLease).where(
                StoreConnectionLease.owner_user_id == target.id,
                StoreConnectionLease.status == "active",
            )
        ).all()
        for lease in leases:
            lease.status = "disconnected"
            lease.disconnected_at = now
        for store in db.scalars(
            select(ManagedStore).where(ManagedStore.owner_user_id == target.id)
        ).all():
            store.owner_user_id = None
        history = db.scalars(
            select(LocalHistoryEntry).where(LocalHistoryEntry.user_id == target.id)
        ).all()
        tabs = db.scalars(
            select(LocalTabSnapshot).where(LocalTabSnapshot.user_id == target.id)
        ).all()
        for item in [*history, *tabs]:
            db.delete(item)
        sessions = db.scalars(
            select(BrowserSession).where(
                BrowserSession.user_id == target.id,
                BrowserSession.status.in_(["starting", "running"]),
            )
        ).all()
        for session in sessions:
            runner.stop(session.id)
            session.status = "stopped"
            session.endpoint = None
            session.updated_at = now
        target.username = f"deleted-user-{target.id}-{uuid.uuid4().hex[:12]}"
        target.password_hash = "!deleted"
        target.enabled = False
        target.token_version += 1
        target.deleted_at = now
        revoked_devices = revoke_device_sessions(db, target.id, now)
        audit(
            db,
            "user.deleted",
            actor.id,
            "user",
            str(target.id),
            {
                "username": username,
                "revoked_node_grants": len(grants),
                "disconnected_leases": len(leases),
                "deleted_history_entries": len(history),
                "deleted_tab_snapshots": len(tabs),
                "revoked_device_sessions": revoked_devices,
            },
        )
        db.commit()
        return Response(status_code=204)

    def serialize_edge_health(node: EdgeNode) -> dict:
        return {
            "health_status": node.health_status,
            "last_seen_at": node.last_seen_at.isoformat() if node.last_seen_at else None,
            "latency_ms": node.latency_ms,
            "active_connections": node.active_connections,
            "max_connections": node.max_connections,
            "accepted_connections": node.accepted_connections,
            "denied_connections": node.denied_connections,
            "expected_public_ipv4": node.expected_public_ipv4,
            "actual_public_ipv4": node.actual_public_ipv4,
            "load_1m": node.load_1m,
            "memory_total_bytes": node.memory_total_bytes,
            "memory_available_bytes": node.memory_available_bytes,
            "disk_total_bytes": node.disk_total_bytes,
            "disk_free_bytes": node.disk_free_bytes,
            "uptime_seconds": node.uptime_seconds,
            "agent_version": node.agent_version,
            "last_error": node.last_error,
        }

    def serialize_edge_node(node: EdgeNode) -> dict:
        return {
            "id": node.id,
            "name": node.name,
            "platform": node.platform,
            "endpoint": node.endpoint,
            "enabled": node.enabled,
            "maintenance_mode": node.maintenance_mode,
            **serialize_edge_health(node),
        }

    def validate_edge_node_network(endpoint: str, expected_public_ipv4: str | None) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "HTTPS endpoint required")
        if expected_public_ipv4 is None:
            return
        try:
            address = ipaddress.ip_address(expected_public_ipv4)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Global IPv4 address required"
            ) from exc
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Global IPv4 address required"
            )

    def enrollment_hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def serialize_enrollment(db: Session, item: NodeEnrollment) -> dict:
        now = datetime.now(UTC)
        expires_at = (
            item.expires_at.replace(tzinfo=UTC)
            if item.expires_at.tzinfo is None
            else item.expires_at
        )
        if item.status == "pending" and expires_at <= now:
            item.status = "expired"
            item.updated_at = now
            db.flush()
        node = db.get(EdgeNode, item.edge_node_id)
        return {
            "id": item.id,
            "edge_node_id": item.edge_node_id,
            "node_name": node.name,
            "endpoint": node.endpoint,
            "expected_public_ipv4": node.expected_public_ipv4,
            "status": item.status,
            "phase": item.phase,
            "expires_at": item.expires_at.isoformat(),
            "claimed_at": item.claimed_at.isoformat() if item.claimed_at else None,
            "updated_at": item.updated_at.isoformat(),
            "last_error": item.last_error,
            "claimed_public_ipv4": item.claimed_public_ipv4,
            "agent_version": item.agent_version,
        }

    def issue_enrollment(item: NodeEnrollment, node_name: str) -> tuple[str, str]:
        raw = f"{item.id}.{secrets.token_urlsafe(32)}"
        item.token_hash = enrollment_hash(raw)
        origin = (public_origin or "https://api.example.com").rstrip("/")
        command = (
            "p=$(mktemp) && trap 'rm -f \"$p\"' EXIT && "
            "curl --proto '=https' --tlsv1.2 -fsS "
            f'{shlex.quote(origin + "/install-edge.sh")} -o "$p" && '
            f'sudo bash "$p" --server {shlex.quote(origin)} '
            f"--node-name {shlex.quote(node_name)} --token {shlex.quote(raw)}"
        )
        return raw, command

    @app.post("/api/admin/edge-enrollments", status_code=201)
    def create_edge_enrollment(
        body: EdgeEnrollmentCreateBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        validate_edge_node_network(body.endpoint, body.expected_public_ipv4)
        if db.scalar(
            select(EdgeNode).where(
                (EdgeNode.name == body.node_name) | (EdgeNode.endpoint == body.endpoint)
            )
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge node already exists")
        node = EdgeNode(
            name=body.node_name,
            endpoint=body.endpoint,
            expected_public_ipv4=body.expected_public_ipv4,
            shared_secret=secrets.token_urlsafe(32),
            enabled=False,
            health_status="disabled",
        )
        db.add(node)
        try:
            db.flush()
            item = NodeEnrollment(
                id=uuid.uuid4().hex,
                edge_node_id=node.id,
                created_by_user_id=actor.id,
                token_hash="0" * 64,
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
                updated_at=datetime.now(UTC),
            )
            db.add(item)
            raw, command = issue_enrollment(item, node.name)
            db.flush()
            audit(db, "edge_enrollment.created", actor.id, "node_enrollment", item.id)
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge enrollment already exists") from exc
        return {
            **serialize_enrollment(db, item),
            "enrollment_token": raw,
            "install_command": command,
        }

    @app.get("/api/admin/edge-enrollments")
    def list_edge_enrollments(actor: User = Depends(admin), db: Session = Depends(get_db)):
        del actor
        items = db.scalars(select(NodeEnrollment).order_by(NodeEnrollment.updated_at.desc())).all()
        result = [serialize_enrollment(db, item) for item in items]
        db.commit()
        return result

    def invalid_enrollment() -> HTTPException:
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired enrollment")

    def trusted_claim_source(request: Request) -> str | None:
        if enrollment_source_ip:
            candidate = enrollment_source_ip(request)
        else:
            candidate = request.client.host if request.client else None
            try:
                peer = ipaddress.ip_address(candidate) if candidate else None
            except ValueError:
                peer = None
            if peer and peer.is_loopback:
                forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
                candidate = forwarded or candidate
        if not candidate:
            return None
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        return None if address.is_loopback else str(address)

    def invalid_registration() -> HTTPException:
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid registration")

    @app.get("/api/node-registration-source")
    def node_registration_source(request: Request):
        source_ip = trusted_claim_source(request)
        try:
            address = ipaddress.ip_address(source_ip) if source_ip else None
        except ValueError:
            address = None
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise invalid_registration()
        return JSONResponse(
            content={"public_ipv4": str(address)},
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def registration_token_parts(
        request_id: str, authorization: str | None, db: Session
    ) -> tuple[NodeRegistrationRequest, str]:
        if not authorization or not authorization.startswith("Registration "):
            raise invalid_registration()
        raw = authorization[len("Registration ") :]
        token_id, separator, secret = raw.partition(".")
        if not separator or not secret or token_id != request_id or len(raw) > 240:
            raise invalid_registration()
        item = db.get(NodeRegistrationRequest, request_id)
        if item is None or not item.registration_token_hash:
            hmac.compare_digest(enrollment_hash(raw), "0" * 64)
            raise invalid_registration()
        if not hmac.compare_digest(enrollment_hash(raw), item.registration_token_hash):
            raise invalid_registration()
        return item, raw

    def registration_claim_challenge(item: NodeRegistrationRequest) -> str:
        material = (
            f"node-claim-challenge-v1:{item.id}:{item.registration_token_hash or ''}".encode()
        )
        digest = hmac.new(secret_key.encode(), material, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    @app.post("/api/node-registration-requests", status_code=201)
    def create_node_registration(
        body: NodeRegistrationCreateBody,
        request: Request,
        db: Session = Depends(get_db),
    ):
        source_ip = trusted_claim_source(request)
        try:
            address = ipaddress.ip_address(body.public_ipv4)
        except ValueError:
            address = None
        if (
            source_ip is None
            or not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global
            or not hmac.compare_digest(source_ip, body.public_ipv4)
        ):
            raise invalid_registration()
        try:
            public_key = serialization.load_pem_public_key(body.public_key_pem.encode())
        except (TypeError, ValueError):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid registration data")
        if not isinstance(public_key, Ed25519PublicKey):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid registration data")
        canonical_pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        key_der = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        now = datetime.now(UTC)
        request_id = uuid.uuid4().hex
        challenge = secrets.token_urlsafe(32)
        token_secret = secrets.token_urlsafe(32)
        raw_token = f"{request_id}.{token_secret}"
        item = NodeRegistrationRequest(
            id=request_id,
            status="pending_proof",
            public_key_pem=canonical_pem,
            public_key_fingerprint=hashlib.sha256(key_der).hexdigest(),
            machine_fingerprint=body.machine_fingerprint,
            reported_hostname=body.reported_hostname,
            platform=body.platform,
            actual_public_ipv4=body.public_ipv4,
            os_name=body.os_name,
            cpu_count=body.cpu_count,
            memory_total_bytes=body.memory_total_bytes,
            disk_total_bytes=body.disk_total_bytes,
            agent_version=body.agent_version,
            challenge_hash=enrollment_hash(challenge),
            registration_token_hash=enrollment_hash(raw_token),
            challenge_expires_at=now + timedelta(minutes=15),
            created_at=now,
            updated_at=now,
        )
        db.add(item)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Registration already pending") from exc
        return {
            "request_id": request_id,
            "challenge": challenge,
            "registration_token": token_secret,
            "expires_at": item.challenge_expires_at.isoformat(),
        }

    @app.post("/api/node-registration-requests/{request_id}/proof")
    def prove_node_registration(
        request_id: str,
        body: NodeRegistrationProofBody,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(get_db),
    ):
        item, _ = registration_token_parts(request_id, authorization, db)
        source_ip = trusted_claim_source(request)
        if source_ip is None or not hmac.compare_digest(source_ip, item.actual_public_ipv4):
            raise invalid_registration()
        now = datetime.now(UTC)
        expires_at = (
            item.challenge_expires_at.replace(tzinfo=UTC)
            if item.challenge_expires_at.tzinfo is None
            else item.challenge_expires_at
        )
        if expires_at <= now:
            if item.status == "pending_proof":
                item.status = "expired"
                item.challenge_hash = None
                item.updated_at = now
                db.commit()
            raise invalid_registration()
        valid = item.status == "pending_proof" and bool(item.challenge_hash)
        valid = valid and hmac.compare_digest(
            enrollment_hash(body.challenge), item.challenge_hash or ""
        )
        try:
            signature = base64.b64decode(body.signature, validate=True)
            public_key = serialization.load_pem_public_key(item.public_key_pem.encode())
            message = (
                f"hermes-node-registration-v1\n{item.id}\n{body.challenge}\n"
                f"{item.actual_public_ipv4}\n{item.machine_fingerprint}\n"
            ).encode()
            if not isinstance(public_key, Ed25519PublicKey):
                valid = False
            else:
                public_key.verify(signature, message)
        except (InvalidSignature, TypeError, ValueError):
            valid = False
        if not valid:
            raise invalid_registration()
        consumed = db.execute(
            update(NodeRegistrationRequest)
            .where(
                NodeRegistrationRequest.id == item.id,
                NodeRegistrationRequest.status == "pending_proof",
                NodeRegistrationRequest.challenge_hash == item.challenge_hash,
            )
            .values(
                status="pending_approval",
                challenge_hash=None,
                challenge_expires_at=now + timedelta(hours=24),
                proved_at=now,
                updated_at=now,
            )
        )
        if consumed.rowcount != 1:
            db.rollback()
            raise invalid_registration()
        db.commit()
        return {"status": "pending_approval"}

    @app.get("/api/node-registration-requests/{request_id}/status")
    def node_registration_status(
        request_id: str,
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(get_db),
    ):
        item, _ = registration_token_parts(request_id, authorization, db)
        result = {
            "status": item.status,
            "phase": None,
            "error": item.last_error,
            "decision": (
                "accepted"
                if item.status in {"approved", "installing", "ready", "online"}
                else "rejected"
                if item.status == "rejected"
                else None
            ),
        }
        if item.status == "approved" and item.challenge_hash:
            result["claim_challenge"] = registration_claim_challenge(item)
        return result

    def serialize_registration_request(item: NodeRegistrationRequest) -> dict:
        return {
            "id": item.id,
            "status": item.status,
            "public_key_fingerprint": item.public_key_fingerprint,
            "machine_fingerprint": item.machine_fingerprint,
            "reported_hostname": item.reported_hostname,
            "platform": item.platform,
            "actual_public_ipv4": item.actual_public_ipv4,
            "os_name": item.os_name,
            "cpu_count": item.cpu_count,
            "memory_total_bytes": item.memory_total_bytes,
            "disk_total_bytes": item.disk_total_bytes,
            "agent_version": item.agent_version,
            "created_at": item.created_at.isoformat(),
            "updated_at": item.updated_at.isoformat(),
            "proved_at": item.proved_at.isoformat() if item.proved_at else None,
            "decided_at": item.decided_at.isoformat() if item.decided_at else None,
            "decided_by_user_id": item.decided_by_user_id,
            "edge_node_id": item.edge_node_id,
            "last_error": item.last_error,
            "install_admin_ssh_key": item.install_admin_ssh_key,
        }

    @app.get("/api/admin/node-registration-requests")
    def list_node_registration_requests(
        actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        del actor
        now = datetime.now(UTC)
        items = db.scalars(
            select(NodeRegistrationRequest).order_by(NodeRegistrationRequest.created_at.desc())
        ).all()
        for item in items:
            expires = (
                item.challenge_expires_at.replace(tzinfo=UTC)
                if item.challenge_expires_at.tzinfo is None
                else item.challenge_expires_at
            )
            if item.status in {"pending_proof", "pending_approval"} and expires <= now:
                item.status = "expired"
                item.challenge_hash = None
                item.updated_at = now
        db.commit()
        return [serialize_registration_request(item) for item in items]

    def derived_report_token(item: NodeRegistrationRequest, enrollment_id: str) -> str:
        material = f"node-report-v1:{item.registration_token_hash}:{enrollment_id}".encode()
        digest = hmac.new(secret_key.encode(), material, hashlib.sha256).digest()
        return f"{enrollment_id}.{base64.urlsafe_b64encode(digest).decode().rstrip('=')}"

    @app.post("/api/admin/node-registration-requests/{request_id}/accept")
    def accept_node_registration(
        request_id: str,
        body: NodeRegistrationAcceptBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        item = db.get(NodeRegistrationRequest, request_id)
        if item is None or item.status != "pending_approval" or item.proved_at is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Registration cannot be accepted")
        validate_edge_node_network(body.endpoint, body.expected_public_ipv4)
        if not hmac.compare_digest(body.expected_public_ipv4, item.actual_public_ipv4):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Public IPv4 mismatch")
        if db.scalar(
            select(EdgeNode.id).where(
                (EdgeNode.name == body.node_name) | (EdgeNode.endpoint == body.endpoint)
            )
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge node already exists")
        now = datetime.now(UTC)
        claim_challenge = registration_claim_challenge(item)
        decision = db.execute(
            update(NodeRegistrationRequest)
            .where(
                NodeRegistrationRequest.id == item.id,
                NodeRegistrationRequest.status == "pending_approval",
                NodeRegistrationRequest.proved_at.is_not(None),
            )
            .values(
                status="approved",
                decided_at=now,
                decided_by_user_id=actor.id,
                updated_at=now,
                install_admin_ssh_key=body.install_admin_ssh_key,
                challenge_hash=enrollment_hash(claim_challenge),
                challenge_expires_at=now + timedelta(minutes=15),
            )
        )
        if decision.rowcount != 1:
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Registration cannot be accepted")
        node = EdgeNode(
            name=body.node_name,
            endpoint=body.endpoint,
            shared_secret=secrets.token_urlsafe(32),
            platform=item.platform,
            enabled=False,
            health_status="disabled",
            expected_public_ipv4=item.actual_public_ipv4,
            actual_public_ipv4=item.actual_public_ipv4,
        )
        db.add(node)
        try:
            db.flush()
            enrollment = NodeEnrollment(
                id=uuid.uuid4().hex,
                edge_node_id=node.id,
                created_by_user_id=actor.id,
                token_hash=enrollment_hash(secrets.token_urlsafe(32)),
                status="claimed",
                phase=None,
                expires_at=now + timedelta(hours=2),
                claimed_at=now,
                updated_at=now,
                claimed_public_ipv4=item.actual_public_ipv4,
                agent_version=item.agent_version,
            )
            report_token = derived_report_token(item, enrollment.id)
            enrollment.report_token_hash = enrollment_hash(report_token)
            db.add(enrollment)
            item.edge_node_id = node.id
            audit(
                db,
                "node_registration.accepted",
                actor.id,
                "node_registration_request",
                item.id,
                {"node_name": node.name, "actual_public_ipv4": item.actual_public_ipv4},
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Registration cannot be accepted"
            ) from exc
        return {"id": item.id, "status": item.status, "edge_node_id": node.id}

    @app.post("/api/admin/node-registration-requests/{request_id}/reject")
    def reject_node_registration(
        request_id: str,
        body: NodeRegistrationRejectBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        item = db.get(NodeRegistrationRequest, request_id)
        if item is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Registration cannot be rejected")
        now = datetime.now(UTC)
        reason = " ".join(body.reason.replace("\x00", " ").split())[:500]
        decision = db.execute(
            update(NodeRegistrationRequest)
            .where(
                NodeRegistrationRequest.id == item.id,
                NodeRegistrationRequest.status == "pending_approval",
            )
            .values(
                status="rejected",
                challenge_hash=None,
                last_error=reason,
                decided_at=now,
                decided_by_user_id=actor.id,
                updated_at=now,
            )
        )
        if decision.rowcount != 1:
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Registration cannot be rejected")
        audit(
            db,
            "node_registration.rejected",
            actor.id,
            "node_registration_request",
            item.id,
            {"reason": reason},
        )
        db.commit()
        return {"id": item.id, "status": item.status}

    @app.post("/api/node-registration-requests/{request_id}/claim-approved")
    def claim_approved_node_registration(
        request_id: str,
        body: NodeRegistrationClaimBody,
        request: Request,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ):
        item, _ = registration_token_parts(request_id, authorization, db)
        if item.status != "approved" or item.proved_at is None or item.edge_node_id is None:
            raise invalid_registration()
        source_ip = trusted_claim_source(request)
        now = datetime.now(UTC)
        expires_at = (
            item.challenge_expires_at.replace(tzinfo=UTC)
            if item.challenge_expires_at.tzinfo is None
            else item.challenge_expires_at
        )
        valid = (
            source_ip is not None
            and hmac.compare_digest(source_ip, item.actual_public_ipv4)
            and expires_at > now
            and bool(item.challenge_hash)
            and hmac.compare_digest(
                enrollment_hash(body.challenge), item.challenge_hash or ""
            )
        )
        try:
            signature = base64.b64decode(body.signature, validate=True)
            public_key = serialization.load_pem_public_key(item.public_key_pem.encode())
            message = (
                f"hermes-node-claim-v1\n{item.id}\n{body.challenge}\n"
                f"{item.actual_public_ipv4}\n{item.machine_fingerprint}\n"
            ).encode()
            if not isinstance(public_key, Ed25519PublicKey):
                valid = False
            else:
                public_key.verify(signature, message)
        except (InvalidSignature, TypeError, ValueError):
            valid = False
        if not valid:
            raise invalid_registration()
        node = db.get(EdgeNode, item.edge_node_id)
        enrollment = db.scalar(
            select(NodeEnrollment).where(
                NodeEnrollment.edge_node_id == node.id, NodeEnrollment.status == "claimed"
            )
        )
        if enrollment is None:
            raise invalid_registration()
        package_checksum, package_route = verified_edge_package(node.platform)
        report_token = derived_report_token(item, enrollment.id)
        consumed = db.execute(
            update(NodeRegistrationRequest)
            .where(
                NodeRegistrationRequest.id == item.id,
                NodeRegistrationRequest.status == "approved",
                NodeRegistrationRequest.registration_token_hash == item.registration_token_hash,
                NodeRegistrationRequest.challenge_hash == item.challenge_hash,
            )
            .values(
                status="installing",
                registration_token_hash=None,
                challenge_hash=None,
                updated_at=now,
            )
        )
        if consumed.rowcount != 1:
            db.rollback()
            raise invalid_registration()
        enrollment.status = "installing"
        enrollment.phase = "installing"
        enrollment.updated_at = now
        enrollment.expires_at = now + timedelta(hours=2)
        db.commit()
        origin = (public_origin or "https://api.example.com").rstrip("/")
        return {
            "node_id": node.id,
            "node_name": node.name,
            "domain": urlsplit(node.endpoint).hostname,
            "edge_ticket_secret": node.shared_secret,
            "resources": {
                "max_connections": 256,
                "max_frame_bytes": 1_048_576,
                "max_bytes": 2_147_483_648,
                "idle_timeout": 300,
                "max_duration": 28_800,
                "connect_timeout": 10,
                "ticket_max_ttl": 60,
            },
            "package_url": f"{origin}{package_route}",
            "package_sha256": package_checksum,
            "report_token": report_token,
            "enrollment_id": enrollment.id,
            "install_admin_ssh_key": item.install_admin_ssh_key,
        }

    @app.post("/api/edge-enrollments/claim")
    def claim_edge_enrollment(
        body: EdgeEnrollmentClaimBody,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(get_db),
    ):
        if not authorization or not authorization.startswith("Enrollment "):
            raise invalid_enrollment()
        raw = authorization[len("Enrollment ") :]
        token_id, separator, token_secret = raw.partition(".")
        if not separator or not token_secret or len(raw) > 200 or len(token_id) > 64:
            raise invalid_enrollment()
        item = db.get(NodeEnrollment, token_id)
        now = datetime.now(UTC)
        if item is None:
            hmac.compare_digest(enrollment_hash(raw), "0" * 64)
            raise invalid_enrollment()
        node = db.get(EdgeNode, item.edge_node_id)
        expires_at = (
            item.expires_at.replace(tzinfo=UTC)
            if item.expires_at.tzinfo is None
            else item.expires_at
        )
        source_ip = trusted_claim_source(request)
        valid = all(
            (
                hmac.compare_digest(enrollment_hash(raw), item.token_hash),
                item.status == "pending",
                item.claimed_at is None,
                expires_at > now,
                hmac.compare_digest(body.node_name, node.name),
                hmac.compare_digest(body.public_ipv4, node.expected_public_ipv4 or ""),
                source_ip is None or hmac.compare_digest(source_ip, body.public_ipv4),
            )
        )
        try:
            address = ipaddress.ip_address(body.public_ipv4)
            valid = valid and isinstance(address, ipaddress.IPv4Address) and address.is_global
        except ValueError:
            valid = False
        if not valid:
            if item.status == "pending" and expires_at <= now:
                item.status = "expired"
                item.updated_at = now
                db.commit()
            raise invalid_enrollment()
        package_checksum, package_route = verified_edge_package(node.platform)
        consumed = db.execute(
            update(NodeEnrollment)
            .where(
                NodeEnrollment.id == item.id,
                NodeEnrollment.status == "pending",
                NodeEnrollment.claimed_at.is_(None),
                NodeEnrollment.token_hash == item.token_hash,
            )
            .values(
                status="claimed",
                claimed_at=now,
                updated_at=now,
                claimed_public_ipv4=body.public_ipv4,
                agent_version=body.agent_version,
                expires_at=now + timedelta(minutes=30),
                token_hash=enrollment_hash(secrets.token_urlsafe(32)),
            )
        )
        if consumed.rowcount != 1:
            db.rollback()
            raise invalid_enrollment()
        report_token = f"{item.id}.{secrets.token_urlsafe(32)}"
        db.execute(
            update(NodeEnrollment)
            .where(NodeEnrollment.id == item.id)
            .values(report_token_hash=enrollment_hash(report_token))
        )
        db.commit()
        origin = (public_origin or "https://api.example.com").rstrip("/")
        return {
            "node_id": node.id,
            "node_name": node.name,
            "domain": urlsplit(node.endpoint).hostname,
            "edge_ticket_secret": node.shared_secret,
            "resources": {
                "max_connections": 256,
                "max_frame_bytes": 1_048_576,
                "max_bytes": 2_147_483_648,
                "idle_timeout": 300,
                "max_duration": 28_800,
                "connect_timeout": 10,
                "ticket_max_ttl": 60,
            },
            "package_url": f"{origin}{package_route}",
            "package_sha256": package_checksum,
            "report_token": report_token,
        }

    @app.post("/api/edge-enrollments/report")
    def report_edge_enrollment(
        body: EdgeEnrollmentReportBody,
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(get_db),
    ):
        if not authorization or not authorization.startswith("Report "):
            raise invalid_enrollment()
        raw = authorization[len("Report ") :]
        token_id, separator, token_secret = raw.partition(".")
        if not separator or not token_secret or len(raw) > 200:
            raise invalid_enrollment()
        item = db.get(NodeEnrollment, token_id)
        now = datetime.now(UTC)
        if item is None:
            hmac.compare_digest(enrollment_hash(raw), "0" * 64)
            raise invalid_enrollment()
        expires_at = (
            item.expires_at.replace(tzinfo=UTC)
            if item.expires_at.tzinfo is None
            else item.expires_at
        )
        if (
            not item.report_token_hash
            or not hmac.compare_digest(enrollment_hash(raw), item.report_token_hash)
            or item.status in {"revoked", "expired", "online"}
            or expires_at <= now
        ):
            raise invalid_enrollment()
        clean_error = (
            " ".join(body.error.replace("\x00", " ").split())[:500] if body.error else None
        )
        item.phase = body.phase
        item.updated_at = now
        item.last_error = clean_error if body.phase == "failed" else None
        if body.phase == "failed":
            item.status = "failed"
        elif body.phase == "ready":
            item.status = "ready"
            node = db.get(EdgeNode, item.edge_node_id)
            node.enabled = True
            node.health_status = "unknown"
            node.last_error = None
        else:
            item.status = "installing"
        registration = db.scalar(
            select(NodeRegistrationRequest).where(
                NodeRegistrationRequest.edge_node_id == item.edge_node_id
            )
        )
        if registration is not None:
            registration.status = item.status
            registration.updated_at = now
            registration.last_error = item.last_error
        db.commit()
        return {"status": item.status, "phase": item.phase}

    @app.post("/api/admin/edge-enrollments/{enrollment_id}/revoke")
    def revoke_edge_enrollment(
        enrollment_id: str,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        item = db.get(NodeEnrollment, enrollment_id)
        if item is None or item.status in {"revoked", "online"}:
            raise HTTPException(status.HTTP_409_CONFLICT, "Enrollment cannot be revoked")
        item.status = "revoked"
        item.token_hash = enrollment_hash(secrets.token_urlsafe(32))
        item.report_token_hash = None
        item.updated_at = datetime.now(UTC)
        node = db.get(EdgeNode, item.edge_node_id)
        node.enabled = False
        node.health_status = "disabled"
        audit(db, "edge_enrollment.revoked", actor.id, "node_enrollment", item.id)
        db.commit()
        return serialize_enrollment(db, item)

    @app.post("/api/admin/edge-enrollments/{enrollment_id}/regenerate")
    def regenerate_edge_enrollment(
        enrollment_id: str,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        item = db.get(NodeEnrollment, enrollment_id)
        if item is None or item.status not in {"pending", "expired", "revoked"}:
            raise HTTPException(status.HTTP_409_CONFLICT, "Enrollment cannot be regenerated")
        item.status = "pending"
        item.phase = None
        item.claimed_at = None
        item.claimed_public_ipv4 = None
        item.agent_version = None
        item.last_error = None
        item.report_token_hash = None
        item.expires_at = datetime.now(UTC) + timedelta(minutes=15)
        item.updated_at = datetime.now(UTC)
        node = db.get(EdgeNode, item.edge_node_id)
        raw, command = issue_enrollment(item, node.name)
        audit(db, "edge_enrollment.regenerated", actor.id, "node_enrollment", item.id)
        db.commit()
        return {
            **serialize_enrollment(db, item),
            "enrollment_token": raw,
            "install_command": command,
        }

    @app.post("/api/admin/edge-nodes", status_code=201)
    def create_edge_node(
        body: EdgeNodeCreateBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        validate_edge_node_network(body.endpoint, body.expected_public_ipv4)
        if db.scalar(
            select(EdgeNode).where(
                (EdgeNode.name == body.name) | (EdgeNode.endpoint == body.endpoint)
            )
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge node already exists")
        node = EdgeNode(**body.model_dump())
        if node.maintenance_mode:
            node.health_status = "maintenance"
        elif not node.enabled:
            node.health_status = "disabled"
        db.add(node)
        db.flush()
        audit(db, "edge_node.created", actor.id, "edge_node", str(node.id))
        db.commit()
        return serialize_edge_node(node)

    @app.get("/api/admin/edge-nodes")
    def admin_edge_nodes(actor: User = Depends(admin), db: Session = Depends(get_db)):
        del actor
        nodes = db.scalars(select(EdgeNode).order_by(EdgeNode.id)).all()
        return [serialize_edge_node(node) for node in nodes]

    @app.patch("/api/admin/edge-nodes/{node_id}")
    def update_edge_node(
        node_id: int,
        body: EdgeNodeUpdateBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        node = db.get(EdgeNode, node_id)
        if node is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Edge node not found")
        changes = body.model_dump(exclude_unset=True)
        duplicate = db.scalar(
            select(EdgeNode).where(
                EdgeNode.id != node.id,
                (EdgeNode.name == changes.get("name", node.name))
                | (EdgeNode.endpoint == changes.get("endpoint", node.endpoint)),
            )
        )
        if duplicate:
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge node already exists")
        validate_edge_node_network(
            changes.get("endpoint", node.endpoint),
            changes.get("expected_public_ipv4", node.expected_public_ipv4),
        )
        for field, value in changes.items():
            setattr(node, field, value)
        if node.maintenance_mode:
            node.health_status = "maintenance"
        elif not node.enabled:
            node.health_status = "disabled"
        elif "maintenance_mode" in changes or "enabled" in changes:
            node.health_status = "unknown"
        safe_fields = sorted(field for field in changes if field != "shared_secret")
        details = {"changed_fields": safe_fields}
        if "shared_secret" in changes:
            details["credential_rotated"] = True
        audit(db, "edge_node.updated", actor.id, "edge_node", str(node.id), details)
        db.commit()
        return serialize_edge_node(node)

    @app.delete("/api/admin/edge-nodes/{node_id}", status_code=204)
    def delete_edge_node(node_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)):
        node = db.get(EdgeNode, node_id)
        if node is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Edge node not found")
        if db.scalar(select(ManagedStore.id).where(ManagedStore.edge_node_id == node.id)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Edge node is assigned to a store")
        audit(db, "edge_node.deleted", actor.id, "edge_node", str(node.id))
        db.delete(node)
        db.commit()
        return Response(status_code=204)

    def serialize_capability(item: EdgeCapability) -> dict:
        return {
            "id": item.id,
            "edge_node_id": item.edge_node_id,
            "name": item.name,
            "config": json.loads(item.config_json),
        }

    @app.post("/api/admin/edge-nodes/{node_id}/capabilities", status_code=201)
    def create_edge_capability(
        node_id: int,
        body: EdgeCapabilityBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        if db.get(EdgeNode, node_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Edge node not found")
        if db.scalar(
            select(EdgeCapability).where(
                EdgeCapability.edge_node_id == node_id, EdgeCapability.name == body.name
            )
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Capability already exists")
        item = EdgeCapability(
            edge_node_id=node_id,
            name=body.name,
            config_json=json.dumps(body.config, separators=(",", ":")),
        )
        db.add(item)
        db.flush()
        audit(db, "edge_capability.created", actor.id, "edge_capability", str(item.id))
        db.commit()
        return serialize_capability(item)

    @app.get("/api/admin/edge-nodes/{node_id}/capabilities")
    def list_edge_capabilities(
        node_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        del actor
        if db.get(EdgeNode, node_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Edge node not found")
        items = db.scalars(
            select(EdgeCapability)
            .where(EdgeCapability.edge_node_id == node_id)
            .order_by(EdgeCapability.id)
        ).all()
        return [serialize_capability(item) for item in items]

    @app.patch("/api/admin/edge-capabilities/{capability_id}")
    def update_edge_capability(
        capability_id: int,
        body: EdgeCapabilityBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        item = db.get(EdgeCapability, capability_id)
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability not found")
        duplicate = db.scalar(
            select(EdgeCapability).where(
                EdgeCapability.edge_node_id == item.edge_node_id,
                EdgeCapability.name == body.name,
                EdgeCapability.id != item.id,
            )
        )
        if duplicate:
            raise HTTPException(status.HTTP_409_CONFLICT, "Capability already exists")
        item.name = body.name
        item.config_json = json.dumps(body.config, separators=(",", ":"))
        audit(db, "edge_capability.updated", actor.id, "edge_capability", str(item.id))
        db.commit()
        return serialize_capability(item)

    @app.delete("/api/admin/edge-capabilities/{capability_id}", status_code=204)
    def delete_edge_capability(
        capability_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        item = db.get(EdgeCapability, capability_id)
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability not found")
        audit(db, "edge_capability.deleted", actor.id, "edge_capability", str(item.id))
        db.delete(item)
        db.commit()
        return Response(status_code=204)

    def serialize_store(db: Session, store: ManagedStore) -> dict:
        node = db.get(EdgeNode, store.edge_node_id)
        leases = active_store_leases(db, store.id)
        active_leases = []
        for lease in leases:
            lease_owner = db.get(User, lease.owner_user_id)
            active_leases.append(
                {
                    "id": lease.id,
                    "username": lease_owner.username,
                    "device_id": lease.device_id,
                    "last_heartbeat_at": (
                        lease.last_heartbeat_at.isoformat() if lease.last_heartbeat_at else None
                    ),
                    "expires_at": lease.expires_at.isoformat(),
                }
            )
        return {
            "id": store.id,
            "label": store.label,
            "owner_user_id": store.owner_user_id,
            "edge_node_id": store.edge_node_id,
            "edge_node_name": node.name,
            "enabled": store.enabled,
            "active_lease": active_leases[0] if active_leases else None,
            "active_leases": active_leases,
            "active_connection_count": len(active_leases),
            "expected_egress_ips": (
                [node.expected_public_ipv4] if node.expected_public_ipv4 else []
            ),
            **serialize_edge_health(node),
        }

    def validate_store_links(db: Session, owner_user_id: int | None, edge_node_id: int) -> None:
        if owner_user_id is not None:
            owner = db.get(User, owner_user_id)
            if owner is None or not owner.enabled:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Valid owner required")
        if db.get(EdgeNode, edge_node_id) is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Valid edge node required")

    @app.post("/api/admin/stores", status_code=201)
    def create_managed_store(
        body: ManagedStoreCreateBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        if db.scalar(select(ManagedStore).where(ManagedStore.label == body.label)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Store already exists")
        validate_store_links(db, body.owner_user_id, body.edge_node_id)
        store = ManagedStore(**body.model_dump())
        db.add(store)
        db.flush()
        audit(db, "managed_store.created", actor.id, "managed_store", str(store.id))
        db.commit()
        return serialize_store(db, store)

    @app.get("/api/admin/stores")
    def admin_stores(actor: User = Depends(admin), db: Session = Depends(get_db)):
        del actor
        stores = db.scalars(select(ManagedStore).order_by(ManagedStore.id)).all()
        return [serialize_store(db, store) for store in stores]

    @app.patch("/api/admin/stores/{store_id}")
    def update_managed_store(
        store_id: int,
        body: ManagedStoreUpdateBody,
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        store = db.get(ManagedStore, store_id)
        if store is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Store not found")
        changes = body.model_dump(exclude_unset=True)
        if "label" in changes and db.scalar(
            select(ManagedStore.id).where(
                ManagedStore.label == changes["label"], ManagedStore.id != store.id
            )
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Store already exists")
        if (
            "edge_node_id" in changes
            and changes["edge_node_id"] != store.edge_node_id
            and active_store_leases(db, store.id)
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Cannot rebind a store with an active connection"
            )
        validate_store_links(
            db,
            changes.get("owner_user_id", store.owner_user_id),
            changes.get("edge_node_id", store.edge_node_id),
        )
        for field, value in changes.items():
            setattr(store, field, value)
        audit(
            db,
            "managed_store.updated",
            actor.id,
            "managed_store",
            str(store.id),
            {"changed_fields": sorted(changes)},
        )
        db.commit()
        return serialize_store(db, store)

    @app.delete("/api/admin/stores/{store_id}", status_code=204)
    def delete_managed_store(
        store_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        store = db.get(ManagedStore, store_id)
        if store is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Store not found")
        if db.scalar(
            select(StoreConnectionLease.id).where(StoreConnectionLease.store_id == store.id)
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Store has connection history")
        audit(db, "managed_store.deleted", actor.id, "managed_store", str(store.id))
        db.delete(store)
        db.commit()
        return Response(status_code=204)

    @app.post("/api/admin/stores/{store_id}/force-disconnect")
    def force_disconnect_managed_store(
        store_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        store = db.get(ManagedStore, store_id)
        if store is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Store not found")
        leases = active_store_leases(db, store.id)
        if not leases:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store has no active connection")
        disconnected_at = datetime.now(UTC)
        for lease in leases:
            lease.status = "disconnected"
            lease.disconnected_at = disconnected_at
        if len(leases) == 1:
            lease = leases[0]
            owner = db.get(User, lease.owner_user_id)
            details = {
                "lease_id": lease.id,
                "username": owner.username,
                "device_id": lease.device_id,
            }
        else:
            details = {
                "disconnected_count": len(leases),
                "lease_ids": [lease.id for lease in leases],
            }
        audit(
            db,
            "managed_store.force_disconnected",
            actor.id,
            "managed_store",
            str(store.id),
            details,
        )
        db.commit()
        if len(leases) == 1:
            return {"lease_id": leases[0].id, "status": leases[0].status}
        return {
            "status": "disconnected",
            "disconnected_count": len(leases),
            "lease_ids": [lease.id for lease in leases],
        }

    @app.post("/api/admin/store-leases/{lease_id}/force-disconnect")
    def force_disconnect_store_lease(
        lease_id: str, actor: User = Depends(admin), db: Session = Depends(get_db)
    ):
        lease = db.get(StoreConnectionLease, lease_id)
        if lease is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Store lease not found")
        active = {item.id for item in active_store_leases(db, lease.store_id)}
        if lease.id not in active:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store lease is not active")
        lease.status = "disconnected"
        lease.disconnected_at = datetime.now(UTC)
        owner = db.get(User, lease.owner_user_id)
        audit(
            db,
            "managed_store.force_disconnected",
            actor.id,
            "managed_store",
            str(lease.store_id),
            {
                "lease_id": lease.id,
                "username": owner.username,
                "device_id": lease.device_id,
            },
        )
        db.commit()
        return {"lease_id": lease.id, "status": lease.status}

    @app.get("/api/admin/store-leases")
    def list_store_leases(actor: User = Depends(admin), db: Session = Depends(get_db)):
        del actor
        leases = db.scalars(
            select(StoreConnectionLease).order_by(StoreConnectionLease.created_at.desc())
        ).all()
        return [
            {
                "id": lease.id,
                "store_id": lease.store_id,
                "owner_user_id": lease.owner_user_id,
                "device_id": lease.device_id,
                "status": lease.status,
                "created_at": lease.created_at.isoformat(),
                "expires_at": lease.expires_at.isoformat(),
                "disconnected_at": (
                    lease.disconnected_at.isoformat() if lease.disconnected_at else None
                ),
            }
            for lease in leases
        ]

    def accessible_store(db: Session, store_id: int, user: User) -> ManagedStore:
        query = (
            select(ManagedStore)
            .join(EdgeNode, EdgeNode.id == ManagedStore.edge_node_id)
            .where(ManagedStore.id == store_id, EdgeNode.enabled.is_(True))
        )
        if user.role != "admin":
            query = query.join(
                UserEdgeNodeGrant,
                UserEdgeNodeGrant.edge_node_id == ManagedStore.edge_node_id,
            ).where(UserEdgeNodeGrant.user_id == user.id)
        store = db.scalar(query)
        if store is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Store not found")
        return store

    def require_online_edge(node: EdgeNode) -> None:
        if node.health_status != "online":
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "Assigned edge node is unavailable"
            )

    def active_store_leases(db: Session, store_id: int) -> list[StoreConnectionLease]:
        leases = db.scalars(
            select(StoreConnectionLease).where(
                StoreConnectionLease.store_id == store_id,
                StoreConnectionLease.status == "active",
            )
        ).all()
        active: list[StoreConnectionLease] = []
        for lease in leases:
            now_for_lease = datetime.now(UTC)
            if lease.expires_at.tzinfo is None:
                now_for_lease = now_for_lease.replace(tzinfo=None)
            heartbeat_now = now_for_lease
            heartbeat = lease.last_heartbeat_at or lease.created_at
            if heartbeat.tzinfo is None and heartbeat_now.tzinfo is not None:
                heartbeat_now = heartbeat_now.replace(tzinfo=None)
            if (
                lease.expires_at <= now_for_lease
                or heartbeat < heartbeat_now - timedelta(seconds=90)
            ):
                lease.status = "expired"
            else:
                active.append(lease)
        db.flush()
        return active

    def active_store_lease(
        db: Session,
        store_id: int,
        owner_user_id: int,
        device_id: str,
    ) -> StoreConnectionLease | None:
        return next(
            (
                lease
                for lease in active_store_leases(db, store_id)
                if lease.owner_user_id == owner_user_id and lease.device_id == device_id
            ),
            None,
        )

    def requested_store_lease(
        db: Session,
        store_id: int,
        owner_user_id: int,
        lease_id: str | None,
        device_id: str | None,
    ) -> StoreConnectionLease | None:
        if (lease_id is None) != (device_id is None):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "lease_id and device_id must be provided together",
            )
        leases = [
            lease
            for lease in active_store_leases(db, store_id)
            if lease.owner_user_id == owner_user_id
        ]
        if lease_id is not None and device_id is not None:
            return next(
                (
                    lease
                    for lease in leases
                    if lease.id == lease_id and lease.device_id == device_id
                ),
                None,
            )
        if len(leases) > 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Lease identity is required for multi-device connection",
            )
        return leases[0] if leases else None

    def serialize_owner_store(db: Session, store: ManagedStore, user_id: int) -> dict:
        node = db.get(EdgeNode, store.edge_node_id)
        leases = [
            lease
            for lease in active_store_leases(db, store.id)
            if lease.owner_user_id == user_id
        ]
        expected_egress_ips = [node.expected_public_ipv4] if node.expected_public_ipv4 else []
        return {
            "id": store.id,
            "label": store.label,
            "enabled": store.enabled,
            "edge_node_name": node.name,
            "edge_endpoint": node.endpoint,
            "expected_egress_ips": expected_egress_ips,
            "connection_status": "active" if leases else "disconnected",
            "active_device_count": len(leases),
            **serialize_edge_health(node),
        }

    @app.get("/api/stores")
    def list_owned_stores(user: User = Depends(current_user), db: Session = Depends(get_db)):
        query = (
            select(ManagedStore)
            .join(EdgeNode, EdgeNode.id == ManagedStore.edge_node_id)
            .where(EdgeNode.enabled.is_(True))
        )
        if user.role != "admin":
            query = query.join(
                UserEdgeNodeGrant,
                UserEdgeNodeGrant.edge_node_id == ManagedStore.edge_node_id,
            ).where(UserEdgeNodeGrant.user_id == user.id)
        stores = db.scalars(query.order_by(ManagedStore.id)).all()
        result = [serialize_owner_store(db, store, user.id) for store in stores]
        db.commit()
        return result

    @app.post("/api/stores/{store_id}/connect", status_code=201)
    def connect_store(
        store_id: int,
        body: StoreConnectBody | None = None,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        store = accessible_store(db, store_id, user)
        node = db.get(EdgeNode, store.edge_node_id)
        if not store.enabled or not node.enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store or edge node is disabled")
        require_online_edge(node)
        device_id = body.device_id if body else f"legacy-{user.id}"
        active = active_store_lease(db, store.id, user.id, device_id)
        if active:
            now = datetime.now(UTC)
            active.last_heartbeat_at = now
            active.expires_at = now + timedelta(hours=8)
            db.commit()
            return {
                "lease_id": active.id,
                "status": active.status,
                "created_at": active.created_at.isoformat(),
                "expires_at": active.expires_at.isoformat(),
                "edge_endpoint": node.endpoint,
                "expires_in": 8 * 60 * 60,
                "capabilities": [],
                "recovered": True,
            }
        issued_at = datetime.now(UTC)
        lease_seconds = 8 * 60 * 60
        expires_at = issued_at + timedelta(seconds=lease_seconds)
        lease = StoreConnectionLease(
            id=uuid.uuid4().hex,
            store_id=store.id,
            owner_user_id=user.id,
            device_id=device_id,
            status="active",
            expires_at=expires_at,
            last_heartbeat_at=issued_at,
        )
        db.add(lease)
        capabilities = db.scalars(
            select(EdgeCapability)
            .where(EdgeCapability.edge_node_id == node.id)
            .order_by(EdgeCapability.id)
        ).all()
        capability_payload = [serialize_capability(item) for item in capabilities]
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Store already has an active connection"
            ) from exc
        audit(db, "managed_store.connected", user.id, "managed_store", str(store.id))
        db.commit()
        return {
            "lease_id": lease.id,
            "status": lease.status,
            "created_at": lease.created_at.isoformat(),
            "expires_at": lease.expires_at.isoformat(),
            "edge_endpoint": node.endpoint,
            "expires_in": lease_seconds,
            "capabilities": capability_payload,
            "recovered": False,
        }

    @app.post("/api/stores/{store_id}/heartbeat")
    def heartbeat_store(
        store_id: int,
        body: StoreHeartbeatBody,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        store = accessible_store(db, store_id, user)
        lease = active_store_lease(db, store.id, user.id, body.device_id)
        if lease is None or lease.id != body.lease_id:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store lease is not active")
        now = datetime.now(UTC)
        lease.last_heartbeat_at = now
        lease.expires_at = now + timedelta(hours=8)
        db.commit()
        return {"lease_id": lease.id, "status": lease.status, "expires_in": 8 * 60 * 60}

    @app.post("/api/stores/{store_id}/tickets", status_code=201)
    def issue_store_target_ticket(
        store_id: int,
        body: EdgeTargetTicketBody,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        store = accessible_store(db, store_id, user)
        lease = requested_store_lease(
            db,
            store.id,
            user.id,
            body.lease_id,
            body.device_id,
        )
        if lease is None:
            db.commit()
            raise HTTPException(status.HTTP_409_CONFLICT, "Store is not connected")
        node = db.get(EdgeNode, store.edge_node_id)
        if not store.enabled or not node.enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store or edge node is disabled")
        require_online_edge(node)
        try:
            target = PublicTargetPolicy().resolve(body.host, body.port)
        except TunnelTargetDenied as exc:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Target is not public web traffic"
            ) from exc

        now = datetime.now(UTC)
        expires_at = lease.expires_at
        if expires_at.tzinfo is None:
            now = now.replace(tzinfo=None)
        remaining = int((expires_at - now).total_seconds())
        if remaining <= 0:
            lease.status = "expired"
            db.commit()
            raise HTTPException(status.HTTP_409_CONFLICT, "Store is not connected")
        expires_in = min(60, remaining)
        ticket = EdgeTicketIssuer(node.shared_secret, node.name).issue(
            store=str(store.id), host=target.host, port=target.port, ttl=expires_in
        )
        access_details = {
            "domain": target.host,
            "port": target.port,
            "device_id": lease.device_id,
            "node": node.name,
        }
        recent_access = db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "web.domain_accessed",
                AuditEvent.actor_user_id == user.id,
                AuditEvent.target_type == "managed_store",
                AuditEvent.target_id == str(store.id),
                AuditEvent.created_at >= datetime.now(UTC) - timedelta(minutes=5),
            )
            .order_by(AuditEvent.id.desc())
            .limit(100)
        ).all()
        duplicate = any(
            all(
                json.loads(event.details_json).get(key) == value
                for key, value in access_details.items()
            )
            for event in recent_access
        )
        if not duplicate:
            audit(
                db,
                "web.domain_accessed",
                user.id,
                "managed_store",
                str(store.id),
                access_details,
            )
        db.commit()
        return {
            "ticket": ticket,
            "lease_id": lease.id,
            "edge_endpoint": node.endpoint,
            "expires_in": expires_in,
        }

    @app.post("/api/stores/{store_id}/disconnect")
    def disconnect_store(
        store_id: int,
        body: StoreDisconnectBody | None = None,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        store = accessible_store(db, store_id, user)
        lease = requested_store_lease(
            db,
            store.id,
            user.id,
            body.lease_id if body else None,
            body.device_id if body else None,
        )
        if lease is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Store is not connected")
        lease.status = "disconnected"
        lease.disconnected_at = datetime.now(UTC)
        audit(db, "managed_store.disconnected", user.id, "managed_store", str(store.id))
        db.commit()
        return {"lease_id": lease.id, "status": lease.status}

    @app.post("/api/sessions/start")
    def start_session(user: User = Depends(current_user), db: Session = Depends(get_db)):
        active = db.scalar(
            select(BrowserSession).where(
                BrowserSession.user_id == user.id,
                BrowserSession.status.in_(["starting", "running"]),
            )
        )
        if active:
            active.status = runner.status(active.id)
            db.commit()
            if active.status == "running":
                return serialize_session(active)
        session_id = uuid.uuid4().hex
        profile_key = f"user-{user.id}"
        workspace = db.get(Workspace, user.workspace_id)
        egress = db.get(EgressProfile, workspace.egress_profile_id)
        item = BrowserSession(
            id=session_id,
            user_id=user.id,
            workspace_id=user.workspace_id,
            profile_key=profile_key,
            status="starting",
        )
        db.add(item)
        db.commit()
        try:
            started = runner.start(
                session_id,
                profile_key,
                {"kind": egress.kind, "config": json.loads(egress.config_json)},
            )
            item.status = started.status
            item.endpoint = started.endpoint
            item.updated_at = datetime.now(UTC)
            audit(db, "session.started", user.id, "session", session_id)
            db.commit()
        except Exception as exc:
            item.status = "error"
            audit(
                db,
                "session.start_failed",
                user.id,
                "session",
                session_id,
                {"error": type(exc).__name__},
            )
            db.commit()
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "Browser failed to start"
            ) from exc
        return serialize_session(item)

    @app.get("/api/sessions/{session_id}")
    def get_session(
        session_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)
    ):
        item = owned_session(db, session_id, user)
        if item.status == "running":
            item.status = runner.status(item.id)
            db.commit()
        return serialize_session(item)

    @app.get("/api/sessions/{session_id}/browser/tabs")
    def browser_tabs(
        session_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_state(owned_id))

    @app.post("/api/sessions/{session_id}/browser/tabs")
    def browser_new_tab(
        session_id: str,
        body: AddressInputBody,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        try:
            url = normalize_address_input(body.input)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        db.close()
        return browser_result(lambda: runner.browser_new_tab(owned_id, url))

    @app.post("/api/sessions/{session_id}/browser/tabs/{target_id}/activate")
    def browser_activate_tab(
        session_id: str,
        target_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_activate(owned_id, target_id))

    @app.delete("/api/sessions/{session_id}/browser/tabs/{target_id}")
    def browser_close_tab(
        session_id: str,
        target_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_close(owned_id, target_id))

    @app.post("/api/sessions/{session_id}/browser/tabs/{target_id}/navigate")
    def browser_navigate_tab(
        session_id: str,
        target_id: str,
        body: AddressInputBody,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        try:
            url = normalize_address_input(body.input)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        db.close()
        return browser_result(lambda: runner.browser_navigate(owned_id, target_id, url))

    @app.post("/api/sessions/{session_id}/browser/tabs/{target_id}/back")
    def browser_back(
        session_id: str,
        target_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_history(owned_id, target_id, -1))

    @app.post("/api/sessions/{session_id}/browser/tabs/{target_id}/forward")
    def browser_forward(
        session_id: str,
        target_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_history(owned_id, target_id, 1))

    @app.post("/api/sessions/{session_id}/browser/tabs/{target_id}/reload")
    def browser_reload(
        session_id: str,
        target_id: str,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        owned_id = running_browser_session(db, session_id, user)
        db.close()
        return browser_result(lambda: runner.browser_reload(owned_id, target_id))

    @app.post("/api/sessions/{session_id}/stop")
    def stop_session(
        session_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)
    ):
        item = owned_session(db, session_id, user)
        runner.stop(item.id)
        item.status = "stopped"
        item.updated_at = datetime.now(UTC)
        audit(db, "session.stopped", user.id, "session", item.id)
        db.commit()
        return serialize_session(item)

    @app.get("/api/sessions/{session_id}/ticket")
    def session_ticket(
        session_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)
    ):
        item = owned_session(db, session_id, user)
        if item.status != "running":
            raise HTTPException(status.HTTP_409_CONFLICT, "Session is not running")
        return {"ticket": ticket_signer.issue(user.id, item.id), "expires_in": 60}

    @app.post("/api/sessions/{session_id}/viewer-session")
    def establish_viewer_session(
        session_id: str,
        body: ViewerTicketBody,
        response: Response,
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ):
        item = owned_session(db, session_id, user)
        if item.status != "running" or not ticket_signer.verify(body.ticket, user.id, item.id):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired viewer ticket")
        response.set_cookie(
            key=f"cb_viewer_{item.id}",
            value=viewer_signer.issue(user.id, item.id),
            max_age=8 * 60 * 60,
            httponly=True,
            secure=secure_cookies,
            samesite="strict",
            path=f"/viewer/{item.id}",
        )
        return {"ok": True}

    def authorize_viewer(db: Session, session_id: str, ticket: str | None) -> BrowserSession:
        item = db.get(BrowserSession, session_id)
        if (
            not item
            or item.status != "running"
            or not ticket
            or not viewer_signer.verify(ticket, item.user_id, item.id)
        ):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Viewer authorization required")
        return item

    @app.api_route(
        "/viewer/{session_id}/{asset_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def viewer_http(session_id: str, asset_path: str, request: Request):
        ticket = request.cookies.get(f"cb_viewer_{session_id}")
        with SessionLocal() as db:
            item = authorize_viewer(db, session_id, ticket)
            endpoint = item.endpoint
        if not endpoint or not endpoint.startswith("http://127.0.0.1:"):
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Browser endpoint unavailable")
        query = f"?{request.url.query}" if request.url.query else ""
        request_headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower()
            in {
                "accept",
                "content-type",
                "if-modified-since",
                "if-none-match",
                "range",
            }
        }
        try:
            async with httpx.AsyncClient(timeout=15) as proxy:
                upstream = await proxy.request(
                    request.method,
                    f"{endpoint}/{asset_path}{query}",
                    content=await request.body(),
                    headers=request_headers,
                )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "Browser upstream request failed"
            ) from exc
        headers = {}
        for name in (
            "accept-ranges",
            "cache-control",
            "content-disposition",
            "content-range",
            "content-type",
            "etag",
            "last-modified",
        ):
            if name in upstream.headers:
                headers[name] = upstream.headers[name]
        return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)

    @app.websocket("/api/local-tunnel")
    async def local_browser_tunnel(websocket: WebSocket):
        import asyncio
        from contextlib import suppress

        await websocket.accept()
        origin = websocket.headers.get("origin")
        if public_origin and origin and origin != public_origin:
            await websocket.close(code=4403)
            return
        with SessionLocal() as db:
            user = access_user_from_header(websocket.headers.get("authorization"), db)
        if user is None:
            await websocket.close(code=4401)
            return

        try:
            request = await websocket.receive_json()
            host = request.get("host") if isinstance(request, dict) else None
            port = request.get("port") if isinstance(request, dict) else None
            if not isinstance(host, str) or len(host) > 253 or not isinstance(port, int):
                raise TunnelTargetDenied("invalid target")
            target = await asyncio.to_thread(PublicTargetPolicy().resolve, host, port)
        except (TunnelTargetDenied, ValueError, WebSocketDisconnect):
            await websocket.send_json({"status": "error", "message": "target denied"})
            await websocket.close(code=4403)
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.address, target.port, family=target.family),
                timeout=10,
            )
        except (OSError, TimeoutError):
            await websocket.send_json({"status": "error", "message": "target unavailable"})
            await websocket.close(code=1011)
            return

        await websocket.send_json({"status": "connected"})

        async def websocket_to_target():
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                payload = message.get("bytes")
                if payload is None:
                    await websocket.close(code=1003)
                    return
                if len(payload) > 262_144:
                    await websocket.close(code=1009)
                    return
                writer.write(payload)
                await writer.drain()

        async def target_to_websocket():
            while chunk := await reader.read(65_536):
                await websocket.send_bytes(chunk)

        tasks = {
            asyncio.create_task(websocket_to_target()),
            asyncio.create_task(target_to_websocket()),
        }
        try:
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        except WebSocketDisconnect:
            pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            with suppress(Exception):
                await websocket.close()

    @app.websocket("/viewer/{session_id}/{asset_path:path}")
    async def viewer_websocket(websocket: WebSocket, session_id: str, asset_path: str):
        import asyncio

        import websockets

        if not cloud_video_enabled:
            await websocket.close(code=4410, reason="Cloud video is disabled")
            return
        ticket = websocket.cookies.get(f"cb_viewer_{session_id}")
        if public_origin and websocket.headers.get("origin") != public_origin:
            await websocket.close(code=4403)
            return
        with SessionLocal() as db:
            try:
                item = authorize_viewer(db, session_id, ticket)
            except HTTPException:
                await websocket.close(code=4401)
                return
            endpoint = item.endpoint
        if not endpoint or not endpoint.startswith("http://127.0.0.1:"):
            await websocket.close(code=1011)
            return
        query = f"?{websocket.url.query}" if websocket.url.query else ""
        target = endpoint.replace("http://", "ws://", 1) + f"/{asset_path}{query}"
        await websocket.accept()
        try:
            async with websockets.connect(target, max_size=None) as upstream:

                async def client_to_browser():
                    while True:
                        message = await websocket.receive()
                        if message["type"] == "websocket.disconnect":
                            return
                        if message.get("text") is not None:
                            await upstream.send(message["text"])
                        elif message.get("bytes") is not None:
                            await upstream.send(message["bytes"])

                async def browser_to_client():
                    async for message in upstream:
                        if isinstance(message, str):
                            await websocket.send_text(message)
                        else:
                            await websocket.send_bytes(message)

                await asyncio.gather(client_to_browser(), browser_to_client())
        except (WebSocketDisconnect, websockets.ConnectionClosed, OSError):
            return

    @app.get("/api/diagnostics/egress")
    def egress_diagnostic(user: User = Depends(current_user), db: Session = Depends(get_db)):
        item = db.scalar(
            select(BrowserSession).where(
                BrowserSession.user_id == user.id, BrowserSession.status == "running"
            )
        )
        if not item:
            raise HTTPException(status.HTTP_409_CONFLICT, "No running browser")
        return {"ip": runner.egress_ip(item.id), "session_id": item.id}

    @app.get("/api/admin/sessions")
    def admin_sessions(actor: User = Depends(admin), db: Session = Depends(get_db)):
        rows = db.execute(
            select(BrowserSession, User.username)
            .join(User, User.id == BrowserSession.user_id)
            .order_by(BrowserSession.created_at.desc())
        ).all()
        result = []
        for item, username in rows:
            if item.status in {"starting", "running"}:
                item.status = runner.status(item.id)
            result.append(
                {
                    "id": item.id,
                    "user_id": item.user_id,
                    "username": username,
                    "status": item.status,
                    "profile_key": item.profile_key,
                    "created_at": item.created_at.isoformat(),
                    "updated_at": item.updated_at.isoformat(),
                }
            )
        db.commit()
        return result

    @app.post("/api/admin/sessions/{session_id}/force-stop")
    def force_stop(session_id: str, actor: User = Depends(admin), db: Session = Depends(get_db)):
        item = db.get(BrowserSession, session_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
        runner.stop(item.id)
        item.status = "stopped"
        audit(db, "session.force_stopped", actor.id, "session", item.id)
        db.commit()
        return serialize_session(item)

    @app.post("/api/admin/users/{user_id}/disable")
    def disable_user(user_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)):
        target = db.get(User, user_id)
        if not target or target.role == "admin":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
        target.enabled = False
        target.token_version += 1
        sessions = db.scalars(
            select(BrowserSession).where(
                BrowserSession.user_id == target.id,
                BrowserSession.status.in_(["starting", "running"]),
            )
        ).all()
        for item in sessions:
            runner.stop(item.id)
            item.status = "stopped"
        audit(db, "user.disabled", actor.id, "user", str(target.id))
        db.commit()
        return {"id": target.id, "enabled": target.enabled}

    def audit_query(
        event_type: str | None,
        actor_user_id: int | None,
        target_type: str | None,
        target_id: str | None,
        limit: int,
        offset: int = 0,
    ):
        query = select(AuditEvent)
        if event_type is not None:
            query = query.where(AuditEvent.event_type == event_type)
        if actor_user_id is not None:
            query = query.where(AuditEvent.actor_user_id == actor_user_id)
        if target_type is not None:
            query = query.where(AuditEvent.target_type == target_type)
        if target_id is not None:
            query = query.where(AuditEvent.target_id == target_id)
        return query.order_by(AuditEvent.id.desc()).offset(offset).limit(limit)

    audit_labels = {
        "login.succeeded": "用户登录成功",
        "login.failed": "用户登录失败",
        "logout": "用户退出登录",
        "workspace.user_assigned": "管理员创建用户",
        "user.edge_nodes_replaced": "管理员修改用户节点权限",
        "user.password_changed": "管理员修改用户密码",
        "user.deleted": "管理员删除用户",
        "user.disabled": "管理员停用用户",
        "edge_node.created": "管理员创建节点",
        "edge_node.updated": "管理员修改节点",
        "edge_node.deleted": "管理员删除节点",
        "managed_store.created": "管理员创建店铺",
        "managed_store.updated": "管理员修改店铺",
        "managed_store.deleted": "管理员删除店铺",
        "managed_store.force_disconnected": "管理员强制释放店铺租约",
        "managed_store.connected": "用户连接店铺",
        "managed_store.disconnected": "用户断开店铺",
        "web.domain_accessed": "店铺访问域名",
        "local_browser.synced": "本地浏览数据同步",
    }

    def serialize_audit(db: Session, event: AuditEvent) -> dict:
        details = json.loads(event.details_json)
        actor_username = details.pop("_actor_username", None)
        target_name = details.pop("_target_name", None)
        if actor_username is None and event.actor_user_id is not None:
            actor_user = db.get(User, event.actor_user_id)
            actor_username = actor_user.username if actor_user else None
        if event.target_type == "user" and details.get("username"):
            target_name = details["username"]
        if target_name is None:
            target_name = event.target_id
        created_at = event.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        return {
            "id": event.id,
            "event_type": event.event_type,
            "event_label": audit_labels.get(event.event_type, event.event_type),
            "actor_user_id": event.actor_user_id,
            "actor_username": actor_username,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "target_name": target_name,
            "details": details,
            "created_at": created_at.isoformat(),
        }

    @app.get("/api/admin/audit")
    def list_audit(
        event_type: str | None = None,
        actor_user_id: int | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        limit: int = Query(default=15, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        del actor
        events = db.scalars(
            audit_query(event_type, actor_user_id, target_type, target_id, limit, offset)
        ).all()
        return [serialize_audit(db, event) for event in events]

    @app.get("/api/admin/audit.csv")
    def export_audit_csv(
        event_type: str | None = None,
        actor_user_id: int | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        limit: int = Query(default=200, ge=1, le=500),
        actor: User = Depends(admin),
        db: Session = Depends(get_db),
    ):
        del actor
        events = db.scalars(
            audit_query(event_type, actor_user_id, target_type, target_id, limit)
        ).all()
        output = io.StringIO(newline="")
        fields = [
            "id",
            "event_type",
            "event_label",
            "actor_user_id",
            "actor_username",
            "target_type",
            "target_id",
            "target_name",
            "details",
            "created_at",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\r\n")
        writer.writeheader()

        def safe_cell(value) -> str:
            cell = "" if value is None else str(value)
            return f"'{cell}" if cell.startswith(("=", "+", "-", "@")) else cell

        for event in events:
            item = serialize_audit(db, event)
            item["details"] = json.dumps(item["details"], ensure_ascii=False, separators=(",", ":"))
            writer.writerow({field: safe_cell(item[field]) for field in fields})
        return Response(
            content=output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="audit-events.csv"'},
        )

    return app
