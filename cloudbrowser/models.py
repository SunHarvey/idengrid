from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.mysql import DATETIME as MYSQL_DATETIME
from sqlalchemy.dialects.mysql import DOUBLE
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import expression


class Base(DeclarativeBase):
    pass


UTC_DATETIME = DateTime(timezone=True).with_variant(MYSQL_DATETIME(fsp=6), "mysql")
MYSQL_BIGINT = Integer().with_variant(BigInteger, "mysql")
MYSQL_DOUBLE = Float().with_variant(DOUBLE(asdecimal=False), "mysql")


def now() -> datetime:
    return datetime.now(UTC)


class EgressProfile(Base):
    __tablename__ = "egress_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(30), default="host")
    config_json: Mapped[str] = mapped_column(Text, default="{}")


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    egress_profile_id: Mapped[int] = mapped_column(ForeignKey("egress_profiles.id"))


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)


class DeviceSession(Base):
    __tablename__ = "device_sessions"
    __table_args__ = (
        UniqueConstraint("user_id", "device_id"),
        CheckConstraint(
            "platform IN ('macos','windows')",
            name="ck_device_sessions_platform_supported",
        ),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(100))
    device_name: Mapped[str] = mapped_column(String(200))
    platform: Mapped[str] = mapped_column(String(20))
    refresh_token_hash: Mapped[str] = mapped_column(String(64))
    token_generation: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    last_seen_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    revoked_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)


class EdgeNode(Base):
    __tablename__ = "edge_nodes"
    __table_args__ = (
        CheckConstraint("platform IN ('linux','windows')", name="ck_edge_nodes_platform"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    endpoint: Mapped[str] = mapped_column(String(255), unique=True)
    shared_secret: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(20), default="linux", server_default="linux")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    maintenance_mode: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )
    health_status: Mapped[str] = mapped_column(
        String(20), default="unknown", server_default="unknown"
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active_connections: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_connections: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    accepted_connections: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    denied_connections: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    expected_public_ipv4: Mapped[str | None] = mapped_column(String(15), nullable=True)
    actual_public_ipv4: Mapped[str | None] = mapped_column(String(15), nullable=True)
    load_1m: Mapped[float | None] = mapped_column(MYSQL_DOUBLE, nullable=True)
    memory_total_bytes: Mapped[int | None] = mapped_column(MYSQL_BIGINT, nullable=True)
    memory_available_bytes: Mapped[int | None] = mapped_column(MYSQL_BIGINT, nullable=True)
    disk_total_bytes: Mapped[int | None] = mapped_column(MYSQL_BIGINT, nullable=True)
    disk_free_bytes: Mapped[int | None] = mapped_column(MYSQL_BIGINT, nullable=True)
    uptime_seconds: Mapped[float | None] = mapped_column(MYSQL_DOUBLE, nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)


class NodeEnrollment(Base):
    __tablename__ = "node_enrollments"
    __table_args__ = (
        Index(
            "uq_active_node_enrollment",
            "edge_node_id",
            unique=True,
            sqlite_where=expression.column("status").in_(
                ("pending", "claimed", "installing", "ready")
            ),
            postgresql_where=expression.column("status").in_(
                ("pending", "claimed", "installing", "ready")
            ),
        ).ddl_if(dialect=("sqlite", "postgresql")),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    edge_node_id: Mapped[int] = mapped_column(ForeignKey("edge_nodes.id"), index=True)
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    report_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    phase: Mapped[str | None] = mapped_column(String(20), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    claimed_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    claimed_public_ipv4: Mapped[str | None] = mapped_column(String(15), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(100), nullable=True)


class NodeRegistrationRequest(Base):
    __tablename__ = "node_registration_requests"
    __table_args__ = (
        CheckConstraint(
            "platform IN ('linux','windows')", name="ck_node_registration_requests_platform"
        ),
        Index(
            "uq_active_node_registration_machine",
            "machine_fingerprint",
            unique=True,
            sqlite_where=expression.column("status").in_(
                ("pending_proof", "pending_approval", "approved", "installing", "ready")
            ),
            postgresql_where=expression.column("status").in_(
                ("pending_proof", "pending_approval", "approved", "installing", "ready")
            ),
        ).ddl_if(dialect=("sqlite", "postgresql")),
        Index(
            "uq_active_node_registration_key",
            "public_key_fingerprint",
            unique=True,
            sqlite_where=expression.column("status").in_(
                ("pending_proof", "pending_approval", "approved", "installing", "ready")
            ),
            postgresql_where=expression.column("status").in_(
                ("pending_proof", "pending_approval", "approved", "installing", "ready")
            ),
        ).ddl_if(dialect=("sqlite", "postgresql")),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="pending_proof", index=True)
    public_key_pem: Mapped[str] = mapped_column(Text)
    public_key_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    machine_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reported_hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(20), default="linux", server_default="linux")
    actual_public_ipv4: Mapped[str] = mapped_column(String(15))
    os_name: Mapped[str] = mapped_column(String(100))
    cpu_count: Mapped[int] = mapped_column(Integer)
    memory_total_bytes: Mapped[int] = mapped_column(MYSQL_BIGINT)
    disk_total_bytes: Mapped[int] = mapped_column(MYSQL_BIGINT)
    agent_version: Mapped[str] = mapped_column(String(100))
    challenge_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registration_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    challenge_expires_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    proved_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)
    decided_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    edge_node_id: Mapped[int | None] = mapped_column(
        ForeignKey("edge_nodes.id"), nullable=True, index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    install_admin_ssh_key: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=expression.false()
    )


class UserEdgeNodeGrant(Base):
    __tablename__ = "user_edge_node_grants"
    __table_args__ = (UniqueConstraint("user_id", "edge_node_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    edge_node_id: Mapped[int] = mapped_column(ForeignKey("edge_nodes.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)


class EdgeCapability(Base):
    __tablename__ = "edge_capabilities"
    __table_args__ = (UniqueConstraint("edge_node_id", "name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    edge_node_id: Mapped[int] = mapped_column(ForeignKey("edge_nodes.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    config_json: Mapped[str] = mapped_column(Text, default="{}")


class ManagedStore(Base):
    __tablename__ = "managed_stores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(100), unique=True)
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    edge_node_id: Mapped[int] = mapped_column(ForeignKey("edge_nodes.id"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)


class StoreConnectionLease(Base):
    __tablename__ = "store_connection_leases"
    __table_args__ = (
        Index(
            "uq_active_store_user_device_lease",
            "store_id",
            "owner_user_id",
            "device_id",
            unique=True,
            sqlite_where=expression.column("status") == "active",
            postgresql_where=expression.column("status") == "active",
        ).ddl_if(dialect=("sqlite", "postgresql")),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("managed_stores.id"), index=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)
    disconnected_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME, nullable=True)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    profile_key: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="starting")
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)


class LocalHistoryEntry(Base):
    __tablename__ = "local_history_entries"
    __table_args__ = (UniqueConstraint("user_id", "url").ddl_if(dialect=("sqlite", "postgresql")),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(500), default="")
    last_visit_ms: Mapped[int] = mapped_column(MYSQL_BIGINT)
    visit_count: Mapped[int] = mapped_column(Integer, default=1)


class LocalTabSnapshot(Base):
    __tablename__ = "local_tab_snapshots"
    __table_args__ = (UniqueConstraint("user_id", "device_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(80))
    tabs_json: Mapped[str] = mapped_column(Text, default="[]")
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=now)
