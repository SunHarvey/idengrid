from __future__ import annotations

import ipaddress
import logging
import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.orm import Session

from .models import EdgeNode, NodeEnrollment, NodeRegistrationRequest

logger = logging.getLogger(__name__)

_EDGE_HEALTH_COLUMNS = {
    "maintenance_mode": "BOOLEAN NOT NULL DEFAULT 0",
    "health_status": "VARCHAR(20) NOT NULL DEFAULT 'unknown'",
    "last_seen_at": "DATETIME",
    "latency_ms": "INTEGER",
    "active_connections": "INTEGER NOT NULL DEFAULT 0",
    "max_connections": "INTEGER NOT NULL DEFAULT 0",
    "accepted_connections": "INTEGER NOT NULL DEFAULT 0",
    "denied_connections": "INTEGER NOT NULL DEFAULT 0",
    "expected_public_ipv4": "VARCHAR(15)",
    "actual_public_ipv4": "VARCHAR(15)",
    "load_1m": "FLOAT",
    "memory_total_bytes": "INTEGER",
    "memory_available_bytes": "INTEGER",
    "disk_total_bytes": "INTEGER",
    "disk_free_bytes": "INTEGER",
    "uptime_seconds": "FLOAT",
    "agent_version": "VARCHAR(100)",
    "last_error": "TEXT",
}
_METRIC_FIELDS = (
    "active_connections",
    "max_connections",
    "accepted_connections",
    "denied_connections",
)
_STATUS_FIELDS = (
    *_METRIC_FIELDS,
    "actual_public_ipv4",
    "load_1m",
    "memory_total_bytes",
    "memory_available_bytes",
    "disk_total_bytes",
    "disk_free_bytes",
    "uptime_seconds",
    "agent_version",
)


class EdgeProbeError(RuntimeError):
    """A sanitized edge probe failure safe to persist and log."""


def migrate_edge_health_schema(engine: Engine) -> None:
    """Add EdgeNode health columns to an existing SQLite database."""
    if engine.dialect.name != "sqlite" or not inspect(engine).has_table("edge_nodes"):
        return
    existing = {column["name"] for column in inspect(engine).get_columns("edge_nodes")}
    with engine.begin() as connection:
        for name, definition in _EDGE_HEALTH_COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE edge_nodes ADD COLUMN {name} {definition}"))


class EdgeHealthMonitor:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        client: httpx.Client | None = None,
        central_node_name: str = "sg-browser",
        central_status_url: str = "http://127.0.0.1:8787/status",
        timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        timer: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
        sample_count: int = 5,
        min_success: int = 3,
        sample_interval_seconds: float = 1.0,
    ) -> None:
        if sample_count < 3 or not 3 <= min_success <= sample_count:
            raise ValueError("sample_count and min_success must define a valid quorum")
        if sample_interval_seconds < 0:
            raise ValueError("sample_interval_seconds must be non-negative")
        self._session_factory = session_factory
        self._client = client or httpx.Client()
        self._central_node_name = central_node_name
        self._central_status_url = central_status_url
        self._timeout_seconds = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._timer = timer or time.perf_counter
        self._sleeper = sleeper or time.sleep
        self._sample_count = sample_count
        self._min_success = min_success
        self._sample_interval_seconds = sample_interval_seconds

    def run_once(self) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        with self._session_factory() as db:
            nodes = db.scalars(
                select(EdgeNode).where(EdgeNode.enabled.is_(True)).order_by(EdgeNode.id)
            ).all()
            for node in nodes:
                result = self._probe(node)
                effective_status = (
                    "maintenance" if node.maintenance_mode else result["health_status"]
                )
                results.append({"node": node.name, "health_status": effective_status})
                if "latency_ms" in result:
                    node.health_status = effective_status
                    node.last_seen_at = self._clock()
                    node.latency_ms = result["latency_ms"]
                    for field in _STATUS_FIELDS:
                        setattr(node, field, result[field])
                    node.last_error = None
                else:
                    node.health_status = effective_status
                    node.latency_ms = None
                    node.last_error = result["last_error"]
                enrollment = db.scalar(
                    select(NodeEnrollment).where(
                        NodeEnrollment.edge_node_id == node.id,
                        NodeEnrollment.status.in_(["ready", "installing", "claimed", "failed"]),
                    )
                )
                if enrollment and effective_status == "online":
                    enrollment.status = "online"
                    enrollment.phase = "ready"
                    enrollment.updated_at = self._clock()
                    enrollment.report_token_hash = None
                    enrollment.last_error = None
                elif enrollment and effective_status in {"offline", "quarantined"}:
                    enrollment.status = "failed"
                    enrollment.phase = "failed"
                    enrollment.updated_at = self._clock()
                    enrollment.last_error = f"monitor marked node {effective_status}"
                registration = db.scalar(
                    select(NodeRegistrationRequest).where(
                        NodeRegistrationRequest.edge_node_id == node.id,
                        NodeRegistrationRequest.status.in_(
                            ["installing", "ready", "failed", "online"]
                        ),
                    )
                )
                if registration and effective_status == "online":
                    registration.status = "online"
                    registration.updated_at = self._clock()
                    registration.last_error = None
                elif registration and effective_status in {"offline", "quarantined"}:
                    registration.status = "failed"
                    registration.updated_at = self._clock()
                    registration.last_error = f"monitor marked node {effective_status}"
            db.commit()
        return results

    def _probe(self, node: EdgeNode) -> dict[str, Any]:
        url = (
            self._central_status_url
            if node.name == self._central_node_name
            else f"{node.endpoint.rstrip('/')}/status"
        )
        samples: list[dict[str, Any]] = []
        errors: list[str] = []
        fatal_errors: list[str] = []
        for sample_index in range(self._sample_count):
            sample = self._probe_sample(url, node.name)
            if "last_error" in sample:
                errors.append(sample["last_error"])
                if sample["fatal"]:
                    fatal_errors.append(sample["last_error"])
            else:
                samples.append(sample)
            if sample_index < self._sample_count - 1:
                self._sleeper(self._sample_interval_seconds)

        if fatal_errors:
            error = fatal_errors[0]
            logger.warning("Edge health check failed for %s: %s", node.name, error)
            return {"health_status": "offline", "last_error": error}
        if len(samples) < self._min_success:
            error = errors[-1] if errors else "health probe request failed"
            logger.warning("Edge health check failed for %s: %s", node.name, error)
            return {"health_status": "offline", "last_error": error}

        if len({sample["payload"]["public_ipv4"] for sample in samples}) != 1:
            error = "health probe public IPv4 inconsistent between samples"
            logger.warning("Edge health check failed for %s: %s", node.name, error)
            return {"health_status": "quarantined", "last_error": error}

        # Once every successful sample agrees on identity and IP, the final valid payload wins.
        payload = samples[-1]["payload"]
        successful_durations = sorted(sample["duration_seconds"] for sample in samples)
        trimmed_durations = successful_durations[1:-1]
        latency_ms = max(
            0,
            round(sum(trimmed_durations) / len(trimmed_durations) * 1000),
        )
        return {
            "health_status": self._health_status(payload, node.expected_public_ipv4),
            "latency_ms": latency_ms,
            **{
                field: payload["public_ipv4"] if field == "actual_public_ipv4" else payload[field]
                for field in _STATUS_FIELDS
            },
        }

    def _probe_sample(self, url: str, expected_node: str) -> dict[str, Any]:
        started = self._timer()
        try:
            response = self._client.get(url, timeout=self._timeout_seconds)
            response.raise_for_status()
            payload = response.json()
            self._validate_payload(payload, expected_node)
        except EdgeProbeError as exc:
            error = str(exc)
            fatal = True
        except httpx.HTTPError:
            error = "health probe request failed"
            fatal = False
        except (TypeError, ValueError):
            error = "health probe returned invalid JSON"
            fatal = True
        else:
            return {
                "payload": payload,
                "duration_seconds": max(0.0, self._timer() - started),
            }
        return {"last_error": error, "fatal": fatal}

    @staticmethod
    def _validate_payload(payload: Any, expected_node: str) -> None:
        if not isinstance(payload, dict):
            raise EdgeProbeError("health probe returned invalid status")
        if payload.get("node") != expected_node:
            raise EdgeProbeError("health probe node identity mismatch")
        if any(
            not isinstance(payload.get(field), int)
            or isinstance(payload.get(field), bool)
            or payload[field] < 0
            for field in _METRIC_FIELDS
        ):
            raise EdgeProbeError("health probe returned invalid metrics")
        if (
            payload["max_connections"] <= 0
            or payload["active_connections"] > payload["max_connections"]
        ):
            raise EdgeProbeError("health probe returned invalid metrics")
        try:
            address = ipaddress.ip_address(payload.get("public_ipv4"))
        except (TypeError, ValueError) as exc:
            raise EdgeProbeError("health probe returned invalid public IPv4") from exc
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise EdgeProbeError("health probe returned invalid public IPv4")
        integer_resources = (
            "memory_total_bytes",
            "memory_available_bytes",
            "disk_total_bytes",
            "disk_free_bytes",
        )
        if any(
            not isinstance(payload.get(field), int)
            or isinstance(payload.get(field), bool)
            or payload[field] < 0
            for field in integer_resources
        ):
            raise EdgeProbeError("health probe returned invalid resources")
        if (
            payload["memory_total_bytes"] <= 0
            or payload["memory_available_bytes"] > payload["memory_total_bytes"]
            or payload["disk_total_bytes"] <= 0
            or payload["disk_free_bytes"] > payload["disk_total_bytes"]
        ):
            raise EdgeProbeError("health probe returned invalid resources")
        for field in ("load_1m", "uptime_seconds"):
            value = payload.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise EdgeProbeError("health probe returned invalid resources")
        version = payload.get("agent_version")
        if not isinstance(version, str) or not version or len(version) > 100:
            raise EdgeProbeError("health probe returned invalid agent version")

    @staticmethod
    def _health_status(payload: dict[str, Any], expected_public_ipv4: str | None) -> str:
        if expected_public_ipv4 and payload["public_ipv4"] != expected_public_ipv4:
            return "quarantined"
        if (
            payload["memory_available_bytes"] < 128 * 1024 * 1024
            or payload["disk_free_bytes"] < 2 * 1024 * 1024 * 1024
            or payload["active_connections"] * 5 >= payload["max_connections"] * 4
        ):
            return "degraded"
        return "online"
