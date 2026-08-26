from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx
from sqlalchemy.orm import sessionmaker

from cloudbrowser.database import create_database_engine
from cloudbrowser.edge_health import EdgeHealthMonitor, migrate_edge_health_schema


def default_database_url() -> str:
    data_dir = Path(os.getenv("DATA_DIR", "/data/runtime-web"))
    return os.getenv("DATABASE_URL", f"sqlite:///{data_dir / 'cloudbrowser.db'}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe and persist central Edge health")
    parser.add_argument("--database-url", default=default_database_url())
    parser.add_argument(
        "--central-status-url",
        default=os.getenv("CENTRAL_EDGE_STATUS_URL", "http://127.0.0.1:8787/status"),
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    engine = create_database_engine(args.database_url)
    migrate_edge_health_schema(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with httpx.Client() as client:
        results = EdgeHealthMonitor(
            sessions,
            client=client,
            central_status_url=args.central_status_url,
            timeout_seconds=args.timeout,
        ).run_once()
    print(json.dumps(results, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
