from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url


def create_database_engine(database_url: str, **kwargs: Any) -> Engine:
    """Create a sync engine with dialect-safe connection defaults."""
    url = make_url(database_url)
    connect_args = dict(kwargs.pop("connect_args", {}))

    if url.get_backend_name() == "sqlite":
        connect_args.setdefault("check_same_thread", False)
    elif url.get_backend_name() == "mysql":
        url = url.update_query_dict(
            {"charset": "utf8mb4", "init_command": "SET time_zone = '+00:00'"}
        )

    return create_engine(url, connect_args=connect_args, **kwargs)
