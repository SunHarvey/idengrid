from __future__ import annotations

import json
import os
from pathlib import Path

from .app import create_app
from .runner import PodmanBrowserRunner

DATA_DIR = Path(os.getenv("DATA_DIR", "/data/runtime-dev"))
ENVIRONMENT = os.getenv("IDENGRID_ENV", "development").lower()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'cloudbrowser.db'}")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be set to at least 32 characters")

admin_user = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
bootstrap = (admin_user, admin_password) if admin_user and admin_password else None
secure_cookies = os.getenv("COOKIE_SECURE", "true").lower() in {"1", "true", "yes", "on"}
public_origin = os.getenv("PUBLIC_ORIGIN")
if ENVIRONMENT == "production":
    if DATABASE_URL.startswith("sqlite:"):
        raise RuntimeError("Production DATABASE_URL must use an external relational database")
    if not public_origin or not public_origin.startswith("https://"):
        raise RuntimeError("Production PUBLIC_ORIGIN must be an HTTPS origin")


def load_json_config(variable: str) -> dict | None:
    configured = os.getenv(variable)
    if not configured:
        return None
    path = Path(configured)
    if path.stat().st_mode & 0o022:
        raise RuntimeError(f"{variable} must not be group or world writable")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise TypeError(f"{variable} must contain a JSON object")
    return value


bootstrap_topology = load_json_config("IDENGRID_BOOTSTRAP_FILE")
local_environment = load_json_config("IDENGRID_LOCAL_ENVIRONMENT_FILE")
admin_ssh_public_key_file = os.getenv(
    "ADMIN_SSH_PUBLIC_KEY_FILE", "/data/dist/hermes-admin-ssh.pub"
)
cloud_video_enabled = os.getenv("CLOUD_VIDEO_ENABLED", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

DATA_DIR.mkdir(parents=True, exist_ok=True)
app = create_app(
    database_url=DATABASE_URL,
    secret_key=SECRET_KEY,
    runner=PodmanBrowserRunner(DATA_DIR),
    bootstrap_admin=bootstrap,
    secure_cookies=secure_cookies,
    public_origin=public_origin,
    local_environment=local_environment,
    bootstrap_topology=bootstrap_topology,
    cloud_video_enabled=cloud_video_enabled,
    admin_ssh_public_key_file=admin_ssh_public_key_file,
)
