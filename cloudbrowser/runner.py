from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .browser_control import CDPBrowserControl
from .security import NetworkPolicy


@dataclass
class RunnerSession:
    endpoint: str
    status: str = "running"


class BrowserRunner(Protocol):
    def start(self, session_id: str, profile_key: str, egress_profile: dict) -> RunnerSession: ...
    def stop(self, session_id: str) -> None: ...
    def status(self, session_id: str) -> str: ...
    def egress_ip(self, session_id: str) -> str: ...
    def browser_state(self, session_id: str) -> dict: ...
    def browser_new_tab(self, session_id: str, url: str) -> dict: ...
    def browser_activate(self, session_id: str, target_id: str) -> dict: ...
    def browser_close(self, session_id: str, target_id: str) -> dict: ...
    def browser_navigate(self, session_id: str, target_id: str, url: str) -> dict: ...
    def browser_history(self, session_id: str, target_id: str, delta: int) -> dict: ...
    def browser_reload(self, session_id: str, target_id: str) -> dict: ...


@dataclass
class FakeBrowserRunner:
    egress_ip_value: str = "203.0.113.10"
    _sessions: dict[str, RunnerSession] = field(default_factory=dict)
    _profiles: dict[str, dict[str, str]] = field(default_factory=dict)
    _session_profiles: dict[str, str] = field(default_factory=dict)
    _browser_tabs: dict[str, list[dict]] = field(default_factory=dict)
    _active_tabs: dict[str, str] = field(default_factory=dict)
    _reloads: dict[str, int] = field(default_factory=dict)

    def __init__(self, egress_ip: str = "203.0.113.10"):
        self.egress_ip_value = egress_ip
        self._sessions = {}
        self._profiles = {}
        self._session_profiles = {}
        self._browser_tabs = {}
        self._active_tabs = {}
        self._reloads = {}

    def start(self, session_id: str, profile_key: str, egress_profile: dict) -> RunnerSession:
        self._profiles.setdefault(profile_key, {})
        self._session_profiles[session_id] = profile_key
        result = RunnerSession(endpoint=f"fake://{session_id}")
        self._sessions[session_id] = result
        target_id = f"tab-{session_id[:8]}-1"
        self._browser_tabs[session_id] = [
            {
                "target_id": target_id,
                "title": "example.com",
                "url": "https://example.com",
                "loading": False,
                "history": ["https://example.com"],
                "history_index": 0,
            }
        ]
        self._active_tabs[session_id] = target_id
        return result

    def stop(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].status = "stopped"

    def status(self, session_id: str) -> str:
        return self._sessions.get(session_id, RunnerSession("", "stopped")).status

    def egress_ip(self, session_id: str) -> str:
        return self.egress_ip_value

    def profile_for(self, session_id: str) -> str:
        return self._session_profiles[session_id]

    def write_profile_marker(self, session_id: str, key: str, value: str) -> None:
        self._profiles[self.profile_for(session_id)][key] = value

    def read_profile_marker(self, session_id: str, key: str) -> str | None:
        return self._profiles[self.profile_for(session_id)].get(key)

    def _tab(self, session_id: str, target_id: str) -> dict:
        return next(tab for tab in self._browser_tabs[session_id] if tab["target_id"] == target_id)

    def browser_state(self, session_id: str) -> dict:
        active = self._active_tabs[session_id]
        tabs = []
        for item in self._browser_tabs[session_id]:
            index = item["history_index"]
            tabs.append(
                {
                    "target_id": item["target_id"],
                    "title": item["title"],
                    "url": item["url"],
                    "loading": item["loading"],
                    "can_go_back": index > 0,
                    "can_go_forward": index < len(item["history"]) - 1,
                    "active": item["target_id"] == active,
                }
            )
        return {"tabs": tabs, "active_target_id": active}

    def browser_new_tab(self, session_id: str, url: str) -> dict:
        target_id = f"tab-{session_id[:8]}-{len(self._browser_tabs[session_id]) + 1}"
        hostname = url.split("//", 1)[-1].split("/", 1)[0]
        self._browser_tabs[session_id].append(
            {
                "target_id": target_id,
                "title": hostname,
                "url": url,
                "loading": False,
                "history": [url],
                "history_index": 0,
            }
        )
        self._active_tabs[session_id] = target_id
        return self.browser_state(session_id)

    def browser_activate(self, session_id: str, target_id: str) -> dict:
        self._tab(session_id, target_id)
        self._active_tabs[session_id] = target_id
        return self.browser_state(session_id)

    def browser_close(self, session_id: str, target_id: str) -> dict:
        tabs = self._browser_tabs[session_id]
        if len(tabs) <= 1:
            from .browser_control import LastTabError

            raise LastTabError("The last browser tab cannot be closed")
        tabs.remove(self._tab(session_id, target_id))
        if self._active_tabs[session_id] == target_id:
            self._active_tabs[session_id] = tabs[-1]["target_id"]
        return self.browser_state(session_id)

    def browser_navigate(self, session_id: str, target_id: str, url: str) -> dict:
        tab = self._tab(session_id, target_id)
        tab["history"] = tab["history"][: tab["history_index"] + 1] + [url]
        tab["history_index"] += 1
        tab["url"] = url
        tab["title"] = url.split("//", 1)[-1].split("/", 1)[0]
        return self.browser_state(session_id)

    def browser_history(self, session_id: str, target_id: str, delta: int) -> dict:
        tab = self._tab(session_id, target_id)
        tab["history_index"] = max(0, min(len(tab["history"]) - 1, tab["history_index"] + delta))
        tab["url"] = tab["history"][tab["history_index"]]
        tab["title"] = tab["url"].split("//", 1)[-1].split("/", 1)[0]
        return self.browser_state(session_id)

    def browser_reload(self, session_id: str, target_id: str) -> dict:
        self._tab(session_id, target_id)
        self._reloads[target_id] = self._reloads.get(target_id, 0) + 1
        return self.browser_state(session_id)

    def reload_count(self, target_id: str) -> int:
        return self._reloads.get(target_id, 0)


@dataclass
class PodmanBrowserRunner:
    """Starts hardened, per-user Chromium/Selkies containers using Podman."""

    data_dir: Path
    image: str = "localhost/cloud-browser-webrtc:latest"
    _locks: dict[str, object] = field(default_factory=dict, init=False, repr=False)

    @staticmethod
    def _validate(value: str, kind: str) -> None:
        import re

        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}", value):
            raise ValueError(f"invalid {kind}")

    def _name(self, session_id: str) -> str:
        return f"cloud-browser-{session_id}"

    def build_start_command(
        self, session_id: str, profile_key: str, egress_profile: dict
    ) -> list[str]:
        self._validate(session_id, "session id")
        self._validate(profile_key, "profile key")
        if egress_profile.get("kind") not in {"host", "proxy"}:
            raise ValueError("unsupported egress profile")
        profile_dir = (self.data_dir / "profiles" / profile_key).resolve()
        root = (self.data_dir / "profiles").resolve()
        if root not in profile_dir.parents:
            raise ValueError("profile escapes data directory")
        command = [
            "podman",
            "run",
            "-d",
            f"--name={self._name(session_id)}",
            f"--label=cloudbrowser.session={session_id}",
            f"--label=cloudbrowser.profile={profile_key}",
            "--label=com.open-cloud-browser.video=true",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--memory=1536m",
            "--cpus=2",
            "--pids-limit=384",
            "--stop-timeout=20",
            "--network=slirp4netns:allow_host_loopback=false",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777",
            "--tmpfs=/run:rw,nosuid,nodev,size=32m,mode=0755",
            "-p",
            "127.0.0.1::8080",
            "-p",
            "127.0.0.1::9223",
            "-v",
            f"{profile_dir}:/home/ubuntu/profile:Z",
            "-e",
            "SELKIES_MODE=webrtc",
            "-e",
            "SELKIES_ENABLE_DUAL_MODE=true",
            "-e",
            "SELKIES_ENABLE_BASIC_AUTH=false",
        ]
        config = egress_profile.get("config", {})
        start_url = config.get("start_url")
        if start_url:
            if not NetworkPolicy().is_url_allowed(start_url):
                raise ValueError("start URL is blocked by network policy")
            command.extend(["-e", f"START_URL={start_url}"])
        proxy = config.get("proxy_url")
        if egress_profile.get("kind") == "proxy" and proxy:
            command.extend(["-e", f"EGRESS_PROXY={proxy}"])
        command.append(self.image)
        return command

    def cdp_endpoint(self, session_id: str) -> str:
        self._validate(session_id, "session id")
        endpoint = self._run(["podman", "port", self._name(session_id), "9223/tcp"])
        host, port_text = endpoint.rsplit(":", 1)
        if host != "127.0.0.1":
            raise RuntimeError("CDP port is not bound to loopback")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise RuntimeError("invalid CDP port")
        return f"http://127.0.0.1:{port}"

    def _open_app(self, session_id: str, url: str) -> None:
        self._run(
            [
                "podman",
                "exec",
                "--user=1000:1000",
                "--env=DISPLAY=:20",
                "--env=HOME=/home/ubuntu/profile/home",
                self._name(session_id),
                "chromium",
                "--user-data-dir=/home/ubuntu/profile",
                "--no-sandbox",
                "--test-type",
                "--no-first-run",
                "--no-default-browser-check",
                "--start-maximized",
                f"--app={url}",
            ],
            timeout=20,
        )

    def _browser(self, session_id: str) -> CDPBrowserControl:
        endpoint = self.cdp_endpoint(session_id)
        return CDPBrowserControl(endpoint, lambda url: self._open_app(session_id, url))

    def browser_state(self, session_id: str) -> dict:
        return self._browser(session_id).state()

    def browser_new_tab(self, session_id: str, url: str) -> dict:
        return self._browser(session_id).new_tab(url)

    def browser_activate(self, session_id: str, target_id: str) -> dict:
        return self._browser(session_id).activate(target_id)

    def browser_close(self, session_id: str, target_id: str) -> dict:
        return self._browser(session_id).close(target_id)

    def browser_navigate(self, session_id: str, target_id: str, url: str) -> dict:
        return self._browser(session_id).navigate(target_id, url)

    def browser_history(self, session_id: str, target_id: str, delta: int) -> dict:
        return self._browser(session_id).history(target_id, delta)

    def browser_reload(self, session_id: str, target_id: str) -> dict:
        return self._browser(session_id).reload(target_id)

    def remove_stale_chromium_locks(self, profile_dir: Path) -> None:
        for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            (profile_dir / name).unlink(missing_ok=True)

    def _run(self, command: list[str], timeout: int = 30) -> str:
        import subprocess

        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if completed.returncode:
            message = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"container command failed: {message[:500]}")
        return completed.stdout.strip()

    def start(self, session_id: str, profile_key: str, egress_profile: dict) -> RunnerSession:
        import fcntl
        import os
        import time

        command = self.build_start_command(session_id, profile_key, egress_profile)
        profile_dir = (self.data_dir / "profiles" / profile_key).resolve()
        profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(profile_dir, 1000, 1000)
        except PermissionError:
            pass
        lock_path = profile_dir / ".session.lock"
        lock = lock_path.open("a+")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock.close()
            raise RuntimeError("browser profile is already in use") from exc
        existing = self._run(
            ["podman", "ps", "-q", "--filter", f"label=cloudbrowser.profile={profile_key}"]
        )
        if existing:
            lock.close()
            raise RuntimeError("browser profile already has a running container")
        self.remove_stale_chromium_locks(profile_dir)
        self._run(["podman", "rm", "-f", self._name(session_id)]) if self._container_exists(
            session_id
        ) else None
        try:
            self._run(command, timeout=120)
            endpoint = self._run(["podman", "port", self._name(session_id), "8080/tcp"])
            host, port_text = endpoint.rsplit(":", 1)
            port = int(port_text)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    self._run(
                        [
                            "curl",
                            "-fsS",
                            "--max-time",
                            "1",
                            f"http://127.0.0.1:{port}/",
                        ],
                        timeout=2,
                    )
                    break
                except RuntimeError:
                    time.sleep(0.25)
            else:
                logs = self._run(["podman", "logs", self._name(session_id)])
                raise RuntimeError(f"Selkies did not become ready: {logs[-1000:]}")
            cdp_endpoint = self.cdp_endpoint(session_id)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    self._run(
                        [
                            "curl",
                            "-fsS",
                            "--max-time",
                            "1",
                            f"{cdp_endpoint}/json/version",
                        ],
                        timeout=2,
                    )
                    break
                except RuntimeError:
                    time.sleep(0.25)
            else:
                raise RuntimeError("Chromium control channel did not become ready")
        except Exception:
            with suppress(RuntimeError):
                self._run(["podman", "rm", "-f", self._name(session_id)])
            lock.close()
            raise
        self._locks[session_id] = lock
        return RunnerSession(endpoint=f"http://{host}:{port}")

    def _container_exists(self, session_id: str) -> bool:
        return bool(
            self._run(["podman", "ps", "-aq", "--filter", f"name=^{self._name(session_id)}$"])
        )

    def stop(self, session_id: str) -> None:
        self._validate(session_id, "session id")
        if self._container_exists(session_id):
            self._run(["podman", "stop", "--time", "20", self._name(session_id)], timeout=30)
            self._run(["podman", "rm", self._name(session_id)], timeout=10)
        lock = self._locks.pop(session_id, None)
        if lock:
            lock.close()

    def status(self, session_id: str) -> str:
        self._validate(session_id, "session id")
        if not self._container_exists(session_id):
            return "stopped"
        state = self._run(
            ["podman", "inspect", "--format", "{{.State.Status}}", self._name(session_id)]
        )
        return "running" if state == "running" else "error"

    def egress_ip(self, session_id: str) -> str:
        self._validate(session_id, "session id")
        return self._run(
            [
                "podman",
                "exec",
                self._name(session_id),
                "curl",
                "-fsS",
                "--max-time",
                "10",
                "https://api.ipify.org",
            ],
            timeout=15,
        )
