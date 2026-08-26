from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from urllib.parse import quote, quote_plus

import httpx
from websockets.sync.client import connect

from .security import NetworkPolicy


class BrowserControlError(RuntimeError):
    pass


class BrowserTargetNotFound(BrowserControlError):
    pass


class LastTabError(BrowserControlError):
    pass


def normalize_address_input(value: str) -> str:
    text = value.strip()
    if not text:
        return "https://www.google.com/"
    lowered = text.lower()
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*):", lowered)
    explicit_scheme = bool(
        scheme_match
        and (
            scheme_match.group(1) in {"http", "https"}
            or ("." not in scheme_match.group(1) and scheme_match.group(1) != "localhost")
        )
    )
    if explicit_scheme:
        candidate = text
    elif " " not in text and ("." in text or text.startswith("localhost")):
        candidate = f"https://{text}"
    else:
        candidate = f"https://www.google.com/search?q={quote_plus(text)}"
    if not NetworkPolicy().is_url_allowed(candidate):
        raise ValueError("Address is blocked by network policy")
    return candidate


class CDPBrowserControl:
    def __init__(
        self,
        endpoint: str,
        open_app: Callable[[str], None],
        timeout: float = 8.0,
    ):
        if not re.fullmatch(r"http://127\.0\.0\.1:\d{1,5}", endpoint):
            raise BrowserControlError("CDP endpoint is not loopback")
        self.endpoint = endpoint
        self.open_app = open_app
        self.timeout = timeout

    def _request(self, path: str, method: str = "GET") -> httpx.Response:
        try:
            response = httpx.request(method, f"{self.endpoint}{path}", timeout=self.timeout)
            response.raise_for_status()
            return response
        except httpx.HTTPError as exc:
            raise BrowserControlError("Chromium control endpoint unavailable") from exc

    def _json(self, path: str, method: str = "GET") -> object:
        try:
            return self._request(path, method).json()
        except ValueError as exc:
            raise BrowserControlError("Invalid Chromium control response") from exc

    def _targets(self) -> list[dict]:
        rows = self._json("/json/list")
        if not isinstance(rows, list):
            raise BrowserControlError("Invalid Chromium target response")
        return [
            row
            for row in rows
            if isinstance(row, dict)
            and row.get("type") == "page"
            and isinstance(row.get("id"), str)
            and isinstance(row.get("webSocketDebuggerUrl"), str)
        ]

    def _target(self, target_id: str) -> dict:
        if not re.fullmatch(r"[A-F0-9]{32}", target_id):
            raise BrowserTargetNotFound("Browser tab not found")
        target = next((row for row in self._targets() if row["id"] == target_id), None)
        if not target:
            raise BrowserTargetNotFound("Browser tab not found")
        return target

    def _commands(self, websocket_url: str, commands: list[tuple[str, dict]]) -> list[dict]:
        results: dict[int, dict] = {}
        try:
            with connect(websocket_url, open_timeout=self.timeout, close_timeout=1) as socket:
                for command_id, (method, params) in enumerate(commands, 1):
                    socket.send(
                        json.dumps(
                            {"id": command_id, "method": method, "params": params},
                            separators=(",", ":"),
                        )
                    )
                deadline = time.monotonic() + self.timeout
                while len(results) < len(commands) and time.monotonic() < deadline:
                    message = json.loads(socket.recv(timeout=max(0.1, deadline - time.monotonic())))
                    command_id = message.get("id")
                    if command_id in range(1, len(commands) + 1):
                        if "error" in message:
                            raise BrowserControlError("Chromium rejected browser command")
                        results[command_id] = message.get("result", {})
        except BrowserControlError:
            raise
        except Exception as exc:
            raise BrowserControlError("Chromium control connection failed") from exc
        if len(results) != len(commands):
            raise BrowserControlError("Chromium control command timed out")
        return [results[index] for index in range(1, len(commands) + 1)]

    def _target_commands(self, target_id: str, commands: list[tuple[str, dict]]) -> list[dict]:
        target = self._target(target_id)
        return self._commands(target["webSocketDebuggerUrl"], commands)

    def _browser_commands(self, commands: list[tuple[str, dict]]) -> list[dict]:
        version = self._json("/json/version")
        if not isinstance(version, dict) or not isinstance(
            version.get("webSocketDebuggerUrl"), str
        ):
            raise BrowserControlError("Chromium browser endpoint unavailable")
        return self._commands(version["webSocketDebuggerUrl"], commands)

    def _maximize(self, target_id: str) -> None:
        window = self._browser_commands([("Browser.getWindowForTarget", {"targetId": target_id})])[
            0
        ]
        window_id = window.get("windowId")
        if not isinstance(window_id, int):
            raise BrowserControlError("Chromium window not found")
        self._browser_commands(
            [
                (
                    "Browser.setWindowBounds",
                    {"windowId": window_id, "bounds": {"windowState": "maximized"}},
                )
            ]
        )

    def _wait_for_url(self, target_id: str, expected: str, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            target = next((row for row in self._targets() if row["id"] == target_id), None)
            if target and target.get("url") == expected:
                return
            time.sleep(0.05)

    def state(self) -> dict:
        tabs = []
        active_target_id = None
        for target in self._targets():
            target_id = target["id"]
            runtime, history = self._target_commands(
                target_id,
                [
                    (
                        "Runtime.evaluate",
                        {
                            "expression": "({focus:document.hasFocus(),loading:document.readyState!=='complete'})",
                            "returnByValue": True,
                        },
                    ),
                    ("Page.getNavigationHistory", {}),
                ],
            )
            value = runtime.get("result", {}).get("value", {})
            current_index = int(history.get("currentIndex", 0))
            entries = history.get("entries", [])
            focused = bool(value.get("focus"))
            if focused:
                active_target_id = target_id
            tabs.append(
                {
                    "target_id": target_id,
                    "title": target.get("title") or "New tab",
                    "url": target.get("url") or "about:blank",
                    "loading": bool(value.get("loading")),
                    "can_go_back": current_index > 0,
                    "can_go_forward": current_index < len(entries) - 1,
                    "active": focused,
                }
            )
        if tabs and not active_target_id:
            active_target_id = tabs[0]["target_id"]
            tabs[0]["active"] = True
        return {"tabs": tabs, "active_target_id": active_target_id}

    def new_tab(self, url: str) -> dict:
        created = self._browser_commands(
            [("Target.createTarget", {"url": url, "background": False})]
        )[0]
        target_id = created.get("targetId")
        if not isinstance(target_id, str) or not re.fullmatch(r"[A-F0-9]{32}", target_id):
            raise BrowserControlError("Chromium did not create a browser tab")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if any(row["id"] == target_id for row in self._targets()):
                break
            time.sleep(0.05)
        else:
            raise BrowserControlError("Chromium browser tab did not become ready")
        return self.activate(target_id)

    def activate(self, target_id: str) -> dict:
        self._target(target_id)
        self._request(f"/json/activate/{quote(target_id, safe='')}")
        return self.state()

    def close(self, target_id: str) -> dict:
        targets = self._targets()
        self._target(target_id)
        if len(targets) <= 1:
            raise LastTabError("The last browser tab cannot be closed")
        self._request(f"/json/close/{quote(target_id, safe='')}")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline and any(
            row["id"] == target_id for row in self._targets()
        ):
            time.sleep(0.05)
        state = self.state()
        if state["active_target_id"]:
            self.activate(state["active_target_id"])
            state = self.state()
        return state

    def navigate(self, target_id: str, url: str) -> dict:
        self._target_commands(target_id, [("Page.navigate", {"url": url})])
        self._wait_for_url(target_id, url)
        return self.state()

    def history(self, target_id: str, delta: int) -> dict:
        history = self._target_commands(target_id, [("Page.getNavigationHistory", {})])[0]
        entries = history.get("entries", [])
        index = int(history.get("currentIndex", 0)) + delta
        if 0 <= index < len(entries):
            entry_id = entries[index].get("id")
            self._target_commands(
                target_id, [("Page.navigateToHistoryEntry", {"entryId": entry_id})]
            )
        return self.state()

    def reload(self, target_id: str) -> dict:
        self._target_commands(target_id, [("Page.reload", {"ignoreCache": False})])
        return self.state()
