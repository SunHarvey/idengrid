from __future__ import annotations

import time
from pathlib import Path

import httpx

from cloudbrowser.runner import PodmanBrowserRunner

DATA = Path("/data/runtime-concurrency")
runner = PodmanBrowserRunner(DATA)
sessions = []
configs = [
    ("triple01", "user-one", "https://postman-echo.com/get"),
    ("triple02", "user-two", "https://example.com"),
    ("triple03", "user-three", "https://www.iana.org/domains/reserved"),
]
try:
    for session_id, profile, url in configs:
        started = runner.start(session_id, profile, {"kind": "host", "config": {"start_url": url}})
        sessions.append(session_id)
        with httpx.Client(timeout=10) as client:
            viewer = client.get(f"{started.endpoint}/")
            viewer.raise_for_status()
            assert '<div id="root"></div>' in viewer.text
            status = client.get(f"{started.endpoint}/api/status")
            status.raise_for_status()
            assert status.json()["current_mode"] == "webrtc"
        print(f"{session_id}: status={runner.status(session_id)} endpoint={started.endpoint}")
    time.sleep(5)
    ips = [runner.egress_ip(session_id) for session_id in sessions]
    statuses = [runner.status(session_id) for session_id in sessions]
    print(f"statuses={statuses}")
    print(f"egress_ips={ips}")
    assert statuses == ["running", "running", "running"]
    assert len(set(ips)) == 1
finally:
    for session_id in reversed(sessions):
        runner.stop(session_id)
print("concurrency_result=PASS")
