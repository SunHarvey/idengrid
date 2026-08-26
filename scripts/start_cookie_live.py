import time
from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner

runner = PodmanBrowserRunner(Path("/data/runtime-cookie-live"))
session = runner.start(
    "cookielive",
    "user-cookie",
    {
        "kind": "host",
        "config": {"start_url": "https://postman-echo.com/cookies/set?cloudbrowser=persisted"},
    },
)
print(session.endpoint)
time.sleep(15)
print(runner.status("cookielive"))
