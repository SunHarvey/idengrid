from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner

DATA = Path("/data/runtime-cookie-live")
COOKIE_DB = DATA / "profiles" / "user-cookie" / "Default" / "Cookies"
QUERY = (
    "select host_key, name, creation_utc, expires_utc, length(encrypted_value) "
    "from cookies where host_key = ? and name = ?"
)
with sqlite3.connect(COOKIE_DB) as database:
    before = database.execute(QUERY, ("postman-echo.com", "cloudbrowser")).fetchone()
print(f"cookie_before_resume={before}")
assert before and before[4] > 0

runner = PodmanBrowserRunner(DATA)
session = runner.start(
    "resumeold",
    "user-cookie",
    {"kind": "host", "config": {"start_url": "https://example.com"}},
)
print(f"resume_status={runner.status('resumeold')} endpoint={session.endpoint}")
time.sleep(5)
runner.stop("resumeold")

with sqlite3.connect(COOKIE_DB) as database:
    after = database.execute(QUERY, ("postman-echo.com", "cloudbrowser")).fetchone()
print(f"cookie_after_resume={after}")
assert after == before
print("persistence_resume_result=PASS")
