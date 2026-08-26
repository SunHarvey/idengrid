from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner

DATA = Path("/data/runtime-persistence-js-2")
COOKIE_DB = DATA / "profiles" / "user-persist" / "Default" / "Cookies"
HISTORY_DB = DATA / "profiles" / "user-persist" / "Default" / "History"
QUERY = (
    "select host_key, name, creation_utc, expires_utc, length(encrypted_value) "
    "from cookies where host_key = ? and name = ?"
)
HOST = "161.97.115.193.nip.io"
runner = PodmanBrowserRunner(DATA)

first = runner.start(
    "persist01",
    "user-persist",
    {"kind": "host", "config": {"start_url": f"http://{HOST}:18080/set"}},
)
print(f"first_status={runner.status('persist01')} endpoint={first.endpoint}")
time.sleep(35)
runner.stop("persist01")
with sqlite3.connect(COOKIE_DB) as database:
    before = database.execute(QUERY, (HOST, "cloudbrowser_js")).fetchone()
with sqlite3.connect(HISTORY_DB) as database:
    title = database.execute(
        "select title from urls where url like ? order by last_visit_time desc limit 1",
        (f"http://{HOST}:18080/%",),
    ).fetchone()
print(f"cookie_before_resume={before} page_title={title}")
assert title == ("persisted",)
assert before and before[3] > before[2] and before[4] > 0

second = runner.start(
    "persist02",
    "user-persist",
    {"kind": "host", "config": {"start_url": "https://example.com"}},
)
print(f"second_status={runner.status('persist02')} endpoint={second.endpoint}")
time.sleep(5)
runner.stop("persist02")
with sqlite3.connect(COOKIE_DB) as database:
    after = database.execute(QUERY, (HOST, "cloudbrowser_js")).fetchone()
print(f"cookie_after_resume={after}")
assert after == before
print("persistence_result=PASS")
