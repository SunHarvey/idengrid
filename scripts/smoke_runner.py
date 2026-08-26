from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner

runner = PodmanBrowserRunner(Path("/data/runtime"))
session = runner.start("smoke01", "user-smoke", {"kind": "host", "config": {}})
print(f"endpoint={session.endpoint}")
print(f"status={runner.status('smoke01')}")
print(f"egress={runner.egress_ip('smoke01')}")
