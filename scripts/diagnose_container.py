import subprocess
from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner

runner = PodmanBrowserRunner(Path("/data/runtime-cookie-live"))
command = runner.build_start_command(
    "diag01", "user-cookie", {"kind": "host", "config": {"start_url": "https://example.com"}}
)
print(" ".join(command))
result = subprocess.run(command, text=True, capture_output=True, check=False)
print(result.returncode, result.stdout, result.stderr)
