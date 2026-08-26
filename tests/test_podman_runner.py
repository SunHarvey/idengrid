from pathlib import Path

from cloudbrowser.runner import PodmanBrowserRunner


def test_podman_start_command_enforces_container_security_and_limits(tmp_path: Path):
    runner = PodmanBrowserRunner(data_dir=tmp_path, image="cloud-browser:test")

    command = runner.build_start_command("abc123", "user-7", {"kind": "host", "config": {}})
    joined = " ".join(command)

    assert command[:3] == ["podman", "run", "-d"]
    assert "--privileged" not in command
    assert "--cap-drop=all" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--read-only" in command
    assert "--memory=1536m" in command
    assert "--cpus=2" in command
    assert "--pids-limit=384" in command
    assert "--network=slirp4netns:allow_host_loopback=false" in command
    assert "/var/run/docker.sock" not in joined
    assert f"{tmp_path}/profiles/user-7:/home/ubuntu/profile:Z" in command
    assert "127.0.0.1::8080" in command
    assert "127.0.0.1::9223" in command
    assert "SELKIES_MODE=webrtc" in command
    assert "SELKIES_ENABLE_DUAL_MODE=true" in command
    assert "SELKIES_ENABLE_BASIC_AUTH=false" in command
    assert command[-1] == "cloud-browser:test"


def test_cdp_endpoint_is_recovered_from_loopback_podman_mapping(tmp_path: Path):
    class PortRunner(PodmanBrowserRunner):
        def _run(self, command: list[str], timeout: int = 30) -> str:
            assert command == ["podman", "port", "cloud-browser-abc123", "9223/tcp"]
            return "127.0.0.1:45678"

    runner = PortRunner(data_dir=tmp_path)

    assert runner.cdp_endpoint("abc123") == "http://127.0.0.1:45678"


def test_profile_key_rejects_path_traversal(tmp_path: Path):
    runner = PodmanBrowserRunner(data_dir=tmp_path)

    for unsafe in ("../admin", "user/7", "", "user 7"):
        try:
            runner.build_start_command("abc", unsafe, {"kind": "host", "config": {}})
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe profile key accepted: {unsafe}")


def test_runner_accepts_public_start_url_and_rejects_internal_url(tmp_path: Path):
    runner = PodmanBrowserRunner(data_dir=tmp_path)
    command = runner.build_start_command(
        "abc", "user-7", {"kind": "host", "config": {"start_url": "https://example.com/path"}}
    )
    assert "START_URL=https://example.com/path" in command

    for url in ("http://127.0.0.1:8000", "http://169.254.169.254/latest/meta-data"):
        try:
            runner.build_start_command(
                "abc", "user-7", {"kind": "host", "config": {"start_url": url}}
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"internal start URL accepted: {url}")


def test_stale_chromium_singleton_links_are_removed_only_after_exclusive_ownership(tmp_path: Path):
    runner = PodmanBrowserRunner(data_dir=tmp_path)
    profile = tmp_path / "profiles" / "user-7"
    profile.mkdir(parents=True)
    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
        (profile / name).symlink_to(f"stale-{name}")
    keep = profile / "Preferences"
    keep.write_text("keep")

    runner.remove_stale_chromium_locks(profile)

    assert all(
        not (profile / name).exists()
        for name in ("SingletonLock", "SingletonSocket", "SingletonCookie")
    )
    assert keep.read_text() == "keep"


def test_stop_is_graceful_before_container_removal(tmp_path: Path):
    class RecordingRunner(PodmanBrowserRunner):
        def __post_init__(self):
            self.commands = []

        def _container_exists(self, session_id: str) -> bool:
            return True

        def _run(self, command: list[str], timeout: int = 30) -> str:
            self.commands.append(command)
            return ""

    runner = RecordingRunner(data_dir=tmp_path)
    runner.commands = []
    runner.stop("abc")

    assert runner.commands == [
        ["podman", "stop", "--time", "20", "cloud-browser-abc"],
        ["podman", "rm", "cloud-browser-abc"],
    ]


def test_session_id_rejects_shell_or_option_injection(tmp_path: Path):
    runner = PodmanBrowserRunner(data_dir=tmp_path)

    for unsafe in ("--replace", "a;rm", "../x", ""):
        try:
            runner.build_start_command(unsafe, "user-7", {"kind": "host", "config": {}})
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe session id accepted: {unsafe}")
