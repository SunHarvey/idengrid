from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_api_runtime_disables_request_path_access_logs():
    script = (ROOT / "scripts" / "web_up.sh").read_text()
    service = (ROOT / "deploy" / "idengrid-control.service").read_text()
    assert "--no-access-log" in script
    assert "--no-access-log" in service


def test_caddy_does_not_persist_https_paths_or_queries():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text()
    assert "caddy-access.log" not in caddy
    assert "\n\tlog {" not in caddy


def test_web_startup_has_no_retired_cloud_video_build_path():
    script = (ROOT / "scripts" / "web_up.sh").read_text()
    assert "podman" not in script
    assert "browser-webrtc" not in script
    assert "CLOUD_VIDEO_ENABLED must remain false" in script


def test_video_is_disabled_in_public_configuration_templates():
    assert "CLOUD_VIDEO_ENABLED=false" in (ROOT / ".env.example").read_text()
    assert "CLOUD_VIDEO_ENABLED=false" in (ROOT / ".env.development.example").read_text()
    assert "CLOUD_VIDEO_ENABLED=false" in (
        ROOT / "config" / "control.env.example"
    ).read_text()
