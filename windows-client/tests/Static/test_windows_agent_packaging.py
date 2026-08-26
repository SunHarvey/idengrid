from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "native-client" / "agent-rs" / ".cargo" / "config.toml"


def test_windows_msvc_agent_uses_static_crt():
    text = CONFIG.read_text(encoding="utf-8")
    assert '[target.x86_64-pc-windows-msvc]' in text
    assert 'target-feature=+crt-static' in text


def test_windows_named_pipe_acl_is_current_user_and_system_only():
    root = ROOT / "native-client" / "agent-rs"
    security = (root / "src" / "windows_pipe_security.rs").read_text(encoding="utf-8")
    agent = (root / "src" / "agent.rs").read_text(encoding="utf-8")
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    assert "ConvertSidToStringSidW" in security
    assert "ConvertStringSecurityDescriptorToSecurityDescriptorW" in security
    assert 'D:P(A;;GA;;;SY)(A;;GA;;;{sid})' in security
    assert "create_with_security_attributes_raw" in security
    assert "create_secure_named_pipe" in agent
    assert "windows-sys" in cargo
