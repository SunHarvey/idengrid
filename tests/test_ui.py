import re
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_member(client: TestClient, admin: str, username: str) -> dict:
    response = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": username, "password": "Member-password-123"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_workspace_page_uses_official_user_visible_branding(system):
    client, _ = system
    page = client.get("/")

    assert page.status_code == 200
    assert "<title>澜序 IdenGrid</title>" in page.text
    assert '<h1 id="loginTitle">欢迎登录澜序</h1>' in page.text
    assert '<span class="sidebar-wordmark">IdenGrid</span>' in page.text
    assert "多店铺固定出口浏览平台" in page.text
    assert page.text.count("澜序管理控制台") == 1
    assert "开放式云浏览器" not in page.text
    assert "fake://" not in page.text
    assert "vnc.html" not in page.text
    assert "WebRTC" not in page.text
    assert "/api/sessions/start" not in page.text


def test_openapi_metadata_uses_official_brand(system):
    client, _ = system

    schema = client.get("/openapi.json")

    assert schema.status_code == 200
    assert schema.json()["info"]["title"] == "IdenGrid 澜序"


def test_workspace_removes_remote_viewer_controls(system):
    client, _ = system
    page = client.get("/")

    assert 'id="viewer"' not in page.text
    assert 'id="startButton"' not in page.text
    assert "/viewer/" not in page.text
    assert "/api/sessions/" not in page.text
    assert "vnc.html" not in page.text


def test_web_removes_obsolete_local_store_runtime_surface(system):
    client, _ = system
    page = client.get("/")

    obsolete = [
        'id="localStoreDashboard"', 'id="refreshLocalButton"',
        'id="localStoreList"', "HERMES_LOCAL_SERVER", "复制启动命令",
        "下载配置", "localStoreCommand", "renderLocalStores",
        "downloadStoreConfig", "loadLocalStores", "api('/api/stores')",
    ]
    for marker in obsolete:
        assert marker not in page.text
    assert "edge_endpoint" not in page.text
    assert "shared_secret" not in page.text


def test_login_routes_admin_directly_and_members_to_client_notice(system):
    client, _ = system
    page = client.get("/").text

    assert 'id="adminDashboard"' in page
    assert 'id="memberNotice"' in page
    assert "请使用澜序 macOS 客户端" in page
    assert "if(me.role==='admin')" in page
    assert "showAdminConsole()" in page
    assert "showMemberNotice()" in page
    assert 'id="logoutButton"' in page
    assert 'id="memberLogoutButton"' in page
    assert 'id="workspaceNav"' not in page
    assert 'id="adminButton"' not in page
    assert 'id="closeAdminButton"' not in page


def test_admin_dashboard_has_complete_safe_store_node_and_audit_management(system):
    client, _ = system
    page = client.get("/")

    for label in ["概览", "用户", "店铺", "节点", "审计"]:
        assert label in page.text
    for element_id in [
        "adminDashboard",
        "overviewPanel",
        "usersPanel",
        "storesPanel",
        "nodesPanel",
        "auditPanel",
        "createStoreForm",
        "createNodeForm",
        "auditFilters",
    ]:
        assert f'id="{element_id}"' in page.text
    assert 'type="password"' in page.text
    assert "maintenance_mode" in page.text
    assert "active_lease" in page.text
    assert "/api/admin/stores" in page.text
    assert "/force-disconnect" in page.text
    assert "/api/admin/edge-nodes" in page.text
    assert "/api/admin/audit.csv" in page.text
    assert "/api/admin/users/${user.id}" in page.text
    assert "删除用户" in page.text
    assert "将立即撤销权限和登录状态" in page.text
    assert "/api/admin/users/${user.id}/password" in page.text
    assert "更新密码" in page.text
    assert "新密码（至少16位）" in page.text
    assert 'minlength="16"' in page.text
    assert "password.input.minLength=16" in page.text
    assert "function formatAuditTime" in page.text
    assert "Asia/Singapore" in page.text
    assert "event.event_label" in page.text
    assert "event.actor_username" in page.text
    assert "event.target_name" in page.text
    assert "function formatAuditDetails" in page.text
    assert 'value="15"' in page.text
    assert 'id="auditRefreshButton"' in page.text
    assert 'id="auditPreviousButton"' in page.text
    assert 'id="auditNextButton"' in page.text
    assert 'id="auditPageStatus"' in page.text
    assert "auditPage=0" in page.text
    assert "offset" in page.text
    assert "刷新最新信息" in page.text
    assert "confirm(" in page.text
    assert ".innerHTML" not in page.text
    assert "createElement" in page.text
    assert "textContent" in page.text
    assert "shared_secret" not in page.text
    assert "cloud video" not in page.text.lower()
    assert "video controls" not in page.text.lower()


def test_admin_console_has_consistent_page_layout_contracts(system):
    client, _ = system
    page = client.get("/").text

    for class_name in [
        "overview-page", "users-page", "stores-page", "nodes-page", "audit-page",
        "create-bar", "store-row", "audit-toolbar", "compact-toggle",
        "user-identity", "user-status", "node-grants", "password-section", "user-actions",
    ]:
        assert class_name in page
    assert "max-width:1600px" in page
    assert "min-height:46px" in page
    assert "width:20px" in page and "height:20px" in page
    assert "input[type=checkbox]" in page
    assert ".primary{" in page
    assert "button('保存'" in page and "className='primary'" in page
    assert "onboarding-panel" in page
    assert '<details class="onboarding-panel">' in page
    assert '<details class="onboarding-panel" open>' not in page


def test_store_management_is_fully_chinese_and_one_store_per_row(system):
    client, _ = system
    page = client.get("/").text

    for label in [
        "负责人",
        "未分配",
        "节点：",
        "公网 IP：",
        "当前无活动连接",
        "删除门店",
        "释放全部连接",
        "断开此连接",
    ]:
        assert label in page
    for english in [">Owner<", ">Unassigned<", "No active lease", "Force release", "Delete ${store.label}"]:
        assert english not in page
    assert "entity-row store-row" in page


def test_audit_known_codes_and_targets_are_localized(system):
    client, _ = system
    page = client.get("/").text

    assert "function auditEventLabel" in page
    assert "function auditTargetLabel" in page
    for marker in ["native.session.started", "native.session.ended", "managed_store", "device_session"]:
        assert marker in page
    for label in ["客户端会话已开始", "客户端会话已结束", "受管门店", "设备会话"]:
        assert label in page
    assert "auditEventLabel(event.event_type,event.event_label)" in page
    assert "auditTargetLabel(event.target_type)" in page


def test_all_bound_ids_exist_and_inline_javascript_parses(system, tmp_path):
    client, _ = system
    page = client.get("/").text
    script = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert script
    ids = re.search(r"const ids=\[(.*?)\];const el=", script.group(1), re.DOTALL)
    assert ids
    for element_id in re.findall(r"'([^']+)'", ids.group(1)):
        assert f'id="{element_id}"' in page, element_id
    js_file = tmp_path / "inline.js"
    js_file.write_text(script.group(1), encoding="utf-8")
    result = subprocess.run(
        ["node", "--check", str(js_file)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_admin_nodes_has_node_initiated_approval_flow(system):
    client, _ = system
    page = client.get("/")
    assert "接入新节点" in page.text
    assert 'id="genericInstallCommand"' in page.text
    assert 'id="sshInstallCommand"' in page.text
    assert 'id="registrationRequestList"' in page.text
    assert "/bootstrap/edge-install.sh" in page.text
    assert "--install-admin-ssh-key" in page.text
    assert "/api/admin/node-registration-requests" in page.text
    assert "expected.input.readOnly=true" in page.text
    assert "public_key_fingerprint" in page.text
    assert "machine_fingerprint" in page.text
    assert "等待管理员批准" in page.text
    assert "高级手动登记" in page.text
    assert 'id="createEnrollmentForm"' not in page.text
    assert 'id="enrollmentList"' not in page.text
    assert "/api/admin/edge-enrollments" not in page.text
    assert ".innerHTML" not in page.text


def test_users_and_nodes_use_one_entity_per_row_responsive_layout(system):
    client, _ = system
    page = client.get("/")

    assert "entity-list" in page.text
    assert "entity-row user-row" in page.text
    assert "entity-row node-row" in page.text
    assert "entity-main" in page.text
    assert "entity-fields" in page.text
    assert "entity-actions" in page.text
    assert (
        "grid-template-columns:minmax(180px,.8fr) minmax(260px,1.2fr) minmax(420px,2fr) auto"
        in page.text
    )
    assert "@media(max-width:900px)" in page.text


def test_node_metrics_are_formatted_for_humans(system):
    client, _ = system
    page = client.get("/")

    assert "function formatBytes" in page.text
    assert "function formatDuration" in page.text
    assert "function formatPercent" in page.text
    assert "公网 IP" in page.text
    assert "运行时间" in page.text
    assert "在线" in page.text
    assert "已隔离" in page.text
    assert "function resourceUsage" in page.text
    assert "内存使用" in page.text
    assert "磁盘使用" in page.text
    assert "max-width:1680px" in page.text
    assert "font-size:13px" in page.text
    assert "endpoint.input.readOnly=true" in page.text
    assert "节点访问地址（只读）" in page.text


def test_viewer_requires_short_lived_ticket_and_session_ownership(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    create_member(client, admin, "member-a")
    create_member(client, admin, "member-b")
    a = login(client, "member-a", "Member-password-123")
    b = login(client, "member-b", "Member-password-123")
    session = client.post("/api/sessions/start", headers=auth(a)).json()
    ticket = client.get(f"/api/sessions/{session['id']}/ticket", headers=auth(a)).json()["ticket"]

    assert client.get(f"/viewer/{session['id']}/").status_code == 401
    assert (
        client.post(
            f"/api/sessions/{session['id']}/viewer-session",
            headers=auth(b),
            json={"ticket": ticket},
        ).status_code
        == 404
    )
    accepted = client.post(
        f"/api/sessions/{session['id']}/viewer-session",
        headers=auth(a),
        json={"ticket": ticket},
    )
    assert accepted.status_code == 200
    assert "httponly" in accepted.headers["set-cookie"].lower()


def test_successful_refresh_rotation_is_not_audited_or_labeled() -> None:
    root = Path(__file__).parents[1]
    app_source = (root / "cloudbrowser" / "app.py").read_text()
    admin_page = (root / "cloudbrowser" / "templates" / "index.html").read_text()

    assert "native.refresh_rotated" not in app_source
    assert "native.refresh_rotated" not in admin_page
    assert "刷新令牌已轮换" not in admin_page
    assert "native.refresh_replayed" in app_source
    assert "native.refresh_replayed" in admin_page
