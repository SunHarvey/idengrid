import re
from pathlib import Path

BRAND_ASSETS = {
    "favicon.svg": "image/svg+xml",
    "idengrid-32.png": "image/png",
    "idengrid-64.png": "image/png",
    "idengrid-lockup-cn-primary.svg": "image/svg+xml",
    "idengrid-symbol.svg": "image/svg+xml",
    "design-tokens.css": "text/css",
    "site.webmanifest": "application/manifest+json",
}


def test_brand_assets_are_served_with_types_and_immutable_cache(system):
    client, _ = system

    for filename, media_type in BRAND_ASSETS.items():
        response = client.get(f"/static/brand/{filename}")
        assert response.status_code == 200, filename
        assert response.headers["content-type"].startswith(media_type), filename
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content


def test_brand_asset_route_rejects_unknown_nested_and_traversal_paths(system):
    client, _ = system

    assert client.get("/static/brand/not-an-asset.svg").status_code == 404
    assert client.get("/static/brand/nested/favicon.svg").status_code == 404
    assert client.get("/static/brand/%2e%2e/templates/index.html").status_code == 404
    assert client.get("/static/brand/%2e%2e%2fdesign-tokens.css").status_code == 404


def test_manifest_uses_only_local_brand_icons(system):
    client, _ = system

    manifest = client.get("/static/brand/site.webmanifest").json()
    assert manifest["name"] == "澜序 IdenGrid"
    assert manifest["start_url"] == "/"
    assert manifest["theme_color"] == "#0B1739"
    assert manifest["icons"] == [
        {
            "src": "/static/brand/idengrid-32.png",
            "sizes": "32x32",
            "type": "image/png",
        },
        {
            "src": "/static/brand/idengrid-64.png",
            "sizes": "64x64",
            "type": "image/png",
        },
    ]


def test_workspace_page_links_brand_metadata_and_has_no_network_assets(system):
    client, _ = system
    page = client.get("/")

    assert page.status_code == 200
    assert "<title>澜序 IdenGrid</title>" in page.text
    assert 'href="/static/brand/favicon.svg"' in page.text
    assert 'href="/static/brand/idengrid-32.png"' in page.text
    assert 'href="/static/brand/idengrid-64.png"' in page.text
    assert 'href="/static/brand/site.webmanifest"' in page.text
    assert 'href="/static/brand/design-tokens.css"' in page.text
    assert not re.search(r'(?:src|href)=["\']https?://', page.text)
    assert "@import" not in page.text


def test_login_and_management_console_follow_brand_layout_contract(system):
    client, _ = system
    page = client.get("/").text

    assert 'class="login-shell"' in page
    assert 'class="login-brand"' in page
    assert 'src="/static/brand/idengrid-lockup-cn-primary.svg"' in page
    assert 'alt="澜序 IdenGrid Cloud Browser"' in page
    assert 'class="app-sidebar"' in page
    assert 'src="/static/brand/idengrid-symbol.svg"' in page
    assert 'idengrid-symbol-mono-light.svg' not in page
    assert 'alt=""' in page
    assert 'class="sidebar-wordmark"' in page
    assert '>IdenGrid<' in page
    assert 'class="app-content"' in page
    assert "--panel:var(--idengrid-white)" in page
    assert "--accent:var(--idengrid-blue)" in page
    assert "background:var(--idengrid-navy)" in page
    assert "grid-template-columns:248px minmax(0,1fr)" in page
    assert "max-width:1680px" in page
    assert "@media(max-width:760px)" in page
    assert "grid-template-columns:72px minmax(0,1fr)" in page
    assert ".sidebar-wordmark{display:none}" in page
    assert 'id="contentTitle"' in page and 'id="contentSubtitle"' in page
    assert "function showAdminConsole()" in page
    assert "function showMemberNotice()" in page
    assert "stat('用户',users.length)" in page
    assert "stat('店铺',stores.length)" in page
    assert "stat('活动租约'" in page
    assert "stat('在线节点'" in page
    assert '.sidebar-action[aria-current="page"]' in page
    assert ".password-section button{min-width:108px}" in page
    assert ".node-row .entity-fields.form-grid{grid-template-columns:minmax(210px,1.2fr) minmax(145px,.8fr)}" in page
    assert ".node-row .compact-toggle{min-height:24px}" in page
    assert "setStatus('已更新')" not in page
    assert "container-type:inline-size" in page
    assert "container-name:entity-list" in page
    assert "gap:clamp(8px,1vw,14px)" in page
    assert 'grid-template-areas:"identity status grants password actions"' in page
    assert 'grid-template-areas:"main meta fields actions"' in page
    assert "@container entity-list (max-width:980px)" in page
    assert "@container entity-list (max-width:650px)" in page
    assert "repeat(auto-fit,minmax(min(100%,190px),1fr))" in page


def test_brand_copy_contains_only_required_deterministic_assets():
    brand_dir = Path(__file__).parents[1] / "cloudbrowser" / "static" / "brand"

    assert {path.name for path in brand_dir.iterdir() if path.is_file()} == set(BRAND_ASSETS)
    assert not any("concept" in path.name.lower() or "sheet" in path.name.lower() for path in brand_dir.iterdir())
