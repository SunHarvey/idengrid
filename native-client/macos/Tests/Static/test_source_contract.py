import json
import plistlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = ROOT.parent / "release"
SRC = ROOT / "Sources" / "IdenGridApp"
BRAND = ROOT / "Resources" / "Brand"


def all_text():
    return "\n".join(
        p.read_text(errors="ignore")
        for p in ROOT.rglob("*")
        if p.is_file() and p.suffix in {".swift", ".sh", ".json", ".plist", ".yml", ".yaml"}
    )


def test_structure_and_native_stack():
    required = [
        ROOT / "Package.swift",
        SRC / "IdenGridApp.swift",
        SRC / "APIClient.swift",
        SRC / "KeychainStore.swift",
        SRC / "StoreViewModel.swift",
        SRC / "StoreProcessManager.swift",
        SRC / "ContentView.swift",
    ]
    assert all(p.is_file() for p in required)
    text = "\n".join(p.read_text(errors="ignore") for p in SRC.glob("*.swift"))
    assert "URLSession" in text and "Security" in text and "WindowGroup" in text
    assert "MenuBarExtra" not in text
    assert "python" not in text.lower() and "tkinter" not in text.lower()


def test_api_origin_is_loaded_from_signed_bundle_configuration():
    config = (SRC / "ClientConfiguration.swift").read_text()
    app = (SRC / "IdenGridApp.swift").read_text()
    build = (REL / "scripts/build-arm64.sh").read_text()
    assert 'forResource: "client-config"' in config
    assert 'case apiBaseURL = "api_base_url"' in config
    assert "ClientConfiguration.load()" in app
    assert "IDENGRID_API_BASE_URL" not in app
    assert "IDENGRID_API_BASE_URL" in build
    assert "client-config.json" in build


def test_security_and_process_contracts():
    text = (
        "\n".join(p.read_text(errors="ignore") for p in SRC.glob("*.swift"))
        + "\n"
        + "\n".join(p.read_text(errors="ignore") for p in (REL / "scripts").glob("*.sh"))
    )
    assert "kSecClassGenericPassword" in text
    assert "refreshToken" in text and "deviceSessionID" in text
    keychain = (SRC / "KeychainStore.swift").read_text()
    assert "let refreshToken: String" in keychain and "let deviceSessionID: String" in keychain
    assert "chmod(paths.config.path, 0o600)" in text
    assert "IdenGrid Browser.app" in text and "idengrid-agent" in text
    assert "--user-data-dir" in text and "--proxy-server" in text and "--load-extension" in text
    assert "/Applications/Google Chrome" not in text and "google chrome" not in text.lower()
    manager = (SRC / "StoreProcessManager.swift").read_text()
    assert "declaredLegacy" in text
    assert "moveItem(at: paths.profile" not in manager
    assert "moveItem(at: existingLegacy" not in manager
    assert "Hermes Local Browser/Stores/store-" in (SRC / "StorePaths.swift").read_text()
    assert "unix" in text.lower() and "status" in text.lower()


def test_downloads_stay_in_app_support_without_protected_directory_lookup():
    source = "\n".join(p.read_text(errors="ignore") for p in SRC.glob("*.swift"))
    paths = (SRC / "StorePaths.swift").read_text()
    assert ".downloadsDirectory" not in source
    assert "downloadsRoot" not in source
    assert 'root.appendingPathComponent("Downloads", isDirectory: true)' in paths


def test_chinese_ux_contract():
    text = (
        (SRC / "ContentView.swift").read_text()
        + (SRC / "StoreViewModel.swift").read_text()
        + (SRC / "Models.swift").read_text()
    )
    for phrase in [
        "登录",
        "用户名",
        "密码",
        "搜索店铺",
        "启动",
        "关闭",
        "退出全部",
        "正在连接",
        "运行中",
        "启动失败",
    ]:
        assert phrase in text


def test_arm64_and_platform_contract():
    package = (ROOT / "Package.swift").read_text()
    build = (REL / "scripts/build-arm64.sh").read_text()
    assert ".macOS(.v13)" in package
    assert "ARCHS=arm64" in build and "ONLY_ACTIVE_ARCH=YES" in build
    assert "uname -m" in build


def test_manifest_is_pinned_and_fetch_guarded():
    manifest = json.loads((REL / "chromium-manifest.json").read_text())
    assert manifest["schemaVersion"] == 1 and manifest["architecture"] == "arm64"
    assert manifest["revision"].isdigit()
    assert manifest["url"].startswith("https://commondatastorage.googleapis.com/")
    assert len(manifest["sha256"]) == 64 and set(manifest["sha256"]) != {"0"}
    assert manifest["archiveRoot"] == "chrome-mac/Chromium.app"
    script = (REL / "scripts/fetch-chromium.sh").read_text()
    assert "sha256" in script and "arm64" in script and "uname -m" in script
    assert "SOURCE_APP" in script and "IdenGrid Browser.app" in script


def test_plist_and_release_contract():
    with (ROOT / "Resources/Info.plist").open("rb") as f:
        info = plistlib.load(f)
    assert info["LSMinimumSystemVersion"] == "13.0"
    assert info["LSArchitecturePriority"] == ["arm64"]
    assert "SUFeedURL" in info and "SUPublicEDKey" in info
    assert info["SUFeedURL"] == "https://api.example.com/updates/macos-arm64/appcast.xml"
    assert "SPARKLE_PUBLIC_ED_KEY" in (REL / "scripts/build-arm64.sh").read_text()
    release_text = "\n".join(p.read_text(errors="ignore") for p in REL.rglob("*") if p.is_file())
    assert "notarytool" in release_text and "stapler" in release_text and "hdiutil" in release_text
    assert "spctl" in release_text and "codesign" in release_text
    assert "SBOM" in release_text or "sbom" in release_text


def test_no_embedded_secrets_or_fake_dmg():
    text = all_text()
    forbidden = [
        r"AKIA[0-9A-Z]{16}",
        r"BEGIN (RSA |EC )?PRIVATE KEY",
        r"apple-id\s*=\s*[^$]",
        r"password\s*=\s*['\"][^'\"]+",
    ]
    assert not any(re.search(p, text, re.IGNORECASE) for p in forbidden)
    assert not list(ROOT.parent.rglob("*.dmg"))


def test_multidevice_disconnect_binds_exact_preflight_lease_and_device():
    api = (SRC / "APIClient.swift").read_text()
    models = (SRC / "Models.swift").read_text()
    view_model = (SRC / "StoreViewModel.swift").read_text()
    assert "struct StoreDisconnectRequest" in models
    assert 'case leaseId = "lease_id"' in models
    assert 'case deviceId = "device_id"' in models
    assert "leaseId: String" in api and "deviceId: String" in api
    assert "body: StoreDisconnectRequest(" in api
    assert "let preflight = try await api.preflight" in view_model
    assert "leaseId: preflight.leaseId" in view_model
    assert "deviceId: deviceID" in view_model


def test_backend_and_rust_protocol_paths_are_exact():
    api = (SRC / "APIClient.swift").read_text()
    models = (SRC / "Models.swift").read_text()
    manager = (SRC / "StoreProcessManager.swift").read_text()
    app = (SRC / "IdenGridApp.swift").read_text()
    content = (SRC / "ContentView.swift").read_text()
    for path in ["api/native/login", "api/native/refresh", "api/native/stores", "preflight"]:
        assert path in api
    assert "api/stores/\\(storeID)/disconnect" in api
    assert "await api.disconnect" in (SRC / "StoreViewModel.swift").read_text()
    assert "v1/native" not in api
    for field in ["username", "deviceId", "deviceName", "platform"]:
        assert field in models
    for field in [
        "centralURL",
        "nativeAccessToken",
        "storeID",
        "deviceID",
        "controlSocketPath",
        "controlCapability",
        "localPort",
    ]:
        assert field in manager
    assert '\\"capability\\"' in manager and '\\"command\\"' in manager
    assert "GET /v1/status HTTP" not in manager
    assert "socks5://" in models
    assert "api.ipify.org" in manager
    assert "expectedPublicIPv4" in manager
    assert "ClientConfiguration.load()" in app
    assert "IDENGRID_API_BASE_URL" not in app
    assert "邮箱" not in content and "用户名" in content


def test_apple_silicon_source_verifier_accepts_command_line_tools_sdk():
    verifier = (REL / "scripts/verify-on-apple-silicon.sh").read_text()
    assert "xcrun --sdk macosx --show-sdk-path" in verifier
    assert "command -v swift" in verifier
    assert "command -v xcodebuild" not in verifier


def test_swift_contract_tests_need_no_xcode_test_framework():
    tests = "\n".join(
        path.read_text() for path in (ROOT / "Tests/Contract").glob("*") if path.is_file()
    )
    assert "import Testing" not in tests
    assert "import XCTest" not in tests
    package = (ROOT / "Package.swift").read_text()
    assert "swiftlang/swift-testing" not in package
    assert "swiftc" in tests
    assert "Models.swift" in tests and "StorePaths.swift" in tests
    assert "Tests/Contract/run.sh" in (REL / "scripts/verify-on-apple-silicon.sh").read_text()
    assert (
        "swift build -c release --arch arm64"
        in (REL / "scripts/verify-on-apple-silicon.sh").read_text()
    )


def test_unix_socket_callbacks_use_sendable_state_object():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    client = (SRC / "UnixSocketClient.swift").read_text()
    assert "Task.detached" in manager
    assert "UnixSocketClient.request" in manager
    assert "AF_UNIX" in client and "SOCK_STREAM" in client
    assert "firstIndex(of: 0x0A)" in client
    assert "NWConnection" not in manager
    contract = (ROOT / "Tests/Contract/run.sh").read_text()
    assert "UnixSocketClient.swift" in contract
    assert "unix_socket_server.py" in contract
    assert "@main" in (ROOT / "Tests/Contract/unix_socket_main.swift").read_text()


def test_start_button_is_disabled_for_every_transitional_state():
    models = (SRC / "Models.swift").read_text()
    view = (SRC / "ContentView.swift").read_text()
    assert "var isLaunchInProgress" in models
    assert ".isLaunchInProgress" in view
    assert "@ObservedObject private var processes" in view
    assert "_processes = ObservedObject" in view


def test_agent_logs_are_persisted_per_store_with_private_permissions():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    assert 'appendingPathComponent("agent.log")' in manager
    assert "standardError = logHandle" in manager
    assert "standardOutput = logHandle" in manager
    assert "chmod(logURL.path, 0o600)" in manager


def test_latency_line_and_refresh_contract():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    model = (SRC / "StoreViewModel.swift").read_text()
    view = (SRC / "ContentView.swift").read_text()
    models = (SRC / "Models.swift").read_text()
    assert "edgeLatencies" in manager
    assert ".seconds(2)" in manager
    assert ".seconds(30)" in model
    assert ".seconds(15)" not in model
    assert "StoreLatencyLine.text" in view
    assert 'Text("状态：\\(store.healthStatus)")' not in view
    for phrase in ["测量中", "不稳定", "已过期", "未测量"]:
        assert phrase in models
    for forbidden in ["节点参考", "本机实测", "约15秒更新", "次样本"]:
        assert forbidden not in view
    assert "sampleCount" not in view
    assert "edge_latency_ms" not in models


def test_agent_hot_token_update_contract():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    models = (SRC / "Models.swift").read_text()
    assert "updateAccessTokenForRunningAgents" in manager
    assert "AgentControlPayload.updateToken" in manager
    assert "AgentTokenUpdateResponse" in manager
    assert '"update_token"' in models
    assert '"native_access_token"' in models
    assert "JSONEncoder" in models
    assert "failedStoreIDs" in manager
    hot_update = manager[manager.index("func updateAccessTokenForRunningAgents") :]
    hot_update = hot_update[: hot_update.index("\n    private func")]
    assert "process.arguments" not in hot_update
    assert "print(" not in manager and "NSLog(" not in manager


def test_access_token_scheduler_lifecycle_contract():
    model = (SRC / "StoreViewModel.swift").read_text()
    models = (SRC / "Models.swift").read_text()
    assert "AccessTokenRefreshSchedule.delay" in model
    assert "accessExpiresAt" in model
    assert "accessTokenRefreshTask" in model
    assert "refreshAccessTokenIfNeeded" in model
    assert "updateAccessTokenForRunningAgents" in model
    assert "failedStoreIDs.forEach { processes.closeAfterTokenUpdateFailure(storeID: $0) }" in model
    assert model.count("startAccessTokenRefreshScheduler()") >= 3
    assert "cancelAccessTokenRefreshScheduler()" in model
    assert "deinit" not in model
    assert "defaultMargin: TimeInterval = 120" in models
    assert "minimumDelay: TimeInterval = 5" in models
    assert "max(minimumDelay" in models
    assert "initialRetryDelay: TimeInterval = 30" in models
    assert "maximumRetryDelay: TimeInterval = 300" in models
    assert "retryDelay(attempt:" in models
    assert "APIError.server" in model and "status == 401" in model and "status == 403" in model
    assert "authorization: String? = nil" in (SRC / "APIClient.swift").read_text()
    assert model.index("try vault.save(") < model.index("accessToken = session.accessToken")
    vault = (SRC / "KeychainStore.swift").read_text()
    assert "SecItemUpdate" in vault
    assert vault.index("SecItemUpdate") < vault.index("SecItemAdd")
    assert "sessionGeneration" in model
    assert model.count("guard generation == sessionGeneration") >= 5
    assert "sessionGeneration += 1" in model
    assert "closeAfterTokenUpdateFailure" in model
    assert "let refreshedToken = self.accessToken" in model
    signout = model[model.index("func signOut() async") :]
    assert signout.index("isAuthenticated = false") < signout.index("await api.logout")
    assert signout.index("accessToken = nil") < signout.index("await api.logout")
    assert signout.index("try? vault.clear()") < signout.index("await api.logout")


def test_management_window_uses_larger_readable_controls():
    view = (SRC / "ContentView.swift").read_text()
    assert ".controlSize(.large)" in view
    assert ".font(.title2)" in view
    assert view.count(".font(.title3)") >= 4
    assert "minWidth: model.isAuthenticated ? 960 : 0" in view
    assert "minHeight: model.isAuthenticated ? 620 : 0" in view


def test_dev_build_always_rebuilds_agent_after_protocol_changes():
    script = (REL / "scripts/build-dev-arm64.sh").read_text()
    build_command = "cargo build --locked --release --target aarch64-apple-darwin"
    assert build_command in script
    assert 'if [[ ! -x "$AGENT" ]]' not in script
    assert script.index(build_command) < script.index(
        'export IDENGRID_AGENT_BINARY="$AGENT"'
    )


def test_local_development_app_build_is_adhoc_and_separate_from_release():
    script = (REL / "scripts/build-dev-arm64.sh").read_text()
    assert "build-arm64.sh" in script
    assert "DEVELOPER_ID_APPLICATION=-" in script
    assert "sign-nested.sh" in script
    assert "codesign --verify --deep --strict" in script
    assert "notarytool" not in script and "hdiutil" not in script
    assert "IdenGrid-dev.app" in script
    assert "IDGDevelopmentBuild" in script
    assert "Refusing to replace a running development app" in script


def test_development_build_does_not_touch_keychain():
    app = (SRC / "IdenGridApp.swift").read_text()
    vault = (SRC / "KeychainStore.swift").read_text()
    assert "IDGDevelopmentBuild" in app
    assert "EphemeralCredentialVault" in app
    assert "final class EphemeralCredentialVault" in vault


def test_app_bundle_main_binary_has_framework_rpath_before_signing():
    script = (REL / "scripts/build-arm64.sh").read_text()
    assert "install_name_tool" in script
    assert "@executable_path/../Frameworks" in script
    assert script.index("install_name_tool") < script.index('echo "$APP"')


def test_per_store_visual_identity_extension_contract():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    paths = (SRC / "StorePaths.swift").read_text()
    identity = (SRC / "StoreVisualIdentity.swift").read_text()
    manifest = json.loads((ROOT / "Resources/Extension/manifest.json").read_text())
    assert "extensionDirectory" in paths and 'appendingPathComponent("Extension"' in paths
    assert "prepareStoreExtension" in manager
    assert "copyItem" in manager and "identity.json" in manager and ".atomic" in manager
    assert ".Extension-" in manager and "replaceItemAt" in manager
    assert "--load-extension=\\(paths.extensionDirectory.path)" in manager
    assert "--disable-extensions-except=\\(paths.extensionDirectory.path)" in manager
    assert "Bundle.main.resourceURL" in manager
    assert set(re.findall(r'case \w+ = "([^"]+)"', identity)) >= {
        "store_name",
        "short_label",
        "node_name",
        "fixed_ip",
    }
    assert manifest["manifest_version"] == 3
    assert manifest["action"]["default_popup"] == "popup.html"
    matches = manifest["content_scripts"][0]["matches"]
    assert matches == ["http://*/*", "https://*/*"]
    assert "web_accessible_resources" not in manifest
    content = (ROOT / "Resources/Extension/content.js").read_text()
    worker = (ROOT / "Resources/Extension/worker.js").read_text()
    assert "chrome.runtime.sendMessage" in content
    assert "chrome.runtime.onMessage.addListener" in worker
    assert 'message.type !== "get-store-identity"' in worker


def test_identity_artifacts_have_no_secret_or_network_surface():
    extension = ROOT / "Resources/Extension"
    manager = (SRC / "StoreProcessManager.swift").read_text()
    identity_sources = (
        (SRC / "StoreVisualIdentity.swift").read_text()
        + "\n"
        + "\n".join(
            p.read_text(errors="ignore")
            for p in extension.glob("*")
            if p.is_file() and p.name != "manifest.json"
        )
    )
    forbidden = [
        "access_token",
        "refresh_token",
        "nativeAccessToken",
        "controlCapability",
        "Cookie",
        "edge_endpoint",
        "Edge endpoint",
        "XMLHttpRequest",
        "WebSocket",
        "sendBeacon",
        "chrome.tabs",
        "page content",
    ]
    for term in forbidden:
        assert term.lower() not in identity_sources.lower()
    assert "fetch(" in identity_sources
    assert 'chrome.runtime.getURL("identity.json")' in identity_sources
    assert "http://" not in identity_sources and "https://" not in identity_sources
    assert "document.head || document.documentElement" in identity_sources
    assert "observe(document.documentElement" not in identity_sources
    assert "activateIgnoringOtherApps" not in manager


def test_running_store_activation_remains_available_in_management_window():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    content = (SRC / "ContentView.swift").read_text()
    assert "func activate(storeID: String)" in manager
    assert "NSRunningApplication(processIdentifier:" in manager
    assert ".activate(options:" in manager
    assert "func isRunning(storeID: String)" in manager
    assert 'Button("打开")' in content and "processes.activate(storeID: store.id)" in content
    assert "StoreVisualIdentity" in content and "Circle()" in content
    assert 'Button("关闭")' in content
    assert 'Button("退出应用")' in content


def test_visual_identity_contract_dictionary_cast_is_parenthesized():
    contract = (ROOT / "Tests/Contract/main.swift").read_text()
    assert "(try JSONSerialization.jsonObject(with: data) as! [String: Any]).keys" in contract
    assert "as! [String: Any].keys" not in contract


def png_dimensions(path):
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def test_production_brand_resources_are_symbol_only_and_exact_dimensions():
    expected = {
        "idengrid-32.png": (32, 32),
        "idengrid-64.png": (64, 64),
        "idengrid-128.png": (128, 128),
        "idengrid-256.png": (256, 256),
        "idengrid-512.png": (512, 512),
        "idengrid-1024.png": (1024, 1024),
        "idengrid-mono-dark-512.png": (512, 512),
        "idengrid-mono-light-512.png": (512, 512),
    }
    assert {path.name for path in BRAND.glob("*.png")} == set(expected)
    for name, dimensions in expected.items():
        assert png_dimensions(BRAND / name) == dimensions
    assert {path.name for path in BRAND.glob("*.svg")} == {
        "idengrid-symbol.svg",
        "idengrid-symbol-mono-dark.svg",
        "idengrid-symbol-mono-light.svg",
    }
    for path in BRAND.glob("*.svg"):
        svg = path.read_text().lower()
        assert "<text" not in svg and "idengrid-logo-ai-concept" not in svg
    assert not any("lockup" in path.name or "concept" in path.name for path in BRAND.iterdir())


def test_brand_tokens_and_safe_bundled_png_fallback_contract():
    contract = (SRC / "BrandContract.swift").read_text()
    ui = (SRC / "BrandUI.swift").read_text()
    for color in ["0B1739", "315CFF", "28C7B7", "10182B", "66738B", "F4F7FB", "FFFFFF"]:
        assert color in contract
    assert "Bundle.main.url(forResource:" in ui
    assert "NSImage(contentsOf:" in ui
    assert "Image(systemName:" in ui
    assert "BrandSymbolImage" in ui and "BrandPrimaryButtonStyle" in ui
    assert "BrandHeaderButtonStyle" in ui
    assert "menuBarSymbol" not in contract
    assert "MenuBarBrandSymbol" not in ui


def test_webrtc_is_forced_through_proxy_or_disabled():
    manager = (SRC / "StoreProcessManager.swift").read_text()
    manifest = json.loads((ROOT / "Resources/Extension/manifest.json").read_text())
    worker = (ROOT / "Resources/Extension/worker.js").read_text()
    privacy = (ROOT / "Resources/Extension/privacy.js").read_text()
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in manager
    assert "--force-webrtc-ip-handling-policy" not in manager
    assert "privacy" in manifest["permissions"]
    assert 'importScripts("identity-utils.js", "privacy.js")' in worker
    assert "IdenGridPrivacy.apply()" in worker
    assert "webRTCIPHandlingPolicy" in privacy
    assert "disable_non_proxied_udp" in privacy
    assert "webRTCMultipleRoutesEnabled" not in privacy
    assert "webRTCNonProxiedUdpEnabled" not in privacy


def test_branded_views_keep_existing_actions_and_wide_management_window():
    view = (SRC / "ContentView.swift").read_text()
    ui = (SRC / "BrandUI.swift").read_text()
    model = (SRC / "StoreViewModel.swift").read_text()
    for phrase in ["澜序", "IDENGRID CLOUD BROWSER", "IdenGrid", "BrandSymbolImage"]:
        assert phrase in view
    for action in [
        "await model.login()",
        "model.applySearch()",
        "await model.listStores()",
        "model.processes.quitAll()",
        "await model.signOut()",
        "await model.launch(store)",
        "model.close(store)",
        "processes.activate(storeID: store.id)",
    ]:
        assert action in view
    assert "minWidth: model.isAuthenticated ? 960 : 0" in view
    assert "minHeight: model.isAuthenticated ? 620 : 0" in view
    assert "环境独立，协作从容" in view
    assert "身份有界，协作有序" not in view
    assert view.count("BrandSymbolImage(asset: .appSymbol)") >= 2
    assert "BrandSymbolImage(asset: .inverseSymbol)" not in view
    assert "@State private var showsPassword = false" in view
    assert 'TextField("密码", text: $model.password)' in view
    assert 'SecureField("密码", text: $model.password)' in view
    assert 'Image(systemName: showsPassword ? "eye.slash" : "eye")' in view
    assert "showsPassword.toggle()" in view
    assert "密码（不会保存）" not in view
    assert view.count('Button("退出应用")') >= 2
    assert view.count("model.processes.quitAll()") >= 1
    assert view.count("NSApp.terminate(nil)") >= 2
    assert view.count(".buttonStyle(BrandHeaderButtonStyle())") == 4
    assert ".font(.system(size: 33, weight: .bold))" in view
    assert ".font(.system(size: 16))" in view
    assert "VStack(spacing: 12)" in view
    assert view.count(".brandLoginField(") == 2
    assert "height: 50" in ui
    assert "BrandPalette.blue" in ui and "isFocused" in ui
    login_field = ui[ui.index("private struct BrandLoginFieldModifier") :]
    login_field = login_field[: login_field.index("extension View")]
    assert ".foregroundStyle(BrandPalette.ink)" in login_field
    assert "BrandStoreCloseButtonStyle" in ui
    assert ".buttonStyle(BrandStoreCloseButtonStyle())" in view
    search = view[view.index('TextField("搜索店铺"') :]
    search = search[: search.index("List(model.stores)")]
    assert ".foregroundStyle(BrandPalette.ink)" in search
    assert ".padding(.top, 24)" in view
    assert ".padding(.top, 20)" in view
    assert "LoginPresentation.buttonTitle(isBusy: model.isBusy)" in view
    assert "BrandLoginButtonStyle" in view
    assert "LoginPresentation.inlineStatus" in view
    assert "LoginPresentation.toastMessage" in view
    assert "LoginPresentation.loginFailureMessage(statusCode: status)" in model
    assert '"用户名或者密码错误"' in (SRC / "BrandContract.swift").read_text()
    login = model[model.index("func login() async") : model.index("private func apply")]
    assert "error.localizedDescription" not in login
    assert "loginToast" in view
    assert ".padding(.horizontal, 16)" in view
    assert ".frame(maxWidth: 464)" in view


def test_app_exit_waits_for_browser_and_agent_without_lifecycle_expansion():
    app = (SRC / "IdenGridApp.swift").read_text()
    manager = (SRC / "StoreProcessManager.swift").read_text()
    model = (SRC / "StoreViewModel.swift").read_text()
    delegate = (SRC / "AppTerminationDelegate.swift").read_text()
    view = (SRC / "ContentView.swift").read_text()

    assert "@NSApplicationDelegateAdaptor(AppTerminationDelegate.self)" in app
    assert "prepareForApplicationTermination" in app
    assert "applicationShouldTerminate" in delegate
    assert ".terminateLater" in delegate
    assert "reply(toApplicationShouldTerminate:" in delegate
    assert "shutdownHandler?() ?? false" in delegate

    assert "func quitAllAndWait() async -> Bool" in manager
    assert "NSRunningApplication(processIdentifier:" in manager
    assert "await waitForExit" in manager
    shutdown = manager[manager.index("func quitAllAndWait()") :]
    assert shutdown.index("stopBrowserAndWait") < shutdown.index("stopAgentAndWait")
    assert "func prepareForApplicationTermination() async -> Bool" in model

    assert view.count("NSApp.terminate(nil)") >= 2
    for match in re.finditer(r'Button\("退出应用"\)\s*\{', view):
        assert "model.processes.quitAll()" not in view[match.start() : match.start() + 180]
    assert "browserProcessIDs" not in manager
    assert "shutdownBarrier" not in manager
    assert "launchGeneration" not in manager

    assert "try removeAgentConfig(paths.config)" in manager
    assert "private func removeAgentConfig" in manager
    assert "fileExists(atPath: config.path)" in manager
    assert (
        "BrandPalette.navy" in view and "BrandPalette.blue" in view and "BrandPalette.aqua" in view
    )


def test_app_identity_icons_and_brand_resource_build_order():
    with (ROOT / "Resources/Info.plist").open("rb") as f:
        info = plistlib.load(f)
    assert info["CFBundleDisplayName"] == "澜序"
    assert info["CFBundleExecutable"] == "IdenGrid"
    assert info["CFBundleIdentifier"] == "com.idengrid.client"
    assert info["CFBundleIconFile"] == "AppIcon.icns"
    build = (REL / "scripts/build-arm64.sh").read_text()
    icon_builder = (REL / "scripts/build-app-icon.sh").read_text()
    assert 'ditto "$MACOS/Resources/Brand" "$APP/Contents/Resources/Brand"' in build
    assert "build-app-icon.sh" in build
    assert 'AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"' in build
    assert "IdenGrid Browser.app/Contents/Resources/app.icns" not in build
    assert 'plutil -replace CFBundleIconFile -string "app.icns"' not in build
    assert "iconutil -c icns" in icon_builder and "sips -z 16 16" in icon_builder
    assert "require_square_png" in icon_builder
    for size in [32, 64, 128, 256, 512, 1024]:
        assert f"idengrid-{size}.png" in icon_builder
    assert "lockup" not in icon_builder.lower() and "concept" not in icon_builder.lower()
    dev = (REL / "scripts/build-dev-arm64.sh").read_text()
    assert 'CFBundleDisplayName -string "澜序 Dev"' in dev
    assert build.index("build-app-icon.sh") < build.index('echo "$APP"')
    assert dev.index("CFBundleDisplayName") < dev.index("sign-nested.sh")


def test_menu_bar_extra_is_not_present():
    app = (SRC / "IdenGridApp.swift").read_text()
    assert "MenuBarExtra" not in app
    assert "MenuBarBrandSymbol" not in app
