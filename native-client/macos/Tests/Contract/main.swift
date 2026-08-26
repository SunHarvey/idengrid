import Foundation

private func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

private func sampleStore(id: String = "7", legacyProfilePath: String? = nil) -> StoreDTO {
    StoreDTO(
        id: id,
        name: "新加坡01",
        nodeName: "edge-sg01",
        status: "available",
        healthStatus: "online",
        maintenanceMode: false,
        enabled: true,
        expectedPublicIPv4: "198.51.100.20",
        actualPublicIPv4: "198.51.100.20",
        latencyMs: 18,
        activeConnections: 1,
        maxConnections: 256,
        legacyProfilePath: legacyProfilePath
    )
}

private func testSessionDTO() throws {
    let data = Data(
        """
        {"access_token":"access","refresh_token":"session.secret","device_session_id":"session","access_expires_at":"2026-08-19T10:30:00+00:00","refresh_expires_at":"2026-09-18T10:15:00+00:00"}
        """.utf8
    )
    let decoder = JSONDecoder()
    let value = try decoder.decode(SessionDTO.self, from: data)
    require(value.deviceSessionId == "session", "session DTO device ID")
    require(value.refreshToken == "session.secret", "session DTO refresh token")
}

private func testStoreDTO() throws {
    let data = Data(
        """
        {"id":"7","name":"新加坡01","node_name":"edge-sg01","status":"available","health_status":"online","maintenance_mode":false,"enabled":true,"expected_public_ipv4":"198.51.100.20","actual_public_ipv4":"198.51.100.20","latency_ms":18,"active_connections":1,"max_connections":256,"legacy_profile_path":null}
        """.utf8
    )
    let decoder = JSONDecoder()
    let value = try decoder.decode(StoreDTO.self, from: data)
    require(value.nodeName == "edge-sg01", "store DTO node")
    require(value.expectedPublicIPv4 == "198.51.100.20", "store DTO expected IPv4 coding key")
    require(value.actualPublicIPv4 == "198.51.100.20", "store DTO actual IPv4 coding key")
    require(value.expectedPublicIPv4 == value.actualPublicIPv4, "store DTO fixed IP")
}

private func testAgentLatencyDTO() throws {
    let data = Data(
        """
        {"status":"connected","socks_host":"127.0.0.1","socks_port":55233,"store_id":2,"device_id":"mac-test","edge_latency":{"scope":"mac_to_edge_websocket_rtt","source":"websocket_ping","state":"fresh","latest_rtt_ms":86,"ewma_rtt_ms":82,"jitter_ms":4,"sample_count":4,"active_relays":1,"consecutive_failures":0,"updated_at_unix_ms":1787119200000}}
        """.utf8
    )
    let value = try JSONDecoder().decode(AgentStatusDTO.self, from: data)
    require(value.edgeLatency?.scope == "mac_to_edge_websocket_rtt", "Agent latency scope")
    require(value.edgeLatency?.source == "websocket_ping", "Agent latency source")
    require(value.edgeLatency?.state == .fresh, "Agent latency state")
    require(value.edgeLatency?.latestRttMs == 86, "Agent measured Edge RTT")
    require(value.edgeLatency?.sampleCount == 4, "Agent latency sample count")
}

private func testLegacyProfileWins() throws {
    let fileManager = FileManager.default
    let base = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? fileManager.removeItem(at: base) }
    let legacy = base.appendingPathComponent(
        "Hermes Local Browser/Stores/store-7/Profile",
        isDirectory: true
    )
    try fileManager.createDirectory(at: legacy, withIntermediateDirectories: true)
    let paths = StorePaths.resolve(
        store: sampleStore(),
        applicationSupport: base,
        fileManager: fileManager
    )
    require(paths.profile.standardizedFileURL == legacy.standardizedFileURL, "legacy Profile precedence")
}

private func testDeclaredProfileWinsOverExactLegacyPath() throws {
    let fileManager = FileManager.default
    let base = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? fileManager.removeItem(at: base) }
    let declared = base.appendingPathComponent("Declared/Profile", isDirectory: true)
    let exactLegacy = base.appendingPathComponent(
        "Hermes Local Browser/Stores/store-7/Profile",
        isDirectory: true
    )
    try fileManager.createDirectory(at: declared, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: exactLegacy, withIntermediateDirectories: true)
    let paths = StorePaths.resolve(
        store: sampleStore(legacyProfilePath: declared.path),
        applicationSupport: base,
        fileManager: fileManager
    )
    require(paths.profile.standardizedFileURL == declared.standardizedFileURL, "declared Profile precedence")
}

private func testNewProfilePath() {
    let paths = StorePaths.resolve(
        store: sampleStore(),
        applicationSupport: URL(fileURLWithPath: "/tmp/support")
    )
    require(paths.profile.path == "/tmp/support/IdenGrid/Stores/store-7/Profile", "new Profile path")
    require(paths.downloads.path == "/tmp/support/IdenGrid/Stores/store-7/Downloads", "app-owned Downloads path")
    require(paths.extensionDirectory.path == "/tmp/support/IdenGrid/Stores/store-7/Extension", "stable per-store extension path")
}

private func testStoreVisualIdentitySanitizesAndIsDeterministic() throws {
    let hostile = StoreDTO(
        id: "7", name: "\u{202E}\u{0000} 新加坡超级长店铺名称 ", nodeName: "edge\nsg01\u{2066}",
        status: "available", healthStatus: "online", maintenanceMode: false, enabled: true,
        expectedPublicIPv4: "198.51.100.20", actualPublicIPv4: nil, latencyMs: nil,
        activeConnections: 0, maxConnections: 1, legacyProfilePath: nil
    )
    let first = try StoreVisualIdentity(store: hostile)
    let second = try StoreVisualIdentity(store: hostile)
    require(first == second, "identity is deterministic")
    require(first.storeName == "新加坡超级长店铺名称", "store name sanitization")
    require(first.shortLabel == "新加", "short label is two visible characters")
    require(first.nodeName == "edge sg01", "node name sanitization")
    require(first.fixedIP == "198.51.100.20", "expected fixed IPv4")
    require(StoreVisualIdentity.palette.contains(first.color), "color comes from fixed palette")
    let data = try JSONEncoder().encode(first)
    let keys = Set((try JSONSerialization.jsonObject(with: data) as! [String: Any]).keys)
    require(keys == ["store_name", "short_label", "node_name", "fixed_ip", "color"], "identity JSON allowlist")
}

private func testStoreVisualIdentityRejectsMissingOrInvalidFixedIPv4() {
    let missing = sampleStore()
    let invalid = StoreDTO(
        id: missing.id, name: missing.name, nodeName: missing.nodeName, status: missing.status,
        healthStatus: missing.healthStatus, maintenanceMode: missing.maintenanceMode, enabled: missing.enabled,
        expectedPublicIPv4: "999.1.1.1", actualPublicIPv4: nil, latencyMs: nil,
        activeConnections: 0, maxConnections: 1, legacyProfilePath: nil
    )
    do { _ = try StoreVisualIdentity(store: invalid); require(false, "invalid IPv4 rejected") }
    catch { require(true, "invalid IPv4 rejected") }
}

private func edgeLatency(
    state: EdgeLatencyState,
    latest: Int? = 86,
    ewma: Int? = 82
) -> EdgeLatency {
    EdgeLatency(
        scope: "mac_to_edge_websocket_rtt",
        source: "websocket_ping",
        state: state,
        latestRttMs: latest,
        ewmaRttMs: ewma,
        jitterMs: 4,
        sampleCount: 4,
        activeRelays: 1,
        consecutiveFailures: 0,
        updatedAtUnixMs: 1_787_119_200_000
    )
}

private func testChineseLaunchState() {
    require(LaunchState.startingAgent.chineseLabel == "正在连接", "starting label")
    require(LaunchState.running.chineseLabel == "运行中", "running label")
    require(LaunchState.failed("网络").chineseLabel.contains("启动失败"), "failure label")
}

private func testIdleLatencyLineUsesCentralAverage() {
    let text = StoreLatencyLine.text(
        store: sampleStore(),
        launchState: .idle,
        edgeLatency: nil
    )
    require(text == "状态：online · 延迟：18 ms", "idle central latency line")
}

private func testRunningLatencyLineUsesPingPongEWMA() {
    let text = StoreLatencyLine.text(
        store: sampleStore(),
        launchState: .running,
        edgeLatency: edgeLatency(state: .fresh)
    )
    require(text == "状态：online · 延迟：82 ms", "running EWMA latency line")
}

private func testRunningLatencyStateSuffixes() {
    let store = sampleStore()
    require(
        StoreLatencyLine.text(store: store, launchState: .running, edgeLatency: edgeLatency(state: .warming))
            == "状态：online · 延迟：测量中",
        "warming latency state"
    )
    require(
        StoreLatencyLine.text(store: store, launchState: .running, edgeLatency: edgeLatency(state: .degraded))
            == "状态：online · 延迟：82 ms · 不稳定",
        "degraded latency state"
    )
    require(
        StoreLatencyLine.text(store: store, launchState: .running, edgeLatency: edgeLatency(state: .stale))
            == "状态：online · 延迟：82 ms · 已过期",
        "stale latency state"
    )
    require(
        StoreLatencyLine.text(store: store, launchState: .running, edgeLatency: nil)
            == "状态：online · 延迟：未测量",
        "unmeasured latency state"
    )
}

private func testBrandContractIsStableAndSymbolOnly() {
    require(BrandPaletteHex.navy == "#0B1739", "brand navy")
    require(BrandPaletteHex.blue == "#315CFF", "brand blue")
    require(BrandPaletteHex.aqua == "#28C7B7", "brand aqua")
    require(BrandAsset.appSymbol.rawValue == "idengrid-256", "runtime app symbol")
    require(
        BrandAsset.runtimePNGNames.allSatisfy { !$0.lowercased().contains("lockup") },
        "runtime PNGs contain no text lockups"
    )
}

private func testLoginPresentationStates() {
    require(LoginPresentation.buttonTitle(isBusy: false) == "登录", "normal login button")
    require(LoginPresentation.buttonTitle(isBusy: true) == "登录中…", "busy login button")
    require(
        LoginPresentation.inlineStatus("登录失败：用户名或密码错误", isBusy: false)
            == "登录失败：用户名或密码错误",
        "login error remains inline"
    )
    require(LoginPresentation.inlineStatus("正在登录", isBusy: true) == nil, "busy status is in button")
    require(LoginPresentation.inlineStatus("已退出登录", isBusy: false) == nil, "logout is not inline")
    require(LoginPresentation.toastMessage("已退出登录") == "已退出登录", "logout toast")
    require(LoginPresentation.toastDurationSeconds == 2.5, "toast duration")
    require(
        LoginPresentation.loginFailureMessage(statusCode: 401) == "用户名或者密码错误",
        "invalid credentials are human readable"
    )
    require(
        LoginPresentation.loginFailureMessage(statusCode: 500) == "登录失败，请稍后重试",
        "server details are not exposed"
    )
}

private func testAccessTokenRefreshSchedule() {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let expiry = ISO8601DateFormatter().string(from: now.addingTimeInterval(900))
    require(
        AccessTokenRefreshSchedule.delay(expiresAt: expiry, now: now) == 780,
        "refresh uses two minute margin"
    )
    let imminent = ISO8601DateFormatter().string(from: now.addingTimeInterval(30))
    require(
        AccessTokenRefreshSchedule.delay(expiresAt: imminent, now: now) == 5,
        "refresh delay has bounded minimum"
    )
    require(
        AccessTokenRefreshSchedule.delay(expiresAt: "invalid", now: now) == nil,
        "invalid expiry is rejected"
    )
    require(AccessTokenRefreshSchedule.retryDelay(attempt: 0) == 30, "initial retry delay")
    require(AccessTokenRefreshSchedule.retryDelay(attempt: 3) == 240, "retry backoff")
    require(AccessTokenRefreshSchedule.retryDelay(attempt: 9) == 300, "retry delay cap")
}

private func testDisconnectRequestBindsLeaseAndDevice() throws {
    let payload = try JSONEncoder().encode(
        StoreDisconnectRequest(
            leaseId: "0123456789abcdef0123456789abcdef",
            deviceId: "mac-device-01"
        )
    )
    let value = try JSONSerialization.jsonObject(with: payload) as? [String: String]
    require(value?.count == 2, "disconnect payload has no extra fields")
    require(
        value?["lease_id"] == "0123456789abcdef0123456789abcdef",
        "disconnect payload binds lease"
    )
    require(value?["device_id"] == "mac-device-01", "disconnect payload binds device")
}

private func testAgentTokenUpdatePayload() throws {
    let payload = try AgentControlPayload.updateToken(
        capability: "control-capability",
        token: "native-access-token"
    )
    let value = try JSONSerialization.jsonObject(with: payload) as? [String: String]
    require(value?.count == 3, "token update payload has no extra fields")
    require(value?["capability"] == "control-capability", "token update capability")
    require(value?["command"] == "update_token", "token update command")
    require(value?["native_access_token"] == "native-access-token", "token update field")
    let success = try JSONDecoder().decode(
        AgentTokenUpdateResponse.self,
        from: Data("{\"status\":\"updated\"}".utf8)
    )
    require(success.status == "updated", "token update success response")
}

do {
    try testSessionDTO()
    try testStoreDTO()
    try testAgentLatencyDTO()
    try testLegacyProfileWins()
    try testDeclaredProfileWinsOverExactLegacyPath()
    testNewProfilePath()
    try testStoreVisualIdentitySanitizesAndIsDeterministic()
    testStoreVisualIdentityRejectsMissingOrInvalidFixedIPv4()
    testChineseLaunchState()
    testIdleLatencyLineUsesCentralAverage()
    testRunningLatencyLineUsesPingPongEWMA()
    testRunningLatencyStateSuffixes()
    testBrandContractIsStableAndSymbolOnly()
    testLoginPresentationStates()
    testAccessTokenRefreshSchedule()
    try testDisconnectRequestBindsLeaseAndDevice()
    try testAgentTokenUpdatePayload()
    print("Swift contract tests passed: 17")
} catch {
    FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
    exit(1)
}
