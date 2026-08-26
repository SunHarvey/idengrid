import Foundation

struct LoginRequest: Codable, Equatable {
    let username: String
    let password: String
    let deviceId: String
    let deviceName: String
    let platform: String
}

struct StoreDisconnectRequest: Codable, Equatable {
    let leaseId: String
    let deviceId: String

    enum CodingKeys: String, CodingKey {
        case leaseId = "lease_id"
        case deviceId = "device_id"
    }
}

struct SessionDTO: Codable, Equatable {
    let accessToken: String
    let refreshToken: String
    let deviceSessionId: String
    let accessExpiresAt: String
    let refreshExpiresAt: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case deviceSessionId = "device_session_id"
        case accessExpiresAt = "access_expires_at"
        case refreshExpiresAt = "refresh_expires_at"
    }
}

enum AccessTokenRefreshSchedule {
    static let defaultMargin: TimeInterval = 120
    static let minimumDelay: TimeInterval = 5
    static let initialRetryDelay: TimeInterval = 30
    static let maximumRetryDelay: TimeInterval = 300

    static func expiration(from value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    static func delay(
        expiresAt: String,
        now: Date = Date(),
        margin: TimeInterval = defaultMargin,
        minimumDelay: TimeInterval = AccessTokenRefreshSchedule.minimumDelay
    ) -> TimeInterval? {
        guard let expiration = expiration(from: expiresAt) else { return nil }
        return max(minimumDelay, expiration.timeIntervalSince(now) - margin)
    }

    static func retryDelay(attempt: Int) -> TimeInterval {
        let exponent = min(max(attempt, 0), 4)
        return min(maximumRetryDelay, initialRetryDelay * pow(2, Double(exponent)))
    }
}

private struct AgentTokenUpdateRequest: Encodable {
    let capability: String
    let command = "update_token"
    let nativeAccessToken: String

    enum CodingKeys: String, CodingKey {
        case capability, command
        case nativeAccessToken = "native_access_token"
    }
}

struct AgentTokenUpdateResponse: Decodable, Equatable {
    let status: String
}

enum AgentControlPayloadError: Error {
    case invalidToken
}

enum AgentControlPayload {
    static func updateToken(capability: String, token: String) throws -> Data {
        guard (8...(8 * 1_024)).contains(token.utf8.count),
              token.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e })
        else { throw AgentControlPayloadError.invalidToken }
        return try JSONEncoder().encode(
            AgentTokenUpdateRequest(capability: capability, nativeAccessToken: token)
        )
    }
}

struct StoreDTO: Codable, Identifiable, Equatable, Hashable {
    let id: String
    let name: String
    let nodeName: String
    let status: String
    let healthStatus: String
    let maintenanceMode: Bool
    let enabled: Bool
    let expectedPublicIPv4: String?
    let actualPublicIPv4: String?
    let latencyMs: Double?
    let activeConnections: Int
    let maxConnections: Int
    let legacyProfilePath: String?

    enum CodingKeys: String, CodingKey {
        case id, name, status, enabled
        case nodeName = "node_name"
        case healthStatus = "health_status"
        case maintenanceMode = "maintenance_mode"
        case expectedPublicIPv4 = "expected_public_ipv4"
        case actualPublicIPv4 = "actual_public_ipv4"
        case latencyMs = "latency_ms"
        case activeConnections = "active_connections"
        case maxConnections = "max_connections"
        case legacyProfilePath = "legacy_profile_path"
    }
}

struct StoreListDTO: Codable, Equatable {
    let stores: [StoreDTO]
}

struct PreflightDTO: Codable, Equatable {
    let ready: Bool
    let storeId: String
    let leaseId: String
    let expiresAt: String
    let recovered: Bool

    enum CodingKeys: String, CodingKey {
        case ready, recovered
        case storeId = "store_id"
        case leaseId = "lease_id"
        case expiresAt = "expires_at"
    }
}

struct AgentStatusDTO: Codable, Equatable {
    let status: String
    let socksHost: String
    let socksPort: Int
    let storeId: UInt64
    let deviceId: String
    let edgeLatency: EdgeLatency?

    enum CodingKeys: String, CodingKey {
        case status
        case socksHost = "socks_host"
        case socksPort = "socks_port"
        case storeId = "store_id"
        case deviceId = "device_id"
        case edgeLatency = "edge_latency"
    }

    var proxyURL: String { "socks5://\(socksHost):\(socksPort)" }
}

enum EdgeLatencyState: String, Codable, Equatable {
    case warming, fresh, degraded, stale, unavailable
}

struct EdgeLatency: Codable, Equatable {
    let scope: String
    let source: String
    let state: EdgeLatencyState
    let latestRttMs: Int?
    let ewmaRttMs: Int?
    let jitterMs: Int?
    let sampleCount: Int
    let activeRelays: Int
    let consecutiveFailures: Int
    let updatedAtUnixMs: Int64?

    enum CodingKeys: String, CodingKey {
        case scope, source, state
        case latestRttMs = "latest_rtt_ms"
        case ewmaRttMs = "ewma_rtt_ms"
        case jitterMs = "jitter_ms"
        case sampleCount = "sample_count"
        case activeRelays = "active_relays"
        case consecutiveFailures = "consecutive_failures"
        case updatedAtUnixMs = "updated_at_unix_ms"
    }
}

enum LaunchState: Equatable {
    case idle, preflighting, startingAgent, verifyingEgress, launchingBrowser, running
    case failed(String)

    var isLaunchInProgress: Bool {
        switch self {
        case .preflighting, .startingAgent, .verifyingEgress, .launchingBrowser:
            return true
        case .idle, .running, .failed:
            return false
        }
    }

    var chineseLabel: String {
        switch self {
        case .idle: return "未启动"
        case .preflighting: return "正在检查"
        case .startingAgent: return "正在连接"
        case .verifyingEgress: return "正在验证出口"
        case .launchingBrowser: return "正在启动浏览器"
        case .running: return "运行中"
        case .failed(let message): return "启动失败：\(message)"
        }
    }
}

enum StoreLatencyLine {
    static func text(
        store: StoreDTO,
        launchState: LaunchState,
        edgeLatency: EdgeLatency?
    ) -> String {
        let latency: String
        if launchState == .running {
            latency = runningText(edgeLatency)
        } else {
            latency = store.latencyMs.map { "\(Int($0.rounded())) ms" } ?? "—"
        }
        return "状态：\(store.healthStatus) · 延迟：\(latency)"
    }

    private static func runningText(_ latency: EdgeLatency?) -> String {
        guard let latency else { return "未测量" }
        switch latency.state {
        case .warming:
            return "测量中"
        case .fresh:
            return milliseconds(latency) ?? "未测量"
        case .degraded:
            return suffixed(milliseconds(latency), state: "不稳定")
        case .stale:
            return suffixed(milliseconds(latency), state: "已过期")
        case .unavailable:
            return "未测量"
        }
    }

    private static func milliseconds(_ latency: EdgeLatency) -> String? {
        (latency.ewmaRttMs ?? latency.latestRttMs).map { "\($0) ms" }
    }

    private static func suffixed(_ value: String?, state: String) -> String {
        value.map { "\($0) · \(state)" } ?? state
    }
}
