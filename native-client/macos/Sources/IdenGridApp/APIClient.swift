import Foundation

protocol StoreAPI: Sendable {
    func login(
        username: String,
        password: String,
        deviceId: String,
        deviceName: String
    ) async throws -> SessionDTO
    func refresh(refreshToken: String) async throws -> SessionDTO
    func stores(accessToken: String) async throws -> [StoreDTO]
    func preflight(storeID: String, accessToken: String) async throws -> PreflightDTO
    func disconnect(
        storeID: String,
        leaseId: String,
        deviceId: String,
        accessToken: String
    ) async throws
    func logout(accessToken: String) async throws
}

enum APIError: LocalizedError {
    case invalidResponse
    case server(Int, String)

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "服务器响应无效"
        case .server(let code, let text): return "服务器错误 \(code)：\(text)"
        }
    }
}

private struct EmptyBody: Encodable {}
private struct EmptyResponse: Decodable {}

final class APIClient: StoreAPI, @unchecked Sendable {
    private let baseURL: URL
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
        encoder = JSONEncoder()
        decoder = JSONDecoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
    }

    private func endpoint(_ path: String) throws -> URL {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw APIError.invalidResponse
        }
        return url
    }

    private func request<Response: Decodable, Body: Encodable>(
        _ path: String,
        method: String,
        body: Body?,
        authorization: String? = nil
    ) async throws -> Response {
        var request = URLRequest(url: try endpoint(path))
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let authorization {
            request.setValue(authorization, forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try encoder.encode(body)
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw APIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw APIError.server(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        return try decoder.decode(Response.self, from: data)
    }

    func login(
        username: String,
        password: String,
        deviceId: String,
        deviceName: String
    ) async throws -> SessionDTO {
        try await request(
            "api/native/login",
            method: "POST",
            body: LoginRequest(
                username: username,
                password: password,
                deviceId: deviceId,
                deviceName: deviceName,
                platform: "macos"
            )
        )
    }

    func refresh(refreshToken: String) async throws -> SessionDTO {
        try await request(
            "api/native/refresh",
            method: "POST",
            body: Optional<EmptyBody>.none,
            authorization: "Refresh \(refreshToken)"
        )
    }

    func stores(accessToken: String) async throws -> [StoreDTO] {
        let response: StoreListDTO = try await request(
            "api/native/stores",
            method: "GET",
            body: Optional<EmptyBody>.none,
            authorization: "Bearer \(accessToken)"
        )
        return response.stores
    }

    func preflight(storeID: String, accessToken: String) async throws -> PreflightDTO {
        try await request(
            "api/native/stores/\(storeID)/preflight",
            method: "POST",
            body: Optional<EmptyBody>.none,
            authorization: "Bearer \(accessToken)"
        )
    }

    func disconnect(
        storeID: String,
        leaseId: String,
        deviceId: String,
        accessToken: String
    ) async throws {
        let _: EmptyResponse = try await request(
            "api/stores/\(storeID)/disconnect",
            method: "POST",
            body: StoreDisconnectRequest(leaseId: leaseId, deviceId: deviceId),
            authorization: "Bearer \(accessToken)"
        )
    }

    func logout(accessToken: String) async throws {
        let _: EmptyResponse = try await request(
            "api/native/logout",
            method: "POST",
            body: Optional<EmptyBody>.none,
            authorization: "Bearer \(accessToken)"
        )
    }
}
