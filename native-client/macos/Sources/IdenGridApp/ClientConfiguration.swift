import Foundation

struct ClientConfiguration: Decodable {
    let apiBaseURL: URL

    enum CodingKeys: String, CodingKey {
        case apiBaseURL = "api_base_url"
    }

    static func load(bundle: Bundle = .main) throws -> ClientConfiguration {
        guard let url = bundle.url(forResource: "client-config", withExtension: "json") else {
            throw ConfigurationError.missing
        }
        let value = try JSONDecoder().decode(ClientConfiguration.self, from: Data(contentsOf: url))
        guard value.apiBaseURL.scheme == "https",
              value.apiBaseURL.user == nil,
              value.apiBaseURL.password == nil,
              value.apiBaseURL.host != nil
        else { throw ConfigurationError.invalid }
        return value
    }
}

enum ConfigurationError: LocalizedError {
    case missing
    case invalid

    var errorDescription: String? {
        switch self {
        case .missing: return "客户端缺少服务器配置"
        case .invalid: return "客户端服务器配置无效"
        }
    }
}
