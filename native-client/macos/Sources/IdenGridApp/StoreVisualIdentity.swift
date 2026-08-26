import Foundation

struct StoreVisualIdentity: Codable, Equatable {
    let storeName: String
    let shortLabel: String
    let nodeName: String
    let fixedIP: String
    let color: String

    static let palette = [
        "#2563EB", "#7C3AED", "#DB2777", "#DC2626",
        "#EA580C", "#16A34A", "#0891B2", "#4F46E5",
    ]

    enum CodingKeys: String, CodingKey {
        case storeName = "store_name"
        case shortLabel = "short_label"
        case nodeName = "node_name"
        case fixedIP = "fixed_ip"
        case color
    }

    init(store: StoreDTO) throws {
        let name = Self.sanitize(store.name, maximumCharacters: 80, fallback: "店铺")
        storeName = name
        shortLabel = String(name.prefix(2))
        nodeName = Self.sanitize(store.nodeName, maximumCharacters: 80, fallback: "未知节点")
        guard let expected = store.expectedPublicIPv4,
              Self.isValidIPv4(expected)
        else { throw StoreVisualIdentityError.invalidFixedIPv4 }
        fixedIP = expected
        color = Self.palette[Self.paletteIndex(store.id)]
    }

    private static func sanitize(_ raw: String, maximumCharacters: Int, fallback: String) -> String {
        var cleaned = ""
        for scalar in raw.unicodeScalars {
            let value = scalar.value
            if value <= 0x1F || (0x7F...0x9F).contains(value) || isBidiControl(value) {
                cleaned.append(" ")
            } else {
                cleaned.unicodeScalars.append(scalar)
            }
        }
        let collapsed = cleaned
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
        let limited = String(collapsed.prefix(maximumCharacters))
        return limited.isEmpty ? fallback : limited
    }

    private static func isBidiControl(_ value: UInt32) -> Bool {
        value == 0x061C || value == 0x200E || value == 0x200F
            || (0x202A...0x202E).contains(value)
            || (0x2066...0x2069).contains(value)
    }

    private static func isValidIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard !part.isEmpty, part.allSatisfy(\.isNumber),
                  let octet = UInt8(part), String(octet) == part
            else { return false }
            return true
        }
    }

    private static func paletteIndex(_ storeID: String) -> Int {
        var hash: UInt32 = 2_166_136_261
        for byte in storeID.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 16_777_619
        }
        return Int(hash % UInt32(palette.count))
    }
}

enum StoreVisualIdentityError: LocalizedError {
    case invalidFixedIPv4

    var errorDescription: String? { "店铺缺少有效的固定 IPv4" }
}
