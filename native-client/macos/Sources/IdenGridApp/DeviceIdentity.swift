import Foundation

struct DeviceIdentity {
    private static let key = "IdenGridDeviceID"

    static func current(defaults: UserDefaults = .standard) -> String {
        if let existing = defaults.string(forKey: key), !existing.isEmpty { return existing }
        let value = "mac-" + UUID().uuidString.lowercased()
        defaults.set(value, forKey: key)
        return value
    }
}
