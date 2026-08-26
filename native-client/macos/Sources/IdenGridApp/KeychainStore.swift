import Foundation
import Security

protocol CredentialVault: Sendable {
    func save(refreshToken: String, deviceSessionID: String) throws
    func load() throws -> (refreshToken: String, deviceSessionID: String)?
    func clear() throws
}

final class EphemeralCredentialVault: CredentialVault, @unchecked Sendable {
    private let lock = NSLock()
    private var session: (refreshToken: String, deviceSessionID: String)?

    func save(refreshToken: String, deviceSessionID: String) throws {
        lock.lock()
        session = (refreshToken, deviceSessionID)
        lock.unlock()
    }

    func load() throws -> (refreshToken: String, deviceSessionID: String)? {
        lock.lock()
        defer { lock.unlock() }
        return session
    }

    func clear() throws {
        lock.lock()
        session = nil
        lock.unlock()
    }
}

final class KeychainStore: CredentialVault, @unchecked Sendable {
    private let service = "com.idengrid.client.native-session"
    private let account = "current-device"

    private struct PersistedSession: Codable {
        let refreshToken: String
        let deviceSessionID: String
    }

    func save(refreshToken: String, deviceSessionID: String) throws {
        let data = try JSONEncoder().encode(
            PersistedSession(refreshToken: refreshToken, deviceSessionID: deviceSessionID)
        )
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let update: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(identity as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw CocoaError(.fileWriteNoPermission)
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data,
        ]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
            throw CocoaError(.fileWriteNoPermission)
        }
    }

    func load() throws -> (refreshToken: String, deviceSessionID: String)? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw CocoaError(.fileReadNoPermission)
        }
        let value = try JSONDecoder().decode(PersistedSession.self, from: data)
        return (value.refreshToken, value.deviceSessionID)
    }

    func clear() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CocoaError(.fileWriteNoPermission)
        }
    }
}
