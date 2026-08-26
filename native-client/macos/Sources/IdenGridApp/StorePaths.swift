import Foundation

struct StorePaths: Equatable {
    let root: URL
    let profile: URL
    let downloads: URL
    let runtime: URL
    let socket: URL
    let config: URL
    let lock: URL
    let extensionDirectory: URL

    static func resolve(store: StoreDTO, applicationSupport: URL, fileManager: FileManager = .default) -> StorePaths {
        let storesRoot = applicationSupport.appendingPathComponent("IdenGrid/Stores", isDirectory: true)
        let root = storesRoot.appendingPathComponent("store-\(store.id)", isDirectory: true)
        let hermesLegacy = applicationSupport.appendingPathComponent(
            "Hermes Local Browser/Stores/store-\(store.id)/Profile",
            isDirectory: true
        )
        let declaredLegacy = store.legacyProfilePath.map { URL(fileURLWithPath: NSString(string: $0).expandingTildeInPath, isDirectory: true) }
        let candidates = [declaredLegacy, hermesLegacy].compactMap { $0 }
        let existingLegacy = candidates.first { fileManager.fileExists(atPath: $0.path) }
        return StorePaths(
            root: root,
            profile: existingLegacy ?? root.appendingPathComponent("Profile", isDirectory: true),
            downloads: root.appendingPathComponent("Downloads", isDirectory: true),
            runtime: root.appendingPathComponent("Runtime", isDirectory: true),
            socket: root.appendingPathComponent("Runtime/agent.sock"),
            config: root.appendingPathComponent("Runtime/agent.json"),
            lock: root.appendingPathComponent("Runtime/store.lock"),
            extensionDirectory: root.appendingPathComponent("Extension", isDirectory: true)
        )
    }
}
