import Foundation
import Combine
import Darwin
import CFNetwork
import AppKit

struct AgentConfiguration: Codable {
    let centralURL: String
    let nativeAccessToken: String
    let storeID: UInt64
    let deviceID: String
    let controlSocketPath: String
    let controlCapability: String
    let localPort: UInt16
}

@MainActor
final class StoreProcessManager: ObservableObject {
    struct RunningStore {
        let agent: Process
        let browser: Process
        let lockFD: Int32
        let paths: StorePaths
        let controlToken: String
    }
    @Published private(set) var states: [String: LaunchState] = [:]
    @Published private(set) var edgeLatencies: [String: EdgeLatency] = [:]
    private var running: [String: RunningStore] = [:]
    private var latencyTasks: [String: Task<Void, Never>] = [:]
    private let fileManager: FileManager
    private let support: URL
    private let upstreamBaseURL: URL
    private let deviceID: String


    init(fileManager: FileManager = .default, upstreamBaseURL: URL, deviceID: String) {
        self.fileManager = fileManager; self.upstreamBaseURL = upstreamBaseURL
        self.deviceID = deviceID
        let supportURL = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        support = supportURL

        recoverStaleLocks()
    }

    func launch(store: StoreDTO, accessToken: String) async -> Bool {
        guard running[store.id] == nil else { return true }
        var acquiredLock: Int32 = -1
        let paths = StorePaths.resolve(store: store, applicationSupport: support, fileManager: fileManager)
        do {
            states[store.id] = .preflighting
            try createDirectories(paths)
            acquiredLock = try acquireLock(paths.lock)
            try prepareStoreExtension(store: store, paths: paths)
            let binaries = try preflight()

            let controlToken = UUID().uuidString + UUID().uuidString
            try writeAgentConfig(store: store, paths: paths, controlToken: controlToken, accessToken: accessToken)
            states[store.id] = .startingAgent
            let agent = try spawnAgent(at: binaries.agent, config: paths.config)
            do {
                try await waitForAuthenticatedReady(socket: paths.socket, token: controlToken, timeout: 20)
                try removeAgentConfig(paths.config)
                states[store.id] = .verifyingEgress
                let status = try await agentStatus(socket: paths.socket, token: controlToken)
                guard status.status == "connected", status.deviceId == deviceID else { throw ProcessError.invalidAgentResponse }
                guard status.socksHost == "127.0.0.1", status.socksPort > 0 else { throw ProcessError.invalidAgentResponse }
                try await verifyEgress(status: status, expectedIPv4: store.expectedPublicIPv4)
                states[store.id] = .launchingBrowser
                let browser = try spawnBrowser(at: binaries.browser, paths: paths, proxyURL: status.proxyURL)
                let record = RunningStore(
                    agent: agent,
                    browser: browser,
                    lockFD: acquiredLock,
                    paths: paths,
                    controlToken: controlToken
                )
                running[store.id] = record
                installCrashRecovery(storeID: store.id, agent: agent, browser: browser)
                states[store.id] = .running
                await refreshEdgeLatency(
                    storeID: store.id,
                    socket: paths.socket,
                    token: controlToken
                )
                startLatencyPolling(
                    storeID: store.id,
                    socket: paths.socket,
                    token: controlToken
                )
                return true
            } catch {
                terminate(agent); releaseLock(acquiredLock, at: paths.lock); acquiredLock = -1; throw error
            }
        } catch {
            if acquiredLock >= 0 { releaseLock(acquiredLock, at: paths.lock) }
            states[store.id] = .failed(error.localizedDescription)
            return false
        }
    }

    func close(storeID: String) {
        latencyTasks.removeValue(forKey: storeID)?.cancel()
        edgeLatencies.removeValue(forKey: storeID)
        guard let record = running.removeValue(forKey: storeID) else { return }
        record.browser.terminationHandler = nil; record.agent.terminationHandler = nil
        terminate(record.browser); terminate(record.agent); releaseLock(record.lockFD, at: record.paths.lock)
        states[storeID] = .idle
    }
    func closeAfterTokenUpdateFailure(storeID: String) {
        close(storeID: storeID)
        states[storeID] = .failed("会话凭据更新失败，已安全关闭")
    }
    func isRunning(storeID: String) -> Bool {
        running[storeID]?.browser.isRunning == true
    }
    @discardableResult
    func activate(storeID: String) -> Bool {
        guard let browser = running[storeID]?.browser, browser.isRunning,
              let application = NSRunningApplication(processIdentifier: browser.processIdentifier)
        else { return false }
        return application.activate(options: [.activateAllWindows])
    }
    func quitAll() { Array(running.keys).forEach(close) }

    func quitAllAndWait() async -> Bool {
        var success = true
        for storeID in Array(running.keys).sorted() {
            latencyTasks.removeValue(forKey: storeID)?.cancel()
            edgeLatencies.removeValue(forKey: storeID)
            guard let record = running.removeValue(forKey: storeID) else { continue }
            record.browser.terminationHandler = nil
            record.agent.terminationHandler = nil

            let browserStopped = await stopBrowserAndWait(record.browser)
            let agentStopped = await stopAgentAndWait(
                record.agent,
                socket: record.paths.socket,
                capability: record.controlToken
            )
            if browserStopped && agentStopped {
                try? fileManager.removeItem(at: record.paths.config)
                try? fileManager.removeItem(at: record.paths.socket)
                releaseLock(record.lockFD, at: record.paths.lock)
                states[storeID] = .idle
            } else {
                running[storeID] = record
                installCrashRecovery(
                    storeID: storeID,
                    agent: record.agent,
                    browser: record.browser
                )
                states[storeID] = .failed("浏览器未能安全结束，请重试退出")
                success = false
            }
        }
        return success && running.isEmpty
    }

    func updateAccessTokenForRunningAgents(_ token: String) async -> [String] {
        let agents = running.map { storeID, record in
            (storeID: storeID, socket: record.paths.socket, capability: record.controlToken)
        }
        var failedStoreIDs: [String] = []
        for agent in agents {
            do {
                var payload = try AgentControlPayload.updateToken(
                    capability: agent.capability,
                    token: token
                )
                payload.append(0x0a)
                let responseData = try await unixHTTPRequest(
                    socket: agent.socket.path,
                    request: String(decoding: payload, as: UTF8.self)
                )
                let response = try JSONDecoder().decode(
                    AgentTokenUpdateResponse.self,
                    from: responseData
                )
                guard response.status == "updated" else {
                    throw ProcessError.invalidAgentResponse
                }
            } catch {
                failedStoreIDs.append(agent.storeID)
            }
        }
        return failedStoreIDs.sorted()
    }

    private func createDirectories(_ paths: StorePaths) throws {
        for url in [paths.root, paths.profile, paths.downloads, paths.runtime] { try fileManager.createDirectory(at: url, withIntermediateDirectories: true) }
    }
    private func prepareStoreExtension(store: StoreDTO, paths: StorePaths) throws {
        guard let bundled = Bundle.main.resourceURL?.appendingPathComponent("Extension", isDirectory: true),
              fileManager.fileExists(atPath: bundled.path)
        else { throw ProcessError.missingExtension }
        let staging = paths.root.appendingPathComponent(
            ".Extension-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
        var completed = false
        defer { if !completed { try? fileManager.removeItem(at: staging) } }
        for source in try fileManager.contentsOfDirectory(
            at: bundled,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) {
            guard source.lastPathComponent != "identity.json" else { continue }
            let values = try source.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }
            let destination = staging.appendingPathComponent(source.lastPathComponent)
            try fileManager.copyItem(at: source, to: destination)
        }
        let identity = try StoreVisualIdentity(store: store)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let identityData = try encoder.encode(identity)
        try identityData.write(
            to: staging.appendingPathComponent("identity.json"),
            options: .atomic
        )
        if fileManager.fileExists(atPath: paths.extensionDirectory.path) {
            _ = try fileManager.replaceItemAt(
                paths.extensionDirectory,
                withItemAt: staging,
                backupItemName: nil,
                options: []
            )
        } else {
            try fileManager.moveItem(at: staging, to: paths.extensionDirectory)
        }
        completed = true
    }
    private func acquireLock(_ url: URL) throws -> Int32 {
        let fd = open(url.path, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw ProcessError.storeAlreadyRunning }
        let pid = "\(getpid())\n"; _ = pid.withCString { write(fd, $0, strlen($0)) }
        return fd
    }
    private func releaseLock(_ fd: Int32, at url: URL) { if fd >= 0 { Darwin.close(fd) }; try? fileManager.removeItem(at: url) }
    private func recoverStaleLocks() {
        let stores = support.appendingPathComponent("IdenGrid/Stores")
        guard let children = try? fileManager.contentsOfDirectory(at: stores, includingPropertiesForKeys: nil) else { return }
        for child in children {
            let lock = child.appendingPathComponent("Runtime/store.lock")
            guard let text = try? String(contentsOf: lock), let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), kill(pid, 0) != 0, errno == ESRCH else { continue }
            try? fileManager.removeItem(at: lock)
        }
    }

    private func preflight() throws -> (agent: URL, browser: URL) {
        guard let agent = Bundle.main.url(forAuxiliaryExecutable: "idengrid-agent") else { throw ProcessError.missingAgent }
        let browser = Bundle.main.bundleURL.appendingPathComponent("Contents/Frameworks/IdenGrid Browser.app/Contents/MacOS/Chromium")
        guard fileManager.isExecutableFile(atPath: agent.path), fileManager.isExecutableFile(atPath: browser.path) else { throw ProcessError.missingBundledBrowser }
        try requireArm64(agent); try requireArm64(browser)
        return (agent, browser)
    }
    private func requireArm64(_ binary: URL) throws {
        let task = Process(); let pipe = Pipe(); task.executableURL = URL(fileURLWithPath: "/usr/bin/lipo"); task.arguments = ["-archs", binary.path]; task.standardOutput = pipe; task.standardError = pipe
        try task.run(); task.waitUntilExit()
        let archs = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard task.terminationStatus == 0, archs.split(whereSeparator: \.isWhitespace).contains("arm64"), !archs.contains("x86_64") else { throw ProcessError.wrongArchitecture }
    }
    private func writeAgentConfig(store: StoreDTO, paths: StorePaths, controlToken: String, accessToken: String) throws {
        guard let storeID = UInt64(store.id) else { throw ProcessError.invalidAgentResponse }
        let value = AgentConfiguration(centralURL: upstreamBaseURL.absoluteString, nativeAccessToken: accessToken, storeID: storeID, deviceID: deviceID, controlSocketPath: paths.socket.path, controlCapability: controlToken, localPort: 0)
        let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(value); try data.write(to: paths.config, options: .atomic)
        guard chmod(paths.config.path, 0o600) == 0 else { throw ProcessError.configPermissions }
    }
    private func removeAgentConfig(_ config: URL) throws {
        try fileManager.removeItem(at: config)
        guard !fileManager.fileExists(atPath: config.path) else {
            throw ProcessError.configPermissions
        }
    }
    private func spawnAgent(at executable: URL, config: URL) throws -> Process {
        let logURL = config.deletingLastPathComponent().appendingPathComponent("agent.log")
        _ = fileManager.createFile(atPath: logURL.path, contents: nil)
        guard chmod(logURL.path, 0o600) == 0 else { throw ProcessError.configPermissions }
        let logHandle = try FileHandle(forWritingTo: logURL)
        try logHandle.truncate(atOffset: 0)
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--config", config.path]
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()
        try logHandle.close()
        return process
    }
    private func spawnBrowser(at executable: URL, paths: StorePaths, proxyURL: String) throws -> Process {
        let policyURL = paths.root.appendingPathComponent("Managed Policies", isDirectory: true)
        try fileManager.createDirectory(at: policyURL, withIntermediateDirectories: true)
        let policy: [String: Any] = ["BrowserSignin": 0, "PasswordManagerEnabled": false, "SyncDisabled": true]
        let policyData = try JSONSerialization.data(withJSONObject: policy, options: [.prettyPrinted, .sortedKeys]); try policyData.write(to: policyURL.appendingPathComponent("idengrid.json"), options: .atomic)
        let process = Process(); process.executableURL = executable
        process.arguments = ["--user-data-dir=\(paths.profile.path)", "--downloads-path=\(paths.downloads.path)", "--proxy-server=\(proxyURL)", "--proxy-bypass-list=<-loopback>", "--load-extension=\(paths.extensionDirectory.path)", "--disable-extensions-except=\(paths.extensionDirectory.path)", "--disable-quic", "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--no-first-run", "--no-default-browser-check", "--disable-sync"]
        try process.run(); return process
    }
    private func installCrashRecovery(storeID: String, agent: Process, browser: Process) {
        agent.terminationHandler = { [weak self] _ in Task { @MainActor in self?.handleUnexpectedExit(storeID: storeID, reason: "Agent 已意外退出") } }
        browser.terminationHandler = { [weak self] _ in Task { @MainActor in self?.handleUnexpectedExit(storeID: storeID, reason: "浏览器已意外退出") } }
    }
    private func handleUnexpectedExit(storeID: String, reason: String) {
        latencyTasks.removeValue(forKey: storeID)?.cancel()
        edgeLatencies.removeValue(forKey: storeID)
        guard let record = running.removeValue(forKey: storeID) else { return }
        record.agent.terminationHandler = nil; record.browser.terminationHandler = nil
        terminate(record.browser); terminate(record.agent); releaseLock(record.lockFD, at: record.paths.lock)
        states[storeID] = .failed(reason)
    }
    private func terminate(_ process: Process) { if process.isRunning { process.terminate(); DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if process.isRunning { kill(process.processIdentifier, SIGKILL) } } } }

    private func stopBrowserAndWait(_ process: Process) async -> Bool {
        guard process.isRunning else { return true }
        if let application = NSRunningApplication(processIdentifier: process.processIdentifier) {
            _ = application.terminate()
            if await waitForExit(process, timeout: 5) { return true }
        }
        process.terminate()
        if await waitForExit(process, timeout: 3) { return true }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        return await waitForExit(process, timeout: 2)
    }

    private func stopAgentAndWait(
        _ process: Process,
        socket: URL,
        capability: String
    ) async -> Bool {
        guard process.isRunning else { return true }
        let request = "{\"capability\":\"\(capability)\",\"command\":\"shutdown\"}\n"
        _ = try? await unixHTTPRequest(socket: socket.path, request: request)
        if await waitForExit(process, timeout: 3) { return true }
        process.terminate()
        if await waitForExit(process, timeout: 3) { return true }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        return await waitForExit(process, timeout: 2)
    }

    private func waitForExit(_ process: Process, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
        return !process.isRunning
    }

    private func waitForAuthenticatedReady(socket: URL, token: String, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let status = try? await agentStatus(socket: socket, token: token), status.status == "connected" { return }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw ProcessError.agentTimeout
    }
    private func agentStatus(socket: URL, token: String) async throws -> AgentStatusDTO {
        let request = "{\"capability\":\"\(token)\",\"command\":\"status\"}\n"
        let data = try await unixHTTPRequest(socket: socket.path, request: request)
        let decoder = JSONDecoder()
        return try decoder.decode(AgentStatusDTO.self, from: data)
    }

    private func startLatencyPolling(storeID: String, socket: URL, token: String) {
        latencyTasks.removeValue(forKey: storeID)?.cancel()
        latencyTasks[storeID] = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled, let self else { return }
                await self.refreshEdgeLatency(storeID: storeID, socket: socket, token: token)
            }
        }
    }

    private func refreshEdgeLatency(storeID: String, socket: URL, token: String) async {
        guard let status = try? await agentStatus(socket: socket, token: token),
              let latency = status.edgeLatency,
              latency.scope == "mac_to_edge_websocket_rtt",
              latency.source == "websocket_ping"
        else { return }
        edgeLatencies[storeID] = latency
    }

    private func verifyEgress(status: AgentStatusDTO, expectedIPv4: String?) async throws {
        guard let expectedIPv4, !expectedIPv4.isEmpty else { throw ProcessError.egressUnavailable }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesSOCKSEnable as String: true,
            kCFNetworkProxiesSOCKSProxy as String: status.socksHost,
            kCFNetworkProxiesSOCKSPort as String: status.socksPort,
        ]
        let session = URLSession(configuration: configuration)
        let (data, response) = try await session.data(from: URL(string: "https://api.ipify.org")!)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw ProcessError.egressUnavailable }
        let actual = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard actual == expectedIPv4 else { throw ProcessError.egressUnavailable }
    }
    private func unixHTTPRequest(socket: String, request: String) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            try UnixSocketClient.request(path: socket, payload: request)
        }.value
    }
}

enum ProcessError: LocalizedError {
    case storeAlreadyRunning, missingAgent, missingBundledBrowser, missingExtension, wrongArchitecture, configPermissions, agentTimeout, invalidAgentResponse, egressUnavailable
    var errorDescription: String? { switch self {
    case .storeAlreadyRunning: return "店铺已在运行"; case .missingAgent: return "缺少内置 Agent"; case .missingBundledBrowser: return "缺少内置浏览器"; case .missingExtension: return "缺少内置扩展"; case .wrongArchitecture: return "组件不是纯 arm64"; case .configPermissions: return "无法保护 Agent 配置"; case .agentTimeout: return "Agent 就绪超时"; case .invalidAgentResponse: return "Agent 状态无效"; case .egressUnavailable: return "出口验证失败" }
    }
}
