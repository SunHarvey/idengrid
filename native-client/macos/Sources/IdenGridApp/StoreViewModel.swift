import Combine
import Foundation

@MainActor
final class StoreViewModel: ObservableObject {
    @Published var username = ""
    @Published var password = ""
    @Published var searchText = ""
    @Published private(set) var stores: [StoreDTO] = []
    @Published private(set) var isAuthenticated = false
    @Published private(set) var statusText = "请登录"
    @Published private(set) var isBusy = false

    let processes: StoreProcessManager
    private let api: StoreAPI
    private let vault: CredentialVault
    private let deviceID: String
    private let deviceName: String
    private var accessToken: String?
    private var accessExpiresAt: String?
    private var allStores: [StoreDTO] = []
    private var storeRefreshTask: Task<Void, Never>?
    private var accessTokenRefreshTask: Task<Void, Never>?
    private var isRefreshingAccessToken = false
    private var refreshRetryAttempt = 0
    private var sessionGeneration = 0

    init(
        api: StoreAPI,
        vault: CredentialVault,
        processes: StoreProcessManager,
        deviceID: String,
        deviceName: String
    ) {
        self.api = api
        self.vault = vault
        self.processes = processes
        self.deviceID = deviceID
        self.deviceName = deviceName
    }

    func restoreSession() async {
        guard (try? vault.load()) != nil else { return }
        let generation = sessionGeneration
        if await refreshSession() {
            guard generation == sessionGeneration, isAuthenticated else { return }
            statusText = "会话已恢复"
            await listStores()
            guard generation == sessionGeneration, isAuthenticated else { return }
            startStoreAutoRefresh()
            startAccessTokenRefreshScheduler()
        }
    }

    @discardableResult
    func refreshSession() async -> Bool {
        let generation = sessionGeneration
        do {
            guard let saved = try vault.load() else { return false }
            let session = try await api.refresh(refreshToken: saved.refreshToken)
            guard generation == sessionGeneration else { return false }
            try apply(session)
            return true
        } catch APIError.server(let status, _) where status == 401 || status == 403 {
            guard generation == sessionGeneration else { return false }
            cancelAccessTokenRefreshScheduler()
            try? vault.clear()
            accessToken = nil
            accessExpiresAt = nil
            isAuthenticated = false
            statusText = "会话已过期，请重新登录"
            return false
        } catch {
            guard generation == sessionGeneration else { return false }
            statusText = "暂时无法恢复会话，请检查网络后重试"
            return false
        }
    }

    func login() async {
        guard !username.isEmpty, !password.isEmpty else {
            statusText = "请输入用户名和密码"
            return
        }
        sessionGeneration += 1
        let generation = sessionGeneration
        isBusy = true
        statusText = "正在登录"
        defer {
            password = ""
            isBusy = false
        }
        do {
            let session = try await api.login(
                username: username,
                password: password,
                deviceId: deviceID,
                deviceName: deviceName
            )
            guard generation == sessionGeneration else { return }
            try apply(session)
            statusText = "登录成功"
            await listStores()
            guard generation == sessionGeneration, isAuthenticated else { return }
            startStoreAutoRefresh()
            startAccessTokenRefreshScheduler()
        } catch APIError.server(let status, _) {
            guard generation == sessionGeneration else { return }
            statusText = LoginPresentation.loginFailureMessage(statusCode: status)
        } catch {
            guard generation == sessionGeneration else { return }
            statusText = LoginPresentation.loginFailureMessage(statusCode: nil)
        }
    }

    private func apply(_ session: SessionDTO) throws {
        guard AccessTokenRefreshSchedule.expiration(from: session.accessExpiresAt) != nil else {
            throw APIError.invalidResponse
        }
        try vault.save(
            refreshToken: session.refreshToken,
            deviceSessionID: session.deviceSessionId
        )
        accessToken = session.accessToken
        accessExpiresAt = session.accessExpiresAt
        isAuthenticated = true
    }

    func listStores() async {
        guard let accessToken else { return }
        isBusy = true
        statusText = "正在加载店铺"
        defer { isBusy = false }
        do {
            allStores = try await api.stores(accessToken: accessToken)
            applySearch()
            statusText = stores.isEmpty ? "没有匹配的店铺" : "已加载 \(stores.count) 个店铺"
        } catch APIError.server(let status, _) where status == 401 || status == 403 {
            guard await refreshAccessTokenIfNeeded(), let refreshedToken = self.accessToken else { return }
            do {
                allStores = try await api.stores(accessToken: refreshedToken)
                applySearch()
                statusText = stores.isEmpty ? "没有匹配的店铺" : "已加载 \(stores.count) 个店铺"
            } catch {
                statusText = "加载失败：\(error.localizedDescription)"
            }
        } catch {
            statusText = "加载失败：\(error.localizedDescription)"
        }
    }

    func applySearch() {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        stores = query.isEmpty
            ? allStores
            : allStores.filter {
                $0.name.localizedCaseInsensitiveContains(query)
                    || $0.nodeName.localizedCaseInsensitiveContains(query)
            }
    }

    private func startStoreAutoRefresh() {
        guard storeRefreshTask == nil else { return }
        storeRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled, let self else { return }
                await self.refreshStoresSilently()
            }
        }
    }

    private func startAccessTokenRefreshScheduler(after override: TimeInterval? = nil) {
        accessTokenRefreshTask?.cancel()
        guard isAuthenticated else {
            accessTokenRefreshTask = nil
            return
        }
        let delay: TimeInterval
        if let override {
            delay = override
        } else if let accessExpiresAt,
                  let scheduled = AccessTokenRefreshSchedule.delay(expiresAt: accessExpiresAt) {
            delay = scheduled
        } else {
            accessTokenRefreshTask = nil
            return
        }
        accessTokenRefreshTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(delay))
                guard !Task.isCancelled, let self else { return }
                self.accessTokenRefreshTask = nil
                _ = await self.refreshAccessTokenIfNeeded()
            } catch {
                return
            }
        }
    }

    private func cancelAccessTokenRefreshScheduler() {
        accessTokenRefreshTask?.cancel()
        accessTokenRefreshTask = nil
        refreshRetryAttempt = 0
    }

    private func refreshAccessTokenIfNeeded() async -> Bool {
        guard !isRefreshingAccessToken, isAuthenticated else { return false }
        isRefreshingAccessToken = true
        defer { isRefreshingAccessToken = false }
        let generation = sessionGeneration
        do {
            guard let saved = try vault.load() else { throw APIError.invalidResponse }
            let session = try await api.refresh(refreshToken: saved.refreshToken)
            guard generation == sessionGeneration, isAuthenticated else { return false }
            try apply(session)
            let failedStoreIDs = await processes.updateAccessTokenForRunningAgents(
                session.accessToken
            )
            failedStoreIDs.forEach { processes.closeAfterTokenUpdateFailure(storeID: $0) }
            refreshRetryAttempt = 0
            startAccessTokenRefreshScheduler()
            return true
        } catch APIError.server(let status, _) where status == 401 || status == 403 {
            guard generation == sessionGeneration, isAuthenticated else { return false }
            cancelAccessTokenRefreshScheduler()
            storeRefreshTask?.cancel()
            storeRefreshTask = nil
            processes.quitAll()
            try? vault.clear()
            accessToken = nil
            accessExpiresAt = nil
            isAuthenticated = false
            statusText = "会话已过期，请重新登录"
            return false
        } catch {
            guard generation == sessionGeneration, isAuthenticated else { return false }
            let retry = AccessTokenRefreshSchedule.retryDelay(attempt: refreshRetryAttempt)
            refreshRetryAttempt += 1
            startAccessTokenRefreshScheduler(after: retry)
            return false
        }
    }

    private func refreshStoresSilently() async {
        guard let accessToken else { return }
        do {
            allStores = try await api.stores(accessToken: accessToken)
            applySearch()
        } catch APIError.server(let status, _) where status == 401 || status == 403 {
            guard await refreshAccessTokenIfNeeded(), let refreshedToken = self.accessToken else { return }
            guard let latest = try? await api.stores(accessToken: refreshedToken) else { return }
            allStores = latest
            applySearch()
        } catch {
            return
        }
    }

    func launch(_ store: StoreDTO) async {
        guard let accessToken else { return }
        do {
            try await launch(store, accessToken: accessToken)
        } catch APIError.server(let status, _) where status == 401 || status == 403 {
            guard await refreshAccessTokenIfNeeded(), let refreshedToken = self.accessToken else {
                return
            }
            do {
                try await launch(store, accessToken: refreshedToken)
            } catch {
                statusText = "启动前检查失败：\(error.localizedDescription)"
            }
        } catch {
            statusText = "启动前检查失败：\(error.localizedDescription)"
        }
    }

    private func launch(_ store: StoreDTO, accessToken: String) async throws {
        let preflight = try await api.preflight(storeID: store.id, accessToken: accessToken)
        let launched = await processes.launch(store: store, accessToken: accessToken)
        if !launched {
            try? await api.disconnect(
                storeID: store.id,
                leaseId: preflight.leaseId,
                deviceId: deviceID,
                accessToken: accessToken
            )
        }
    }

    func close(_ store: StoreDTO) { processes.close(storeID: store.id) }

    func prepareForApplicationTermination() async -> Bool {
        cancelAccessTokenRefreshScheduler()
        storeRefreshTask?.cancel()
        storeRefreshTask = nil
        let success = await processes.quitAllAndWait()
        if !success {
            statusText = "浏览器未能安全结束，已取消退出应用"
            if isAuthenticated {
                startStoreAutoRefresh()
                startAccessTokenRefreshScheduler()
            }
        }
        return success
    }

    func signOut() async {
        let tokenForLogout = accessToken
        sessionGeneration += 1
        cancelAccessTokenRefreshScheduler()
        storeRefreshTask?.cancel()
        storeRefreshTask = nil
        isAuthenticated = false
        accessToken = nil
        accessExpiresAt = nil
        try? vault.clear()
        allStores = []
        stores = []
        password = ""
        statusText = "已退出登录"
        processes.quitAll()
        if let tokenForLogout { try? await api.logout(accessToken: tokenForLogout) }
    }
}
