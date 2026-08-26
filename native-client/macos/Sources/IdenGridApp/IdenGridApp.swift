import Sparkle
import SwiftUI

@main
@MainActor
struct IdenGridApp: App {
    @NSApplicationDelegateAdaptor(AppTerminationDelegate.self)
    private var terminationDelegate
    @StateObject private var model: StoreViewModel
    private let updater = SPUStandardUpdaterController(
        startingUpdater: true,
        updaterDelegate: nil,
        userDriverDelegate: nil
    )

    init() {
        guard let configuration = try? ClientConfiguration.load() else {
            fatalError("IdenGrid client configuration is missing or invalid")
        }
        let base = configuration.apiBaseURL
        let deviceID = DeviceIdentity.current()
        let deviceName = Host.current().localizedName ?? "MacBook"
        let isDevelopmentBuild = Bundle.main.object(
            forInfoDictionaryKey: "IDGDevelopmentBuild"
        ) as? Bool == true
        let vault: any CredentialVault = isDevelopmentBuild
            ? EphemeralCredentialVault()
            : KeychainStore()
        let manager = StoreProcessManager(
            upstreamBaseURL: base,
            deviceID: deviceID
        )
        let viewModel = StoreViewModel(
            api: APIClient(baseURL: base),
            vault: vault,
            processes: manager,
            deviceID: deviceID,
            deviceName: deviceName
        )
        _model = StateObject(wrappedValue: viewModel)
        terminationDelegate.shutdownHandler = { [weak viewModel] in
            await viewModel?.prepareForApplicationTermination() ?? false
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView(model: model).task { await model.restoreSession() }
        }
    }
}
