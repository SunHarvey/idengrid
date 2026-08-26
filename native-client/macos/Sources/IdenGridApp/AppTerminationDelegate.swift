import AppKit

@MainActor
final class AppTerminationDelegate: NSObject, NSApplicationDelegate {
    var shutdownHandler: (() async -> Bool)?
    private var terminationInProgress = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if terminationInProgress { return .terminateLater }
        terminationInProgress = true
        Task { @MainActor [weak self] in
            guard let self else {
                sender.reply(toApplicationShouldTerminate: false)
                return
            }
            let success = await shutdownHandler?() ?? false
            terminationInProgress = false
            sender.reply(toApplicationShouldTerminate: success)
        }
        return .terminateLater
    }
}
