enum BrandPaletteHex {
    static let navy = "#0B1739"
    static let blue = "#315CFF"
    static let aqua = "#28C7B7"
    static let ink = "#10182B"
    static let slate = "#66738B"
    static let mist = "#F4F7FB"
    static let white = "#FFFFFF"
}

enum BrandAsset: String, CaseIterable {
    case appSymbol = "idengrid-256"
    case inverseSymbol = "idengrid-mono-light-512"

    static let runtimePNGNames = allCases.map(\.rawValue)
}

enum LoginPresentation {
    static let toastDurationSeconds = 2.5

    static func buttonTitle(isBusy: Bool) -> String {
        isBusy ? "登录中…" : "登录"
    }

    static func loginFailureMessage(statusCode: Int?) -> String {
        if statusCode == 401 || statusCode == 403 {
            return "用户名或者密码错误"
        }
        return "登录失败，请稍后重试"
    }

    static func inlineStatus(_ status: String, isBusy: Bool) -> String? {
        if isBusy || status == "已退出登录" { return nil }
        return status
    }

    static func toastMessage(_ status: String) -> String? {
        status == "已退出登录" ? status : nil
    }
}
