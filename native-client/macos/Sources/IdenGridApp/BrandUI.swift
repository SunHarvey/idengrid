import AppKit
import SwiftUI

enum BrandPalette {
    static let navy = Color(red: 11 / 255, green: 23 / 255, blue: 57 / 255)
    static let blue = Color(red: 49 / 255, green: 92 / 255, blue: 255 / 255)
    static let aqua = Color(red: 40 / 255, green: 199 / 255, blue: 183 / 255)
    static let ink = Color(red: 16 / 255, green: 24 / 255, blue: 43 / 255)
    static let slate = Color(red: 102 / 255, green: 115 / 255, blue: 139 / 255)
    static let mist = Color(red: 244 / 255, green: 247 / 255, blue: 251 / 255)
    static let white = Color.white
}

struct BrandSymbolImage: View {
    let asset: BrandAsset
    var fallbackSystemName = "square.grid.2x2"

    var body: some View {
        if let image = Self.bundledImage(asset) {
            Image(nsImage: image)
                .resizable()
                .antialiased(true)
                .aspectRatio(contentMode: .fit)
        } else {
            Image(systemName: fallbackSystemName)
                .resizable()
                .aspectRatio(contentMode: .fit)
        }
    }

    private static func bundledImage(_ asset: BrandAsset) -> NSImage? {
        guard let url = Bundle.main.url(forResource: asset.rawValue, withExtension: "png", subdirectory: "Brand") else {
            return nil
        }
        return NSImage(contentsOf: url)
    }
}

struct BrandPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .fontWeight(.semibold)
            .foregroundStyle(BrandPalette.white)
            .padding(.horizontal, 18)
            .padding(.vertical, 9)
            .background(configuration.isPressed ? BrandPalette.navy : BrandPalette.blue)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct BrandHeaderButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .fontWeight(.semibold)
            .foregroundStyle(BrandPalette.white)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(
                BrandPalette.white.opacity(configuration.isPressed ? 0.24 : 0.12)
            )
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(BrandPalette.white.opacity(0.28), lineWidth: 1)
            }
    }
}

struct BrandStoreCloseButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .fontWeight(.semibold)
            .foregroundStyle(isEnabled ? Color.red : BrandPalette.slate.opacity(0.55))
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
            .background(
                isEnabled
                    ? Color.red.opacity(configuration.isPressed ? 0.16 : 0.08)
                    : BrandPalette.slate.opacity(0.06)
            )
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(
                        isEnabled ? Color.red.opacity(0.42) : BrandPalette.slate.opacity(0.18),
                        lineWidth: 1
                    )
            }
    }
}

struct BrandLoginButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 16, weight: .semibold))
            .foregroundStyle(BrandPalette.white)
            .frame(maxWidth: .infinity)
            .frame(height: 46)
            .background(
                isEnabled
                    ? (configuration.isPressed ? BrandPalette.navy : BrandPalette.blue)
                    : BrandPalette.blue.opacity(0.55)
            )
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

private struct BrandLoginFieldModifier: ViewModifier {
    let isFocused: Bool
    let hasTrailingAccessory: Bool

    func body(content: Content) -> some View {
        content
            .foregroundStyle(BrandPalette.ink)
            .padding(.leading, 14)
            .padding(.trailing, hasTrailingAccessory ? 44 : 14)
            .frame(height: 50)
            .background(BrandPalette.white)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(
                        isFocused ? BrandPalette.blue : BrandPalette.slate.opacity(0.28),
                        lineWidth: isFocused ? 2 : 1
                    )
            }
            .shadow(
                color: isFocused ? BrandPalette.blue.opacity(0.16) : Color.clear,
                radius: 4
            )
    }
}

extension View {
    func brandLoginField(
        isFocused: Bool,
        hasTrailingAccessory: Bool = false
    ) -> some View {
        modifier(
            BrandLoginFieldModifier(
                isFocused: isFocused,
                hasTrailingAccessory: hasTrailingAccessory
            )
        )
    }
}

struct BrandCard<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(.horizontal, 30)
            .padding(.vertical, 36)
            .background(BrandPalette.white)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(BrandPalette.blue.opacity(0.12), lineWidth: 1)
            }
            .shadow(color: BrandPalette.navy.opacity(0.10), radius: 24, y: 10)
    }
}
