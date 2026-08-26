// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "IdenGrid",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "IdenGrid", targets: ["IdenGridApp"])],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.4")
    ],
    targets: [
        .executableTarget(name: "IdenGridApp", dependencies: [.product(name: "Sparkle", package: "Sparkle")], path: "Sources/IdenGridApp")
    ]
)
