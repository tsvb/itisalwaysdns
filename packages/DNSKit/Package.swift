// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DNSKit",
    // The engine is intentionally portable; only the app target needs macOS 26.
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "DNSKit", targets: ["DNSKit"]),
        // CLI is named `idns` (not `iiadns`) so it doesn't collide with the
        // app's `iiadns` scheme when the app links this package via xcodebuild.
        .executable(name: "idns", targets: ["idns"]),
    ],
    targets: [
        // The DNS engine: wire-format codec, transport, resolver, system config.
        // Zero external dependencies on purpose — it stays embeddable and auditable.
        .target(
            name: "DNSKit",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // A mini-dig that wraps DNSKit. Doubles as a headless validation harness.
        .executableTarget(
            name: "idns",
            dependencies: ["DNSKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "DNSKitTests",
            dependencies: ["DNSKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
