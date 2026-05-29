// swift-tools-version: 5.9
// Shyware SDK — Swift package exposing DPIAHelpers for Stack 5 DPIA consumer tests
import PackageDescription

let package = Package(
    name: "web",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "DPIAHelpers", targets: ["DPIAHelpers"]),
    ],
    dependencies: [
        .package(path: "../ios"),
    ],
    targets: [
        .target(
            name: "DPIAHelpers",
            path: "Sources/DPIAHelpers"
        ),
        // SDK protocol invariant suite — no consumer dependency, no network
        .testTarget(
            name: "DPIASdkProtocol",
            dependencies: [
                "DPIAHelpers",
                .product(name: "ShywareSDK", package: "ios"),
            ],
            path: "tests/swift"
        ),
    ]
)
