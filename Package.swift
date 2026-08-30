// swift-tools-version: 5.9
// Shyware SDK — Swift/iOS client
import PackageDescription

let package = Package(
    name: "ShywareSDK",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "ShywareSDK", targets: ["ShywareSDK"]),
        .library(name: "DPIAHelpers", targets: ["DPIAHelpers"]),
    ],
    targets: [
        .target(
            name: "ShywareSDK",
            path: "Sources/ShywareSDK"
        ),
        .target(
            name: "DPIAHelpers",
            path: "Sources/DPIAHelpers",
            exclude: ["dpia_test_helpers.kt"]
        ),
        .testTarget(
            name: "ShywareSDKTests",
            dependencies: ["ShywareSDK"],
            path: "Tests/ShywareSDKTests"
        ),
    ]
)
