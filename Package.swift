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
    ],
    targets: [
        .target(
            name: "ShywareSDK",
            path: "Sources/ShywareSDK"
        ),
        .testTarget(
            name: "ShywareSDKTests",
            dependencies: ["ShywareSDK"],
            path: "Tests/ShywareSDKTests"
        ),
    ]
)
