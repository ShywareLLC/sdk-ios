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
            path: "Sources/ShywareSDK",
            resources: [
                // wasm_exec.js, zk-prover.html, zk-prover.wasm (cmd/zk-prover-wasm,
                // unchanged) -- hosted in a WKWebView's real JavaScriptCore JIT,
                // not WasmKit's pure interpreter, which measured 3000x+ too slow
                // for a real Groth16 Prove() call (see
                // ShywareLLC/core/cmd/zk-prover-wasi/main.go's doc comment).
                // .copy, not .process: these are consumed as literal files by
                // WKWebView.loadFileURL, not compiled as app resources.
                .copy("Resources/zkweb")
            ]
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
