# @shyware/sdk-ios

Swift package for the Shyware SDK — iOS/macOS client.

> **Early access.** The `DPIAHelpers` target ships DPIA stack-5 protocol verification helpers. A full consumer-facing iOS SDK is in development.

## What it does

Provides `DPIAHelpers` — a Swift library of assertion utilities used to verify structural invariant compliance (two-list write, rejection predicate, count-match) against a live or mock Shyware node from iOS/macOS test suites.

The `DPIASdkProtocol` test target runs the stack-5 DPIA evidence suite: 14 suites, 385 assertions covering the write-kernel, vote-write, and cover-traffic families.

## Requirements

- Swift 5.9+
- macOS 13+ / iOS 16+
- Xcode 15+

## Installation

### Swift Package Manager

```swift
.package(url: "https://github.com/ShywareLLC/sdk-ios.git", from: "0.4.0")
```

Then add `DPIAHelpers` to your target dependencies:

```swift
.target(
    name: "MyTarget",
    dependencies: [
        .product(name: "DPIAHelpers", package: "sdk-ios")
    ]
)
```

## Quick start

```swift
import DPIAHelpers

// Verify rejection predicate over a test node
let result = try await ShywareDPIARunner.run(node: nodeURL, suite: .writeKernel)
assert(result.passed == result.total)
```

Full documentation: [docs.shyware.fyi](https://docs.shyware.fyi)

## License

Evaluation use only. Production deployment requires a Commercial License.
See [LICENSE](./LICENSE) and [shyware.fyi/legal](https://shyware.fyi/legal/).

Patent Pending, U.S. App. No. 64/074,348.
Copyright © 2026 Nicholas Carducci / Shyware LLC.
