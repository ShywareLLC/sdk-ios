import Foundation
#if canImport(WebKit)
import WebKit

/// Hosts cmd/zk-prover-wasm (the GOOS=js GOARCH=wasm build, unchanged) inside
/// a real WKWebView -- its JavaScriptCore engine is a real JIT compiler
/// Apple permits its own sandboxed WebKit code to run, a fundamentally
/// different performance class from WasmKit's pure interpreter (which
/// exists specifically because iOS blocks THIRD-PARTY JIT -- a restriction
/// that doesn't apply to Apple's own WebKit).
///
/// Why this exists instead of a native WASI runtime: measured live,
/// 2026-10-05 -- a real Groth16 Prove() call via WasmKit (WASI) was still
/// running after 8+ minutes of 100% CPU before being killed; the identical
/// call via this WebView approach (validated first via a Node/V8 harness,
/// same JS-engine family as WKWebView/Android WebView) completed in ~400ms,
/// matching native Go's ~144ms. See ShywareLLC/core/cmd/zk-prover-wasi/main.go's
/// doc comment for the full finding. `person_secret` never leaves this
/// WKWebView's own JS context -- only the values callers explicitly pass
/// into the methods below, or the JS side's own computed results, cross the
/// native/JS boundary via `evaluateJavaScript`.
///
/// One instance per prover session is enough -- the underlying WASM module
/// stays loaded (it blocks forever via `select{}` on the Go side, by
/// design, to keep its exposed globals alive) for the lifetime of this
/// object's WKWebView. Construct once, reuse for every
/// commitment/nullifier/proof call in that session, rather than recreating
/// per call.
@available(iOS 15.0, macOS 12.0, *)
public final class WebViewZKProver: NSObject {
    private let webView: WKWebView
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var isReady = false

    public enum ProverError: Error, LocalizedError {
        case resourceNotFound
        case jsError(String)
        case unexpectedResultShape(Any?)

        public var errorDescription: String? {
            switch self {
            case .resourceNotFound: return "zk-prover.html not found in ShywareSDK's bundled resources"
            case .jsError(let message): return "ZK prover JS error: \(message)"
            case .unexpectedResultShape(let value): return "Unexpected result from ZK prover JS: \(String(describing: value))"
            }
        }
    }

    public override init() {
        let config = WKWebViewConfiguration()
        self.webView = WKWebView(frame: .zero, configuration: config)
        super.init()
    }

    /// Loads zk-prover.html (and its co-located wasm_exec.js/zk-prover.wasm,
    /// via `allowingReadAccessTo` on the containing directory) and waits for
    /// the page's own `shywareReadyPromise` to resolve. Call once before any
    /// other method; safe to call again (a no-op) if already ready.
    public func prepare() async throws {
        if isReady { return }
        guard let htmlURL = Bundle.module.url(
            forResource: "zk-prover", withExtension: "html", subdirectory: "zkweb"
        ) else {
            throw ProverError.resourceNotFound
        }
        let directoryURL = htmlURL.deletingLastPathComponent()

        webView.navigationDelegate = self
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            self.readyContinuation = continuation
            self.webView.loadFileURL(htmlURL, allowingReadAccessTo: directoryURL)
        }

        // Poll for window.shywareZKReady here, once, rather than having
        // every evalZKCall evaluate `window.shywareReadyPromise.then(...)`:
        // WKWebView.evaluateJavaScript DOES await a returned Promise (unlike
        // Android's WebView.evaluateJavascript, which does not -- see
        // sdk-android's WebViewZKProver.kt for the bug that difference
        // caused there), but relying on that platform-specific behavior
        // when the same result is achievable with one shared pattern on
        // both platforms isn't worth the inconsistency.
        while true {
            let ready = try await webView.evaluateJavaScript("!!window.shywareZKReady")
            if (ready as? Bool) == true { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        isReady = true
    }

    public func computeCommitment(personSecret: String) async throws -> String {
        let escaped = Self.jsStringLiteral(personSecret)
        let result = try await evalZKCall("shywareZKComputeCommitment(\(escaped))")
        return try Self.extractValue(result)
    }

    public func computeNullifier(personSecret: String, pollId: String) async throws -> String {
        let args = "\(Self.jsStringLiteral(personSecret)), \(Self.jsStringLiteral(pollId))"
        let result = try await evalZKCall("shywareZKComputeNullifier(\(args))")
        return try Self.extractValue(result)
    }

    public struct ProveResult {
        public let proofBase64: String
        public let commitmentHex: String
        public let nullifierHex: String
    }

    /// `provingKeyBase64` is a large value (hundreds of KB) -- passed as a
    /// JS string literal via evaluateJavaScript, which has no meaningful
    /// size limit for this purpose (confirmed against the same size class
    /// in the Node/V8 validation harness this design is based on).
    public func prove(personSecret: String, pollId: String, provingKeyBase64: String) async throws -> ProveResult {
        let args = "\(Self.jsStringLiteral(personSecret)), \(Self.jsStringLiteral(pollId)), \(Self.jsStringLiteral(provingKeyBase64))"
        let result = try await evalZKCall("shywareZKProve(\(args))")
        guard let dict = result as? [String: Any],
              let proof = dict["proof"] as? String,
              let commitment = dict["commitment"] as? String,
              let nullifier = dict["nullifier"] as? String
        else {
            throw ProverError.unexpectedResultShape(result)
        }
        return ProveResult(proofBase64: proof, commitmentHex: commitment, nullifierHex: nullifier)
    }

    // MARK: - Private

    /// Evaluates `jsCall`, which must be one of the `shywareZK*` globals
    /// zk-prover-wasm exposes -- all of which return a plain `{ok, value}`
    /// or `{ok, error}` object synchronously, not a Promise (confirmed
    /// against cmd/zk-prover-wasm/main.go's actual js.FuncOf return
    /// values). Callers must have already awaited `prepare()` -- readiness
    /// is established there, once, not re-checked per call.
    private func evalZKCall(_ jsCall: String) async throws -> Any? {
        let result = try await webView.evaluateJavaScript(jsCall)
        guard let dict = result as? [String: Any], let ok = dict["ok"] as? Bool else {
            throw ProverError.unexpectedResultShape(result)
        }
        if !ok {
            throw ProverError.jsError(dict["error"] as? String ?? "unknown error")
        }
        return dict["value"]
    }

    private static func extractValue(_ result: Any?) throws -> String {
        guard let value = result as? String else {
            throw ProverError.unexpectedResultShape(result)
        }
        return value
    }

    /// Encodes a Swift string as a JS double-quoted string literal via
    /// JSONSerialization (handles escaping correctly, including embedded
    /// quotes/backslashes/newlines -- person_secret and the base64 proving
    /// key are opaque data, not assumed to be free of any particular
    /// character).
    private static func jsStringLiteral(_ s: String) -> String {
        let data = try! JSONSerialization.data(withJSONObject: [s])
        let json = String(decoding: data, as: UTF8.self)
        // json is `["<escaped s>"]` -- strip the surrounding array brackets.
        return String(json.dropFirst().dropLast())
    }
}

@available(iOS 15.0, macOS 12.0, *)
extension WebViewZKProver: WKNavigationDelegate {
    public func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        readyContinuation?.resume(returning: ())
        readyContinuation = nil
    }

    public func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        readyContinuation?.resume(throwing: error)
        readyContinuation = nil
    }

    public func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        readyContinuation?.resume(throwing: error)
        readyContinuation = nil
    }
}
#endif
