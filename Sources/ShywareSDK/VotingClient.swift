import CryptoKit
import Foundation
import Security

// MARK: - Result types

public struct BallotResult: Sendable {
    public let ballotId: String
    public let ballotNonce: String
    public let identityHash: String
    public let txJson: String
}

public struct ReceiptVerification: Sendable {
    public let verified: Bool
    public let ballotId: String
    public let matchedChoice: String?
}

// MARK: - Manifest validation
// Mirrors assertVotingManifest in votingClient.js

public func assertVotingManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shyvoting-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shyvoting-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    let required: Set<String> = ["poll_read", "ballot_build", "ballot_submit", "receipt_verify"]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required flow: \(flow)")
    }
    guard config.identity.provider != "none" else {
        throw ShywareError.invalidManifest("A real identity provider is required")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
}

// MARK: - Posture override

/// Response from the deployment's optional `deployment.posture_endpoint`.
/// The operator (reconciling authority / admin) writes this server-side;
/// all clients read it on init. Acts as a global kill switch or open switch.
public struct PostureOverride: Decodable, Sendable {
    /// `"write_only"` | `"recoverable"` | `nil` (no active override — use manifest default)
    public let posture: String?
    /// `"operator"` — informational, for UI labeling.
    public let source: String?
}

// MARK: - Client

/// A closure that, given raw request body data, returns an App Attest assertion.
/// Takes `requestData` (typically the POST body or URL bytes for GET requests),
/// and returns the raw assertion bytes to be base64-encoded into `X-App-Attest-Assertion`.
public typealias ShyAssertionProvider = (Data) async throws -> Data

public actor VotingClient {
    public nonisolated let manifest: ShyConfig
    private var signals: RuntimeSignals
    private let receiptStore: KeychainReceiptStore
    private let session: URLSession
    private let assertionProvider: ShyAssertionProvider?

    /// Operator-pushed posture. Fetched from `deployment.posture_endpoint` on init.
    /// Wins over user preference, runtime fallbacks, and manifest default.
    private var operatorPosture: String?

    /// User's local posture preference. Wins over runtime fallbacks and manifest
    /// default, but loses to operator override. Stored in UserDefaults per app ID.
    /// Nil means "follow the system" (operator + fallbacks decide).
    private var userPostureKey: String { "shyware.\(manifest.app.id).userPosture" }
    public var userPosturePreference: String? {
        get { UserDefaults.standard.string(forKey: userPostureKey) }
    }

    /// Create a client from a validated shyconfig.
    /// - Parameter assertionProvider: Required when `api.auth_scheme == "app_attest"`.
    ///   The closure receives raw request data and must return assertion bytes.
    ///   Use `AppAttestProvider.assert(requestData:)` or wrap your own `AppAttestService`.
    public static func from(_ shyconfig: ShyConfig, assertionProvider: ShyAssertionProvider? = nil) throws -> VotingClient {
        try assertVotingManifest(shyconfig)
        return VotingClient(manifest: shyconfig, assertionProvider: assertionProvider)
    }

    private init(manifest: ShyConfig, assertionProvider: ShyAssertionProvider?) {
        self.manifest = manifest
        self.signals = .untrusted
        self.receiptStore = KeychainReceiptStore(appId: manifest.app.id)
        self.session = URLSession.shared
        self.assertionProvider = assertionProvider
    }

    // MARK: - Posture

    public func setRuntimeSignals(_ s: RuntimeSignals) {
        signals = s
    }

    /// Fetches the operator-pushed posture from `deployment.posture_endpoint` if configured.
    /// Call after `setRuntimeSignals` during initialization. Silently no-ops if no endpoint.
    public func fetchOperatorPosture() async {
        guard let path = manifest.deployment.postureEndpoint else { return }
        let base = manifest.api.baseURL.hasSuffix("/")
            ? String(manifest.api.baseURL.dropLast()) : manifest.api.baseURL
        guard let url = URL(string: base + path) else { return }
        var req = URLRequest(url: url)
        try? await injectAuth(&req, requestData: Data(url.absoluteString.utf8))
        guard let (data, _) = try? await session.data(for: req),
              let override = try? JSONDecoder().decode(PostureOverride.self, from: data)
        else { return }
        operatorPosture = override.posture
    }

    /// User opts into a specific posture locally. Pass `nil` to revert to system default.
    /// Only takes effect when `deployment.allow_user_posture_override` is true.
    public func setUserPosture(_ posture: String?) {
        guard manifest.deployment.allowUserPostureOverride else { return }
        UserDefaults.standard.set(posture, forKey: userPostureKey)
    }

    /// Resolves posture with full precedence stack:
    ///   operator override > user preference > runtime fallbacks > manifest default
    public func effectivePosture() -> PostureResult {
        // Start from manifest + runtime signals
        var result = resolveEffectivePosture(manifest: manifest, signals: signals)

        // User preference applies only in non-hostile contexts (no active fallback reasons
        // from device/network signals). A hostile-environment client cannot opt into
        // recoverable posture — only into write-only (which the fallbacks already enforce).
        let signalFallbackActive = result.fallbackReasons.contains(where: {
            $0 == "untrusted_device_attestation" || $0 == "missing_play_integrity" || $0 == "hostile_network"
        })
        if let userPref = UserDefaults.standard.string(forKey: userPostureKey),
           manifest.deployment.allowUserPostureOverride,
           operatorPosture == nil,
           !signalFallbackActive || userPref == "write_only" {
            let isWriteOnly = userPref == "write_only"
            result = PostureResult(
                configuredPosture: result.configuredPosture,
                effectivePosture: isWriteOnly ? "write_only" : "recoverable",
                fallbackActive: isWriteOnly,
                fallbackReasons: isWriteOnly ? ["user_preference"] : []
            )
        }

        // Operator override wins unconditionally
        if let op = operatorPosture {
            result = PostureResult(
                configuredPosture: result.configuredPosture,
                effectivePosture: op,
                fallbackActive: op == "write_only",
                fallbackReasons: op == "write_only" ? ["operator_override"] : []
            )
        }

        return result
    }

    // MARK: - Read

    public func getAllPolls() async throws -> [Poll] {
        let response: PollsResponse = try await get("/api/vote/polls")
        return response.polls
    }

    public func getPoll(_ id: String) async throws -> Poll {
        return try await get("/api/vote/polls/\(id)")
    }

    public func getTally(_ id: String) async throws -> Tally {
        return try await get("/api/vote/polls/\(id)/count")
    }

    public func getVotes(_ id: String) async throws -> [VoteRecord] {
        let response: VotesResponse = try await get("/api/vote/reconcile/ballot?pollId=\(id)")
        return response.votes
    }

    // MARK: - Build

    public func buildBallot(pollId: String, choice: String, input: IdentityInput) async throws -> BallotResult {
        let nonce = randomHex(32)
        let ballotId = sha256hex(nonce)
        let commitment = try createIdentityCommitment(manifest: manifest, input: input)
        let identityHash = sha256hex(commitment + pollId)

        let payload: [String: Any] = [
            "poll_id": pollId,
            "identity_hash": identityHash,
            "choice": choice,
            "ballot_nonce": nonce,
            "timestamp": Int(Date().timeIntervalSince1970),
        ]
        let envelope: [String: Any] = ["type": 2, "signature": "AQ==", "data": payload]
        let txData = try JSONSerialization.data(withJSONObject: envelope)
        let txJson = String(decoding: txData, as: UTF8.self)

        return BallotResult(ballotId: ballotId, ballotNonce: nonce, identityHash: identityHash, txJson: txJson)
    }

    // MARK: - Submit

    public func submitBallot(pollId: String, choice: String) async throws {
        try await post("/api/vote/cast", body: ["pollId": pollId, "direction": choice])
    }

    public func flushQueuedBallots(pollId: String) async throws {
        try await post("/polls/\(pollId)/flush", body: [:] as [String: String])
    }

    public func castBallot(pollId: String, choice: String, input: IdentityInput) async throws -> BallotResult {
        let result = try await buildBallot(pollId: pollId, choice: choice, input: input)
        try await submitBallot(pollId: pollId, choice: choice)

        let posture = effectivePosture()
        if !posture.writeOnly {
            let receipt = BallotReceipt(
                pollId: pollId,
                ballotId: result.ballotId,
                ballotNonce: result.ballotNonce,
                choice: choice,
                identityHash: result.identityHash
            )
            try? receiptStore.save(receipt)
        }
        return result
    }

    // MARK: - Verify

    public func verifyReceipt(nonce: String, expectedChoice: String, votes: [VoteRecord]) -> ReceiptVerification {
        let ballotId = sha256hex(nonce)
        let match = votes.first { $0.ballotId == ballotId && $0.choices.contains(expectedChoice) }
        return ReceiptVerification(
            verified: match != nil,
            ballotId: ballotId,
            matchedChoice: match?.choices.first
        )
    }

    public func loadReceipt(pollId: String) throws -> BallotReceipt? {
        try receiptStore.load(pollId: pollId)
    }

    // MARK: - HTTP

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let base = manifest.api.baseURL.hasSuffix("/")
            ? String(manifest.api.baseURL.dropLast())
            : manifest.api.baseURL
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        var req = URLRequest(url: url)
        try await injectAuth(&req, requestData: Data(url.absoluteString.utf8))
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let submitBase = manifest.api.submitBaseURL ?? manifest.api.baseURL
        let base = submitBase.hasSuffix("/") ? String(submitBase.dropLast()) : submitBase
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        req.httpBody = bodyData
        try await injectAuth(&req, requestData: bodyData)
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func post(_ path: String, body: [String: Any]) async throws {
        let submitBase = manifest.api.submitBaseURL ?? manifest.api.baseURL
        let base = submitBase.hasSuffix("/") ? String(submitBase.dropLast()) : submitBase
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        req.httpBody = bodyData
        try await injectAuth(&req, requestData: bodyData)
        let (_, response) = try await session.data(for: req)
        try validate(response: response)
    }

    /// Injects authentication into a request based on api.auth_scheme.
    ///
    /// - `app_attest`: calls `assertionProvider(requestData)` and attaches the
    ///   base64-encoded assertion as `X-App-Attest-Assertion`. Fails silently if
    ///   the provider is nil — the server will reject unauthenticated requests.
    /// - `firebase_bearer`: no-op here; the caller (SwiftUI/ViewModel layer)
    ///   is responsible for setting `Authorization: Bearer <idToken>` on the
    ///   `URLSession` or on each request before it reaches this client.
    private func injectAuth(_ req: inout URLRequest, requestData: Data) async throws {
        guard manifest.api.requiresAuth, manifest.api.authScheme == "app_attest" else { return }
        guard let provider = assertionProvider else { return }
        if let assertion = try? await provider(requestData) {
            req.setValue(assertion.base64EncodedString(), forHTTPHeaderField: "X-App-Attest-Assertion")
        }
    }

    private func validate(response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw ShywareError.apiError("HTTP \(http.statusCode)")
        }
    }
}

// MARK: - Errors

public enum ShywareError: Error, LocalizedError {
    case invalidManifest(String)
    case invalidInput(String)
    case apiError(String)
    case http(statusCode: Int, message: String)

    public var errorDescription: String? {
        switch self {
        case .invalidManifest(let m): return "Invalid shyconfig manifest: \(m)"
        case .invalidInput(let m):    return "Invalid input: \(m)"
        case .apiError(let m):        return "API error: \(m)"
        case .http(let code, let m):  return "HTTP \(code): \(m)"
        }
    }

    /// HTTP status code, if this error encodes one. Parses both the explicit
    /// `.http(statusCode:)` case and the legacy `.apiError("HTTP <code>")`
    /// message form so callers can branch uniformly.
    public var statusCode: Int? {
        switch self {
        case .http(let code, _): return code
        case .apiError(let m):
            let prefix = "HTTP "
            guard m.hasPrefix(prefix) else { return nil }
            let tail = m.dropFirst(prefix.count)
            let digits = tail.prefix(while: { $0.isNumber })
            return Int(digits)
        default: return nil
        }
    }

    public var isHTTP400: Bool { statusCode == 400 }
    public var isHTTP401: Bool { statusCode == 401 }
    public var isHTTP404: Bool { statusCode == 404 }
    public var isHTTP409: Bool { statusCode == 409 }
    public var isHTTP503: Bool { statusCode == 503 }
}

// randomHex is defined in CryptoUtils.swift (module-internal)
