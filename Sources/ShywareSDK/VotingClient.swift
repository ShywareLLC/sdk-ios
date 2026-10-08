import CryptoKit
import Foundation
import Security

// MARK: - Result types

public struct BallotResult: Sendable {
    public let ballotId: String
    public let ballotNonce: String
    public let identityHash: String
    public let txJson: String
    /// Required to ever recompute ballotId again (verifyReceipt, or a future
    /// buildBallotUpdate call) -- ballotId is SHA-256(beacon||nonce), not
    /// SHA-256(nonce) alone, so the beacon used for THIS submission has to
    /// be persisted alongside the nonce. See deriveSubmissionIdHex.
    public let beaconBlockHash: String
    public init(ballotId: String, ballotNonce: String, identityHash: String, txJson: String, beaconBlockHash: String) {
        self.ballotId = ballotId
        self.ballotNonce = ballotNonce
        self.identityHash = identityHash
        self.txJson = txJson
        self.beaconBlockHash = beaconBlockHash
    }

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

/// A closure that, given raw request body data, returns the value to send verbatim
/// as the `X-Attest-Token` header (UTF-8-encoded). Takes `requestData` (typically
/// the POST body or URL bytes for GET requests).
///
/// For App Attest, the real server's verifier (ShywareLLC/core
/// `services/attest/verifier.go` `AppAttestVerifier.Verify`) expects the token in
/// the form `"<keyID>:<assertionBase64>:<requestHashHex>"` — see
/// `AppAttestProvider.attestToken(requestData:)`, which builds exactly this string.
public typealias ShyAssertionProvider = (Data) async throws -> Data

/// Supplies a fresh Firebase ID token on demand (e.g.
/// `{ try await Auth.auth().currentUser?.getIDToken() }`). Independent of
/// `ShyAssertionProvider`/`api.auth_scheme` -- see the doc comment on
/// `firebaseIDTokenProvider` in `VotingClient.from` for why these are two
/// separate, stackable server-side gates rather than alternative "auth
/// schemes", despite `api.auth_scheme` suggesting a single choice.
public typealias ShyFirebaseIDTokenProvider = () async throws -> String?

public actor VotingClient {
    public nonisolated let manifest: ShyConfig
    private var signals: RuntimeSignals
    private let receiptStore: KeychainReceiptStore
    private let voterKeyStore: KeychainVoterKeyStore
    private let session: URLSession
    private let assertionProvider: ShyAssertionProvider?
    private let firebaseIDTokenProvider: ShyFirebaseIDTokenProvider?
    private let enclaveClient: EnclaveAttestationClient?
    private var sessionReceipts: [String: BallotReceipt] = [:]
    private var sessionVoterKeys: [String: Curve25519.Signing.PrivateKey] = [:]

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
    /// - Parameter firebaseIDTokenProvider: Pass when the relay is deployed with
    ///   `--firebase-creds`, which wraps *every* POST route (including `/ballots`)
    ///   in an unconditional Firebase-JWT check (`middleware.FirebaseAuth.OnWrites`
    ///   in `ShywareLLC/core`) regardless of `api.auth_scheme`. This is a separate,
    ///   stackable server-side gate from the device-attestation check inside
    ///   `submitBallot` itself (`s.attester`, controlled by whether the relay was
    ///   given `--ios-app-attest-team-id`) -- `api.auth_scheme` only describes which
    ///   *device*-attestation mechanism this client uses, not whether the relay's
    ///   outer Firebase gate is active, so don't assume setting `auth_scheme:
    ///   "app_attest"` means this provider is unnecessary. Found live 2026-10-03:
    ///   a deployment with `auth_scheme: "app_attest"` and device-attestation
    ///   enforcement intentionally still off (no `--ios-app-attest-team-id`) had
    ///   every real `castBallot` call 401 at this exact gate, because nothing set
    ///   this header -- `app_attest`'s own `assertionProvider` only ever sets
    ///   `X-Attest-Token`, never `Authorization`. Required for a deployment outside
    ///   a sanctioned/coercion-resistant jurisdiction, where attestation enforcement
    ///   is reserved for that posture rather than used as this deployment's write
    ///   gate; not a privacy regression for canonical state (which stays exactly as
    ///   unlinkable either way) -- it does expose "this Firebase UID submitted to
    ///   this poll at this time" to the relay's own request log, an accepted
    ///   tradeoff for this deployment, not a change to what's ever written on-chain.
    public static func from(
        _ shyconfig: ShyConfig,
        assertionProvider: ShyAssertionProvider? = nil,
        firebaseIDTokenProvider: ShyFirebaseIDTokenProvider? = nil,
        storageScope: String? = nil,
        session: URLSession = .shared
    ) throws -> VotingClient {
        try assertVotingManifest(shyconfig)
        return VotingClient(manifest: shyconfig, assertionProvider: assertionProvider, firebaseIDTokenProvider: firebaseIDTokenProvider, storageScope: storageScope, session: session)
    }

    private init(manifest: ShyConfig, assertionProvider: ShyAssertionProvider?, firebaseIDTokenProvider: ShyFirebaseIDTokenProvider?, storageScope: String?, session: URLSession) {
        self.manifest = manifest
        self.signals = .untrusted
        self.receiptStore = KeychainReceiptStore(appId: manifest.app.id, storageScope: storageScope)
        self.voterKeyStore = KeychainVoterKeyStore(appId: manifest.app.id, storageScope: storageScope)
        self.session = session
        self.assertionProvider = assertionProvider
        self.firebaseIDTokenProvider = firebaseIDTokenProvider
        // Deployment-specific: each Shyware consumer configures its own
        // attestation-service endpoint in its own shyconfig. `enclaveClient`
        // is nil (and buildBallot's Didit-attestation path is unavailable)
        // for deployments that haven't configured one, rather than silently
        // falling back to any hardcoded default.
        if let baseURL = manifest.identity.attestationServiceBaseURL {
            let pinnedHost = URL(string: baseURL)?.host
            self.enclaveClient = EnclaveAttestationClient(
                baseURL: baseURL,
                pinnedHost: pinnedHost,
                pinnedSPKISHA256Base64: manifest.identity.attestationServiceTLSPinSHA256Base64
            )
        } else {
            self.enclaveClient = nil
        }
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
    ///   runtime safety fallbacks > operator override > user preference > manifest default
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

        // Operators may restrict retention, but cannot relax active safety fallbacks.
        if let op = operatorPosture, !signalFallbackActive || op == "write_only" {
            result = PostureResult(
                configuredPosture: result.configuredPosture,
                effectivePosture: op,
                fallbackActive: op == "write_only",
                fallbackReasons: op == "write_only" ? ["operator_override"] : []
            )
        }

        return result
    }

    /// Erases the caller's off-chain recovery index and encrypted recovery secret.
    /// This requires server-verified Firebase authentication and leaves canonical records intact.
    public func deleteRecoveryData() async throws {
        let _: [String: Bool] = try await post("/recovery/delete", body: [String: String]())
    }

    // MARK: - Read
    //
    // Routes below match the real Go server exactly — see
    // ShywareLLC/core api/server/router.go `Router()`:
    //   GET  /polls
    //   GET  /polls/{poll_id}
    //   GET  /polls/{poll_id}/tally
    //   GET  /polls/{poll_id}/votes

    public func getAllPolls() async throws -> [Poll] {
        let response: PollsResponse = try await get("/polls")
        return response.polls
    }

    public func getPoll(_ id: String) async throws -> Poll {
        return try await get("/polls/\(id)")
    }

    public func getTally(_ id: String) async throws -> Tally {
        return try await get("/polls/\(id)/tally")
    }

    public func getVoterCount(_ id: String) async throws -> Int64 {
        struct Response: Decodable { let count: Int64 }
        let response: Response = try await get("/polls/\(id)/voters")
        return response.count
    }

    public func getVotes(_ id: String) async throws -> [VoteRecord] {
        let response: VotesResponse = try await get("/polls/\(id)/votes")
        return response.votes
    }

    // MARK: - Beacon
    //
    // Decodes the CometBFT `/status` payload proxied verbatim by the real
    // server's GET /health (ShywareLLC/core api/server/router.go `health`).
    // Used to populate beacon_block_hash / beacon_block_height on a ballot: the
    // state machine's beacon window (ShywareLLC/core protocol/submission/nonce.go
    // ValidateBeacon) requires these to name a block that was already canonical
    // before the submission nonce was generated.
    private struct CometStatusResponse: Decodable {
        struct SyncInfo: Decodable {
            let latestBlockHash: String
            let latestBlockHeight: String
            enum CodingKeys: String, CodingKey {
                case latestBlockHash = "latest_block_hash"
                case latestBlockHeight = "latest_block_height"
            }
        }
        struct Result: Decodable {
            let syncInfo: SyncInfo
            enum CodingKeys: String, CodingKey { case syncInfo = "sync_info" }
        }
        let result: Result
    }

    private func fetchBeacon() async throws -> (hash: String, height: Int64) {
        let status: CometStatusResponse = try await get("/health")
        guard let height = Int64(status.result.syncInfo.latestBlockHeight) else {
            throw ShywareError.apiError("Invalid latest_block_height in /health response")
        }
        // CometBFT's RPC serializes block hashes as uppercase hex. The Go state
        // machine's beacon window stores hex.EncodeToString output, which is
        // always lowercase (ShywareLLC/core app/app.go: RecordBeacon(req.Height,
        // hex.EncodeToString(req.Hash))). ValidateBeacon does an exact string
        // comparison, so this must be normalized to lowercase or every ballot
        // fails beacon validation at flush time.
        let hash = status.result.syncInfo.latestBlockHash.lowercased()
        return (hash, height)
    }

    // MARK: - Build

    /// Builds a fully signed TxTypeBallotCast envelope matching the real server's
    /// wire schema exactly (ShywareLLC/core protocol/tx/tx.go `BallotCastData`).
    ///
    /// Device signature (oracle-forgery prevention): a fresh per-poll Ed25519
    /// keypair is generated on-device. Its private key signs
    /// `submission_nonce + ":" + scoping_id` locally and is never transmitted or
    /// retained — only `voter_pub_key` (hex) and `voter_sig` (base64) leave this
    /// method. This matches ShywareLLC/core domain/state/ballots.go
    /// `voterDeviceSigMessage` / `validateBallotCast` exactly, so the IDV provider
    /// — which never holds this private key — cannot forge a ballot even though
    /// it attests the resulting public key (see the idv_attestation_sig TODO below).
    public func buildBallot(
        pollId: String,
        choice: String,
        input: IdentityInput,
        diditSessionId: String? = nil
    ) async throws -> BallotResult {
        let nonce = randomHex(32)

        // Per-poll Ed25519 keypair -- persisted in the Keychain and reused
        // across calls for the same pollId, not regenerated fresh every
        // time. Generating fresh on every call means every retry after a
        // transient failure looks like a different voter to the IDV
        // attestation enclave's one-time-use-per-poll replay guard,
        // permanently orphaning that poll for the underlying Didit session
        // on the very first failed attempt, regardless of whether the
        // ballot itself ever reached canonical state. Confirmed live
        // 2026-10-03: this was happening on every single poll tested.
        let voterKey = try voterKey(for: pollId)
        let voterPubKeyHex = voterKey.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let deviceMessage = Data((nonce + ":" + pollId).utf8)
        let voterSig = try voterKey.signature(for: deviceMessage)

        // identity_hash is enclave-attested (sha256(didit_document_key ||
        // poll_id), computed inside the enclave from Didit's id_verification
        // document data -- this device never sees the document data behind
        // it). Populated below once the enclave call returns; used both on
        // the wire (required for the chain to verify idv_attestation_sig,
        // which covers it) and for the local receipt.
        var identityHash = ""

        let beacon = try await fetchBeacon()
        guard let ballotId = deriveSubmissionIdHex(beaconBlockHash: beacon.hash, nonceHex: nonce) else {
            throw ShywareError.invalidManifest("Could not derive ballotId from beacon.hash/nonce hex")
        }

        var data: [String: Any] = [
            "scoping_id": pollId,
            "choices": [choice],
            "submission_nonce": nonce,
            "beacon_block_hash": beacon.hash,
            "beacon_block_height": beacon.height,
            "timestamp": Int(Date().timeIntervalSince1970),
            "voter_pub_key": voterPubKeyHex,
            "voter_sig": voterSig.base64EncodedString(),
        ]

        // idv_attestation_sig: obtained from the IDV attestation enclave, an
        // independent OCI AMD SEV-SNP confidential-computing service that holds
        // its own Ed25519 signing keypair (never held by this app, the backend,
        // or any operator) and independently re-verifies the Didit session
        // against Didit's real session-status API before signing — see
        // EnclaveAttestationClient. `diditSessionId` must be the Didit
        // verification session_id backing this voter_pub_key; ShywareLLC/core's
        // domain/state/ballots.go rejects reuse of the same session_id across
        // any poll or voter_pub_key (on-chain, authoritative — see
        // State.consumedSessions), so a fresh registration always requires a
        // fresh (unconsumed) session.
        //
        // `input` is accepted for interface stability but not otherwise used —
        // the enclave, not this device, is the party attesting the keypair.
        _ = input
        if let diditSessionId, !diditSessionId.isEmpty {
            guard let enclaveClient else {
                throw ShywareError.invalidManifest(
                    "identity.attestation_service_base_url is not configured, but a Didit session_id was provided to buildBallot"
                )
            }
            let attestation = try await enclaveClient.attest(
                sessionId: diditSessionId,
                voterPubKeyHex: voterPubKeyHex,
                pollId: pollId
            )
            data["idv_attestation_sig"] = attestation.signature.base64EncodedString()
            data["didit_session_id"] = diditSessionId
            data["identity_hash"] = attestation.identityHash
            identityHash = attestation.identityHash
        }

        let envelope: [String: Any] = ["type": 2, "signature": "AQ==", "data": data]
        let txData = try JSONSerialization.data(withJSONObject: envelope)
        let txJson = String(decoding: txData, as: UTF8.self)

        return BallotResult(ballotId: ballotId, ballotNonce: nonce, identityHash: identityHash, txJson: txJson, beaconBlockHash: beacon.hash)
    }

    // MARK: - Build (update)

    /// Builds a fully signed TxTypeUpdateBallot envelope matching the real
    /// server's wire schema (ShywareLLC/core protocol/tx/tx.go `BallotUpdateData`).
    /// `newChoices: []` represents a rescission (withdrawal) rather than a
    /// replacement — matches the Go core's own convention.
    ///
    /// Reuses the SAME per-poll keypair as the original cast (via
    /// `voterKeyStore.keypair(forPollId:)`, which loads rather than
    /// regenerates) — required: the chain re-derives `identity_hash` from
    /// `voter_pub_key`, so a different key here would register as a
    /// different voter entirely, not an update to the existing one.
    ///
    /// Device signature message is `"update:" + newNonce + ":" + pollId`
    /// (matches `ballotrules.BallotUpdateDeviceSigMessage` in
    /// ShywareLLC/core/protocol/ballotrules/ballotrules.go) — the "update:"
    /// prefix is what stops a cast-time signature being replayed as an update.
    public func buildBallotUpdate(
        pollId: String,
        newChoices: [String],
        oldBallotId: String,
        diditSessionId: String? = nil
    ) async throws -> BallotResult {
        let nonce = randomHex(32)

        let voterKey = try voterKey(for: pollId)
        let voterPubKeyHex = voterKey.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let deviceMessage = Data(("update:" + nonce + ":" + pollId).utf8)
        let voterSig = try voterKey.signature(for: deviceMessage)

        // identity_hash is enclave-attested -- see buildBallot's identical comment above.
        var identityHash = ""
        let beacon = try await fetchBeacon()
        guard let ballotId = deriveSubmissionIdHex(beaconBlockHash: beacon.hash, nonceHex: nonce) else {
            throw ShywareError.invalidManifest("Could not derive ballotId from beacon.hash/nonce hex")
        }

        var data: [String: Any] = [
            "scoping_id": pollId,
            "old_submission_id": oldBallotId,
            "new_submission_nonce": nonce,
            "beacon_block_hash": beacon.hash,
            "beacon_block_height": beacon.height,
            "new_choices": newChoices,
            "timestamp": Int(Date().timeIntervalSince1970),
            "voter_pub_key": voterPubKeyHex,
            "voter_sig": voterSig.base64EncodedString(),
        ]

        // idv_attestation_sig is required unconditionally by the Go
        // verifier's VerifyAndIdentifyUpdate, same as at cast time — see
        // buildBallot's own comment above for the full rationale. The
        // enclave's replay guard is idempotent for the same (session_id,
        // poll_id, voter_pub_key) triple, so reusing the cast-time session
        // id here (when still on hand) works with no enclave changes.
        if let diditSessionId, !diditSessionId.isEmpty {
            guard let enclaveClient else {
                throw ShywareError.invalidManifest(
                    "identity.attestation_service_base_url is not configured, but a Didit session_id was provided to buildBallotUpdate"
                )
            }
            let attestation = try await enclaveClient.attest(
                sessionId: diditSessionId,
                voterPubKeyHex: voterPubKeyHex,
                pollId: pollId
            )
            data["idv_attestation_sig"] = attestation.signature.base64EncodedString()
            data["didit_session_id"] = diditSessionId
            data["identity_hash"] = attestation.identityHash
            identityHash = attestation.identityHash
        }

        let envelope: [String: Any] = ["type": 6, "signature": "AQ==", "data": data]
        let txData = try JSONSerialization.data(withJSONObject: envelope)
        let txJson = String(decoding: txData, as: UTF8.self)

        return BallotResult(ballotId: ballotId, ballotNonce: nonce, identityHash: identityHash, txJson: txJson, beaconBlockHash: beacon.hash)
    }

    // MARK: - Submit

    /// Submits an already-built, signed ballot envelope (from `buildBallot`) to
    /// the real server's `POST /ballots` (ShywareLLC/core api/server/router.go
    /// `submitBallot`), which expects exactly `{"tx": "<json-encoded Tx>"}`.
    public func submitBallot(txJson: String) async throws {
        try await post("/ballots", body: ["tx": txJson])
    }

    /// Matches the real server's `POST /polls/{poll_id}/flush`
    /// (ShywareLLC/core api/server/router.go `flushQueuedBallots`) — already
    /// correct; kept here for symmetry with the other route-aligned methods above.
    public func flushQueuedBallots(pollId: String) async throws {
        try await post("/polls/\(pollId)/flush", body: [:] as [String: String])
    }

    public func castBallot(
        pollId: String,
        choice: String,
        input: IdentityInput,
        diditSessionId: String? = nil
    ) async throws -> BallotResult {
        let result = try await buildBallot(pollId: pollId, choice: choice, input: input, diditSessionId: diditSessionId)
        try await submitBallot(txJson: result.txJson)

        do {
            let receipt = BallotReceipt(
                pollId: pollId,
                ballotId: result.ballotId,
                ballotNonce: result.ballotNonce,
                choice: choice,
                identityHash: result.identityHash,
                beaconBlockHash: result.beaconBlockHash
            )
            remember(receipt)
        }
        return result
    }

    /// Updates (replaces or rescinds, when `newChoices` is empty) a
    /// previously cast ballot for `pollId`. Requires a local receipt from
    /// the original cast (`receiptStore.load`) to supply `old_submission_id`
    /// — this is the device-receipt path (`router.go`'s `updateBallot`,
    /// `POST /ballots/update` with `{"tx": "<json Tx>"}`), not the
    /// server-reconciled path, since the client already holds its own
    /// receipt. Throws if no receipt exists for this poll on this device.
    @discardableResult
    public func updateBallot(
        pollId: String,
        newChoices: [String],
        diditSessionId: String? = nil
    ) async throws -> BallotResult {
        guard let receipt = try loadReceipt(pollId: pollId) else {
            throw ShywareError.invalidInput("No existing receipt for poll \(pollId) — cannot update a ballot that was never cast on this device")
        }
        let result = try await buildBallotUpdate(
            pollId: pollId,
            newChoices: newChoices,
            oldBallotId: receipt.ballotId,
            diditSessionId: diditSessionId
        )
        try await post("/ballots/update", body: ["tx": result.txJson])

        if newChoices.isEmpty {
            sessionReceipts.removeValue(forKey: pollId)
            receiptStore.delete(pollId: pollId)
        } else {
            let newReceipt = BallotReceipt(
                pollId: pollId,
                ballotId: result.ballotId,
                ballotNonce: result.ballotNonce,
                choice: newChoices[0],
                identityHash: result.identityHash,
                beaconBlockHash: result.beaconBlockHash
            )
            remember(newReceipt)
        }
        return result
    }

    /// Convenience: withdraw a previously cast ballot entirely.
    @discardableResult
    public func rescindBallot(pollId: String, diditSessionId: String? = nil) async throws -> BallotResult {
        try await updateBallot(pollId: pollId, newChoices: [], diditSessionId: diditSessionId)
    }

    // MARK: - Recovery (no local receipt)

    /// Attempts a server-reconciled ballot update — `POST /ballots/update`
    /// with a flat body (no `{"tx": ...}` wrapper, unlike `updateBallot`
    /// above) — for a participant whose `identity_hash` may already be
    /// registered on this poll from a DIFFERENT device or app install, even
    /// though this device holds no local receipt for it. This is real
    /// cross-device/reinstall recovery, not a new mechanism: `identity_hash`
    /// is already person-stable (derived from the verified document, not
    /// this device's keypair — see `buildBallot`'s doc comment), and
    /// ShywareLLC/core's `api/server/router.go` `updateBallot` has always
    /// supported looking up `old_submission_id` itself via its reconcile
    /// store given `scoping_id` + `identity_hash` alone; nothing server-side
    /// needed to change to make this reachable, only a client willing to
    /// call it.
    ///
    /// Returns `nil` — not an error — specifically when the server reports
    /// no matching receipt (its "no receipt found for this voter on poll"
    /// 404): that means this identity has genuinely never voted on this
    /// poll from any device, not that recovery failed. Any other failure
    /// (network, a real server error, an unapproved Didit session) propagates
    /// normally. Callers should fall through to a normal `castBallot` on a
    /// `nil` result — see `castOrRecoverBallot` below, which does exactly
    /// that using the same per-poll keypair.
    public func updateBallotReconciled(
        pollId: String,
        newChoices: [String],
        diditSessionId: String
    ) async throws -> BallotResult? {
        let nonce = randomHex(32)

        // Same per-poll keypair castBallot/updateBallot already use —
        // deterministic per (device, pollId), so a subsequent cast-fallback
        // call (if this returns nil) reuses the identical key and the
        // enclave sees the same (session_id, poll_id, voter_pub_key) triple
        // on both calls — its own replay guard treats that as an idempotent
        // retry, not a conflict (see idv-enclave/server.js's `/attest`
        // handler: "Same request retried ... idempotent, not an attack").
        let voterKey = try voterKey(for: pollId)
        let voterPubKeyHex = voterKey.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let deviceMessage = Data(("update:" + nonce + ":" + pollId).utf8)
        let voterSig = try voterKey.signature(for: deviceMessage)

        guard let enclaveClient else {
            throw ShywareError.invalidManifest(
                "identity.attestation_service_base_url is not configured, but reconciled recovery requires a fresh enclave attestation"
            )
        }
        let attestation = try await enclaveClient.attest(
            sessionId: diditSessionId,
            voterPubKeyHex: voterPubKeyHex,
            pollId: pollId
        )

        let beacon = try await fetchBeacon()
        guard let ballotId = deriveSubmissionIdHex(beaconBlockHash: beacon.hash, nonceHex: nonce) else {
            throw ShywareError.invalidManifest("Could not derive ballotId from beacon.hash/nonce hex")
        }

        // Flat, unwrapped body — router.go's reconciled branch decodes this
        // directly into {identity_hash} + tx.BallotUpdateData, then fills
        // old_submission_id itself and builds/broadcasts the real envelope
        // server-side. This device never learns (and doesn't need) the
        // original cast's ballot_id — that's the entire point of this path.
        let body: [String: Any] = [
            "identity_hash": attestation.identityHash,
            "scoping_id": pollId,
            "new_submission_nonce": nonce,
            "beacon_block_hash": beacon.hash,
            "beacon_block_height": beacon.height,
            "new_choices": newChoices,
            "timestamp": Int(Date().timeIntervalSince1970),
            "voter_pub_key": voterPubKeyHex,
            "voter_sig": voterSig.base64EncodedString(),
            "idv_attestation_sig": attestation.signature.base64EncodedString(),
            "didit_session_id": diditSessionId,
        ]

        do {
            try await post("/ballots/update", body: body)
        } catch let error as ShywareError where error.statusCode == 404 {
            return nil
        }

        let result = BallotResult(ballotId: ballotId, ballotNonce: nonce, identityHash: attestation.identityHash, txJson: "", beaconBlockHash: beacon.hash)
        if !newChoices.isEmpty {
            remember(BallotReceipt(
                pollId: pollId,
                ballotId: result.ballotId,
                ballotNonce: result.ballotNonce,
                choice: newChoices[0],
                identityHash: result.identityHash,
                beaconBlockHash: result.beaconBlockHash
            ))
        }
        return result
    }

    /// Casts a new ballot — unless this participant already has a vote
    /// registered on this poll from a different device/install with no
    /// local receipt here, in which case this recovers and updates that
    /// existing vote instead of hitting the chain's duplicate-vote
    /// rejection. See `updateBallotReconciled`'s doc comment for the
    /// recovery mechanism; this just sequences it ahead of a normal cast,
    /// sharing one per-poll keypair across both attempts.
    @discardableResult
    public func castOrRecoverBallot(
        pollId: String,
        choice: String,
        input: IdentityInput,
        diditSessionId: String
    ) async throws -> BallotResult {
        if effectivePosture().writeOnly {
            return try await castBallot(pollId: pollId, choice: choice, input: input, diditSessionId: diditSessionId)
        }
        if let recovered = try await updateBallotReconciled(pollId: pollId, newChoices: [choice], diditSessionId: diditSessionId) {
            return recovered
        }
        return try await castBallot(pollId: pollId, choice: choice, input: input, diditSessionId: diditSessionId)
    }

    // MARK: - Verify

    public func verifyReceipt(nonce: String, expectedChoice: String, votes: [VoteRecord], beaconBlockHash: String) -> ReceiptVerification {
        guard let ballotId = deriveSubmissionIdHex(beaconBlockHash: beaconBlockHash, nonceHex: nonce) else {
            return ReceiptVerification(verified: false, ballotId: "", matchedChoice: nil)
        }
        let match = votes.first { $0.ballotId == ballotId && $0.choices.contains(expectedChoice) }
        return ReceiptVerification(
            verified: match != nil,
            ballotId: ballotId,
            matchedChoice: match?.choices.first
        )
    }

    public func loadReceipt(pollId: String) throws -> BallotReceipt? {
        if let receipt = sessionReceipts[pollId] { return receipt }
        guard !effectivePosture().writeOnly else { return nil }
        return try receiptStore.load(pollId: pollId)
    }

    public func clearSession(deletePersisted: Bool = false) {
        sessionReceipts.removeAll()
        sessionVoterKeys.removeAll()
        if deletePersisted {
            receiptStore.deleteAll()
            voterKeyStore.deleteAll()
            UserDefaults.standard.removeObject(forKey: userPostureKey)
        }
    }

    private func remember(_ receipt: BallotReceipt) {
        sessionReceipts[receipt.pollId] = receipt
        if !effectivePosture().writeOnly { try? receiptStore.save(receipt) }
    }

    private func voterKey(for pollId: String) throws -> Curve25519.Signing.PrivateKey {
        if !effectivePosture().writeOnly { return try voterKeyStore.keypair(forPollId: pollId) }
        if let key = sessionVoterKeys[pollId] { return key }
        // Reuse an existing key to preserve enclave retry authorization, without a new write.
        let key = try voterKeyStore.existingKey(forPollId: pollId) ?? Curve25519.Signing.PrivateKey()
        sessionVoterKeys[pollId] = key
        return key
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
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        if path == "/ballots" || path == "/ballots/update" {
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw ShywareError.apiError("Invalid ballot submission response")
            }
            if let error = json["error"] { throw ShywareError.apiError("Ballot submission rejected: \(error)") }
            if json["queued"] as? Bool == true { return }
            guard let result = json["result"] as? [String: Any],
                  let check = result["check_tx"] as? [String: Any], let applied = result["tx_result"] as? [String: Any],
                  check["code"] as? Int == 0, applied["code"] as? Int == 0 else {
                throw ShywareError.apiError("The ledger did not accept this ballot")
            }
        }
    }

    /// Injects authentication into a request based on api.auth_scheme.
    ///
    /// - `app_attest`: calls `assertionProvider(requestData)` and sets its
    ///   UTF-8-decoded result verbatim as `X-Attest-Token`, plus
    ///   `X-Attest-Platform: "ios"`. These are the exact header names the real
    ///   server's middleware reads (ShywareLLC/core api/server/router.go
    ///   `submitBallot`: `r.Header.Get("X-Attest-Platform")` /
    ///   `r.Header.Get("X-Attest-Token")`). Fails silently if the provider is
    ///   nil — the server will reject unauthenticated requests (401, or
    ///   write-only fallback per the deployment's runtime_fallbacks).
    /// - `firebase_bearer`: historically a no-op here (see `firebaseIDTokenProvider`
    ///   below for why that was wrong in practice -- nothing outside this client
    ///   ever actually set the header this comment described).
    ///
    /// Device-attestation (`X-Attest-Token`) and the relay's outer Firebase gate
    /// (`Authorization: Bearer`) are independent checks -- both run below,
    /// unconditionally on whether `firebaseIDTokenProvider` was supplied,
    /// regardless of `api.auth_scheme`. See the doc comment on
    /// `firebaseIDTokenProvider` in `from(_:assertionProvider:firebaseIDTokenProvider:)`.
    private func injectAuth(_ req: inout URLRequest, requestData: Data) async throws {
        if effectivePosture().writeOnly { req.setValue("write_only", forHTTPHeaderField: "X-Shyware-Posture") }
        if manifest.api.requiresAuth, manifest.api.authScheme == "app_attest", let provider = assertionProvider,
           let token = try? await provider(requestData) {
            req.setValue(String(decoding: token, as: UTF8.self), forHTTPHeaderField: "X-Attest-Token")
            req.setValue("ios", forHTTPHeaderField: "X-Attest-Platform")
        }
        if let firebaseIDTokenProvider, let idToken = try await firebaseIDTokenProvider() {
            req.setValue("Bearer \(idToken)", forHTTPHeaderField: "Authorization")
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
