import CryptoKit
import Foundation
import Security

// MARK: - Result types

public struct AccountResult: Codable, Sendable {
    public let accountCommitment: String
    public let txJson: String?
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case accountCommitment = "accountId"   // service returns camelCase "accountId"
        case txJson            = "txJson"
        case ok
    }
}

public struct TransferResult: Codable, Sendable {
    /// Canonical on-chain List 1 identifier — `transfer_id = H(transfer_nonce)`.
    /// Matches the server canonical field name. Alias `submissionId` retained for
    /// SDK-level callers that prefer the cross-domain term.
    public let transferId: String
    public let submissionNonce: String
    public let nullifier: String
    public let txJson: String?

    /// Cross-domain alias for `transferId` (matches web SDK `wireSubmission` return).
    public var submissionId: String { transferId }

    enum CodingKeys: String, CodingKey {
        case transferId      = "transferId"      // service returns camelCase
        case submissionNonce = "submissionNonce"
        case nullifier
        case txJson          = "txJson"
    }

    public init(transferId: String, submissionNonce: String, nullifier: String, txJson: String?) {
        self.transferId = transferId
        self.submissionNonce = submissionNonce
        self.nullifier = nullifier
        self.txJson = txJson
    }
}

public struct SupplyResult: Codable, Sendable {
    public let assetId: String
    public let totalSupply: Int64
    public let circulatingSupply: Int64

    /// Consumer-domain alias for `totalSupply` used by shywire-USDCe deployments.
    public var totalUSDCe: Int64 { totalSupply }

    enum CodingKeys: String, CodingKey {
        case assetId           = "assetId"           // camelCase from service
        case totalSupply       = "totalUSDCe"        // service returns "totalUSDCe"
        case circulatingSupply = "circulatingSupply"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        assetId = (try? c.decodeIfPresent(String.self, forKey: .assetId)) ?? ""
        totalSupply = (try? c.decodeIfPresent(Int64.self, forKey: .totalSupply)) ?? 0
        circulatingSupply = (try? c.decodeIfPresent(Int64.self, forKey: .circulatingSupply)) ?? totalSupply
    }
}

public struct CountResult: Codable, Sendable {
    public let transferId: String
    public let count: Int64
    /// List 1 record count for this scoping id.
    public let l1Count: Int64
    /// List 2 record count for this scoping id.
    public let l2Count: Int64
    /// `count_match` invariant — `l1Count == l2Count`.
    public let countMatch: Bool

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case count
        case l1Count    = "l1_count"
        case l2Count    = "l2_count"
        case countMatch = "count_match"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transferId = (try? c.decodeIfPresent(String.self, forKey: .transferId)) ?? ""
        // Accept either flat `count` (single record) or `l1_count`/`l2_count`
        // pair (full canonical count-match response). Both forms are returned
        // by shywire backends depending on the route.
        let l1 = try? c.decodeIfPresent(Int64.self, forKey: .l1Count)
        let l2 = try? c.decodeIfPresent(Int64.self, forKey: .l2Count)
        let flat = try? c.decodeIfPresent(Int64.self, forKey: .count)
        l1Count = l1 ?? flat ?? 0
        l2Count = l2 ?? flat ?? 0
        count = flat ?? l1 ?? 0
        if let cm = try? c.decodeIfPresent(Bool.self, forKey: .countMatch) {
            countMatch = cm
        } else {
            countMatch = l1Count == l2Count
        }
    }
}

public struct FeedResult: Decodable, Sendable {
    public let records: [TransferRecord]
    public let total: Int64?

    enum CodingKeys: String, CodingKey {
        case records = "entries"   // canonical feed returns "entries"
        case transfers             // history endpoint returns "transfers"
        case total
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        records = (try? c.decodeIfPresent([TransferRecord].self, forKey: .records))
               ?? (try? c.decodeIfPresent([TransferRecord].self, forKey: .transfers))
               ?? []
        total = try? c.decodeIfPresent(Int64.self, forKey: .total)
    }
}

public struct TransferRecord: Codable, Sendable {
    public let transferId: String
    public let scopingId: String
    public let nullifier: String
    public let amount: Int64
    public let timestamp: Int64

    /// Consumer-domain alias for `amount` used by shywire-USDCe deployments.
    /// Returns `nil` when the canonical L1 record omits amount (Claim 5).
    public let amountUSDCe: Int64?
    /// Sender uid — always `nil` on canonical L1 records (Claim 5). Exposed
    /// for completeness in reconciling-authority responses that may include it.
    public let senderUid: String?

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case scopingId  = "scoping_id"
        case nullifier
        case amount
        case timestamp
        case amountUSDCe = "amount_usdce"
        case senderUid   = "sender_uid"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transferId = (try? c.decodeIfPresent(String.self, forKey: .transferId)) ?? ""
        scopingId  = (try? c.decodeIfPresent(String.self, forKey: .scopingId)) ?? ""
        nullifier  = (try? c.decodeIfPresent(String.self, forKey: .nullifier)) ?? ""
        amount     = (try? c.decodeIfPresent(Int64.self, forKey: .amount)) ?? 0
        timestamp  = (try? c.decodeIfPresent(Int64.self, forKey: .timestamp)) ?? 0
        amountUSDCe = try? c.decodeIfPresent(Int64.self, forKey: .amountUSDCe)
        senderUid   = try? c.decodeIfPresent(String.self, forKey: .senderUid)
    }
}

public struct AttestationResult: Codable, Sendable {
    public let scopingId: String
    public let l1MerkleRoot: String
    public let l2MerkleRoot: String
    public let signature: String
    public let attestedAt: Int64

    /// Alias for `signature` (HSM-signed period-close attestation).
    public var attestation: String { signature }

    enum CodingKeys: String, CodingKey {
        case scopingId    = "scopingId"
        case l1MerkleRoot = "l1MerkleRoot"
        case l2MerkleRoot = "l2MerkleRoot"
        case signature    = "attestation"   // service returns "attestation"
        case attestedAt   = "attestedAt"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        scopingId    = (try? c.decodeIfPresent(String.self, forKey: .scopingId)) ?? ""
        l1MerkleRoot = (try? c.decodeIfPresent(String.self, forKey: .l1MerkleRoot)) ?? ""
        l2MerkleRoot = (try? c.decodeIfPresent(String.self, forKey: .l2MerkleRoot)) ?? ""
        // Accept either canonical `signature` or legacy `attestation` from older
        // consumer ledgers.
        if let s = try? c.decodeIfPresent(String.self, forKey: .signature) {
            signature = s
        } else {
            signature = ""
        }
        attestedAt = (try? c.decodeIfPresent(Int64.self, forKey: .attestedAt)) ?? 0
    }
}

public struct RescindResult: Codable, Sendable {
    public let transferId: String
    public let rescinded: Bool

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case rescinded
    }
}

// MARK: - Wire receipt (Keychain-backed)

public struct WireReceipt: Codable, Sendable {
    public let transferId: String
    public let submissionNonce: String
    public let nullifier: String
    public let scopingId: String
    public let amount: Int64
    public let submittedAt: Date

    public init(transferId: String, submissionNonce: String, nullifier: String,
                scopingId: String, amount: Int64, submittedAt: Date = Date()) {
        self.transferId      = transferId
        self.submissionNonce = submissionNonce
        self.nullifier       = nullifier
        self.scopingId       = scopingId
        self.amount          = amount
        self.submittedAt     = submittedAt
    }
}

// MARK: - Manifest validation

public func assertWireManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shywire-v1" || config.contractVersion == "shylots-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shywire-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    let required: Set<String> = ["wire_issue", "wire_transfer", "wire_redeem"]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required wire flow: \(flow)")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
}

// MARK: - WireClient

public actor WireClient {
    public nonisolated let manifest: ShyConfig
    private let session: URLSession
    private let receiptStore: KeychainReceiptStore

    public static func from(_ config: ShyConfig) throws -> WireClient {
        try assertWireManifest(config)
        return WireClient(manifest: config)
    }

    private init(manifest: ShyConfig) {
        self.manifest     = manifest
        self.session      = URLSession.shared
        self.receiptStore = KeychainReceiptStore(appId: manifest.app.id)
    }

    // MARK: - Account

    public func registerAccount(walletAddress: String) async throws -> AccountResult {
        let commitment = sha256hex("account:\(manifest.identity.provider):\(walletAddress.lowercased())")
        let nonce      = randomHex(32)
        let proof      = Data((commitment + ":" + walletAddress).utf8).base64EncodedString()
        let body: [String: Any] = [
            "account_commitment": commitment,
            "wallet_proof": proof,
            "enrollment_token": "",
            "enrollment_proof": ""
        ]
        let tx: [String: Any] = ["type": 5, "signature": "AQ==", "data": body]
        let txJson = try jsonString(tx)
        return try await post("/api/wire/accounts", body: ["tx": txJson])
    }

    // MARK: - Transfer

    /// Pure construction — no network call.
    public func buildTransfer(
        scopingId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) -> TransferResult {
        let nonce     = randomHex(32)
        let nullifier = sha256hex("\(senderCommitment):\(scopingId):\(nonce)")
        let submissionId = sha256hex(nonce)
        let data: [String: Any] = [
            "asset_id":             scopingId,
            "sender_commitment":    senderCommitment,
            "recipient_commitment": recipientCommitment,
            "amount":               amount,
            "nullifier":            nullifier,
            "submission_nonce":     nonce,
            "sender_proof":         "AQ==",
            "timestamp":            Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 4, "signature": "AQ==", "data": data]
        let txJson = (try? jsonString(tx)) ?? "{}"
        return TransferResult(
            transferId: submissionId,
            submissionNonce: nonce,
            nullifier: nullifier,
            txJson: txJson
        )
    }

    public func wireSubmission(
        scopingId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) async throws -> TransferResult {
        let result = buildTransfer(
            scopingId: scopingId,
            senderCommitment: senderCommitment,
            recipientCommitment: recipientCommitment,
            amount: amount
        )
        guard let txJson = result.txJson else {
            throw ShywareError.invalidInput("Failed to build transfer tx")
        }
        let _: EmptyResponse = try await post("/api/wire/transfer", body: ["tx": txJson])
        let receipt = WireReceipt(
            transferId: result.transferId,
            submissionNonce: result.submissionNonce,
            nullifier: result.nullifier,
            scopingId: scopingId,
            amount: Int64(amount)
        )
        try? receiptStore.saveWire(receipt)
        return result
    }

    // MARK: - Supply / feeds

    public func getSupply() async throws -> SupplyResult {
        return try await get("/api/wire/supply")
    }

    public func getCanonicalCount(transferId: String) async throws -> CountResult {
        return try await get("/api/wire/canonical/count/\(transferId)")
    }

    public func getCanonicalFeed() async throws -> FeedResult {
        return try await get("/api/wire/reconcile/feed")
    }

    public func getReconcileHistory() async throws -> [TransferRecord] {
        let response: FeedResult = try await get("/api/wire/reconcile/history")
        return response.records
    }

    // MARK: - Period close

    public func periodClose(
        scopingId: String,
        l1MerkleRoot: String,
        l2MerkleRoot: String
    ) async throws -> AttestationResult {
        let body: [String: Any] = [
            "scopingId":    scopingId,
            "l1MerkleRoot": l1MerkleRoot,
            "l2MerkleRoot": l2MerkleRoot,
            "timestamp":    Int(Date().timeIntervalSince1970)
        ]
        return try await post("/api/wire/period-close", body: body)
    }

    // MARK: - Rescind

    public func rescind(transferId: String, eligibilityToken: String) async throws -> RescindResult {
        let body: [String: Any] = [
            "transfer_id":       transferId,
            "eligibility_token": eligibilityToken
        ]
        return try await post("/api/wire/rescind/\(transferId)", body: body)
    }

    // MARK: - Receipt

    public func loadReceipt(transferId: String) throws -> WireReceipt? {
        try receiptStore.loadWire(transferId: transferId)
    }

    // MARK: - HTTP helpers

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = try resolveURL(path, useSubmit: false)
        let req = URLRequest(url: url)
        let (data, response) = try await fetch(req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let url = try resolveURL(path, useSubmit: true)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await fetch(req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // Use dataTask (callback-based) so URLProtocol subclasses registered via
    // URLProtocol.registerClass() are correctly called. The async URLSession.data(for:)
    // API does not reliably invoke registered protocol classes on all macOS versions.
    private func fetch(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            session.dataTask(with: request) { data, response, error in
                if let error = error { continuation.resume(throwing: error); return }
                guard let data = data, let response = response else {
                    continuation.resume(throwing: URLError(.badServerResponse)); return
                }
                continuation.resume(returning: (data, response))
            }.resume()
        }
    }

    private func resolveURL(_ path: String, useSubmit: Bool) throws -> URL {
        let rawBase = useSubmit
            ? (manifest.api.submitBaseURL ?? manifest.api.baseURL)
            : manifest.api.baseURL
        let base = rawBase.hasSuffix("/") ? String(rawBase.dropLast()) : rawBase
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        return url
    }

    private func validate(response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw ShywareError.apiError("HTTP \(http.statusCode)")
        }
    }
}

// MARK: - Keychain extension for WireReceipt

extension KeychainReceiptStore {
    private var wireService: String { service + ".wire" }

    func saveWire(_ receipt: WireReceipt) throws {
        let data = try JSONEncoder().encode(receipt)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: wireService,
            kSecAttrAccount: receipt.transferId,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainReceiptStore.ReceiptStoreError.keychainFailure(status)
        }
    }

    func loadWire(transferId: String) throws -> WireReceipt? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: wireService,
            kSecAttrAccount: transferId,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return try JSONDecoder().decode(WireReceipt.self, from: data)
    }
}

// MARK: - Private utilities

private struct EmptyResponse: Decodable {}

private func jsonString(_ value: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value)
    return String(decoding: data, as: UTF8.self)
}
