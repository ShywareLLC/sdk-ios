import CryptoKit
import Foundation

// MARK: - Result types

public struct LotResult: Codable, Sendable {
    public let lotId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case lotId = "lot_id"
        case ok
    }
}

public struct SiloResult: Codable, Sendable {
    public let assetId: String
    public let accountCommitment: String
    public let amount: Int64
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case assetId            = "asset_id"
        case accountCommitment  = "account_commitment"
        case amount
        case ok
    }
}

public struct SiloTransferResult: Codable, Sendable {
    public let transferId: String
    public let nullifier: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case nullifier
        case ok
    }
}

public struct RedemptionResult: Codable, Sendable {
    public let requestId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case ok
    }
}

public struct BalanceResult: Codable, Sendable {
    public let assetId: String
    public let accountCommitment: String
    public let balance: Int64

    enum CodingKeys: String, CodingKey {
        case assetId           = "asset_id"
        case accountCommitment = "account_commitment"
        case balance
    }
}

public struct LotPolicy: Codable, Sendable {
    public let policyId: String
    public let assetId: String
    public let name: String
    public let redemptionMode: String
    public let redemptionRouting: String
    public let demurrageRateBps: Int
    public let operatorFeeBps: Int

    enum CodingKeys: String, CodingKey {
        case policyId          = "policy_id"
        case assetId           = "asset_id"
        case name
        case redemptionMode    = "redemption_mode"
        case redemptionRouting = "redemption_routing"
        case demurrageRateBps  = "demurrage_rate_bps"
        case operatorFeeBps    = "operator_fee_bps"
    }
}

// MARK: - Manifest validation

public func assertCustodyManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shycustody-v1" || config.contractVersion == "shylots-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shycustody-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
    let required: Set<String> = [
        "policy_read", "lot_record", "silo_transfer",
        "redemption_request", "redemption_settlement", "demurrage_apply"
    ]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required custody flow: \(flow)")
    }
}

// MARK: - CustodyClient

public actor CustodyClient {
    public nonisolated let manifest: ShyConfig
    private let session: URLSession

    /// `transfer_layer` is optional; if declared it must be "shywire".
    public static func from(_ config: ShyConfig) throws -> CustodyClient {
        try assertCustodyManifest(config)
        return CustodyClient(manifest: config)
    }

    private init(manifest: ShyConfig) {
        self.manifest = manifest
        self.session  = URLSession.shared
    }

    // MARK: - Lot intake

    public func recordIntakeLot(
        lotId: String,
        policyId: String,
        assetId: String,
        operatorId: String,
        warehouseId: String,
        accountCommitment: String,
        skuClassId: String,
        quantity: Int,
        mintedAmount: Int,
        videoSessionRef: String,
        evidenceRefs: [String]
    ) async throws -> LotResult {
        let data: [String: Any] = [
            "lot_id":             lotId,
            "policy_id":          policyId,
            "asset_id":           assetId,
            "operator_id":        operatorId,
            "warehouse_id":       warehouseId,
            "account_commitment": accountCommitment,
            "sku_class_id":       skuClassId,
            "quantity":           quantity,
            "minted_amount":      mintedAmount,
            "video_session_ref":  videoSessionRef,
            "evidence_refs":      evidenceRefs,
            "timestamp":          Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 13, "signature": "AQ==", "data": data]
        let txJson = try jsonString(tx)
        return try await post("/custody/lots", body: ["tx": txJson])
    }

    // MARK: - Silo operations

    public func mintSilo(
        assetId: String,
        accountCommitment: String,
        amount: Int
    ) async throws -> SiloResult {
        let data: [String: Any] = [
            "asset_id":           assetId,
            "account_commitment": accountCommitment,
            "amount":             amount,
            "timestamp":          Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 2, "signature": "AQ==", "data": data]
        let txJson = try jsonString(tx)
        return try await post("/mint", body: ["tx": txJson])
    }

    public func transferSilo(
        assetId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) async throws -> SiloTransferResult {
        let nonce     = randomHex(32)
        let nullifier = sha256hex("\(senderCommitment):\(assetId):\(nonce)")
        let transferId = sha256hex(nonce)
        let data: [String: Any] = [
            "asset_id":             assetId,
            "sender_commitment":    senderCommitment,
            "recipient_commitment": recipientCommitment,
            "amount":               amount,
            "nullifier":            nullifier,
            "transfer_nonce":       nonce,
            "sender_proof":         "AQ==",
            "timestamp":            Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 4, "signature": "AQ==", "data": data]
        let txJson = try jsonString(tx)
        let _: EmptyCustodyResponse = try await post("/transfers", body: ["tx": txJson])
        return SiloTransferResult(transferId: transferId, nullifier: nullifier, ok: true)
    }

    // MARK: - Redemption

    public func requestLotRedemption(
        assetId: String,
        accountCommitment: String,
        warehouseId: String,
        skuClassId: String,
        siloAmount: Int,
        requestedQuantity: Int
    ) async throws -> RedemptionResult {
        let requestId = sha256hex(randomHex(8) + ":\(Int(Date().timeIntervalSince1970))")
        let data: [String: Any] = [
            "request_id":         requestId,
            "asset_id":           assetId,
            "account_commitment": accountCommitment,
            "warehouse_id":       warehouseId,
            "sku_class_id":       skuClassId,
            "silo_amount":        siloAmount,
            "requested_quantity": requestedQuantity,
            "destination_ref":    "",
            "timestamp":          Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 14, "signature": "AQ==", "data": data]
        let txJson = try jsonString(tx)
        return try await post("/custody/redemptions", body: ["tx": txJson])
    }

    // MARK: - Balance / policy

    public func getSiloBalance(assetId: String, accountCommitment: String) async throws -> BalanceResult {
        return try await get("/balance/\(assetId)/\(accountCommitment)")
    }

    public func getLotPolicy(policyId: String) async throws -> LotPolicy {
        return try await get("/custody/policies/\(policyId)")
    }

    // MARK: - Period close

    public func periodClose(
        scopingId: String,
        l1MerkleRoot: String,
        l2MerkleRoot: String
    ) async throws -> AttestationResult {
        let body: [String: Any] = [
            "scoping_id":     scopingId,
            "l1_merkle_root": l1MerkleRoot,
            "l2_merkle_root": l2MerkleRoot,
            "timestamp":      Int(Date().timeIntervalSince1970)
        ]
        return try await post("/period-close", body: body)
    }

    // MARK: - HTTP

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = try resolveURL(path, useSubmit: false)
        let req = URLRequest(url: url)
        let (data, response) = try await session.data(for: req)
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
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
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

// MARK: - Private utilities

private struct EmptyCustodyResponse: Decodable {}

private func jsonString(_ value: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value)
    return String(decoding: data, as: UTF8.self)
}
