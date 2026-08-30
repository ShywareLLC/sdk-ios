import CryptoKit
import Foundation

// MARK: - Result types

public struct ContractResult: Codable, Sendable {
    public let contractId: String
    public let contractHash: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case contractId   = "contract_id"
        case contractHash = "contract_hash"
        case ok
    }
}

public struct ExecutionResult: Codable, Sendable {
    public let executionId: String
    public let nullifier: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case executionId = "execution_id"
        case nullifier
        case ok
    }
}

public struct Contract: Codable, Sendable {
    public let contractId: String
    public let assetId: String?
    public let contractType: String
    public let contractHash: String
    public let parties: [ContractParty]
    public let status: String
    public let timestamp: Int64

    enum CodingKeys: String, CodingKey {
        case contractId   = "contract_id"
        case assetId      = "asset_id"
        case contractType = "contract_type"
        case contractHash = "contract_hash"
        case parties, status, timestamp
    }
}

public struct ContractParty: Codable, Sendable {
    public let role: String
    public let commitment: String
    public let allocationBps: Int
    public let seniority: Int

    enum CodingKeys: String, CodingKey {
        case role, commitment
        case allocationBps = "allocation_bps"
        case seniority
    }
}

public struct ContractState: Codable, Sendable {
    public let contractId: String
    public let status: String
    public let executionCount: Int64
    public let lastExecutedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case contractId      = "contract_id"
        case status
        case executionCount  = "execution_count"
        case lastExecutedAt  = "last_executed_at"
    }
}

// MARK: - Manifest validation

public func assertContractsManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shycontracts-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shycontracts-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
    let required: Set<String> = ["contract_register", "contract_activate", "contract_execute"]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required contracts flow: \(flow)")
    }
    // transfer_layer, if declared, must be "shywire"
    // (checked at build time via ShyFullConfig.resolvedContracts.transferLayer)
}

// MARK: - ContractsClient

public actor ContractsClient {
    public nonisolated let manifest: ShyConfig
    private let session: URLSession

    public static func from(_ config: ShyConfig) throws -> ContractsClient {
        try assertContractsManifest(config)
        return ContractsClient(manifest: config)
    }

    private init(manifest: ShyConfig) {
        self.manifest = manifest
        self.session  = URLSession.shared
    }

    // MARK: - Contract lifecycle

    public func registerContract(
        assetId: String,
        parties: [[String: Any]],
        contractType: String,
        termsRef: String? = nil
    ) async throws -> ContractResult {
        let timestamp = Int(Date().timeIntervalSince1970)
        // Build a stable hash from type + parties + termsRef
        let hashInput = "\(contractType):\(parties.map { ($0["commitment"] as? String) ?? "" }.joined(separator: ",")):\(termsRef ?? ""):\(timestamp)"
        let contractHash = sha256hex(hashInput)
        let contractId   = sha256hex(contractHash + ":" + randomHex(16))
        let data: [String: Any] = [
            "contract_id":   contractId,
            "asset_id":      assetId,
            "contract_type": contractType,
            "contract_hash": contractHash,
            "parties":       parties,
            "timestamp":     timestamp
        ]
        let tx: [String: Any] = ["type": 7, "signature": "AQ==", "data": data]
        let txJson = try jsonStringContracts(tx)
        let _: EmptyContractsResponse = try await post("/contracts", body: ["tx": txJson])
        return ContractResult(contractId: contractId, contractHash: contractHash, ok: true)
    }

    public func activateContract(contractId: String) async throws {
        let evidenceHash = sha256hex("operator_activation:\(contractId)")
        let data: [String: Any] = [
            "contract_id":   contractId,
            "evidence_hash": evidenceHash,
            "evidence_type": "operator_attestation",
            "activated_at":  Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 9, "signature": "AQ==", "data": data]
        let txJson = try jsonStringContracts(tx)
        let _: EmptyContractsResponse = try await post("/contracts/activate", body: ["tx": txJson])
    }

    public func executeContract(
        contractId: String,
        partyCommitment: String,
        counterpartyCommitment: String,
        sourceRef: String,
        amount: Int? = nil
    ) async throws -> ExecutionResult {
        let nonce     = randomHex(32)
        let nullifier = sha256hex("\(partyCommitment):\(contractId):\(sourceRef)")
        let executionId = sha256hex(nonce)
        var data: [String: Any] = [
            "contract_id":             contractId,
            "party_commitment":        partyCommitment,
            "counterparty_commitment": counterpartyCommitment,
            "execution_type":          "execution",
            "source_ref":              sourceRef,
            "nullifier":               nullifier,
            "transfer_nonce":          nonce,
            "timestamp":               Int(Date().timeIntervalSince1970)
        ]
        if let amount {
            data["amount"] = amount
        }
        let tx: [String: Any] = ["type": 8, "signature": "AQ==", "data": data]
        let txJson = try jsonStringContracts(tx)
        let _: EmptyContractsResponse = try await post("/contracts/executions", body: ["tx": txJson])
        return ExecutionResult(executionId: executionId, nullifier: nullifier, ok: true)
    }

    // MARK: - Read

    public func getContract(contractId: String) async throws -> Contract {
        return try await get("/contracts/\(contractId)")
    }

    public func getContractState(contractId: String) async throws -> ContractState {
        return try await get("/contracts/\(contractId)/state")
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

private struct EmptyContractsResponse: Decodable {}

private func jsonStringContracts(_ value: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value)
    return String(decoding: data, as: UTF8.self)
}
