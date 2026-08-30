import CryptoKit
import Foundation

// MARK: - Result types

public struct ProposalResult: Codable, Sendable {
    public let proposalId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case proposalId   // service returns camelCase "proposalId" — matches property name
        case ok
    }
}

public struct SharesBallotResult: Codable, Sendable {
    public let ok: Bool?
    public let proposalId: String?
    public let ballotId: String
    public let ballotNonce: String?
    public let identityHash: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case proposalId         // camelCase from service
        case ballotId           // camelCase from service
        case ballotNonce        // camelCase from service
        case identityHash       // camelCase from service
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ok            = try? c.decodeIfPresent(Bool.self,   forKey: .ok)
        proposalId    = try? c.decodeIfPresent(String.self, forKey: .proposalId)
        ballotId      = (try? c.decodeIfPresent(String.self, forKey: .ballotId)) ?? ""
        ballotNonce   = try? c.decodeIfPresent(String.self, forKey: .ballotNonce)
        identityHash  = try? c.decodeIfPresent(String.self, forKey: .identityHash)
    }
}

public struct SharesTally: Codable, Sendable {
    public let proposalId: String
    public let counts: [String: Int64]
    public let totalVotes: Int64
    public let status: String

    enum CodingKeys: String, CodingKey {
        case proposalId = "proposal_id"
        case counts
        case totalVotes = "total_votes"
        case status
    }
}

public struct Action: Codable, Sendable {
    public let actionId: String
    public let proposalId: String
    public let adapter: String
    public let status: String
    public let queuedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case actionId   = "action_id"
        case proposalId = "proposal_id"
        case adapter, status
        case queuedAt   = "queued_at"
    }
}

public struct DispatchResult: Codable, Sendable {
    public let actionId: String
    public let dispatched: Bool

    enum CodingKeys: String, CodingKey {
        case actionId   = "action_id"
        case dispatched
    }
}

public struct MembershipSnapshot: Codable, Sendable {
    public let accountCommitment: String
    public let weight: Int64
    public let joinedAt: Int64?
    public let status: String

    enum CodingKeys: String, CodingKey {
        case accountCommitment = "account_commitment"
        case weight
        case joinedAt          = "joined_at"
        case status
    }
}

// MARK: - Manifest validation

public func assertSharesManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shyshares-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shyshares-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
    let required: Set<String> = [
        "organization_read", "membership_snapshot_read",
        "proposal_create", "weighted_ballot_submit",
        "tally_read", "action_queue_read", "action_dispatch"
    ]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required shares flow: \(flow)")
    }
}

// MARK: - SharesClient

public actor SharesClient {
    public nonisolated let manifest: ShyConfig
    private let session: URLSession

    /// `governance.transfer_layer` is optional; if declared it must be "shywire".
    public static func from(_ config: ShyConfig) throws -> SharesClient {
        try assertSharesManifest(config)
        return SharesClient(manifest: config)
    }

    private init(manifest: ShyConfig) {
        self.manifest = manifest
        self.session  = URLSession.shared
    }

    // MARK: - Proposals

    public func createProposal(
        proposalClass: String,
        question: String,
        options: [String],
        startTime: Int64,
        endTime: Int64
    ) async throws -> ProposalResult {
        let body: [String: Any] = [
            "title":   question,    // service uses "title" for the proposal question
            "options": options,
        ]
        return try await post("/api/shares/proposals", body: body)
    }

    // MARK: - Ballots

    public func submitWeightedBallot(
        proposalId: String,
        choice: String,
        accountCommitment: String
    ) async throws -> SharesBallotResult {
        let body: [String: Any] = [
            "proposal_id":        proposalId,
            "choice":             choice,
            "account_commitment": accountCommitment,
            "submitted_at":       Int(Date().timeIntervalSince1970)
        ]
        return try await post("/api/shares/cast", body: body)
    }

    // MARK: - Tally

    public func getProposalTally(proposalId: String) async throws -> SharesTally {
        return try await get("/api/shares/proposals/\(proposalId)/count")
    }

    // MARK: - Action queue

    public func getActionQueue() async throws -> [Action] {
        let response: ActionsResponse = try await get("/actions")
        return response.actions ?? []
    }

    public func dispatchAction(
        actionId: String,
        adapter: String,
        adapterPayload: [String: Any]
    ) async throws -> DispatchResult {
        var body: [String: Any] = ["adapter": adapter]
        body.merge(adapterPayload) { _, new in new }
        return try await post("/api/shares/proposals/\(actionId)/close", body: body)
    }

    // MARK: - Membership

    public func getMembershipSnapshot() async throws -> MembershipSnapshot {
        return try await get("/memberships/snapshot")
    }

    // MARK: - HTTP

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

// MARK: - Private response wrappers

private struct ActionsResponse: Decodable {
    let actions: [Action]?
}
