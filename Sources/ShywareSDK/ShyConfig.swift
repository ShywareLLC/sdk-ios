import Foundation

// MARK: - Top-level manifest

public struct ShyConfig: Codable, Sendable {
    public let contractVersion: String
    public let app: AppConfig
    public let api: APIConfig
    public let identity: IdentityConfig
    public let signing: SigningConfig
    public let anonLayer: AnonLayerConfig
    public let receipts: ReceiptsConfig
    public let deployment: DeploymentConfig
    /// Optional shywire / shybets domain block. Decoded directly from the
    /// top-level `wire` key when present. Parity with the Android SDK
    /// (`ShyConfig.wire`) and the web SDK (`shyconfig.wire`).
    public let wire: WireConfig?
    /// Optional shycustody / shylots domain block.
    public let custody: CustodyConfig?
    /// Optional shycontracts (or legacy `financing`) domain block.
    public let contracts: ContractsConfig?
    /// Optional shyshares governance domain block.
    public let governance: GovernanceConfig?
    /// Optional shyshares execution domain block.
    public let execution: ExecutionConfig?
    /// Optional shystore / shychat / shyrest / shycustody store domain block.
    public let store: StoreConfig?
    /// Optional shychat / shyrest messaging domain block.
    public let messaging: MessagingConfig?
    /// Optional sealer block — used by shystore, shychat, shybrowser, shyshares.
    public let sealer: SealerConfig?
    /// Optional shystream / shycustody stream domain block.
    public let stream: StreamConfig?
    /// Optional shylots auction domain block.
    public let lots: LotsConfig?

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case app, api, identity, signing
        case anonLayer = "anon_layer"
        case receipts, deployment
        case wire, custody, contracts, financing
        case governance, execution
        case store, messaging, sealer, stream, lots
    }

    public init(
        contractVersion: String,
        app: AppConfig,
        api: APIConfig,
        identity: IdentityConfig,
        signing: SigningConfig,
        anonLayer: AnonLayerConfig,
        receipts: ReceiptsConfig,
        deployment: DeploymentConfig,
        wire: WireConfig? = nil,
        custody: CustodyConfig? = nil,
        contracts: ContractsConfig? = nil,
        governance: GovernanceConfig? = nil,
        execution: ExecutionConfig? = nil,
        store: StoreConfig? = nil,
        messaging: MessagingConfig? = nil,
        sealer: SealerConfig? = nil,
        stream: StreamConfig? = nil,
        lots: LotsConfig? = nil
    ) {
        self.contractVersion = contractVersion
        self.app = app
        self.api = api
        self.identity = identity
        self.signing = signing
        self.anonLayer = anonLayer
        self.receipts = receipts
        self.deployment = deployment
        self.wire = wire
        self.custody = custody
        self.contracts = contracts
        self.governance = governance
        self.execution = execution
        self.store = store
        self.messaging = messaging
        self.sealer = sealer
        self.stream = stream
        self.lots = lots
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        contractVersion = try c.decode(String.self, forKey: .contractVersion)
        app             = try c.decode(AppConfig.self, forKey: .app)
        api             = try c.decode(APIConfig.self, forKey: .api)
        identity        = try c.decode(IdentityConfig.self, forKey: .identity)
        signing         = try c.decode(SigningConfig.self, forKey: .signing)
        anonLayer       = try c.decode(AnonLayerConfig.self, forKey: .anonLayer)
        receipts        = try c.decode(ReceiptsConfig.self, forKey: .receipts)
        deployment      = try c.decode(DeploymentConfig.self, forKey: .deployment)
        wire            = try? c.decodeIfPresent(WireConfig.self,        forKey: .wire)
        custody         = try? c.decodeIfPresent(CustodyConfig.self,     forKey: .custody)
        // Prefer `contracts`, fall back to legacy `financing` key.
        if let cz = try? c.decodeIfPresent(ContractsConfig.self, forKey: .contracts) {
            contracts = cz
        } else {
            contracts = try? c.decodeIfPresent(ContractsConfig.self, forKey: .financing)
        }
        governance      = try? c.decodeIfPresent(GovernanceConfig.self,  forKey: .governance)
        execution       = try? c.decodeIfPresent(ExecutionConfig.self,   forKey: .execution)
        store           = try? c.decodeIfPresent(StoreConfig.self,       forKey: .store)
        messaging       = try? c.decodeIfPresent(MessagingConfig.self,   forKey: .messaging)
        sealer          = try? c.decodeIfPresent(SealerConfig.self,      forKey: .sealer)
        stream          = try? c.decodeIfPresent(StreamConfig.self,      forKey: .stream)
        lots            = try? c.decodeIfPresent(LotsConfig.self,        forKey: .lots)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(contractVersion, forKey: .contractVersion)
        try c.encode(app, forKey: .app)
        try c.encode(api, forKey: .api)
        try c.encode(identity, forKey: .identity)
        try c.encode(signing, forKey: .signing)
        try c.encode(anonLayer, forKey: .anonLayer)
        try c.encode(receipts, forKey: .receipts)
        try c.encode(deployment, forKey: .deployment)
        try c.encodeIfPresent(wire, forKey: .wire)
        try c.encodeIfPresent(custody, forKey: .custody)
        try c.encodeIfPresent(contracts, forKey: .contracts)
        try c.encodeIfPresent(governance, forKey: .governance)
        try c.encodeIfPresent(execution, forKey: .execution)
        try c.encodeIfPresent(store, forKey: .store)
        try c.encodeIfPresent(messaging, forKey: .messaging)
        try c.encodeIfPresent(sealer, forKey: .sealer)
        try c.encodeIfPresent(stream, forKey: .stream)
        try c.encodeIfPresent(lots, forKey: .lots)
    }
}

public struct AppConfig: Codable, Sendable {
    public let id: String
    public let chainId: String?
    enum CodingKeys: String, CodingKey {
        case id
        case chainId = "chain_id"
    }
    public init(id: String, chainId: String? = nil) { self.id = id; self.chainId = chainId }
}

public struct APIConfig: Codable, Sendable {
    public let baseURL: String
    public let submitBaseURL: String?
    public let requiresAuth: Bool
    public let authScheme: String?
    enum CodingKeys: String, CodingKey {
        case baseURL = "base_url"
        case submitBaseURL = "submit_base_url"
        case requiresAuth = "requires_auth"
        case authScheme = "auth_scheme"
    }
    public init(baseURL: String, submitBaseURL: String? = nil, requiresAuth: Bool = false, authScheme: String? = nil) {
        self.baseURL = baseURL; self.submitBaseURL = submitBaseURL
        self.requiresAuth = requiresAuth; self.authScheme = authScheme
    }
}

public struct IdentityConfig: Codable, Sendable {
    public let provider: String
    public let mode: String
    public let issuerDid: String?
    public let workflowId: String?
    public let recommendedIdv: String?
    public let kycRequired: Bool
    public let byoidPolicy: String?
    enum CodingKeys: String, CodingKey {
        case provider, mode
        case issuerDid = "issuer_did"
        case workflowId = "workflow_id"
        case recommendedIdv = "recommended_idv"
        case kycRequired = "kyc_required"
        case byoidPolicy = "byoid_policy"
    }
    public init(provider: String, mode: String, issuerDid: String? = nil, workflowId: String? = nil,
                recommendedIdv: String? = nil, kycRequired: Bool = false, byoidPolicy: String? = nil) {
        self.provider = provider; self.mode = mode; self.issuerDid = issuerDid
        self.workflowId = workflowId; self.recommendedIdv = recommendedIdv
        self.kycRequired = kycRequired; self.byoidPolicy = byoidPolicy
    }
}

public struct SigningConfig: Codable, Sendable {
    public let required: Bool
    public let backend: String
    public let validatorKeyId: String?
    public let tallyKeyId: String?
    enum CodingKeys: String, CodingKey {
        case required, backend
        case validatorKeyId = "validator_key_id"
        case tallyKeyId = "tally_key_id"
    }
    public init(required: Bool, backend: String, validatorKeyId: String? = nil, tallyKeyId: String? = nil) {
        self.required = required; self.backend = backend
        self.validatorKeyId = validatorKeyId; self.tallyKeyId = tallyKeyId
    }
}

public struct AnonLayerConfig: Codable, Sendable {
    public let blackBoxRequired: Bool
    public let requiredFlows: [String]
    enum CodingKeys: String, CodingKey {
        case blackBoxRequired = "black_box_required"
        case requiredFlows = "required_flows"
    }
    public init(blackBoxRequired: Bool, requiredFlows: [String] = []) {
        self.blackBoxRequired = blackBoxRequired; self.requiredFlows = requiredFlows
    }
}

public struct ReceiptsConfig: Codable, Sendable {
    public let matchStore: String
    public let userAccess: String
    public let doubleVoteEnforcement: String
    /// ISO 3166-1 alpha-2 country codes that are considered high-risk.
    /// The calling app should resolve the device IP to a country code and
    /// set `network.hostile = true` when the code appears in this list.
    public let highRiskRegionBlocklist: [String]
    enum CodingKeys: String, CodingKey {
        case matchStore = "match_store"
        case userAccess = "user_access"
        case doubleVoteEnforcement = "double_vote_enforcement"
        case highRiskRegionBlocklist = "high_risk_region_blocklist"
    }
    public init(matchStore: String = "canonical", userAccess: String = "no_access",
                doubleVoteEnforcement: String = "strict", highRiskRegionBlocklist: [String] = []) {
        self.matchStore = matchStore; self.userAccess = userAccess
        self.doubleVoteEnforcement = doubleVoteEnforcement
        self.highRiskRegionBlocklist = highRiskRegionBlocklist
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        matchStore = try c.decode(String.self, forKey: .matchStore)
        userAccess = try c.decode(String.self, forKey: .userAccess)
        doubleVoteEnforcement = try c.decode(String.self, forKey: .doubleVoteEnforcement)
        highRiskRegionBlocklist = (try? c.decodeIfPresent([String].self, forKey: .highRiskRegionBlocklist)) ?? []
    }
}

public struct DeploymentConfig: Codable, Sendable {
    public let defaultPosture: String
    public let runtimeFallbacks: RuntimeFallbacks
    /// Optional endpoint the client GETs to receive an operator-pushed posture override.
    /// Path relative to api.base_url, e.g. "/posture". Nil = no remote override.
    public let postureEndpoint: String?
    /// Whether users are permitted to override posture locally (privacy mode toggle).
    public let allowUserPostureOverride: Bool
    enum CodingKeys: String, CodingKey {
        case defaultPosture = "default_posture"
        case runtimeFallbacks = "runtime_fallbacks"
        case postureEndpoint = "posture_endpoint"
        case allowUserPostureOverride = "allow_user_posture_override"
    }
    public init(defaultPosture: String = "recoverable", runtimeFallbacks: RuntimeFallbacks = .none(),
                postureEndpoint: String? = nil, allowUserPostureOverride: Bool = false) {
        self.defaultPosture = defaultPosture; self.runtimeFallbacks = runtimeFallbacks
        self.postureEndpoint = postureEndpoint; self.allowUserPostureOverride = allowUserPostureOverride
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        defaultPosture = try c.decode(String.self, forKey: .defaultPosture)
        runtimeFallbacks = try c.decode(RuntimeFallbacks.self, forKey: .runtimeFallbacks)
        postureEndpoint = try? c.decodeIfPresent(String.self, forKey: .postureEndpoint)
        allowUserPostureOverride = (try? c.decodeIfPresent(Bool.self, forKey: .allowUserPostureOverride)) ?? false
    }
}

public struct RuntimeFallbacks: Codable, Sendable {
    public let writeOnlyOnMissingPlayIntegrity: Bool
    public let writeOnlyOnUntrustedDeviceAttestation: Bool
    public let writeOnlyOnHostileNetwork: Bool
    public let writeOnlyOnHSMUnavailable: Bool
    enum CodingKeys: String, CodingKey {
        case writeOnlyOnMissingPlayIntegrity = "write_only_on_missing_play_integrity"
        case writeOnlyOnUntrustedDeviceAttestation = "write_only_on_untrusted_device_attestation"
        case writeOnlyOnHostileNetwork = "write_only_on_hostile_network"
        case writeOnlyOnHSMUnavailable = "write_only_on_hsm_unavailable"
    }
    public init(writeOnlyOnMissingPlayIntegrity: Bool = false,
                writeOnlyOnUntrustedDeviceAttestation: Bool = false,
                writeOnlyOnHostileNetwork: Bool = false,
                writeOnlyOnHSMUnavailable: Bool = false) {
        self.writeOnlyOnMissingPlayIntegrity = writeOnlyOnMissingPlayIntegrity
        self.writeOnlyOnUntrustedDeviceAttestation = writeOnlyOnUntrustedDeviceAttestation
        self.writeOnlyOnHostileNetwork = writeOnlyOnHostileNetwork
        self.writeOnlyOnHSMUnavailable = writeOnlyOnHSMUnavailable
    }
    public static func none() -> RuntimeFallbacks { RuntimeFallbacks() }
}

// MARK: - Runtime response models

public struct Poll: Codable, Sendable {
    public let pollId: String
    public let question: String
    public let options: [String]
    public let votingMethod: String
    public let startTime: Int64
    public let endTime: Int64
    public let status: String
    enum CodingKeys: String, CodingKey {
        case pollId = "poll_id"
        case question, options
        case votingMethod = "voting_method"
        case startTime = "start_time"
        case endTime = "end_time"
        case status
    }
}

public struct Tally: Codable, Sendable {
    public let pollId: String
    public let counts: [String: Int64]
    public let totalVotes: Int64
    public let confirmedCount: Int64
    public let voteMerkleRoot: String
    public let voterMerkleRoot: String
    public let signature: String
    public let publicKey: String
    enum CodingKeys: String, CodingKey {
        case pollId = "poll_id"
        case counts
        case totalVotes = "total_votes"
        case confirmedCount = "confirmed_count"
        case voteMerkleRoot = "vote_merkle_root"
        case voterMerkleRoot = "voter_merkle_root"
        case signature
        case publicKey = "public_key"
    }

    enum CountKeys: String, CodingKey {
        case pollId
        case ledger
    }

    enum LedgerKeys: String, CodingKey {
        case l1Count
        case l2Count
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if let pollId = try values.decodeIfPresent(String.self, forKey: .pollId) {
            self.pollId = pollId
            self.counts = try values.decodeIfPresent([String: Int64].self, forKey: .counts) ?? [:]
            self.totalVotes = try values.decodeIfPresent(Int64.self, forKey: .totalVotes) ?? 0
            self.confirmedCount = try values.decodeIfPresent(Int64.self, forKey: .confirmedCount) ?? totalVotes
            self.voteMerkleRoot = try values.decodeIfPresent(String.self, forKey: .voteMerkleRoot) ?? ""
            self.voterMerkleRoot = try values.decodeIfPresent(String.self, forKey: .voterMerkleRoot) ?? ""
            self.signature = try values.decodeIfPresent(String.self, forKey: .signature) ?? ""
            self.publicKey = try values.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
            return
        }

        let count = try decoder.container(keyedBy: CountKeys.self)
        self.pollId = try count.decode(String.self, forKey: .pollId)
        let ledger = try count.nestedContainer(keyedBy: LedgerKeys.self, forKey: .ledger)
        self.totalVotes = try ledger.decode(Int64.self, forKey: .l1Count)
        self.confirmedCount = try ledger.decode(Int64.self, forKey: .l2Count)
        self.counts = [:]
        self.voteMerkleRoot = ""
        self.voterMerkleRoot = ""
        self.signature = ""
        self.publicKey = ""
    }
}

public struct VoteRecord: Codable, Sendable {
    public let ballotId: String
    public let choices: [String]
    enum CodingKeys: String, CodingKey {
        case ballotId = "ballot_id"
        case choices
    }

    enum AlternateKeys: String, CodingKey {
        case ballotId
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if let ballotId = try values.decodeIfPresent(String.self, forKey: .ballotId) {
            self.ballotId = ballotId
            self.choices = try values.decodeIfPresent([String].self, forKey: .choices) ?? []
            return
        }
        let alternate = try decoder.container(keyedBy: AlternateKeys.self)
        self.ballotId = try alternate.decode(String.self, forKey: .ballotId)
        self.choices = []
    }
}

public struct PollsResponse: Codable, Sendable {
    public let polls: [Poll]
}

public struct SubmitResponse: Codable, Sendable {
    public let ok: Bool?
    public let ballotId: String?
    enum CodingKeys: String, CodingKey {
        case ok
        case ballotId = "ballot_id"
    }
}

public struct VotesResponse: Codable, Sendable {
    public let votes: [VoteRecord]

    enum CodingKeys: String, CodingKey {
        case votes
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if let votes = try values.decodeIfPresent([VoteRecord].self, forKey: .votes) {
            self.votes = votes
            return
        }
        self.votes = [try VoteRecord(from: decoder)]
    }
}
