import Foundation

// MARK: - Domain-specific config blocks

/// Wire block — declared in shywire-v1 and shybets-v1 manifests.
public struct WireConfig: Codable, Sendable {
    public let provider: String?
    public let backingAsset: String?
    public let issuerName: String?
    public let supportedNetworks: [String]
    public let operatorMintBurn: Bool
    public let assetId: String?
    public let providerConfig: WireProviderConfig?

    enum CodingKeys: String, CodingKey {
        case provider
        case backingAsset    = "backing_asset"
        case issuerName      = "issuer_name"
        case supportedNetworks = "supported_networks"
        case operatorMintBurn  = "operator_mint_burn"
        case assetId         = "asset_id"
        case providerConfig  = "provider_config"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        provider            = try? c.decodeIfPresent(String.self,              forKey: .provider)
        backingAsset        = try? c.decodeIfPresent(String.self,              forKey: .backingAsset)
        issuerName          = try? c.decodeIfPresent(String.self,              forKey: .issuerName)
        supportedNetworks   = (try? c.decodeIfPresent([String].self,           forKey: .supportedNetworks)) ?? []
        operatorMintBurn    = (try? c.decodeIfPresent(Bool.self,               forKey: .operatorMintBurn)) ?? false
        assetId             = try? c.decodeIfPresent(String.self,              forKey: .assetId)
        providerConfig      = try? c.decodeIfPresent(WireProviderConfig.self,  forKey: .providerConfig)
    }
}

public struct WireProviderConfig: Codable, Sendable {
    public let mode: String
    public let intentPath: String?
    public let settlementAsset: String?
    public let supportedRails: [String]
    public let requiresOperatorReview: Bool

    enum CodingKeys: String, CodingKey {
        case mode
        case intentPath              = "intent_path"
        case settlementAsset         = "settlement_asset"
        case supportedRails          = "supported_rails"
        case requiresOperatorReview  = "requires_operator_review"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode                    = (try? c.decodeIfPresent(String.self,   forKey: .mode))   ?? "sandbox"
        intentPath              = try? c.decodeIfPresent(String.self,    forKey: .intentPath)
        settlementAsset         = try? c.decodeIfPresent(String.self,    forKey: .settlementAsset)
        supportedRails          = (try? c.decodeIfPresent([String].self, forKey: .supportedRails)) ?? ["blockchain"]
        requiresOperatorReview  = (try? c.decodeIfPresent(Bool.self,     forKey: .requiresOperatorReview)) ?? true
    }
}

/// Custody block — declared in shycustody-v1 and shylots-v1 manifests.
public struct CustodyConfig: Codable, Sendable {
    public let transferLayer: String?
    public let assetId: String?
    public let operatorMintBurn: Bool
    public let evidenceRequirements: [String]

    enum CodingKeys: String, CodingKey {
        case transferLayer         = "transfer_layer"
        case assetId               = "asset_id"
        case operatorMintBurn      = "operator_mint_burn"
        case evidenceRequirements  = "evidence_requirements"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transferLayer        = try? c.decodeIfPresent(String.self,   forKey: .transferLayer)
        assetId              = try? c.decodeIfPresent(String.self,   forKey: .assetId)
        operatorMintBurn     = (try? c.decodeIfPresent(Bool.self,    forKey: .operatorMintBurn)) ?? false
        evidenceRequirements = (try? c.decodeIfPresent([String].self, forKey: .evidenceRequirements)) ?? []
    }
}

/// Contracts block — declared in shycontracts-v1 manifests. Also accepts legacy "financing" key.
public struct ContractsConfig: Codable, Sendable {
    public let transferLayer: String?
    public let contractKeyId: String?

    enum CodingKeys: String, CodingKey {
        case transferLayer  = "transfer_layer"
        case contractKeyId  = "contract_key_id"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transferLayer  = try? c.decodeIfPresent(String.self, forKey: .transferLayer)
        contractKeyId  = try? c.decodeIfPresent(String.self, forKey: .contractKeyId)
    }
}

/// Governance block — declared in shyshares-v1 manifests.
public struct GovernanceConfig: Codable, Sendable {
    public let transferLayer: String?
    public let votingMethod: String

    enum CodingKeys: String, CodingKey {
        case transferLayer  = "transfer_layer"
        case votingMethod   = "voting_method"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transferLayer  = try? c.decodeIfPresent(String.self, forKey: .transferLayer)
        votingMethod   = (try? c.decodeIfPresent(String.self, forKey: .votingMethod)) ?? "weighted"
    }
}

/// Execution block — declared in shyshares-v1 manifests alongside governance.
public struct ExecutionConfig: Codable, Sendable {
    public let adapter: String?
    public let actionQueueEnabled: Bool

    enum CodingKeys: String, CodingKey {
        case adapter             = "adapter"
        case actionQueueEnabled  = "action_queue_enabled"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        adapter             = try? c.decodeIfPresent(String.self, forKey: .adapter)
        actionQueueEnabled  = (try? c.decodeIfPresent(Bool.self,  forKey: .actionQueueEnabled)) ?? true
    }
}

/// Store block — declared in shystore-v1, shychat-v1, shyrest-v1, shycustody-v1 manifests.
public struct StoreConfig: Codable, Sendable {
    public let sealer: SealerConfig?
    public let secretCategories: [String]
    public let recoveryMode: String?
    public let selectiveDisclosure: Bool
    public let payloadEncryption: PayloadEncryptionConfig?

    enum CodingKeys: String, CodingKey {
        case sealer
        case secretCategories     = "secret_categories"
        case recoveryMode         = "recovery_mode"
        case selectiveDisclosure  = "selective_disclosure"
        case payloadEncryption    = "payload_encryption"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sealer               = try? c.decodeIfPresent(SealerConfig.self,            forKey: .sealer)
        secretCategories     = (try? c.decodeIfPresent([String].self,               forKey: .secretCategories)) ?? []
        recoveryMode         = try? c.decodeIfPresent(String.self,                  forKey: .recoveryMode)
        selectiveDisclosure  = (try? c.decodeIfPresent(Bool.self,                   forKey: .selectiveDisclosure)) ?? false
        payloadEncryption    = try? c.decodeIfPresent(PayloadEncryptionConfig.self, forKey: .payloadEncryption)
    }
}

public struct PayloadEncryptionConfig: Codable, Sendable {
    public let mode: String

    enum CodingKeys: String, CodingKey {
        case mode
    }
}

/// Sealer block — used by shystore, shychat, shybrowser, shyshares.
public struct SealerConfig: Codable, Sendable {
    public let mode: String
    public let enabled: Bool

    enum CodingKeys: String, CodingKey {
        case mode
        case enabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode    = (try? c.decodeIfPresent(String.self, forKey: .mode))    ?? "sealed_storage"
        enabled = (try? c.decodeIfPresent(Bool.self,   forKey: .enabled)) ?? false
    }
}

/// Messaging block — declared in shychat-v1 and shyrest-v1 manifests.
public struct MessagingConfig: Codable, Sendable {
    public let surfaceModel: String
    public let payloadModel: String
    public let mailboxModel: String
    public let deliveryModel: String
    public let retentionPolicy: String
    public let allowedPayloadFormats: [String]

    enum CodingKeys: String, CodingKey {
        case surfaceModel           = "surface_model"
        case payloadModel           = "payload_model"
        case mailboxModel           = "mailbox_model"
        case deliveryModel          = "delivery_model"
        case retentionPolicy        = "retention_policy"
        case allowedPayloadFormats  = "allowed_payload_formats"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        surfaceModel          = (try? c.decodeIfPresent(String.self,   forKey: .surfaceModel))         ?? "mail"
        payloadModel          = (try? c.decodeIfPresent(String.self,   forKey: .payloadModel))         ?? "sealed_private_content"
        mailboxModel          = (try? c.decodeIfPresent(String.self,   forKey: .mailboxModel))         ?? "single_mailbox"
        deliveryModel         = (try? c.decodeIfPresent(String.self,   forKey: .deliveryModel))        ?? "dispatch_queue"
        retentionPolicy       = (try? c.decodeIfPresent(String.self,   forKey: .retentionPolicy))      ?? "no_retention"
        allowedPayloadFormats = (try? c.decodeIfPresent([String].self, forKey: .allowedPayloadFormats)) ?? ["mail_text"]
    }
}

/// Stream block — declared in shystream-v1 and shycustody-v1 manifests.
public struct StreamConfig: Codable, Sendable {
    public let provider: String?
    public let ingestionMode: String

    enum CodingKeys: String, CodingKey {
        case provider
        case ingestionMode = "ingestion_mode"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        provider      = try? c.decodeIfPresent(String.self, forKey: .provider)
        ingestionMode = (try? c.decodeIfPresent(String.self, forKey: .ingestionMode)) ?? "live"
    }
}

/// Lots block — declared in shylots-v1 manifests.
public struct LotsConfig: Codable, Sendable {
    public let marketOperator: String?
    public let saleModes: [String]
    public let openMode: String
    public let bidVisibility: String
    public let reserveFundingMode: String
    public let settlementAssetId: String?
    public let bidderIdentityMode: String
    public let evidenceMode: String
    public let redemptionSurface: String
    public let disputeWindowHours: Int

    enum CodingKeys: String, CodingKey {
        case marketOperator      = "market_operator"
        case saleModes           = "sale_modes"
        case openMode            = "open_mode"
        case bidVisibility       = "bid_visibility"
        case reserveFundingMode  = "reserve_funding_mode"
        case settlementAssetId   = "settlement_asset_id"
        case bidderIdentityMode  = "bidder_identity_mode"
        case evidenceMode        = "evidence_mode"
        case redemptionSurface   = "redemption_surface"
        case disputeWindowHours  = "dispute_window_hours"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        marketOperator     = try? c.decodeIfPresent(String.self,   forKey: .marketOperator)
        saleModes          = (try? c.decodeIfPresent([String].self, forKey: .saleModes))         ?? ["sealed_bid"]
        openMode           = (try? c.decodeIfPresent(String.self,   forKey: .openMode))          ?? "operator_attested_close"
        bidVisibility      = (try? c.decodeIfPresent(String.self,   forKey: .bidVisibility))     ?? "sealed_until_close"
        reserveFundingMode = (try? c.decodeIfPresent(String.self,   forKey: .reserveFundingMode)) ?? "bid_bond_transfer"
        settlementAssetId  = try? c.decodeIfPresent(String.self,    forKey: .settlementAssetId)
        bidderIdentityMode = (try? c.decodeIfPresent(String.self,   forKey: .bidderIdentityMode)) ?? "anonymous_commitment"
        evidenceMode       = (try? c.decodeIfPresent(String.self,   forKey: .evidenceMode))      ?? "custody_refs"
        redemptionSurface  = (try? c.decodeIfPresent(String.self,   forKey: .redemptionSurface)) ?? "custody_request"
        disputeWindowHours = (try? c.decodeIfPresent(Int.self,      forKey: .disputeWindowHours)) ?? 0
    }
}

// MARK: - Dev sealer key provider for DPIA tests

import CryptoKit

/// Static-key SealerKeyProvider for DPIA test environments.
/// Uses a fixed 32-byte key derived from the provided raw string — NOT secure for production.
public struct DevSealerKeyProvider: SealerKeyProvider {
    private let keyData: Data
    public init(rawKey: String = "shybrowser-dev-sealer-key-000000") {
        let bytes = Array(rawKey.utf8.prefix(32)).padded(toLength: 32, with: 0)
        self.keyData = Data(bytes)
    }
    public func deriveSealerKey(config: ShyConfig, input: IdentityInput) throws -> Data { keyData }
}

private extension Array where Element == UInt8 {
    func padded(toLength length: Int, with value: UInt8) -> [UInt8] {
        self.count >= length ? Array(self.prefix(length)) : self + Array(repeating: value, count: length - self.count)
    }
}

// MARK: - Static test factories

extension ShyConfig {
    /// Convenience factory for DPIA test helpers — fills in default receipts and deployment.
    public static func dpia(
        contractVersion: String,
        app: AppConfig,
        api: APIConfig,
        identity: IdentityConfig,
        signing: SigningConfig,
        anonLayer: AnonLayerConfig,
        receipts: ReceiptsConfig? = nil,
        deployment: DeploymentConfig? = nil
    ) -> ShyConfig {
        let r = receipts ?? ReceiptsConfig(matchStore: "canonical", userAccess: "no_access",
                                           doubleVoteEnforcement: "strict", highRiskRegionBlocklist: [])
        let d = deployment ?? DeploymentConfig(defaultPosture: "recoverable",
                                               runtimeFallbacks: RuntimeFallbacks.none(),
                                               postureEndpoint: nil, allowUserPostureOverride: false)
        return ShyConfig(contractVersion: contractVersion, app: app, api: api,
                         identity: identity, signing: signing, anonLayer: anonLayer,
                         receipts: r, deployment: d)
    }
}

// MARK: - ShyConfig extensions for optional domain blocks

/// Extended ShyConfig that includes optional domain-specific config blocks.
extension ShyConfig {}

/// Full manifest that includes all optional domain blocks.
/// Use this when parsing a manifest that may carry wire/custody/contracts/governance blocks.
public struct ShyFullConfig: Codable, Sendable {
    public let base: ShyConfig
    public let wire: WireConfig?
    public let custody: CustodyConfig?
    public let contracts: ContractsConfig?
    public let financing: ContractsConfig?   // legacy alias for contracts
    public let governance: GovernanceConfig?
    public let execution: ExecutionConfig?
    public let store: StoreConfig?
    public let messaging: MessagingConfig?
    public let sealer: SealerConfig?
    public let stream: StreamConfig?
    public let lots: LotsConfig?

    // Decoded from the top-level JSON object.
    enum CodingKeys: String, CodingKey {
        // Base keys
        case contractVersion = "contract_version"
        case app, api, identity, signing
        case anonLayer  = "anon_layer"
        case receipts, deployment
        // Domain keys
        case wire, custody, contracts, financing
        case governance, execution
        case store, messaging, sealer, stream, lots
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Re-decode the base struct from the same container.
        base       = try ShyConfig(from: decoder)
        wire       = try? c.decodeIfPresent(WireConfig.self,        forKey: .wire)
        custody    = try? c.decodeIfPresent(CustodyConfig.self,     forKey: .custody)
        contracts  = try? c.decodeIfPresent(ContractsConfig.self,   forKey: .contracts)
        financing  = try? c.decodeIfPresent(ContractsConfig.self,   forKey: .financing)
        governance = try? c.decodeIfPresent(GovernanceConfig.self,  forKey: .governance)
        execution  = try? c.decodeIfPresent(ExecutionConfig.self,   forKey: .execution)
        store      = try? c.decodeIfPresent(StoreConfig.self,       forKey: .store)
        messaging  = try? c.decodeIfPresent(MessagingConfig.self,   forKey: .messaging)
        sealer     = try? c.decodeIfPresent(SealerConfig.self,      forKey: .sealer)
        stream     = try? c.decodeIfPresent(StreamConfig.self,      forKey: .stream)
        lots       = try? c.decodeIfPresent(LotsConfig.self,        forKey: .lots)
    }

    public func encode(to encoder: Encoder) throws {
        try base.encode(to: encoder)
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(wire,       forKey: .wire)
        try c.encodeIfPresent(custody,    forKey: .custody)
        try c.encodeIfPresent(contracts,  forKey: .contracts)
        try c.encodeIfPresent(financing,  forKey: .financing)
        try c.encodeIfPresent(governance, forKey: .governance)
        try c.encodeIfPresent(execution,  forKey: .execution)
        try c.encodeIfPresent(store,      forKey: .store)
        try c.encodeIfPresent(messaging,  forKey: .messaging)
        try c.encodeIfPresent(sealer,     forKey: .sealer)
        try c.encodeIfPresent(stream,     forKey: .stream)
        try c.encodeIfPresent(lots,       forKey: .lots)
    }

    /// Resolved contracts config — prefers `contracts`, falls back to `financing`.
    public var resolvedContracts: ContractsConfig? { contracts ?? financing }
}
public typealias KeyboxClient = StoreClient
