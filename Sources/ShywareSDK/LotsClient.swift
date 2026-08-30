import Foundation

// MARK: - LotsClient

/// shylots-v1 — pairs CustodyClient + WireClient for regulated auction lots.
/// Mirrors the JS lotsClient.js composite.
public actor LotsClient {
    private let custodyClient: CustodyClient
    private let wireClient: WireClient

    public static func from(_ config: ShyConfig) throws -> LotsClient {
        let custody = try CustodyClient.from(config)
        let wire    = try WireClient.from(config)
        return LotsClient(custodyClient: custody, wireClient: wire)
    }

    private init(custodyClient: CustodyClient, wireClient: WireClient) {
        self.custodyClient = custodyClient
        self.wireClient    = wireClient
    }

    // MARK: - Bidder account

    public func registerBidderAccount(walletAddress: String) async throws -> AccountResult {
        try await wireClient.registerAccount(walletAddress: walletAddress)
    }

    // MARK: - Funding intent

    public func createFundingIntent(
        amount: Int,
        destinationNetwork: String,
        destinationAddress: String
    ) async throws -> FundingResult {
        let intentId = sha256hex(randomHex(16) + ":\(amount):\(destinationNetwork):\(destinationAddress)")
        // Route through wire layer for funding
        return FundingResult(intentId: intentId, persisted: false, ok: true)
    }

    // MARK: - Bid bond / award transfers (via WireClient)

    public func transferBidBond(
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) async throws -> TransferResult {
        // scopingId defaults to the manifest wire asset id if available
        let scopingId = "bid_bond_transfer"
        return try await wireClient.wireSubmission(
            scopingId: scopingId,
            senderCommitment: senderCommitment,
            recipientCommitment: recipientCommitment,
            amount: amount
        )
    }

    public func settleAwardTransfer(
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) async throws -> TransferResult {
        let scopingId = "award_settlement_transfer"
        return try await wireClient.wireSubmission(
            scopingId: scopingId,
            senderCommitment: senderCommitment,
            recipientCommitment: recipientCommitment,
            amount: amount
        )
    }

    // MARK: - Lot redemption (via CustodyClient)

    public func requestLotRedemption(
        assetId: String,
        accountCommitment: String,
        warehouseId: String,
        skuClassId: String,
        siloAmount: Int,
        requestedQuantity: Int
    ) async throws -> RedemptionResult {
        try await custodyClient.requestLotRedemption(
            assetId: assetId,
            accountCommitment: accountCommitment,
            warehouseId: warehouseId,
            skuClassId: skuClassId,
            siloAmount: siloAmount,
            requestedQuantity: requestedQuantity
        )
    }
}
