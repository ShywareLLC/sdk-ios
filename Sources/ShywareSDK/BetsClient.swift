import CryptoKit
import Foundation

// MARK: - Result types

public struct FundingResult: Codable, Sendable {
    public let intentId: String
    public let persisted: Bool
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case intentId = "intent_id"
        case persisted
        case ok
    }
}

public struct EventResult: Codable, Sendable {
    public let eventId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case eventId = "event_id"
        case ok
    }
}

public struct OrderResult: Codable, Sendable {
    public let orderId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case orderId = "order_id"
        case ok
    }
}

public struct SettlementResult: Codable, Sendable {
    public let eventId: String
    public let winningOutcome: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case eventId        = "event_id"
        case winningOutcome = "winning_outcome"
        case ok
    }
}

public struct PayoutResult: Codable, Sendable {
    public let intentId: String
    public let persisted: Bool
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case intentId = "intent_id"
        case persisted
        case ok
    }
}

public struct Event: Codable, Sendable {
    public let eventId: String
    public let marketId: String
    public let title: String
    public let outcomes: [String]
    public let closesAt: Int64
    public let status: String?

    enum CodingKeys: String, CodingKey {
        case eventId  = "event_id"
        case marketId = "market_id"
        case title, outcomes
        case closesAt = "closes_at"
        case status
    }
}

public struct OrderBook: Codable, Sendable {
    public let eventId: String
    public let bids: [OrderEntry]
    public let asks: [OrderEntry]

    enum CodingKeys: String, CodingKey {
        case eventId = "event_id"
        case bids, asks
    }
}

public struct OrderEntry: Codable, Sendable {
    public let orderId: String
    public let side: String
    public let outcome: String
    public let stake: Int64
    public let odds: String

    enum CodingKeys: String, CodingKey {
        case orderId = "order_id"
        case side, outcome, stake, odds
    }
}

public struct Order: Codable, Sendable {
    public let orderId: String
    public let eventId: String
    public let side: String
    public let outcome: String
    public let stake: Int64
    public let status: String?

    enum CodingKeys: String, CodingKey {
        case orderId  = "order_id"
        case eventId  = "event_id"
        case side, outcome, stake, status
    }
}

public struct Settlement: Codable, Sendable {
    public let eventId: String
    public let winningOutcome: String
    public let settledAt: Int64?

    enum CodingKeys: String, CodingKey {
        case eventId        = "event_id"
        case winningOutcome = "winning_outcome"
        case settledAt      = "settled_at"
    }
}

// MARK: - Manifest validation

public func assertBetsManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shybets-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shybets-v1")
    }
    guard config.anonLayer.blackBoxRequired else {
        throw ShywareError.invalidManifest("anon_layer.black_box_required must be true")
    }
    guard config.signing.required, config.signing.backend != "none" else {
        throw ShywareError.invalidManifest("Signing must be required and enabled")
    }
    let required: Set<String> = [
        "event_create", "order_place", "order_book_read",
        "settlement_read", "settlement_finalize", "reconcile_request"
    ]
    for flow in required where !config.anonLayer.requiredFlows.contains(flow) {
        throw ShywareError.invalidManifest("Missing required bets flow: \(flow)")
    }
}

// MARK: - BetsClient

public actor BetsClient {
    public nonisolated let manifest: ShyConfig
    private let wireClient: WireClient
    private let session: URLSession

    public static func from(_ config: ShyConfig) throws -> BetsClient {
        try assertBetsManifest(config)
        let wire = try WireClient.from(config)
        return BetsClient(manifest: config, wireClient: wire)
    }

    private init(manifest: ShyConfig, wireClient: WireClient) {
        self.manifest    = manifest
        self.wireClient  = wireClient
        self.session     = URLSession.shared
    }

    // MARK: - Wire delegation

    public func getSettlementClient() -> WireClient { wireClient }

    public func registerSettlementAccount(walletAddress: String) async throws -> AccountResult {
        try await wireClient.registerAccount(walletAddress: walletAddress)
    }

    public func createFundingIntent(
        amount: Int,
        destinationNetwork: String,
        destinationAddress: String
    ) async throws -> FundingResult {
        let intentId = sha256hex(randomHex(16) + ":\(amount):\(destinationNetwork):\(destinationAddress)")
        let body: [String: Any] = [
            "kind":                "issue",
            "intent_id":           intentId,
            "amount":              amount,
            "destination_network": destinationNetwork,
            "destination_address": destinationAddress
        ]
        let _: EmptyBetsResponse = try await post("/wire/issue-intents", body: body)
        return FundingResult(intentId: intentId, persisted: true, ok: true)
    }

    public func transferStake(
        scopingId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Int
    ) async throws -> TransferResult {
        try await wireClient.wireSubmission(
            scopingId: scopingId,
            senderCommitment: senderCommitment,
            recipientCommitment: recipientCommitment,
            amount: amount
        )
    }

    public func createPayoutIntent(
        amount: Int,
        accountCommitment: String,
        payoutRail: String,
        payoutDestination: String
    ) async throws -> PayoutResult {
        let intentId = sha256hex(randomHex(16) + ":\(amount):\(payoutRail):\(payoutDestination)")
        let body: [String: Any] = [
            "kind":               "redeem",
            "intent_id":          intentId,
            "amount":             amount,
            "account_commitment": accountCommitment,
            "payout_rail":        payoutRail,
            "payout_destination": payoutDestination
        ]
        let _: EmptyBetsResponse = try await post("/wire/redeem-intents", body: body)
        return PayoutResult(intentId: intentId, persisted: true, ok: true)
    }

    // MARK: - Event lifecycle

    public func createEvent(
        marketId: String,
        title: String,
        outcomes: [String],
        closesAt: Int64
    ) async throws -> EventResult {
        let eventId = sha256hex("\(marketId):\(title):\(closesAt)")
        let data: [String: Any] = [
            "event_id":  eventId,
            "market_id": marketId,
            "title":     title,
            "outcomes":  outcomes,
            "closes_at": closesAt,
            "timestamp": Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 1, "signature": "AQ==", "data": data]
        let txJson = try jsonStringBets(tx)
        let _: EmptyBetsResponse = try await post("/bets/events/tx", body: ["tx": txJson])
        return EventResult(eventId: eventId, ok: true)
    }

    public func placeOrder(
        eventId: String,
        side: String,
        outcome: String,
        stake: Int,
        odds: String,
        accountCommitment: String
    ) async throws -> OrderResult {
        let nonce   = randomHex(32)
        let orderId = sha256hex("\(eventId):\(accountCommitment):\(nonce)")
        let data: [String: Any] = [
            "order_id":          orderId,
            "event_id":          eventId,
            "side":              side,
            "outcome":           outcome,
            "stake":             stake,
            "odds":              odds,
            "account_commitment": accountCommitment,
            "order_nonce":       nonce,
            "timestamp":         Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 2, "signature": "AQ==", "data": data]
        let txJson = try jsonStringBets(tx)
        let _: EmptyBetsResponse = try await post("/bets/orders/tx", body: ["tx": txJson])
        return OrderResult(orderId: orderId, ok: true)
    }

    public func settleEvent(eventId: String, winningOutcome: String) async throws -> SettlementResult {
        let data: [String: Any] = [
            "event_id":        eventId,
            "winning_outcome": winningOutcome,
            "source":          "operator_attested",
            "timestamp":       Int(Date().timeIntervalSince1970)
        ]
        let tx: [String: Any] = ["type": 3, "signature": "AQ==", "data": data]
        let txJson = try jsonStringBets(tx)
        let _: EmptyBetsResponse = try await post("/bets/settlements/tx", body: ["tx": txJson])
        return SettlementResult(eventId: eventId, winningOutcome: winningOutcome, ok: true)
    }

    // MARK: - Read

    public func listEvents(status: String? = nil, marketId: String? = nil) async throws -> [Event] {
        var path = "/bets/events"
        var params: [String] = []
        if let status  { params.append("status=\(status)") }
        if let marketId { params.append("market_id=\(marketId)") }
        if !params.isEmpty { path += "?" + params.joined(separator: "&") }
        let response: EventsResponse = try await get(path)
        return response.events ?? []
    }

    public func getEvent(eventId: String) async throws -> Event {
        return try await get("/bets/events/\(eventId)")
    }

    public func listOrderBook(eventId: String) async throws -> OrderBook {
        return try await get("/bets/events/\(eventId)/order-book")
    }

    public func listOrders(eventId: String? = nil) async throws -> [Order] {
        var path = "/bets/orders"
        if let eventId { path += "?event_id=\(eventId)" }
        let response: OrdersResponse = try await get(path)
        return response.orders ?? []
    }

    public func getSettlement(eventId: String) async throws -> Settlement {
        return try await get("/bets/settlements/\(eventId)")
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

private struct EmptyBetsResponse: Decodable {}

private struct EventsResponse: Decodable {
    let events: [Event]?
}

private struct OrdersResponse: Decodable {
    let orders: [Order]?
}

private func jsonStringBets(_ value: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value)
    return String(decoding: data, as: UTF8.self)
}
