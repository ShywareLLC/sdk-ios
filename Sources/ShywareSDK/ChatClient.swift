import CryptoKit
import Foundation

// MARK: - Result types

public struct MailboxResult: Codable, Sendable {
    public let mailboxId: String
    public let label: String?
    public let address: String?

    enum CodingKeys: String, CodingKey {
        case mailboxId = "mailbox_id"
        case label, address
    }
}

public struct ChatDispatchResult: Codable, Sendable {
    public let dispatchId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case dispatchId = "dispatch_id"
        case ok
    }
}

public struct Mailbox: Codable, Sendable {
    public let mailboxId: String
    public let label: String?
    public let address: String?
    public let status: String?

    enum CodingKeys: String, CodingKey {
        case mailboxId = "mailbox_id"
        case label, address, status
    }
}

public struct Message: Codable, Sendable {
    public let dispatchId: String
    public let mailboxId: String
    public let subject: String?
    public let contentClass: String?
    public let receivedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case dispatchId  = "dispatch_id"
        case mailboxId   = "mailbox_id"
        case subject
        case contentClass = "content_class"
        case receivedAt  = "received_at"
    }
}

// MARK: - ChatClient

public actor ChatClient {
    public nonisolated let manifest: ShyConfig
    private let sealerKeyProvider: SealerKeyProvider
    private let session: URLSession

    public static func from(
        _ config: ShyConfig,
        sealerKeyProvider: SealerKeyProvider
    ) throws -> ChatClient {
        return ChatClient(manifest: config, sealerKeyProvider: sealerKeyProvider)
    }

    private init(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider) {
        self.manifest          = manifest
        self.sealerKeyProvider = sealerKeyProvider
        self.session           = URLSession.shared
    }

    // MARK: - Mailbox lifecycle

    public func createMailbox(
        label: String,
        address: String,
        routeHint: String? = nil
    ) async throws -> MailboxResult {
        var body: [String: Any] = [
            "label":   label,
            "address": address
        ]
        if let routeHint {
            body["route_hint"] = routeHint
        }
        let response: MailboxResponse = try await post("/messages/mailboxes", body: body)
        return response.mailbox ?? MailboxResult(mailboxId: "", label: label, address: address)
    }

    // MARK: - Dispatch

    public func queueDispatch(
        mailboxId: String,
        recipientAddress: String,
        subject: String,
        body: String,
        contentClass: String
    ) async throws -> ChatDispatchResult {
        let sealedBody: Any
        // Seal if sealer is enabled in manifest
        if let sealerEnabled = try? sealerEnabled(), sealerEnabled {
            let key    = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: mailboxId))
            let sealed = try aesGCMSeal(Data(body.utf8), key: key)
            sealedBody = sealed.base64EncodedString()
        } else {
            sealedBody = body
        }
        let requestBody: [String: Any] = [
            "mailbox_id":        mailboxId,
            "recipient_address": recipientAddress,
            "subject":           subject,
            "body":              sealedBody,
            "content_class":     contentClass
        ]
        return try await post("/messages/dispatches", body: requestBody)
    }

    // MARK: - Read

    public func getMailbox(mailboxId: String) async throws -> Mailbox {
        let response: MailboxDetailResponse = try await get("/messages/mailboxes/\(mailboxId)?include_content=true")
        guard let mailbox = response.mailbox else {
            throw ShywareError.apiError("Mailbox \(mailboxId) not found")
        }
        return mailbox
    }

    public func getInbox(mailboxId: String) async throws -> [Message] {
        let response: InboxResponse = try await get("/messages/mailboxes/\(mailboxId)/inbox")
        return response.messages ?? []
    }

    // MARK: - Close

    public func closeDispatch(dispatchId: String) async throws {
        let _: EmptyChatResponse = try await post("/messages/dispatches/\(dispatchId)/close", body: [:])
    }

    // MARK: - HTTP

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = try resolveURL(path)
        let req = URLRequest(url: url)
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let url = try resolveURL(path)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func resolveURL(_ path: String) throws -> URL {
        let raw  = manifest.api.baseURL
        let base = raw.hasSuffix("/") ? String(raw.dropLast()) : raw
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

    private func sealerEnabled() throws -> Bool {
        // Check manifest sealer block via JSON round-trip to ShyFullConfig
        guard let data = try? JSONEncoder().encode(manifest),
              let full  = try? JSONDecoder().decode(ShyFullConfig.self, from: data) else {
            return false
        }
        return full.sealer?.enabled == true
    }
}

// MARK: - Private response wrappers

private struct MailboxResponse: Decodable {
    let mailbox: MailboxResult?
}

private struct MailboxDetailResponse: Decodable {
    let mailbox: Mailbox?
}

private struct InboxResponse: Decodable {
    let messages: [Message]?
}

private struct EmptyChatResponse: Decodable {}
