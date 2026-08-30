import CryptoKit
import Foundation

// MARK: - Result types

public struct BrowserResult: Codable, Sendable {
    public let recordId: String
    public let category: String
    public let list: Int
    public let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case recordId  = "record_id"
        case category
        case list
        case createdAt = "created_at"
    }
}

// MARK: - Manifest validation

public func assertBrowserManifest(_ config: ShyConfig) throws {
    guard config.contractVersion == "shybrowser-v1" else {
        throw ShywareError.invalidManifest("contract_version must be shybrowser-v1")
    }
    // sealer.mode must be "sealed_storage" — checked via ShyFullConfig
}

// MARK: - BrowserClient

/// Sealed local browser/session storage plus optional sealed identity-side submission.
/// Mirrors the JS shybrowser-v1 client.
public actor BrowserClient {
    public nonisolated let manifest: ShyConfig
    private let sealerKeyProvider: SealerKeyProvider
    private let session: URLSession

    public static func from(
        _ config: ShyConfig,
        sealerKeyProvider: SealerKeyProvider
    ) throws -> BrowserClient {
        try assertBrowserManifest(config)
        return BrowserClient(manifest: config, sealerKeyProvider: sealerKeyProvider)
    }

    private init(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider) {
        self.manifest          = manifest
        self.sealerKeyProvider = sealerKeyProvider
        self.session           = URLSession.shared
    }

    // MARK: - Seal and store browser data (List 1)

    /// Seals `data` with AES-256-GCM and posts to the List 1 store endpoint.
    public func storeSealedBrowserData(_ data: Data, category: String) async throws -> BrowserResult {
        let key    = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: category))
        let sealed = try aesGCMSeal(data, key: key)
        let recordId = randomHex(16)
        let body: [String: Any] = [
            "record_id":      recordId,
            "category":       category,
            "list":           1,
            "created_at":     Int(Date().timeIntervalSince1970),
            "sealed_payload": sealed.base64EncodedString()
        ]
        let response: BrowserStoreResponse = try await post("/browser/store", body: body)
        return BrowserResult(
            recordId:   response.recordId ?? recordId,
            category:   category,
            list:       1,
            createdAt:  Int64(Date().timeIntervalSince1970)
        )
    }

    // MARK: - Submit List 2 identity attribute

    /// Seals and submits an identity attribute to the List 2 identity endpoint.
    public func submitList2IdentityAttribute(
        _ attribute: String,
        attributeType: String
    ) async throws {
        let key    = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: attributeType))
        let sealed = try aesGCMSeal(Data(attribute.utf8), key: key)
        let body: [String: Any] = [
            "category":       attributeType,
            "sealed_payload": sealed.base64EncodedString()
        ]
        let _: EmptyBrowserResponse = try await post("/list2-identity", body: body)
    }

    // MARK: - HTTP

    @discardableResult
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let raw  = manifest.api.baseURL
        let base = raw.hasSuffix("/") ? String(raw.dropLast()) : raw
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw ShywareError.apiError("HTTP error on \(path)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}

// MARK: - Private response wrappers

private struct BrowserStoreResponse: Decodable {
    let recordId: String?

    enum CodingKeys: String, CodingKey {
        case recordId = "record_id"
    }
}

private struct EmptyBrowserResponse: Decodable {}
