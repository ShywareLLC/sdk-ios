import CryptoKit
import Foundation

// MARK: - Result types

public struct StoreResult: Codable, Sendable {
    public let submissionId: String
    public let submissionNonce: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case submissionId    = "submission_id"
        case submissionNonce = "submission_nonce"
        case ok
    }
}

public struct Bucket: Codable, Sendable {
    public let scopingId: String
    public let allowedCategories: [String]
    public let status: String?

    enum CodingKeys: String, CodingKey {
        case scopingId         = "scoping_id"
        case allowedCategories = "allowed_categories"
        case status
    }
}

// MARK: - StoreClient

public actor StoreClient {
    let manifest: ShyConfig
    let sealerKeyProvider: SealerKeyProvider
    let session: URLSession

    public static func from(
        _ config: ShyConfig,
        sealerKeyProvider: SealerKeyProvider
    ) throws -> StoreClient {
        return StoreClient(manifest: config, sealerKeyProvider: sealerKeyProvider)
    }

    init(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider) {
        self.manifest          = manifest
        self.sealerKeyProvider = sealerKeyProvider
        self.session           = URLSession.shared
    }

    // MARK: - Bucket lifecycle

    public func listBuckets(scopingId: String) async throws -> [Bucket] {
        let response: BucketsResponse = try await get("/store/buckets")
        return response.buckets ?? []
    }

    // MARK: - Store submission (atomic two-list write)

    public func storeSubmission(
        scopingId: String,
        plaintext: Data,
        category: String
    ) async throws -> StoreResult {
        let nonce        = randomHex(32)
        let submissionId = sha256hex(nonce)
        let key          = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: scopingId))
        let sealed       = try aesGCMSeal(plaintext, key: key)
        let sealedBase64 = sealed.base64EncodedString()
        let body: [String: Any] = [
            "type":       1,
            "signature":  [1],
            "data": [
                "scoping_id":         scopingId,
                "submission_nonce":   nonce,
                "timestamp":          Int(Date().timeIntervalSince1970),
                "partition_id":       "sealed",
                "category":           category,
                "sealed_payload":     sealedBase64
            ]
        ]
        let result: StoreSubmitResponse = try await post("/store/broadcast", body: body)
        return StoreResult(submissionId: submissionId, submissionNonce: nonce, ok: result.ok)
    }

    // MARK: - Reveal and decrypt

    public func revealAndDecryptStore(scopingId: String, submissionId: String) async throws -> Data {
        // Emit on-chain reveal event
        let revealBody: [String: Any] = [
            "type":      2,
            "signature": [1],
            "data": [
                "scoping_id":    scopingId,
                "submission_id": submissionId,
                "timestamp":     Int(Date().timeIntervalSince1970)
            ]
        ]
        let _: StoreSubmitResponse = try await post("/store/broadcast", body: revealBody)
        // Fetch sealed payload from reconcile authority
        let receipt: SealedReceiptResponse = try await get("/store/buckets/\(scopingId)/secrets/\(submissionId)/receipt")
        guard let sealedBase64 = receipt.sealedPayload,
              let sealedData   = Data(base64Encoded: sealedBase64) else {
            throw ShywareError.apiError("No sealed payload returned for submission \(submissionId)")
        }
        let key = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: scopingId))
        return try aesGCMOpen(sealedData, key: key)
    }

    // MARK: - Delete

    public func deleteStore(scopingId: String, submissionId: String) async throws {
        let body: [String: Any] = [
            "type":      5,
            "signature": [1],
            "data": [
                "scoping_id":    scopingId,
                "submission_id": submissionId,
                "timestamp":     Int(Date().timeIntervalSince1970)
            ]
        ]
        let _: StoreSubmitResponse = try await post("/store/broadcast", body: body)
    }

    // MARK: - Replace (rotate)

    public func replaceStore(
        scopingId: String,
        submissionId: String,
        plaintext: Data,
        category: String
    ) async throws -> StoreResult {
        let nonce         = randomHex(32)
        let newSubmissionId = sha256hex(nonce)
        let key           = try sealerKeyProvider.deriveSealerKey(config: manifest, input: .raw(value: scopingId))
        let sealed        = try aesGCMSeal(plaintext, key: key)
        let sealedBase64  = sealed.base64EncodedString()
        let body: [String: Any] = [
            "type":      3,
            "signature": [1],
            "data": [
                "scoping_id":         scopingId,
                "old_submission_id":  submissionId,
                "new_submission_nonce": nonce,
                "new_sealed_payload": sealedBase64,
                "timestamp":          Int(Date().timeIntervalSince1970)
            ]
        ]
        let _: StoreSubmitResponse = try await post("/store/broadcast", body: body)
        return StoreResult(submissionId: newSubmissionId, submissionNonce: nonce, ok: true)
    }

    // MARK: - HTTP (internal, reused by StreamClient)

    func get<T: Decodable>(_ path: String) async throws -> T {
        let url = try resolveURL(path, useSubmit: false)
        let req = URLRequest(url: url)
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let url = try resolveURL(path, useSubmit: false)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        try validate(response: response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    func resolveURL(_ path: String, useSubmit: Bool) throws -> URL {
        let rawBase = useSubmit
            ? (manifest.api.submitBaseURL ?? manifest.api.baseURL)
            : manifest.api.baseURL
        let base = rawBase.hasSuffix("/") ? String(rawBase.dropLast()) : rawBase
        guard let url = URL(string: base + path) else {
            throw ShywareError.invalidInput("Invalid URL: \(base + path)")
        }
        return url
    }

    func validate(response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw ShywareError.apiError("HTTP \(http.statusCode)")
        }
    }
}

// MARK: - Private response types

private struct BucketsResponse: Decodable {
    let buckets: [Bucket]?
}

private struct StoreSubmitResponse: Decodable {
    let ok: Bool?
}

private struct SealedReceiptResponse: Decodable {
    let sealedPayload: String?

    enum CodingKeys: String, CodingKey {
        case sealedPayload = "sealed_payload"
    }
}
