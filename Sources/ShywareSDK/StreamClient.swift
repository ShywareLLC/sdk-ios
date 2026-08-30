import Foundation

// MARK: - Result types

public struct BucketResult: Codable, Sendable {
    public let scopingId: String
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case scopingId = "scoping_id"
        case ok
    }
}

public struct SegmentResult: Codable, Sendable {
    public let submissionId: String
    public let submissionNonce: String
    public let sequence: Int
    public let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case submissionId    = "submission_id"
        case submissionNonce = "submission_nonce"
        case sequence
        case ok
    }
}

// MARK: - LiveQueue

/// An actor-based live queue that accumulates segments and flushes automatically
/// when `minBatchSize` is reached or when `flush()` is called directly.
public actor LiveQueue {
    private let bucketID: String
    private let streamID: String
    private let minBatchSize: Int
    private let flushIntervalMs: Int
    private let streamClient: StreamClient

    private var queue: [(sequence: Int, segment: Data)] = []

    init(
        bucketID: String,
        streamID: String,
        minBatchSize: Int,
        flushIntervalMs: Int,
        streamClient: StreamClient
    ) {
        self.bucketID       = bucketID
        self.streamID       = streamID
        self.minBatchSize   = minBatchSize
        self.flushIntervalMs = flushIntervalMs
        self.streamClient   = streamClient
    }

    /// Enqueue a raw segment Data. Provide a monotonically increasing sequence number.
    public func enqueue(_ segment: Data, sequence: Int) async throws {
        queue.append((sequence: sequence, segment: segment))
        if queue.count >= minBatchSize {
            try await flush()
        }
    }

    /// Force-flush all pending segments.
    @discardableResult
    public func flush() async throws -> [SegmentResult] {
        let pending = queue
        queue.removeAll()
        var results: [SegmentResult] = []
        for item in pending {
            let result = try await streamClient.sealLiveSegment(
                bucketID: bucketID,
                streamID: streamID,
                sequence: item.sequence,
                segment: item.segment
            )
            results.append(result)
        }
        return results
    }

    public var queueDepth: Int { queue.count }
}

// MARK: - StreamClient

/// shystream-v1 client — extends StoreClient semantics for live-stream segments.
public actor StreamClient {
    private let storeClient: StoreClient

    public static func from(
        _ config: ShyConfig,
        sealerKeyProvider: SealerKeyProvider
    ) throws -> StreamClient {
        let store = try StoreClient.from(config, sealerKeyProvider: sealerKeyProvider)
        return StreamClient(storeClient: store)
    }

    private init(storeClient: StoreClient) {
        self.storeClient = storeClient
    }

    // MARK: - Bucket

    public func createBucket(
        scopingId: String,
        allowedCategories: [String]
    ) async throws -> BucketResult {
        let body: [String: Any] = [
            "scoping_id":          scopingId,
            "allowed_categories":  allowedCategories
        ]
        let response: BucketCreateResponse = try await storeClient.post("/store/buckets", body: body)
        return BucketResult(scopingId: response.scopingId ?? scopingId, ok: response.ok)
    }

    // MARK: - Seal segments

    /// Seals a live segment into the store layer.
    public func sealLiveSegment(
        bucketID: String,
        streamID: String,
        sequence: Int,
        segment: Data
    ) async throws -> SegmentResult {
        // Wrap segment in the shystream.segment.v1 schema before sealing.
        let payload = try buildSegmentPayload(
            streamID: streamID,
            sequence: sequence,
            segment: segment,
            mode: "live"
        )
        let storeResult = try await storeClient.storeSubmission(
            scopingId: bucketID,
            plaintext: payload,
            category: "stream_event"
        )
        return SegmentResult(
            submissionId:    storeResult.submissionId,
            submissionNonce: storeResult.submissionNonce,
            sequence:        sequence,
            ok:              storeResult.ok
        )
    }

    // MARK: - LiveQueue factory

    public func createLiveQueue(
        bucketID: String,
        streamID: String,
        minBatchSize: Int,
        flushIntervalMs: Int
    ) -> LiveQueue {
        LiveQueue(
            bucketID:       bucketID,
            streamID:       streamID,
            minBatchSize:   minBatchSize,
            flushIntervalMs: flushIntervalMs,
            streamClient:   self
        )
    }

    // MARK: - Delegate all StoreClient methods

    public func listBuckets(scopingId: String) async throws -> [Bucket] {
        try await storeClient.listBuckets(scopingId: scopingId)
    }

    public func storeSubmission(scopingId: String, plaintext: Data, category: String) async throws -> StoreResult {
        try await storeClient.storeSubmission(scopingId: scopingId, plaintext: plaintext, category: category)
    }

    public func revealAndDecryptStore(scopingId: String, submissionId: String) async throws -> Data {
        try await storeClient.revealAndDecryptStore(scopingId: scopingId, submissionId: submissionId)
    }

    public func deleteStore(scopingId: String, submissionId: String) async throws {
        try await storeClient.deleteStore(scopingId: scopingId, submissionId: submissionId)
    }

    public func replaceStore(
        scopingId: String,
        submissionId: String,
        plaintext: Data,
        category: String
    ) async throws -> StoreResult {
        try await storeClient.replaceStore(
            scopingId: scopingId,
            submissionId: submissionId,
            plaintext: plaintext,
            category: category
        )
    }

    // MARK: - Private helpers

    private func buildSegmentPayload(
        streamID: String,
        sequence: Int,
        segment: Data,
        mode: String
    ) throws -> Data {
        let envelope: [String: Any] = [
            "schema":     "shystream.segment.v1",
            "mode":       mode,
            "stream_id":  streamID,
            "sequence":   sequence,
            "started_at": Int(Date().timeIntervalSince1970 * 1000),
            "mime_type":  "video/mp2t",
            "codec":      "h264",
            "segment":    segment.base64EncodedString()
        ]
        return try JSONSerialization.data(withJSONObject: envelope)
    }
}

// MARK: - Private response types

private struct BucketCreateResponse: Decodable {
    let scopingId: String?
    let ok: Bool?

    enum CodingKeys: String, CodingKey {
        case scopingId = "scoping_id"
        case ok
    }
}
