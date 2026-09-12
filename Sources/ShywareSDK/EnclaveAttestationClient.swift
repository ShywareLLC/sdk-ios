import CryptoKit
import Foundation
import Security

// MARK: - Enclave IDV attestation client
//
// Talks to the independent OCI AMD SEV-SNP confidential-computing attestation
// service ("the enclave") that replaces the previous trust model where the
// backend/operator held the Didit-attesting Ed25519 private key directly.
// The enclave generates and retains its own Ed25519 signing keypair on first
// boot — nothing outside the enclave ever holds the private key — and
// independently re-verifies the Didit session against Didit's real session
// API before signing, rather than trusting the caller's claim that the
// session is valid.
//
// Wire contract (matches the enclave's actual deployed API, not a proposal):
//   POST /attest
//   Request:  {"session_id": "...", "voter_pub_key": "...", "poll_id": "..."}
//   Response: {"idv_attestation_sig": "<hex>", "voter_pub_key": "...",
//              "poll_id": "...", "session_id": "..."}
//
// Message format note (flagged, not silently resolved): the enclave signs
// sha256("<voter_pub_key>:<poll_id>") — a colon-joined UTF-8 string — before
// hex-encoding the Ed25519 signature. ShywareLLC/core's existing verifier
// (services/identity/didit.go diditDeviceAttestMessage) instead checks
// sha256(voter_pub_key || poll_id) — a bare concatenation, no separator, and
// the same convention used consistently across every other embodiment in
// that file (confirm-receipt, ZK commitment, ballot update). This client
// does not attempt to paper over that mismatch: it calls the enclave exactly
// as documented and forwards exactly what comes back, because the fix
// belongs on whichever side is wrong (most likely the enclave, since the
// Go core's no-separator convention is the established one) — see the
// commit message / task report for the flagged conflict. Do not "fix" this
// by reformatting the message on the client; the client never constructs
// the signed message, only the enclave does.
public struct EnclaveAttestationResponse: Decodable, Sendable {
    public let idvAttestationSigHex: String
    public let voterPubKey: String
    public let pollId: String
    public let sessionId: String

    enum CodingKeys: String, CodingKey {
        case idvAttestationSigHex = "idv_attestation_sig"
        case voterPubKey = "voter_pub_key"
        case pollId = "poll_id"
        case sessionId = "session_id"
    }
}

public enum EnclaveAttestationError: Error, LocalizedError {
    case invalidURL
    case httpError(statusCode: Int, body: String)
    case invalidSignatureHex
    case pinningFailed

    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid enclave attestation URL"
        case .httpError(let code, let body): return "Enclave attestation HTTP \(code): \(body)"
        case .invalidSignatureHex: return "Enclave returned a non-hex idv_attestation_sig"
        case .pinningFailed: return "Enclave TLS certificate did not match the pinned public key"
        }
    }
}

/// Client for the IDV attestation enclave's `POST /attest` endpoint.
///
/// TLS: the enclave currently serves a self-signed certificate (documented,
/// accepted limitation of the current deployment — not something this SDK
/// works around insecurely). This client pins to that ONE certificate's
/// public key via `EnclaveCertificatePinningDelegate` rather than disabling
/// TLS validation outright. Pinning is scoped to this client's dedicated
/// `URLSession` / this one host only — it never weakens validation for any
/// other request the SDK makes (e.g. `VotingClient`'s own `URLSession.shared`
/// use for the real relay/API is untouched).
public actor EnclaveAttestationClient {
    private let baseURL: String
    private let session: URLSession

    /// No default `baseURL` is provided deliberately: this SDK is shared
    /// across every Shyware voting-type consumer, and each deployment runs
    /// its own independent attestation service (its own enclave, its own
    /// trust boundary) -- hardcoding one deployment's endpoint here would
    /// silently route every other consumer's traffic through it. Read
    /// `identity.attestation_service_base_url` (and, if present,
    /// `identity.attestation_service_tls_pin_sha256_base64`) from this
    /// deployment's own shyconfig and pass them in explicitly.
    ///
    /// - Parameters:
    ///   - baseURL: this deployment's own attestation-service base URL.
    ///   - pinnedHost: host to apply certificate pinning to (typically the
    ///     host component of `baseURL`). Pass `nil` to skip pinning (e.g.
    ///     once the service has a CA-issued certificate).
    ///   - pinnedSPKISHA256Base64: Base64(SHA-256(SubjectPublicKeyInfo DER))
    ///     of the service's current certificate, required if `pinnedHost`
    ///     is non-nil.
    public init(baseURL: String, pinnedHost: String? = nil, pinnedSPKISHA256Base64: String? = nil) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.ephemeral
        let delegate: URLSessionDelegate? = pinnedHost.map { host in
            EnclaveCertificatePinningDelegate(pinnedHost: host, pinnedSPKISHA256Base64: pinnedSPKISHA256Base64 ?? "")
        }
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    /// Requests an IDV attestation signature for `voterPubKeyHex` over `pollId`,
    /// backed by the Didit verification session `sessionId`. The enclave
    /// independently re-checks the session against Didit's real session-status
    /// API before signing — it does not trust this call's claim that the
    /// session is verified.
    ///
    /// - Returns: the raw Ed25519 signature bytes (decoded from the enclave's
    ///   hex response), ready to be base64-encoded into the outgoing
    ///   `idv_attestation_sig` transaction field.
    public func attest(sessionId: String, voterPubKeyHex: String, pollId: String) async throws -> Data {
        guard let url = URL(string: baseURL + "/attest") else {
            throw EnclaveAttestationError.invalidURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: String] = [
            "session_id": sessionId,
            "voter_pub_key": voterPubKeyHex,
            "poll_id": pollId,
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: req)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw EnclaveAttestationError.httpError(statusCode: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        let decoded = try JSONDecoder().decode(EnclaveAttestationResponse.self, from: data)
        guard let sigBytes = Data(hexString: decoded.idvAttestationSigHex) else {
            throw EnclaveAttestationError.invalidSignatureHex
        }
        return sigBytes
    }
}

/// Pins TLS connections to one configured host to the exact public key of
/// that deployment's own attestation service's current self-signed
/// certificate, identified by SHA-256(SubjectPublicKeyInfo). This is real
/// certificate/public-key pinning — not a blanket "trust everything"
/// override — and is scoped to exactly the host it's constructed with, via
/// `URLSessionDelegate`, which is only ever attached to
/// `EnclaveAttestationClient`'s own dedicated `URLSession`.
///
/// Both the host and the pin are supplied by the caller (sourced from that
/// deployment's own shyconfig — see `EnclaveAttestationClient.init`) rather
/// than hardcoded here, since this SDK is shared across every Shyware
/// voting-type consumer and each one runs its own independent service.
///
/// Rotation: if the service's certificate is ever reissued (e.g. after a
/// redeploy that regenerates its self-signed cert), the deployment's
/// configured pin must be updated or every request will fail closed (by
/// design — failing closed on a pin mismatch is the whole point of pinning).
final class EnclaveCertificatePinningDelegate: NSObject, URLSessionDelegate {
    /// Only this host gets pinned/self-signed-cert handling. Any other host
    /// falls through to normal system trust evaluation.
    let pinnedHost: String

    /// Base64(SHA-256(SubjectPublicKeyInfo DER)) of this deployment's
    /// attestation service's current RSA-2048 public key.
    let pinnedSPKISHA256Base64: String

    init(pinnedHost: String, pinnedSPKISHA256Base64: String) {
        self.pinnedHost = pinnedHost
        self.pinnedSPKISHA256Base64 = pinnedSPKISHA256Base64
    }

    /// Standard SPKI ASN.1 header for a 2048-bit RSA public key (rsaEncryption
    /// OID + BIT STRING wrapper), prepended to the raw PKCS#1 key bytes that
    /// `SecKeyCopyExternalRepresentation` returns for RSA keys, to reconstruct
    /// the full SubjectPublicKeyInfo DER before hashing.
    private static let rsa2048SPKIHeader: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    ]

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard challenge.protectionSpace.host == pinnedHost else {
            // Not this deployment's attestation service — defer to normal
            // system trust evaluation. (This delegate is only ever attached
            // to EnclaveAttestationClient's own URLSession, so in practice
            // this host is always pinnedHost, but the guard keeps the intent
            // explicit and safe if that changes.)
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let leafKeyData = Self.leafPublicKeyData(from: serverTrust),
              Self.spkiSHA256Base64(rsaPublicKeyDER: leafKeyData) == pinnedSPKISHA256Base64
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

    private static func leafPublicKeyData(from trust: SecTrust) -> Data? {
        guard let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              let publicKey = SecCertificateCopyKey(certificate),
              let externalRepresentation = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else { return nil }
        return externalRepresentation
    }

    private static func spkiSHA256Base64(rsaPublicKeyDER pkcs1: Data) -> String {
        var full = Data(rsa2048SPKIHeader)
        full.append(pkcs1)
        let digest = SHA256.hash(data: full)
        return Data(digest).base64EncodedString()
    }
}

// MARK: - Hex decoding helper

extension Data {
    /// Decodes a hex string (even length, no "0x" prefix expected) into bytes.
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            bytes.append(byte)
            i += 2
        }
        self = Data(bytes)
    }
}
