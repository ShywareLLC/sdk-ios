import DeviceCheck
import CryptoKit
import Foundation

// Maps iOS App Attest to the RuntimeSignals shape that resolveEffectivePosture reads.
// On iOS, App Attest replaces Play Integrity — both map to deviceAttestation.trusted.
//
// AppAttestProvider is the canonical implementation for any shyware deployment
// using auth_scheme: "app_attest". It handles:
//   • Simulator / SwiftUI Preview detection (returns .untrusted gracefully)
//   • Key generation with UserDefaults persistence across app restarts
//   • Attestation ceremony + configurable backend registration
//   • Per-request assertions using SHA-256(method:url:body)

public class AppAttestProvider {
    private let dcService = DCAppAttestService.shared
    private let userDefaultsKey: String
    private let registrationURL: URL?

    private(set) public var keyId: String?

    /// - Parameters:
    ///   - storageKey: UserDefaults key for persisting the attested key ID.
    ///     Defaults to `"shyware.appAttest.keyId"`.
    ///   - registrationURL: Backend endpoint that validates the attestation object
    ///     with Apple and stores the key ID for future assertion verification.
    ///     Pass `nil` to skip backend registration (dev/test only).
    public init(
        storageKey: String = "shyware.appAttest.keyId",
        registrationURL: URL? = nil
    ) {
        self.userDefaultsKey = storageKey
        self.registrationURL = registrationURL
        self.keyId = UserDefaults.standard.string(forKey: storageKey)
    }

    // MARK: - Device support

    /// False on simulators, SwiftUI Previews, and devices where App Attest is unavailable.
    public var isSupported: Bool {
        guard !Self.isSimulator, !Self.isPreview else { return false }
        return dcService.isSupported
    }

    private static var isSimulator: Bool {
#if targetEnvironment(simulator)
        return true
#else
        return false
#endif
    }

    private static var isPreview: Bool {
        ProcessInfo.processInfo.environment["XCODE_RUNNING_FOR_PREVIEWS"] == "1"
    }

    // MARK: - Key lifecycle

    /// Ensures the device has an attested key and registers it with the backend.
    /// Idempotent — returns the stored key ID if the ceremony already completed.
    /// Clears the stored key and throws on any failure so the caller can fall
    /// back to write-only posture.
    @discardableResult
    public func attestKey() async throws -> String {
        if let stored = keyId { return stored }

        let newKey = try await dcService.generateKey()
        let challenge = randomBytes(32)
        let clientDataHash = Data(SHA256.hash(data: challenge))
        let attestation = try await dcService.attestKey(newKey, clientDataHash: clientDataHash)

        if let url = registrationURL {
            try await registerWithBackend(keyId: newKey, attestation: attestation, challenge: challenge, url: url)
        }

        UserDefaults.standard.set(newKey, forKey: userDefaultsKey)
        self.keyId = newKey
        return newKey
    }

    /// Restore a previously stored key ID — useful if you manage storage externally.
    public func restoreKey(_ id: String) {
        self.keyId = id
        UserDefaults.standard.set(id, forKey: userDefaultsKey)
    }

    /// Clear stored key, forcing full re-attestation on next `attestKey()` call.
    public func reset() {
        keyId = nil
        UserDefaults.standard.removeObject(forKey: userDefaultsKey)
    }

    // MARK: - Signals

    /// Runs the full attestation ceremony and returns `RuntimeSignals`.
    /// Call this during app launch, before initializing VotingClient.
    ///
    /// - Parameter network: The caller-supplied network signal. The SDK cannot
    ///   assess VPN activity or IP jurisdiction — that is the calling app's
    ///   responsibility. If `network.hostile` is `true` and the shyconfig has
    ///   `write_only_on_hostile_network: true`, the client will be write-only
    ///   regardless of device attestation status. Pass `.init(hostile: false)`
    ///   only after your app has verified the network is clean (e.g., no VPN
    ///   active, client IP not in the deployment's `high_risk_region_blocklist`).
    ///
    /// Returns `.untrusted` on unsupported devices or attestation failure.
    public func resolveSignals(
        network: RuntimeSignals.NetworkSignal = .init(hostile: false)
    ) async -> RuntimeSignals {
        guard isSupported else {
            return RuntimeSignals(
                playIntegrity: .init(available: false, passed: false),
                deviceAttestation: .init(trusted: false),
                network: network
            )
        }
        do {
            try await attestKey()
            return RuntimeSignals(
                playIntegrity: .init(available: false, passed: false),
                deviceAttestation: .init(trusted: true),
                network: network
            )
        } catch {
            return RuntimeSignals(
                playIntegrity: .init(available: false, passed: false),
                deviceAttestation: .init(trusted: false),
                network: network
            )
        }
    }

    // MARK: - Per-request assertion

    /// Generate an App Attest assertion for a single request.
    /// - Parameter requestData: The raw request body for POST requests, or
    ///   UTF-8 bytes of the absolute URL for GET requests.
    ///   The assertion covers `SHA-256(requestData)`.
    public func assert(requestData: Data) async throws -> Data {
        guard let id = keyId else {
            throw ShywareError.invalidInput("No attested App Attest key — call attestKey() first.")
        }
        let hash = Data(SHA256.hash(data: requestData))
        return try await dcService.generateAssertion(id, clientDataHash: hash)
    }

    /// Generate an assertion covering a `URLRequest` (method + URL + body).
    /// Matches the hash strategy used by Populist's AppAttestService.
    public func assert(for request: URLRequest) async throws -> Data {
        var components: [String] = []
        if let method = request.httpMethod { components.append(method) }
        if let url = request.url?.absoluteString { components.append(url) }
        if let body = request.httpBody { components.append(body.base64EncodedString()) }
        let combined = components.joined(separator: ":")
        let data = Data(combined.utf8)
        return try await assert(requestData: data)
    }

    /// Returns a `ShyAssertionProvider` closure wrapping this provider.
    /// Pass to `VotingClient.from(_:assertionProvider:)`.
    public func assertionProvider() -> ShyAssertionProvider {
        return { [weak self] requestData in
            guard let self else {
                throw ShywareError.invalidInput("AppAttestProvider deallocated.")
            }
            return try await self.assert(requestData: requestData)
        }
    }

    // MARK: - Private

    private func registerWithBackend(keyId: String, attestation: Data, challenge: Data, url: URL) async throws {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload: [String: Any] = [
            "keyId": keyId,
            "attestation": attestation.base64EncodedString(),
            "challenge": challenge.base64EncodedString(),
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (_, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw ShywareError.apiError("App Attest backend registration failed.")
        }
    }

    private func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
