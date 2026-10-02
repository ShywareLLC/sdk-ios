import XCTest
@testable import ShywareSDK

final class ShywareSDKTests: XCTestCase {
    func testCreateIdentityCommitmentUsesProviderSpecificSource() throws {
        let manifest = makeManifest(provider: "didit")

        let commitmentA = try createIdentityCommitment(
            manifest: manifest,
            input: .didit(personId: "person-123"),
            scope: "poll-1"
        )
        let commitmentB = try createIdentityCommitment(
            manifest: manifest,
            input: .didit(personId: "person-123"),
            scope: "poll-1"
        )
        let commitmentC = try createIdentityCommitment(
            manifest: manifest,
            input: .didit(personId: "person-123"),
            scope: "poll-2"
        )

        XCTAssertEqual(commitmentA, commitmentB)
        XCTAssertNotEqual(commitmentA, commitmentC)
    }

    func testCreateIdentityCommitmentRejectsMismatchedProvider() {
        let manifest = makeManifest(provider: "didit")

        XCTAssertThrowsError(
            try createIdentityCommitment(manifest: manifest, input: .wallet(address: "0xabc"))
        )
    }

    func testResolveEffectivePostureFallsBackToWriteOnlyWhenDeviceUntrusted() {
        let manifest = makeManifest(
            defaultPosture: "recoverable",
            writeOnlyOnUntrustedDeviceAttestation: true
        )

        let result = resolveEffectivePosture(manifest: manifest, signals: .untrusted)

        XCTAssertEqual(result.configuredPosture, "recoverable")
        XCTAssertEqual(result.effectivePosture, "write_only")
        XCTAssertTrue(result.fallbackActive)
        XCTAssertTrue(result.writeOnly)
        XCTAssertEqual(result.fallbackReasons, ["untrusted_device_attestation"])
    }

    func testResolveEffectivePosturePreservesRecoverableWhenTrusted() {
        let manifest = makeManifest(
            defaultPosture: "recoverable",
            writeOnlyOnUntrustedDeviceAttestation: true
        )

        let result = resolveEffectivePosture(manifest: manifest, signals: .trusted)

        XCTAssertEqual(result.effectivePosture, "recoverable")
        XCTAssertFalse(result.fallbackActive)
        XCTAssertTrue(result.recoverable)
        XCTAssertEqual(result.fallbackReasons, [])
    }

    func testAssertVotingManifestAcceptsMinimalValidVotingConfig() throws {
        try assertVotingManifest(makeManifest())
    }

    /// Regression test for a real production bug: Populist's bundled
    /// shyconfig.json omitted write_only_on_hsm_unavailable from
    /// deployment.runtime_fallbacks (it's optional in
    /// shyconfig.schema.json -- no "required" array on that object, and
    /// the Go server defaults an absent flag to false). RuntimeFallbacks
    /// relied on Swift's auto-synthesized Decodable, which required every
    /// one of its four non-optional stored properties to be present
    /// regardless of the memberwise init's own default parameter values
    /// (those only apply to programmatic construction, never decoding).
    /// The result: ShyConfig's decode failed entirely, VotingClient.from
    /// never returned a client, and every single vote and bookmark in the
    /// app failed before any network request was made -- confirmed live
    /// via a real device's exported debug log:
    /// "DecodingError.keyNotFound: ... write_only_on_hsm_unavailable".
    /// This test decodes a manifest missing that key (and, for good
    /// measure, every other runtime_fallbacks key too) and asserts it
    /// succeeds with every flag defaulting to false, rather than throwing.
    func testRuntimeFallbacksDecodeSucceedsWhenKeysAreMissing() throws {
        let json = """
        {
          "contract_version": "shyvoting-v1",
          "app": { "id": "populist", "chain_id": "shyware-1" },
          "api": { "base_url": "https://vote.example.com", "requires_auth": true, "auth_scheme": "app_attest" },
          "identity": { "provider": "didit", "mode": "stable", "kyc_required": true },
          "signing": { "required": true, "backend": "managed_hsm" },
          "anon_layer": { "black_box_required": true, "required_flows": [] },
          "receipts": { "match_store": "keychain", "user_access": "device_bound", "double_vote_enforcement": "server_side", "high_risk_region_blocklist": [] },
          "deployment": {
            "default_posture": "recoverable",
            "runtime_fallbacks": {},
            "allow_user_posture_override": false
          }
        }
        """
        let config = try JSONDecoder().decode(ShyConfig.self, from: Data(json.utf8))
        XCTAssertFalse(config.deployment.runtimeFallbacks.writeOnlyOnHSMUnavailable)
        XCTAssertFalse(config.deployment.runtimeFallbacks.writeOnlyOnMissingPlayIntegrity)
        XCTAssertFalse(config.deployment.runtimeFallbacks.writeOnlyOnUntrustedDeviceAttestation)
        XCTAssertFalse(config.deployment.runtimeFallbacks.writeOnlyOnHostileNetwork)
    }

    /// Same bug, the exact real-world shape: every OTHER runtime_fallbacks
    /// key present and true, only write_only_on_hsm_unavailable missing --
    /// matching Populist's actual bundled shyconfig.json byte-for-byte.
    func testRuntimeFallbacksDecodeSucceedsWhenOnlyHSMKeyIsMissing() throws {
        let json = """
        {
          "contract_version": "shyvoting-v1",
          "app": { "id": "populist", "chain_id": "shyware-1" },
          "api": { "base_url": "https://vote.example.com", "requires_auth": true, "auth_scheme": "app_attest" },
          "identity": { "provider": "didit", "mode": "stable", "kyc_required": true },
          "signing": { "required": true, "backend": "managed_hsm" },
          "anon_layer": { "black_box_required": true, "required_flows": [] },
          "receipts": { "match_store": "keychain", "user_access": "device_bound", "double_vote_enforcement": "server_side", "high_risk_region_blocklist": [] },
          "deployment": {
            "default_posture": "recoverable",
            "runtime_fallbacks": {
              "write_only_on_missing_play_integrity": false,
              "write_only_on_hostile_network": true,
              "write_only_on_untrusted_device_attestation": true
            },
            "allow_user_posture_override": false
          }
        }
        """
        let config = try JSONDecoder().decode(ShyConfig.self, from: Data(json.utf8))
        XCTAssertFalse(config.deployment.runtimeFallbacks.writeOnlyOnHSMUnavailable)
        XCTAssertTrue(config.deployment.runtimeFallbacks.writeOnlyOnHostileNetwork)
        XCTAssertTrue(config.deployment.runtimeFallbacks.writeOnlyOnUntrustedDeviceAttestation)
    }

    private func makeManifest(
        provider: String = "didit",
        defaultPosture: String = "recoverable",
        writeOnlyOnUntrustedDeviceAttestation: Bool = false
    ) -> ShyConfig {
        let json = """
        {
          "contract_version": "shyvoting-v1",
          "app": {
            "id": "populist",
            "chain_id": "shyware-1"
          },
          "api": {
            "base_url": "https://vote.example.com",
            "requires_auth": true,
            "auth_scheme": "app_attest"
          },
          "identity": {
            "provider": "\(provider)",
            "mode": "stable",
            "kyc_required": true
          },
          "signing": {
            "required": true,
            "backend": "managed_hsm"
          },
          "anon_layer": {
            "black_box_required": true,
            "required_flows": ["poll_read", "ballot_build", "ballot_submit", "receipt_verify"]
          },
          "receipts": {
            "match_store": "keychain",
            "user_access": "device_bound",
            "double_vote_enforcement": "server_side",
            "high_risk_region_blocklist": []
          },
          "deployment": {
            "default_posture": "\(defaultPosture)",
            "runtime_fallbacks": {
              "write_only_on_missing_play_integrity": false,
              "write_only_on_untrusted_device_attestation": \(writeOnlyOnUntrustedDeviceAttestation),
              "write_only_on_hostile_network": false,
              "write_only_on_hsm_unavailable": false
            },
            "allow_user_posture_override": false
          }
        }
        """

        return try! JSONDecoder().decode(
            ShyConfig.self,
            from: Data(json.utf8)
        )
    }
}
