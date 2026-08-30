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
