import XCTest
@testable import ShywareSDK

final class ShywareSDKTests: XCTestCase {
    func testUnsignedDomainClientsRetainStructuralValidation() throws {
        let cases: [(String, [String], (ShyConfig) throws -> Void)] = [
            ("shywire-v1", ["wire_issue", "wire_transfer", "wire_redeem"], assertWireManifest),
            ("shycontracts-v1", ["contract_register", "contract_activate", "contract_execute"], assertContractsManifest),
            ("shycustody-v1", ["policy_read", "lot_record", "silo_transfer", "redemption_request", "redemption_settlement", "demurrage_apply"], assertCustodyManifest),
            ("shyshares-v1", ["organization_read", "membership_snapshot_read", "proposal_create", "weighted_ballot_submit", "tally_read", "action_queue_read", "action_dispatch"], assertSharesManifest),
            ("shybets-v1", ["event_create", "order_place", "order_book_read", "settlement_read", "settlement_finalize", "reconcile_request"], assertBetsManifest),
        ]
        for (contract, flows, validate) in cases {
            var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(makeManifest(signingRequired: false, signingBackend: "none"))) as! [String: Any]
            json["contract_version"] = contract
            json["anon_layer"] = ["black_box_required": true, "required_flows": flows]
            var config = try JSONDecoder().decode(ShyConfig.self, from: JSONSerialization.data(withJSONObject: json))
            XCTAssertNoThrow(try validate(config), contract)
            json["signing"] = ["required": false, "backend": "software"]
            config = try JSONDecoder().decode(ShyConfig.self, from: JSONSerialization.data(withJSONObject: json))
            XCTAssertNoThrow(try validate(config), contract)
            json["anon_layer"] = ["black_box_required": false, "required_flows": flows]
            config = try JSONDecoder().decode(ShyConfig.self, from: JSONSerialization.data(withJSONObject: json))
            XCTAssertThrowsError(try validate(config), contract)
        }
    }

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

    func testUnsignedVotingManifestIsValid() throws {
        let config = makeManifest(signingRequired: false, signingBackend: "none")
        XCTAssertNoThrow(try assertVotingManifest(config))
    }

    func testReceiptVerificationMatchesCanonicalBeaconDerivedID() async throws {
        let client = try VotingClient.from(makeManifest(signingRequired: false, signingBackend: "none"))
        let beacon = String(repeating: "11", count: 32)
        let nonce = String(repeating: "22", count: 32)
        let expected = "5189c77d29fe5d546a045ec46986852785fea5c13ac7da9c115ff5fb6edf817c"
        XCTAssertEqual(deriveSubmissionIdHex(beaconBlockHash: beacon, nonceHex: nonce), expected)
        let votes = try JSONDecoder().decode([VoteRecord].self,
            from: Data("[{\"ballot_id\":\"\(expected)\",\"choices\":[\"yes\"]}]".utf8))
        let valid = await client.verifyReceipt(nonce: nonce, expectedChoice: "yes", votes: votes, beaconBlockHash: beacon)
        XCTAssertTrue(valid.verified)
        let wrongChoice = await client.verifyReceipt(nonce: nonce, expectedChoice: "no", votes: votes, beaconBlockHash: beacon)
        XCTAssertFalse(wrongChoice.verified)
        let missingBeacon = await client.verifyReceipt(nonce: nonce, expectedChoice: "yes", votes: votes)
        XCTAssertFalse(missingBeacon.verified)
    }

    func testReceiptAndVoterKeysAreIsolatedByAccount() {
        XCTAssertNotEqual(KeychainReceiptStore(appId: "test", storageScope: "alice").service,
                          KeychainReceiptStore(appId: "test", storageScope: "bob").service)
        XCTAssertNotEqual(KeychainVoterKeyStore(appId: "test", storageScope: "alice").service,
                          KeychainVoterKeyStore(appId: "test", storageScope: "bob").service)
    }

    func testCanonicalVotesDictionaryDecodes() throws {
        let json = "{\"abc\":{\"ballot_id\":\"abc\",\"choices\":[\"yes\"]}}"
        let response = try JSONDecoder().decode(VotesResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.votes.count, 1)
        XCTAssertEqual(response.votes[0].ballotId, "abc")
        XCTAssertEqual(response.votes[0].choices, ["yes"])
        let empty = try JSONDecoder().decode(VotesResponse.self, from: Data("{}".utf8))
        XCTAssertTrue(empty.votes.isEmpty)
    }

    func testUnknownNetworkDefaultsToHostile() async {
        let signals = await AppAttestProvider(storageKey: UUID().uuidString).resolveSignals()
        XCTAssertTrue(signals.network.hostile)
    }

    func testAppAttestRegistrationUsesFreshAuthentication() async throws {
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VotingTestURLProtocol.self]
        let session = URLSession(configuration: sessionConfig)
        defer { session.invalidateAndCancel(); VotingTestURLProtocol.handler = nil }
        let url = URL(string: "https://example.test/attest/register")!
        var requests = 0
        VotingTestURLProtocol.handler = { request in
            requests += 1
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer fresh-token")
            return Data("{}".utf8)
        }
        let provider = AppAttestProvider(registrationURL: url, registrationTokenProvider: { "fresh-token" }, session: session)
        try await provider.registerWithBackend(keyId: "key", attestation: Data([1]), challenge: Data([2]), url: url)
        XCTAssertEqual(requests, 1)
        let signedOut = AppAttestProvider(registrationURL: url, registrationTokenProvider: { nil }, session: session)
        do {
            try await signedOut.registerWithBackend(keyId: "key", attestation: Data([1]), challenge: Data([2]), url: url)
            XCTFail("Registration proceeded without configured authentication")
        } catch { }
        XCTAssertEqual(requests, 1)
    }

    func testWriteOnlyCastAndUpdateKeepReceiptOnlyInMemory() async throws {
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VotingTestURLProtocol.self]
        let session = URLSession(configuration: sessionConfig)
        let scope = UUID().uuidString
        let config = makeManifest(signingRequired: false, signingBackend: "none", writeOnlyOnUntrustedDeviceAttestation: true)
        let client = try VotingClient.from(config, storageScope: scope, session: session)
        VotingTestURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Shyware-Posture"), "write_only")
            if request.url?.path == "/health" {
                return Data("{\"result\":{\"sync_info\":{\"latest_block_hash\":\"\(String(repeating: "11", count: 32))\",\"latest_block_height\":\"1\"}}}".utf8)
            }
            return Data("{\"queued\":true}".utf8)
        }
        defer { session.invalidateAndCancel(); VotingTestURLProtocol.handler = nil }
        let result = try await client.castBallot(pollId: "poll-1", choice: "yes", input: .didit(personId: "alice"))
        let receipt = try await client.loadReceipt(pollId: "poll-1")
        XCTAssertEqual(receipt?.ballotId, result.ballotId)
        XCTAssertNil(try KeychainReceiptStore(appId: config.app.id, storageScope: scope).load(pollId: "poll-1"))
        XCTAssertNil(try KeychainVoterKeyStore(appId: config.app.id, storageScope: scope).existingKey(forPollId: "poll-1"))
        _ = try await client.updateBallot(pollId: "poll-1", newChoices: ["no"])
        let updated = try await client.loadReceipt(pollId: "poll-1")
        XCTAssertEqual(updated?.choice, "no")
        XCTAssertNil(try KeychainReceiptStore(appId: config.app.id, storageScope: scope).load(pollId: "poll-1"))
        await client.clearSession()
        let cleared = try await client.loadReceipt(pollId: "poll-1")
        XCTAssertNil(cleared)
    }

    func testOperatorCannotMakeHostileNetworkRecoverable() async throws {
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(makeManifest(signingRequired: false, signingBackend: "none"))) as! [String: Any]
        var deployment = json["deployment"] as! [String: Any]
        deployment["posture_endpoint"] = "/posture"
        var fallbacks = deployment["runtime_fallbacks"] as! [String: Any]
        fallbacks["write_only_on_hostile_network"] = true
        deployment["runtime_fallbacks"] = fallbacks
        json["deployment"] = deployment
        let config = try JSONDecoder().decode(ShyConfig.self, from: JSONSerialization.data(withJSONObject: json))
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VotingTestURLProtocol.self]
        let session = URLSession(configuration: sessionConfig)
        VotingTestURLProtocol.handler = { _ in Data("{\"posture\":\"recoverable\",\"source\":\"operator\"}".utf8) }
        defer { session.invalidateAndCancel(); VotingTestURLProtocol.handler = nil }
        let client = try VotingClient.from(config, session: session)
        await client.setRuntimeSignals(RuntimeSignals(network: .init(hostile: true)))
        await client.fetchOperatorPosture()
        let posture = await client.effectivePosture()
        XCTAssertTrue(posture.writeOnly)
        XCTAssertTrue(posture.fallbackReasons.contains("hostile_network"))
    }

    func testRejectedCastDoesNotCreateReceipt() async throws {
        let config = makeManifest(signingRequired: false, signingBackend: "none", defaultPosture: "write_only")
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [VotingTestURLProtocol.self]
        let session = URLSession(configuration: sessionConfig)
        VotingTestURLProtocol.handler = { request in
            if request.url?.path == "/health" {
                return Data("{\"result\":{\"sync_info\":{\"latest_block_hash\":\"\(String(repeating: "11", count: 32))\",\"latest_block_height\":\"1\"}}}".utf8)
            }
            return Data("{\"result\":{\"check_tx\":{\"code\":0},\"tx_result\":{\"code\":1}}}".utf8)
        }
        defer { session.invalidateAndCancel(); VotingTestURLProtocol.handler = nil }
        let client = try VotingClient.from(config, session: session)
        do {
            _ = try await client.castBallot(pollId: "rejected", choice: "yes", input: .didit(personId: "alice"))
            XCTFail("Rejected ballot appeared submitted")
        } catch ShywareError.apiError {}
        let receipt = try await client.loadReceipt(pollId: "rejected")
        XCTAssertNil(receipt)
    }

    private func makeManifest(
        provider: String = "didit",
        signingRequired: Bool = true,
        signingBackend: String = "managed_hsm",
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
            "required": \(signingRequired),
            "backend": "\(signingBackend)"
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

private final class VotingTestURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> Data)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let data = try Self.handler!(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
