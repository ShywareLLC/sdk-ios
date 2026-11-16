import XCTest
import CryptoKit
@testable import ShywareSDK

final class VoteShareGrantTests: XCTestCase {
    /// The reconciling authority (voteShareGrants.cjs grantMessage) signs over
    /// exactly these bytes; any drift breaks every grant.
    func testGrantMessageMatchesTheServerFormat() {
        let grant: [String: Any] = [
            "v": 1, "grant_id": "6f1c0e4a-0000-4000-8000-000000000001", "purpose": "vote_share", "scope": "all_votes",
            "grantor_uid": "alice", "grantee_uid": "bob", "issued_at": "2026-11-16T16:00:00Z",
        ]
        XCTAssertEqual(VotingClient.voteShareGrantMessage(grant),
            "shyware-vote-share-grant-v1\n6f1c0e4a-0000-4000-8000-000000000001\nvote_share\nall_votes\nalice\nbob\n2026-11-16T16:00:00Z")
    }

    func testADeviceSignatureVerifiesWithItsPublicKey() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("shyware-vote-share-grant-v1\nx".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, 64, "the server expects a 64-byte Ed25519 signature")
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
    }

    /// The enclave (voteShareGrants.cjs) computes the same HMAC over the same
    /// newline-joined fields; this value came from it.
    func testKeyRequestMACMatchesTheEnclave() {
        let message = ["shyware-vote-share-key-request-v1", "alice", "6f1c0e4a-0000-4000-8000-000000000001",
                       String(repeating: "cd", count: 32), "2026-11-16T17:00:00Z"].joined(separator: "\n")
        let secret = SymmetricKey(data: Data(repeating: 0xab, count: 32))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: secret).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(mac, "16c12e3ccf6945cd3072cdf63ef3036abcdad3b4a319d55688a7350fa6267c71")
    }
}
