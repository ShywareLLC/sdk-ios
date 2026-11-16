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
}
