import CryptoKit
import Foundation
import Security

public struct BallotReceipt: Codable, Sendable {
    public let pollId: String
    public let ballotId: String
    public let ballotNonce: String
    public let choice: String
    public let identityHash: String
    public let submittedAt: Date
    /// Required to ever recompute ballotId again (verifyReceipt, or a future
    /// buildBallotUpdate call) -- see deriveSubmissionIdHex. Optional, not
    /// defaulted, specifically so Codable's synthesized decoder can still
    /// read receipts already persisted in the Keychain from before this
    /// field existed (2026-10-07) -- those decode with beaconBlockHash: nil
    /// rather than failing to decode at all.
    public let beaconBlockHash: String?

    public init(pollId: String, ballotId: String, ballotNonce: String,
                choice: String, identityHash: String, submittedAt: Date = Date(),
                beaconBlockHash: String? = nil) {
        self.pollId = pollId
        self.ballotId = ballotId
        self.ballotNonce = ballotNonce
        self.choice = choice
        self.identityHash = identityHash
        self.submittedAt = submittedAt
        self.beaconBlockHash = beaconBlockHash
    }
}

/// Stores ballot receipts in the iOS Keychain under kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
/// Items survive app reinstall but are device-bound — consistent with the write-only / recovery model.
public class KeychainReceiptStore {
    let service: String

    public init(appId: String) {
        self.service = "com.comission.shyware.\(appId).receipts"
    }

    public func save(_ receipt: BallotReceipt) throws {
        let data = try JSONEncoder().encode(receipt)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: receipt.pollId,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ReceiptStoreError.keychainFailure(status)
        }
    }

    public func load(pollId: String) throws -> BallotReceipt? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: pollId,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return try JSONDecoder().decode(BallotReceipt.self, from: data)
    }

    public func delete(pollId: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: pollId,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Deletes all receipts for this deployment. Called during privacy wipe.
    public func deleteAll() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public enum ReceiptStoreError: Error {
        case keychainFailure(OSStatus)
    }
}

/// Stores one Ed25519 per-poll voter keypair per poll_id in the iOS Keychain,
/// same accessibility/service-naming pattern as KeychainReceiptStore above
/// (device-bound, survives app reinstall).
///
/// This exists because VotingClient.buildBallot previously generated a fresh
/// Curve25519.Signing.PrivateKey() on every single call, with no persistence
/// at all. That meant any retry after a transient failure (a network blip,
/// an unrelated downstream error, even just the user tapping twice) looked
/// like a *different* voter to the IDV attestation enclave's one-time-use-
/// per-poll replay guard, permanently orphaning that poll for the
/// underlying Didit session on the very first failed attempt -- regardless
/// of whether the ballot itself ever actually reached canonical state.
/// Found live 2026-10-03 after fixing the exact same bug in the web SDK
/// (votingClient.js's buildVoteEnvelope) and failing to also apply it here,
/// where it was actually being exercised in testing all along.
public class KeychainVoterKeyStore {
    let service: String

    public init(appId: String) {
        self.service = "com.comission.shyware.\(appId).voterkeys"
    }

    /// Returns the existing per-poll keypair if one was already generated
    /// for this poll, or generates, persists, and returns a new one.
    /// Callers should always go through this rather than constructing their
    /// own Curve25519.Signing.PrivateKey() directly for a per-poll ballot.
    public func keypair(forPollId pollId: String) throws -> Curve25519.Signing.PrivateKey {
        if let existing = try load(pollId: pollId) {
            return existing
        }
        let fresh = Curve25519.Signing.PrivateKey()
        try save(fresh, pollId: pollId)
        return fresh
    }

    private func save(_ key: Curve25519.Signing.PrivateKey, pollId: String) throws {
        let data = key.rawRepresentation
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: pollId,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VoterKeyStoreError.keychainFailure(status)
        }
    }

    private func load(pollId: String) throws -> Curve25519.Signing.PrivateKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: pollId,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
    }

    /// Deletes all per-poll voter keys for this deployment. Called during
    /// privacy wipe, same as KeychainReceiptStore.deleteAll().
    public func deleteAll() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public enum VoterKeyStoreError: Error {
        case keychainFailure(OSStatus)
    }
}
