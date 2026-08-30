import Foundation
import Security

public struct BallotReceipt: Codable, Sendable {
    public let pollId: String
    public let ballotId: String
    public let ballotNonce: String
    public let choice: String
    public let identityHash: String
    public let submittedAt: Date

    public init(pollId: String, ballotId: String, ballotNonce: String,
                choice: String, identityHash: String, submittedAt: Date = Date()) {
        self.pollId = pollId
        self.ballotId = ballotId
        self.ballotNonce = ballotNonce
        self.choice = choice
        self.identityHash = identityHash
        self.submittedAt = submittedAt
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
