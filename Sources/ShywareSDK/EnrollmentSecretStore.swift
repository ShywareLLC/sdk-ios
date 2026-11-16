import Foundation
import CryptoKit
import Security

/// The secret a device commits to BEFORE a Didit verification starts.
///
/// The device generates 32 random bytes and sends only their SHA-256 (the
/// commitment) when the verification session is created; the session's
/// vendor_data carries that hash, which Didit returns unchanged. To enroll
/// with the enclave after the scan, the device presents the secret itself.
/// Nobody else -- not the backend that created the session (it saw only the
/// hash), not Didit, not anyone who later learns the session id -- can enroll
/// with that verification. Kept in this device's Keychain only.
public enum EnrollmentSecretStore {
    static let service = "com.comission.shyware.enrollment-secret"

    /// Creates (or reuses) this account's pending secret and returns its
    /// commitment, hex. Call right before starting a verification.
    public static func commitment(for userId: String) throws -> String {
        let secret = try pendingSecret(for: userId) ?? {
            var bytes = Data(count: 32)
            let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            guard status == errSecSuccess else { throw EnrollmentSecretError.keychainFailure(status) }
            try save(bytes, for: userId)
            return bytes
        }()
        return SHA256.hash(data: secret).map { String(format: "%02x", $0) }.joined()
    }

    /// The pending secret, hex, if this device started a verification.
    public static func secretHex(for userId: String) -> String? {
        (try? pendingSecret(for: userId))?.map { String(format: "%02x", $0) }.joined()
    }

    /// Forget the secret once enrollment succeeded (it's single-use).
    public static func clear(for userId: String) {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: userId] as CFDictionary)
    }

    private static func pendingSecret(for userId: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: userId,
            kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw EnrollmentSecretError.keychainFailure(status) }
        return result as? Data
    }

    private static func save(_ data: Data, for userId: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: userId,
            kSecValueData: data, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw EnrollmentSecretError.keychainFailure(status) }
    }
}

public enum EnrollmentSecretError: Error {
    case keychainFailure(OSStatus)
}
