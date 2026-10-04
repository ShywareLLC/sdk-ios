import CryptoKit
import Foundation
import Security

/// Registered-credential embodiment, iOS side: a Secure Enclave-backed P-256
/// keypair, generated once per device and registered against a
/// person-stable Firebase UID (via the IDV attestation enclave's
/// POST /register-browser-credential + a TxTypeRegisterIdentity chain tx),
/// then used to sign every future ballot cast/update -- no further Didit
/// session needed per vote. See
/// ShywareLLC/core/services/identity/registered_credential.go for the exact
/// message/signature scheme this mirrors, and
/// ShywareLLC/sdk/providers/registeredCredential.js for the web equivalent.
///
/// Secure Enclave only supports P-256 ECDSA -- this is why the
/// registered-credential embodiment standardizes on P-256 everywhere
/// (including web's WebCrypto fallback), deliberately different from the
/// existing per-poll Ed25519 voter_pub_key, which is untouched.
///
/// `SecureEnclave.P256.Signing.PrivateKey` itself never leaves the chip --
/// what this store persists in the Keychain is `dataRepresentation`, an
/// opaque, encrypted blob meaningless outside this device's Secure Enclave
/// (CryptoKit's documented pattern for Secure Enclave key persistence).
public class SecureEnclaveCredentialStore {
    let service: String
    let account = "registration_credential"

    public init(appId: String) {
        self.service = "com.comission.shyware.\(appId).registeredcredential"
    }

    /// Returns the existing registered credential if this device already
    /// has one, or generates, persists, and returns a new one.
    public func keypair() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw RegisteredCredentialError.secureEnclaveUnavailable
        }
        if let existing = try load() {
            return existing
        }
        let fresh = try SecureEnclave.P256.Signing.PrivateKey()
        try save(fresh)
        return fresh
    }

    /// True if this device already has a registered credential, without
    /// generating one.
    public func hasRegisteredCredential() -> Bool {
        (try? load()) != nil
    }

    /// Hex-encoded ANSI X9.63 (uncompressed, 0x04||X||Y) public key point --
    /// exactly the format ShywareLLC/core's decodeP256PubKeyHex expects.
    public func publicKeyHex() throws -> String {
        let key = try keypair()
        return key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    }

    private func save(_ key: SecureEnclave.P256.Signing.PrivateKey) throws {
        let data = key.dataRepresentation
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw RegisteredCredentialError.keychainFailure(status)
        }
    }

    private func load() throws -> SecureEnclave.P256.Signing.PrivateKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
    }

    /// Deletes the registered credential. Called during privacy wipe, or if
    /// the device needs to re-register under a fresh credential.
    public func delete() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public enum RegisteredCredentialError: Error {
        case keychainFailure(OSStatus)
        case secureEnclaveUnavailable
    }
}

/// Signs `message` (UTF-8 encoded) with the registered credential's private
/// key, returning an ASN.1 DER-encoded ECDSA signature -- CryptoKit's
/// `derRepresentation` on the resulting signature already matches what Go's
/// `ecdsa.VerifyASN1` expects, with no manual re-encoding needed (unlike the
/// web client, where WebCrypto's ECDSA output is always raw IEEE P1363 and
/// must be converted).
public func signWithRegisteredCredential(
    _ key: SecureEnclave.P256.Signing.PrivateKey,
    message: String
) throws -> Data {
    let signature = try key.signature(for: Data(message.utf8))
    return signature.derRepresentation
}
