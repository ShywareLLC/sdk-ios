import Foundation
import Security

/// Stores a person's recoverable `person_secret` (the client-held value
/// identity_hash = F(person_secret, poll_id) is derived from -- see
/// VotingClient's recovery methods) in the iOS Keychain, gated behind the
/// device's own native passcode/Face ID/Touch ID (`kSecAccessControl` with
/// `.userPresence`) -- NOT merely "device unlocked at some point" the way
/// `KeychainReceiptStore`/`KeychainVoterKeyStore` above are. Every `load()`
/// triggers the OS's own authentication prompt.
///
/// Why a device-local passcode/biometric gate here doesn't weaken Sybil
/// resistance: the chain's own `(poll_id, identity_hash)` uniqueness
/// constraint is what enforces one-person-one-vote, enforced on-chain
/// regardless of how a device gates repeat LOCAL access to an
/// already-recovered secret. What a device-local gate protects against is
/// a narrower, different thing -- device theft / coercion (can someone who
/// has this device and its passcode vote as this person, repeatedly,
/// without any fresh liveness proof) -- which is exactly why `wipe()`
/// below exists: a user-visible panic control, not a Sybil-resistance
/// mechanism.
///
/// Deliberately NOT used under `coercion_resistant` deployment posture
/// (`effectivePosture().writeOnly`) -- see VotingClient's recovery methods,
/// which check posture before ever calling `save()` here. Caching this
/// secret at all under that posture is itself the wrong behavior (evidence
/// of enrollment persists on a device a coercer could compel the passcode
/// for), not something a passcode gate mitigates -- that's a posture-level
/// decision made by the caller, not by this class.
public class KeychainPersonSecretStore {
    let service: String

    public init(appId: String) {
        self.service = "com.comission.shyware.\(appId).personsecret"
    }

    /// Stores `secret` under `account` (the Firebase UID this secret
    /// belongs to -- not the poll_id; one person_secret serves every poll).
    /// Replaces any existing value for the same account.
    public func save(_ secret: Data, account: String) throws {
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            nil
        ) else {
            throw PersonSecretStoreError.accessControlCreationFailed
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: secret,
            kSecAttrAccessControl: access,
        ]
        // Delete first without triggering an auth prompt (a plain delete-by-
        // identifier query, no kSecReturnData/userPresence check applies to
        // SecItemDelete) so a re-save doesn't require two separate prompts.
        let deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PersonSecretStoreError.keychainFailure(status)
        }
    }

    /// Loads the stored secret for `account`, prompting the device's native
    /// passcode/Face ID/Touch ID UI. Returns nil if nothing is stored for
    /// this account (not yet enrolled on this device) -- NOT the same as
    /// an authentication failure, which throws instead.
    public func load(account: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PersonSecretStoreError.keychainFailure(status)
        }
        return data
    }

    /// Panic-wipe: deletes the stored secret for `account`. After this,
    /// the device is indistinguishable from one that never enrolled --
    /// the next vote attempt falls back to a fresh biometric-authentication
    /// recovery round-trip, same as a brand-new device. No auth prompt;
    /// deletion-by-identifier doesn't require unlocking the item first.
    public func wipe(account: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Wipes every account's cached secret under this deployment. Called
    /// during a full privacy wipe, same convention as
    /// KeychainReceiptStore.deleteAll()/KeychainVoterKeyStore.deleteAll().
    public func wipeAll() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public enum PersonSecretStoreError: Error {
        case keychainFailure(OSStatus)
        case accessControlCreationFailed
    }
}
