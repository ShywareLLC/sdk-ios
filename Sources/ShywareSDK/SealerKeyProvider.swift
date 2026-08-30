import CryptoKit
import Foundation

// MARK: - SealerKeyProvider protocol

/// Derives the AES-256-GCM sealer key for payload encryption/decryption.
/// The key derivation must be idempotent for the same config + identity input
/// so that re-derivation equals recovery.
public protocol SealerKeyProvider: Sendable {
    func deriveSealerKey(config: ShyConfig, input: IdentityInput) throws -> Data
}

// MARK: - AES-256-GCM sealing helpers (internal, used by StoreClient/ChatClient/BrowserClient)

/// Sealed envelope written to List 1 in canonical state.
struct SealedEnvelope: Codable, Sendable {
    let ciphertext: Data    // AES-GCM ciphertext
    let nonce: Data         // 12-byte nonce
    let tag: Data           // 16-byte authentication tag
}

/// Seals `plaintext` JSON using AES-256-GCM with the key from `provider`.
func sealJSON(_ value: some Encodable, provider: SealerKeyProvider, config: ShyConfig, input: IdentityInput) throws -> Data {
    let key = try provider.deriveSealerKey(config: config, input: input)
    let plaintext = try JSONEncoder().encode(value)
    return try aesGCMSeal(plaintext, key: key)
}

/// Seals raw `Data` using AES-256-GCM. Returns encoded `SealedEnvelope` JSON.
func aesGCMSeal(_ plaintext: Data, key: Data) throws -> Data {
    guard key.count == 32 else {
        throw ShywareError.invalidInput("Sealer key must be 32 bytes for AES-256-GCM.")
    }
    let symmetricKey = SymmetricKey(data: key)
    let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
    let envelope = SealedEnvelope(
        ciphertext: sealedBox.ciphertext,
        nonce: Data(sealedBox.nonce),
        tag: sealedBox.tag
    )
    return try JSONEncoder().encode(envelope)
}

/// Opens a `SealedEnvelope` JSON blob, returning the decrypted plaintext.
func aesGCMOpen(_ envelopeData: Data, key: Data) throws -> Data {
    guard key.count == 32 else {
        throw ShywareError.invalidInput("Sealer key must be 32 bytes for AES-256-GCM.")
    }
    let envelope = try JSONDecoder().decode(SealedEnvelope.self, from: envelopeData)
    let symmetricKey = SymmetricKey(data: key)
    let nonce = try AES.GCM.Nonce(data: envelope.nonce)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: envelope.ciphertext, tag: envelope.tag)
    return try AES.GCM.open(sealedBox, using: symmetricKey)
}
