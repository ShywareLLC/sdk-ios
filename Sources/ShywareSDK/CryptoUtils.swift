import CryptoKit
import Foundation
import Security

// MARK: - Shared cryptographic utilities
// Used by all SDK clients. Internal (module-visible).

/// Generate a cryptographically random hex string.
/// - Parameter byteCount: Number of random bytes (hex output length = byteCount * 2).
func randomHex(_ byteCount: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
    return bytes.map { String(format: "%02x", $0) }.joined()
}
