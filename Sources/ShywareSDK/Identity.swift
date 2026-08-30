import CryptoKit
import Foundation

// MARK: - Identity input

public enum IdentityInput {
    case didit(personId: String)
    case diditJourney(journeyId: String)
    case wallet(address: String)
    case identus(subjectId: String)
    case raw(value: String)
}

// MARK: - Commitment derivation
// Mirrors identityClient.js: SHA-256(namespace:provider:source[:scope])

public func createIdentityCommitment(
    manifest: ShyConfig,
    input: IdentityInput,
    namespace: String = "stable_identity",
    scope: String = ""
) throws -> String {
    let provider = manifest.identity.provider
    let source = try stableIdentitySource(provider: provider, input: input)
    var parts = [namespace, provider, source]
    if !scope.isEmpty { parts.append(scope) }
    return sha256hex(parts.joined(separator: ":"))
}

// MARK: - Proof hash
// Mirrors identityClient.js: SHA-256("proof":provider:source:workflowId:issuerDid:scope:audience:nonce)

public func createIdentityProofHash(
    manifest: ShyConfig,
    input: IdentityInput,
    scope: String = "",
    audience: String = ""
) throws -> String? {
    let provider = manifest.identity.provider
    guard provider != "wallet", provider != "none" else { return nil }
    let source = try stableIdentitySource(provider: provider, input: input)
    let workflowId = manifest.identity.workflowId ?? ""
    let issuerDid = manifest.identity.issuerDid ?? ""
    let parts = ["proof", provider, source, workflowId, issuerDid, scope, audience, ""]
    return sha256hex(parts.joined(separator: ":"))
}

// MARK: - Internal

private func stableIdentitySource(provider: String, input: IdentityInput) throws -> String {
    switch (provider, input) {
    case ("didit", .didit(let id)):       return id
    case ("didit", .diditJourney(let id)): return id
    case ("wallet", .wallet(let addr)):   return addr.lowercased()
    case ("identus", .identus(let sid)):  return sid
    case (_, .raw(let v)):               return v
    default:
        throw ShywareError.invalidInput("Identity input type does not match manifest provider '\(provider)'.")
    }
}

// MARK: - SHA-256 utility

func sha256hex(_ input: String) -> String {
    let data = Data(input.utf8)
    let digest = SHA256.hash(data: data)
    return digest.map { String(format: "%02x", $0) }.joined()
}
