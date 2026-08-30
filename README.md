# ShywareSDK — iOS

Swift Package for the iOS Shyware client SDK.  
Platforms: macOS 13+, iOS 16+ · Swift 5.9+

---

## Installation

### Swift Package Manager

Add to `Package.swift`:

```swift
.package(url: "https://github.com/NickCarducci/Shyware-SDK.git", from: "0.1.0")
```

Or in Xcode: **File → Add Packages**, enter `https://github.com/NickCarducci/Shyware-SDK.git`.

Then add the target dependency:

```swift
.product(name: "ShywareSDK", package: "ShywareSDK")
```

### Local (monorepo)

```swift
.package(path: "../shyware/sdk/ios")
```

---

## Clients

Each client is constructed from a `ShyConfig` manifest decoded from `shyconfig.json`.

| Client | Contract version | Domain |
|---|---|---|
| `VotingClient` | `shyvoting-v1` | Elections / referenda |
| `WireClient` | `shywire-v1` | Private value transfer |
| `SharesClient` | `shyshares-v1` | DAO governance / tokenized equity |
| `CustodyClient` | `shycustody-v1` | Physical commodity custody |
| `ContractsClient` | `shycontracts-v1` | Revenue-based financing |
| `StoreClient` | `shystore-v1` | Sealed anonymous store |
| `StreamClient` | `shystream-v1` | Anonymous stream segments |
| `ChatClient` | `shychat-v1` | End-to-end sealed messaging |
| `BrowserClient` | `shybrowser-v1` | Anonymous browser analytics |
| `BetsClient` | `shybets-v1` | Anonymous prediction markets |
| `LotsClient` | `shylots-v1` | Sealed-bid auction lots |

---

## Quick start — shyvoting

```swift
import ShywareSDK

let config = ShyConfig(
    contractVersion: "shyvoting-v1",
    app: AppConfig(id: "your-app-id"),
    api: APIConfig(baseURL: "https://vote.yourdomain.com"),
    identity: IdentityConfig(provider: "didit", mode: "stable_person_id"),
    signing: SigningConfig(required: true, backend: "aws_kms"),
    anonLayer: AnonLayerConfig(blackBoxRequired: true,
        requiredFlows: ["poll_read", "ballot_build", "ballot_submit", "receipt_verify"]),
    receipts: ReceiptsConfig(),
    deployment: DeploymentConfig()
)

let client = try VotingClient.from(config)

// Cast a ballot (L1 + L2 two-list atomic write)
let ballot = try await client.castBallot(
    pollId: "poll-2026-general",
    choice: "yes",
    input: .didit(personId: "user-didit-person-id")
)
// ballot.ballotId    — server-assigned direction-free identifier (List 1)
// ballot.ballotNonce — local nonce for inclusion-proof recovery
```

---

## Key types

### `ShyConfig`

The top-level manifest. Decodes from `shyconfig.json` via `JSONDecoder` or
`ShyConfig.dpia(contractVersion:app:api:...)` for test fixtures.

Optional domain blocks (`wire`, `custody`, `store`, etc.) are decoded only when
present; absent blocks produce `nil`.

### `IdentityInput`

```swift
public enum IdentityInput {
    case didit(personId: String)
    case diditJourney(journeyId: String)
    case wallet(address: String)
    case identus(subjectId: String)
    case raw(value: String)
}
```

### `BallotResult` (VotingClient)

```swift
public struct BallotResult {
    public let ballotId: String      // server-assigned List-1 direction-free identifier
    public let ballotNonce: String   // local nonce; used for ballot-inclusion proof
    public let identityHash: String  // H(commitment || pollId) — never sent to IDV
    public let txJson: String        // full transaction payload (audit trail)
}
```

### `TransferResult` (WireClient)

```swift
public struct TransferResult {
    public let transferId: String       // direction-free List-1 identifier
    public let submissionNonce: String
    public let nullifier: String
    public let txJson: String?
    public var submissionId: String { transferId }  // cross-platform alias
}
```

### `SupplyResult` (WireClient)

```swift
public struct SupplyResult {
    public let assetId: String
    public let totalSupply: Int64
    public let circulatingSupply: Int64
    public var totalUSDCe: Int64 { totalSupply }  // USDCe deployment alias
}
```

### `CountResult` (WireClient)

Contains the two-list count-match invariant fields:

```swift
public struct CountResult {
    public let transferId: String
    public let count: Int64
    public let l1Count: Int64    // List-1 record count (direction-free submissions)
    public let l2Count: Int64    // List-2 record count (identity registrations)
    public let countMatch: Bool  // l1Count == l2Count — the structural invariant
}
```

### `AttestationResult` (WireClient, VotingClient, SharesClient)

```swift
public struct AttestationResult {
    public let scopingId: String
    public let l1MerkleRoot: String
    public let l2MerkleRoot: String
    public let signature: String     // HSM-signed period-close attestation
    public let attestedAt: Int64
    public var attestation: String { signature }
}
```

---

## Write-only posture

```swift
import ShywareSDK

var signals = RuntimeSignals()
signals.playIntegrity    = RuntimeSignals.PlayIntegritySignal(available: true, passed: true)
signals.deviceAttestation = RuntimeSignals.DeviceAttestationSignal(trusted: true)
signals.network          = RuntimeSignals.NetworkSignal(hostile: false)

let posture = resolveEffectivePosture(manifest: config, signals: signals)
if posture.writeOnly {
    // suppress all readback — only the direction-free ballot/transfer ID is retained
}
```

Fallback triggers are declared in `deployment.runtime_fallbacks`:

| Trigger | Field |
|---|---|
| Play Integrity unavailable or failed | `write_only_on_missing_play_integrity` |
| Device attestation untrusted | `write_only_on_untrusted_device_attestation` |
| Hostile network detected | `write_only_on_hostile_network` |
| HSM unavailable | `write_only_on_hsm_unavailable` |

---

## Testing — DevBypassURLProtocol

For DPIA / integration tests that need to inject per-user auth headers without
modifying the SDK call sites:

```swift
// In setUp()
DevBypassURLProtocol.aliceToken   = cognitoToken
DevBypassURLProtocol.aliceDevUid  = "alice-domain:alice:\(run)"
DevBypassURLProtocol.activeUser   = "alice"
URLProtocol.registerClass(DevBypassURLProtocol.self)

// In tearDown()
URLProtocol.unregisterClass(DevBypassURLProtocol.self)
```

> **Note:** `async URLSession.data(for:)` does not reliably invoke registered
> `URLProtocol` subclasses on macOS 15. All SDK HTTP methods use
> `dataTask(with:completionHandler:)` wrapped in `withCheckedThrowingContinuation`
> to ensure the protocol intercepts correctly.

---

## Manifest validation

Each `Client.from()` call validates the manifest and throws `ShywareError.invalidManifest`
if the contract version, required flows, signing configuration, or domain block are absent or incorrect.

---

## DPIA / GDPR note

This SDK implements structural anonymity by write architecture: the L1 submission
record and L2 identity record share no join key at the protocol layer.  
See `patent/mainhub/dpia/` for the full GDPR Data Protection Impact Assessment,
per-domain evidence artifacts, and the EDPB DPIA template output.
