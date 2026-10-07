# Changelog

## 0.2.0

- Voting manifest validation accepts deployments without signing keys or KMS. Optional period-close attestations remain independent of the protocol's structural guarantees.
- Receipt verification derives the canonical ballot ID from decoded beacon and nonce bytes. Receipts without a beacon cannot verify.
- Write-only ballots retain receipts and newly generated voter keys in memory and request suppression of relay recovery records. Account-scoped Keychain stores prevent cross-account reuse.
- Runtime device/network safety fallbacks cannot be relaxed by a recoverable operator override.
- Decode canonical poll vote dictionaries and expose voter counts for count-match checks.
- Add authenticated off-chain recovery-data deletion. This requires a relay implementing `POST /recovery/delete`.

Existing unscoped Keychain receipts and keys are not automatically imported into an account's namespace. A deployment may require renewed device/identity verification when updating from earlier clients. Write-only session state is deliberately lost when the process exits.
