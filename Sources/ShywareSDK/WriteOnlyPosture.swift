import Foundation

// Mirrors resolveEffectivePosture in votingClient.js exactly.
// The signal shape is platform-agnostic; the source of signals is platform-specific.

public struct RuntimeSignals: Sendable {
    public struct PlayIntegritySignal {
        public var available: Bool
        public var passed: Bool
        public init(available: Bool = false, passed: Bool = false) {
            self.available = available
            self.passed = passed
        }
    }
    public struct DeviceAttestationSignal {
        public var trusted: Bool
        public init(trusted: Bool = false) {
            self.trusted = trusted
        }
    }
    public struct NetworkSignal {
        public var hostile: Bool
        public init(hostile: Bool = false) {
            self.hostile = hostile
        }
    }
    public struct HSMSignal {
        public var available: Bool
        public init(available: Bool = true) {
            self.available = available
        }
    }

    public var playIntegrity: PlayIntegritySignal
    public var deviceAttestation: DeviceAttestationSignal
    public var network: NetworkSignal
    public var hsm: HSMSignal

    public init(
        playIntegrity: PlayIntegritySignal = .init(),
        deviceAttestation: DeviceAttestationSignal = .init(),
        network: NetworkSignal = .init(),
        hsm: HSMSignal = .init()
    ) {
        self.playIntegrity = playIntegrity
        self.deviceAttestation = deviceAttestation
        self.network = network
        self.hsm = hsm
    }

    // Convenience: device attested, no hostile network.
    public static var trusted: RuntimeSignals {
        RuntimeSignals(
            playIntegrity: .init(available: false, passed: false),
            deviceAttestation: .init(trusted: true),
            network: .init(hostile: false)
        )
    }

    // Convenience: no attestation — write-only fallback will activate.
    public static var untrusted: RuntimeSignals {
        RuntimeSignals()
    }
}

public struct PostureResult: Sendable {
    public let configuredPosture: String
    public let effectivePosture: String
    public let fallbackActive: Bool
    public let fallbackReasons: [String]
    public var writeOnly: Bool { effectivePosture == "write_only" }
    public var recoverable: Bool { effectivePosture == "recoverable" }
}

public func resolveEffectivePosture(manifest: ShyConfig, signals: RuntimeSignals) -> PostureResult {
    let fallbacks = manifest.deployment.runtimeFallbacks
    var reasons: [String] = []

    if fallbacks.writeOnlyOnMissingPlayIntegrity &&
        (!signals.playIntegrity.available || !signals.playIntegrity.passed) {
        reasons.append("missing_play_integrity")
    }
    if fallbacks.writeOnlyOnUntrustedDeviceAttestation && !signals.deviceAttestation.trusted {
        reasons.append("untrusted_device_attestation")
    }
    if fallbacks.writeOnlyOnHostileNetwork && signals.network.hostile {
        reasons.append("hostile_network")
    }
    if fallbacks.writeOnlyOnHSMUnavailable && !signals.hsm.available {
        reasons.append("hsm_unavailable")
    }

    let configured = manifest.deployment.defaultPosture
    let effective: String
    if configured == "coercion_resistant" || !reasons.isEmpty {
        effective = "write_only"
    } else {
        effective = "recoverable"
    }

    return PostureResult(
        configuredPosture: configured,
        effectivePosture: effective,
        fallbackActive: !reasons.isEmpty,
        fallbackReasons: reasons
    )
}
