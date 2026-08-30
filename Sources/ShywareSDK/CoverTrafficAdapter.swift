import Foundation

// Mirrors CoverTrafficInterface (sdk/web/adapters/ledger/coverTraffic.js).
// Wraps any submit closure. Real submissions absorb the next scheduled dummy
// slot so the aggregate transport-layer request rate stays governed by the
// configured cover-traffic schedule (Claim 9).

private let dummyPrefix = "__cover__"

public struct CoverTrafficResult {
    public let isDummy: Bool
    public let canonicalWrite: Bool
}

public class CoverTrafficAdapter {
    private let ratePerMinute: Int
    private var pendingRealCount: Int = 0
    private let lock = NSLock()
    private var timer: Timer?

    public var dummiesFired: Int = 0
    public var dummiesAbsorbed: Int = 0

    public init(ratePerMinute: Int = 10) {
        self.ratePerMinute = ratePerMinute
    }

    public static func isDummy(_ submissionId: String) -> Bool {
        submissionId.hasPrefix(dummyPrefix)
    }

    public func makeDummySubmissionId() -> String {
        dummyPrefix + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    // Call when a real submission is dispatched. Absorbs next dummy slot.
    public func onRealSubmission() {
        lock.lock(); pendingRealCount += 1; lock.unlock()
    }

    // Models one timer tick. Returns true if a dummy was fired, false if absorbed.
    public func tick() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if pendingRealCount > 0 {
            pendingRealCount -= 1
            dummiesAbsorbed += 1
            return false
        }
        dummiesFired += 1
        return true
    }

    public static func wrapSubmit(
        list1SubmissionId: String,
        canonicalCounter: inout Int
    ) -> CoverTrafficResult {
        if list1SubmissionId.hasPrefix(dummyPrefix) {
            return CoverTrafficResult(isDummy: true, canonicalWrite: false)
        }
        canonicalCounter += 1
        return CoverTrafficResult(isDummy: false, canonicalWrite: true)
    }
}
