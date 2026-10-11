import Foundation
import XCTest
@testable import ShywareSDK

private actor LiveCoverObservations {
    struct Slot: Codable {
        let startedAt: Double
        let requestBytes: Int
        let responseBytes: Int
        let httpStatus: Int
        let discarded: Bool
    }
    private var slots: [Slot] = []

    func send(_ bytes: Data, to url: URL, token: String?) async throws -> Data {
        let started = Date().timeIntervalSince1970
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = bytes
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        let (data, response) = try await URLSession.shared.data(for: request)
        let result = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let body = result?["body"] as? [String: Any]
        slots.append(Slot(startedAt: started, requestBytes: bytes.count,
                          responseBytes: data.count,
                          httpStatus: (response as? HTTPURLResponse)?.statusCode ?? 0,
                          discarded: result?["status"] as? Int == 200 && body?["discarded"] as? Bool == true))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw ShywareError.http(statusCode: status, message: "Probe rejected") }
        return data
    }

    func snapshot() -> [Slot] { slots }
}

final class CoverTrafficLiveTests: XCTestCase {
    func testConfiguredTimerAndLiveReceiverAuthorization() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let endpoint = environment["SHYWARE_COVER_PROBE_URL"], let url = URL(string: endpoint),
              url.scheme == "https", url.path == "/dispatch" else {
            throw XCTSkip("Opt-in live dummy-only probe requires SHYWARE_COVER_PROBE_URL")
        }
        let token = environment["SHYWARE_COVER_PROBE_AUTH_TOKEN"]
        let authenticated = token != nil
        let observed = LiveCoverObservations()
        let dispatch = try CoverTrafficAdapter(ratePerMinute: 10) { try await observed.send($0, to: url, token: token) }
        await dispatch.start()
        await dispatch.start()
        let deadline = Date().addingTimeInterval(30)
        while await observed.snapshot().count < 3 && Date() < deadline {
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        await dispatch.stop()
        let atStop = await observed.snapshot().count
        try await Task.sleep(nanoseconds: 7_000_000_000)
        let slots = await observed.snapshot()
        let failures = await dispatch.coverFailures
        XCTAssertEqual(slots.count, 3)
        XCTAssertEqual(slots.count, atStop, "Stopped scheduler emitted another request")
        XCTAssertEqual(failures, authenticated ? 0 : 3)
        for slot in slots {
            XCTAssertEqual(slot.requestBytes, 32768)
            XCTAssertEqual(slot.httpStatus, authenticated ? 200 : 401)
            if authenticated {
                XCTAssertEqual(slot.responseBytes, 32768)
                XCTAssertTrue(slot.discarded)
            } else {
                XCTAssertFalse(slot.discarded, "Unauthenticated probe reached dummy processing")
            }
        }
        for (before, after) in zip(slots, slots.dropFirst()) {
            XCTAssertEqual(after.startedAt - before.startedAt, 6, accuracy: 0.75)
        }
        if let output = environment["SHYWARE_COVER_PROBE_OUTPUT"] {
            let evidence = try JSONSerialization.data(withJSONObject: [
                "endpoint": endpoint, "rate_per_minute": 10, "cover_failures": failures,
                "count_at_stop": atStop, "count_after_stop": slots.count,
                "stop_observation_seconds": 7,
                "scope": "macOS SDK timer and live HTTPS authorization boundary; dummy-only; not a physical iOS trace",
                "authenticated_probe": authenticated,
                "slots": try JSONSerialization.jsonObject(with: JSONEncoder().encode(slots))
            ], options: [.prettyPrinted, .sortedKeys])
            try evidence.write(to: URL(fileURLWithPath: output), options: .withoutOverwriting)
        }
    }
}
