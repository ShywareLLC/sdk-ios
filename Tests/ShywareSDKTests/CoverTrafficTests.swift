import XCTest
@testable import ShywareSDK

private actor ObservedTransport {
    var requests: [Data] = []
    func send(_ data: Data) -> Data { requests.append(data); return Data(#"{"accepted":true}"#.utf8) }
    func count() -> Int { requests.count }
    func kinds() throws -> [String] { try requests.map { try JSONSerialization.jsonObject(with: $0) as! [String: Any] }.map { $0["kind"] as! String } }
}

final class CoverTrafficTests: XCTestCase {
    func testPaddingAndValidation() throws {
        for kind in ["dummy", "cast", "update"] {
            XCTAssertEqual(try CoverTrafficAdapter.encode(kind: kind, body: Data(#"{"tx":"é"}"#.utf8)).count, 32768)
        }
        XCTAssertThrowsError(try CoverTrafficAdapter.encode(kind: "cast", body: JSONSerialization.data(withJSONObject: ["tx": String(repeating: "x", count: 32768)])))
        XCTAssertThrowsError(try CoverTrafficAdapter(ratePerMinute: 0) { _ in Data() })
    }

    func testDummiesAndRealOperationsOccupySlots() async throws {
        let observed = ObservedTransport()
        let dispatch = try CoverTrafficAdapter(ratePerMinute: 0.01) { await observed.send($0) }
        await dispatch.start()
        await dispatch.tick()
        let request = Task { try await dispatch.submit(kind: "cast", body: Data(#"{"tx":"cast"}"#.utf8)) }
        // Let the submission reach the queue without waiting for a timer slot.
        try await Task.sleep(nanoseconds: 10_000_000)
        let before = await observed.count()
        XCTAssertEqual(before, 1)
        await dispatch.tick()
        _ = try await request.value
        await dispatch.tick()
        let kinds = try await observed.kinds()
        XCTAssertEqual(kinds, ["dummy", "cast", "dummy"])
        await dispatch.stop()
        do { _ = try await dispatch.submit(kind: "update", body: Data("{}".utf8)); XCTFail("Stopped dispatcher accepted a vote") } catch {}
    }
}
