// Stack 5 — Swift/URLSession DPIA test helpers
// Mirrors dpia_test_helpers.mjs for use in XCTest-based DPIA suites.

import Foundation

// MARK: - Environment

public func env(_ key: String, _ fallback: String = "") -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

// MARK: - Auth

public struct CognitoTokenFetcher {
    let region: String
    let clientId: String
    let password: String
    public init(region: String, clientId: String, password: String) {
        self.region = region; self.clientId = clientId; self.password = password
    }

    public func fetchToken(username: String) async throws -> String {
        let url = URL(string: "https://cognito-idp.\(region).amazonaws.com/")!
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-amz-json-1.1", forHTTPHeaderField: "Content-Type")
        req.setValue("AWSCognitoIdentityProviderService.InitiateAuth", forHTTPHeaderField: "X-Amz-Target")
        let body: [String: Any] = [
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": clientId,
            "AuthParameters": ["USERNAME": username, "PASSWORD": password]
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await URLSession.shared.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let authResult = json?["AuthenticationResult"] as? [String: Any]
        guard let token = authResult?["IdToken"] as? String ?? authResult?["AccessToken"] as? String else {
            throw NSError(domain: "DPIAAuth", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Cognito failed: \(String(data: data, encoding: .utf8) ?? "")"])
        }
        return token
    }
}

// MARK: - HTTP client

public struct DPIAResponse {
    public let status: Int
    public let body: [String: Any]
    public init(status: Int, body: [String: Any]) { self.status = status; self.body = body }
}

public func dpiaRequest(
    method: String,
    url: String,
    body: [String: Any]?,
    token: String?,
    devUid: String?
) async throws -> DPIAResponse {
    guard let requestURL = URL(string: url) else {
        throw NSError(domain: "DPIARequest", code: 0,
            userInfo: [NSLocalizedDescriptionKey: "Invalid URL: \(url)"])
    }
    var req = URLRequest(url: requestURL)
    req.httpMethod = method
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if let token = token {
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else if let devUid = devUid {
        req.setValue(devUid, forHTTPHeaderField: "x-dev-uid")
    }
    if let body = body {
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    let (data, response) = try await URLSession.shared.data(for: req)
    let httpResponse = response as! HTTPURLResponse
    let json = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    return DPIAResponse(status: httpResponse.statusCode, body: json)
}

// MARK: - Results model

public struct DPIAAssertion: Codable {
    public var label: String
    public var claim: String
    public var result: String   // "pass" | "fail" | "pending"
    public var ms: Int

    public init(label: String, claim: String) {
        self.label = label
        self.claim = claim
        self.result = "pending"
        self.ms = 0
    }
}

public struct DPIASection: Codable {
    public var name: String
    public var assertions: [DPIAAssertion]
    public init(name: String) { self.name = name; self.assertions = [] }
}

public struct DPIAResults: Codable {
    public var stack: String
    public var run: String
    public var githubRunId: String?
    public var timestamp: String
    public var auth: String
    public var ledger: String
    public var sections: [DPIASection]
    public init(stack: String, run: String, githubRunId: String?, timestamp: String, auth: String, ledger: String, sections: [DPIASection] = []) {
        self.stack = stack; self.run = run; self.githubRunId = githubRunId
        self.timestamp = timestamp; self.auth = auth; self.ledger = ledger; self.sections = sections
    }
}

// MARK: - Section builder

private enum DPIAResultStore {
    static var sections: [DPIASection] = []

    static func sectionIndex(named name: String) -> Int {
        if let index = sections.firstIndex(where: { $0.name == name }) {
            return index
        }
        sections.append(DPIASection(name: name))
        return sections.count - 1
    }

    static func append(_ assertion: DPIAAssertion, toSectionAt index: Int) {
        guard sections.indices.contains(index) else { return }
        sections[index].assertions.append(assertion)
    }
}

public class DPIASectionBuilder {
    public typealias ResultsMutator = (inout DPIAResults) -> Void
    private let mutate: ResultsMutator

    private var sectionIndex: Int = -1
    private var resultsRef: UnsafeMutablePointer<DPIAResults>

    public init(resultsPointer: UnsafeMutablePointer<DPIAResults>, sectionName: String) {
        self.resultsRef = resultsPointer
        self.mutate = { _ in }
        let sec = DPIASection(name: sectionName)
        resultsPointer.pointee.sections.append(sec)
        sectionIndex = resultsPointer.pointee.sections.count - 1
        _ = DPIAResultStore.sectionIndex(named: sectionName)
    }

    public func record(label: String, claim: String, start: Date, passed: Bool) {
        let ms = Int(Date().timeIntervalSince(start) * 1000)
        let assertion = DPIAAssertion(label: label, claim: claim)
        var updated = assertion
        updated.result = passed ? "pass" : "fail"
        updated.ms = ms
        resultsRef.pointee.sections[sectionIndex].assertions.append(updated)
        DPIAResultStore.append(updated, toSectionAt: DPIAResultStore.sectionIndex(named: resultsRef.pointee.sections[sectionIndex].name))
    }

    /// Overload accepting a millisecond timestamp (e.g. `Int64(Date().timeIntervalSince1970 * 1000)`).
    public func record(label: String, claim: String, startMs: Int64, passed: Bool) {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let assertion = DPIAAssertion(label: label, claim: claim)
        var updated = assertion
        updated.result = passed ? "pass" : "fail"
        updated.ms = Int(nowMs - startMs)
        resultsRef.pointee.sections[sectionIndex].assertions.append(updated)
        DPIAResultStore.append(updated, toSectionAt: DPIAResultStore.sectionIndex(named: resultsRef.pointee.sections[sectionIndex].name))
    }
}

// MARK: - Write results

public func writeResults(results: DPIAResults, outDir: String, stackNum: String) {
    var output = results
    if output.sections.allSatisfy({ $0.assertions.isEmpty }) && !DPIAResultStore.sections.isEmpty {
        output.sections = DPIAResultStore.sections
    }
    let fm = FileManager.default
    try? fm.createDirectory(atPath: outDir, withIntermediateDirectories: true)
    let outPath = (outDir as NSString).appendingPathComponent("unit-results-stack\(stackNum).json")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(output) {
        try? data.write(to: URL(fileURLWithPath: outPath))
    }
    let total = output.sections.reduce(0) { $0 + $1.assertions.count }
    let passed = output.sections.reduce(0) { $0 + $1.assertions.filter { $0.result == "pass" }.count }
    print("\n  Unit results: \(passed)/\(total) assertions passed")
    print("  Written: \(outPath)")
    for sec in output.sections {
        for a in sec.assertions {
            let icon = a.result == "pass" ? "✓" : a.result == "pending" ? "○" : "✗"
            print("    \(icon) [\(sec.name)] \(a.label)")
        }
    }
}
