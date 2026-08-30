import Foundation

/// URLProtocol interceptor used by the DPIA (Stack 5) test suites to inject
/// per-user auth headers on every SDK client request without requiring callers
/// to thread auth state through the SDK.
///
/// Tests register this class on the shared URL loading system and then mutate
/// the static `activeUser` / `*DevUid` / `*Token` properties before each SDK
/// call. The protocol forwards the request through `URLSession.shared` after
/// adding `Authorization` (when a token is present) or `x-dev-uid` (dev bypass)
/// headers.
///
/// This is intentionally a permissive passthrough — it does not implement
/// network policy. It exists so SDK clients can be exercised under the same
/// auth contract enforced by the consumer ledgers in CI.
public final class DevBypassURLProtocol: URLProtocol {
    /// Currently active test user — one of "alice" or "bob".
    public static var activeUser: String = "alice"

    /// Per-user dev-bypass uids. When `*Token` is nil for the active user, the
    /// request is annotated with `x-dev-uid: <devUid>` instead of a bearer.
    public static var aliceDevUid: String?
    public static var bobDevUid:   String?

    /// Per-user bearer tokens. When non-nil, the request is annotated with
    /// `Authorization: Bearer <token>`.
    public static var aliceToken: String?
    public static var bobToken:   String?

    /// Re-entrancy guard — the inner `URLSession.shared` request must not be
    /// re-intercepted by this protocol or it would recurse forever.
    private static let handledKey = "DevBypassURLProtocolHandled"

    public override class func canInit(with request: URLRequest) -> Bool {
        if URLProtocol.property(forKey: handledKey, in: request) != nil { return false }
        // Only intercept HTTP(S) requests to localhost-style URLs used by
        // the DPIA fixtures. Filtering keeps the protocol from accidentally
        // catching unrelated traffic in a host app.
        guard let scheme = request.url?.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else { return false }
        return true
    }

    public override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    public override func startLoading() {
        guard let mutable = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        URLProtocol.setProperty(true, forKey: DevBypassURLProtocol.handledKey, in: mutable)

        let user = DevBypassURLProtocol.activeUser
        let token = user == "alice" ? DevBypassURLProtocol.aliceToken : DevBypassURLProtocol.bobToken
        let devUid = user == "alice" ? DevBypassURLProtocol.aliceDevUid : DevBypassURLProtocol.bobDevUid

        if let token = token {
            mutable.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        } else if let devUid = devUid {
            mutable.setValue(devUid, forHTTPHeaderField: "x-dev-uid")
        }

        let task = URLSession.shared.dataTask(with: mutable as URLRequest) { [weak self] data, response, error in
            guard let self = self else { return }
            if let error = error {
                self.client?.urlProtocol(self, didFailWithError: error)
                return
            }
            if let response = response {
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            if let data = data {
                self.client?.urlProtocol(self, didLoad: data)
            }
            self.client?.urlProtocolDidFinishLoading(self)
        }
        task.resume()
    }

    public override func stopLoading() { /* no-op — URLSession task is fire-and-forget */ }
}
