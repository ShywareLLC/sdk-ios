import Foundation

// MARK: - RestClient

/// shyrest-v1 — pairs StoreClient + ChatClient behind a single entrypoint.
/// Mirrors the JS restClient.js composite.
public actor RestClient {
    private let storeClient: StoreClient
    private let chatClient: ChatClient

    public static func from(
        _ config: ShyConfig,
        sealerKeyProvider: SealerKeyProvider
    ) throws -> RestClient {
        let store = try StoreClient.from(config, sealerKeyProvider: sealerKeyProvider)
        let chat  = try ChatClient.from(config, sealerKeyProvider: sealerKeyProvider)
        return RestClient(storeClient: store, chatClient: chat)
    }

    private init(storeClient: StoreClient, chatClient: ChatClient) {
        self.storeClient = storeClient
        self.chatClient  = chatClient
    }

    // MARK: - Client accessors

    public func getStoreClient() -> StoreClient { storeClient }
    public func getChatClient()  -> ChatClient  { chatClient  }

    // MARK: - StoreClient surface

    public func listBuckets(scopingId: String) async throws -> [Bucket] {
        try await storeClient.listBuckets(scopingId: scopingId)
    }

    public func storeSubmission(
        scopingId: String,
        plaintext: Data,
        category: String
    ) async throws -> StoreResult {
        try await storeClient.storeSubmission(scopingId: scopingId, plaintext: plaintext, category: category)
    }

    public func revealAndDecryptStore(scopingId: String, submissionId: String) async throws -> Data {
        try await storeClient.revealAndDecryptStore(scopingId: scopingId, submissionId: submissionId)
    }

    public func deleteStore(scopingId: String, submissionId: String) async throws {
        try await storeClient.deleteStore(scopingId: scopingId, submissionId: submissionId)
    }

    public func replaceStore(
        scopingId: String,
        submissionId: String,
        plaintext: Data,
        category: String
    ) async throws -> StoreResult {
        try await storeClient.replaceStore(
            scopingId: scopingId,
            submissionId: submissionId,
            plaintext: plaintext,
            category: category
        )
    }

    // MARK: - ChatClient surface

    public func createMailbox(
        label: String,
        address: String,
        routeHint: String? = nil
    ) async throws -> MailboxResult {
        try await chatClient.createMailbox(label: label, address: address, routeHint: routeHint)
    }

    public func queueDispatch(
        mailboxId: String,
        recipientAddress: String,
        subject: String,
        body: String,
        contentClass: String
    ) async throws -> ChatDispatchResult {
        try await chatClient.queueDispatch(
            mailboxId: mailboxId,
            recipientAddress: recipientAddress,
            subject: subject,
            body: body,
            contentClass: contentClass
        )
    }

    public func getMailbox(mailboxId: String) async throws -> Mailbox {
        try await chatClient.getMailbox(mailboxId: mailboxId)
    }

    public func getInbox(mailboxId: String) async throws -> [Message] {
        try await chatClient.getInbox(mailboxId: mailboxId)
    }

    public func closeDispatch(dispatchId: String) async throws {
        try await chatClient.closeDispatch(dispatchId: dispatchId)
    }
}
