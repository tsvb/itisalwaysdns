import Foundation

/// Knobs for a single query.
public struct QueryOptions: Sendable {
    public var recursionDesired: Bool
    public var dnssecOK: Bool          // sets EDNS DO bit
    public var ednsBufferSize: UInt16  // 0 disables EDNS entirely
    public var timeout: TimeInterval
    public var retries: Int            // additional UDP attempts after the first
    public var tcpFallbackOnTruncation: Bool

    public init(
        recursionDesired: Bool = true,
        dnssecOK: Bool = false,
        ednsBufferSize: UInt16 = 1232,
        timeout: TimeInterval = 5.0,
        retries: Int = 2,
        tcpFallbackOnTruncation: Bool = true
    ) {
        self.recursionDesired = recursionDesired
        self.dnssecOK = dnssecOK
        self.ednsBufferSize = ednsBufferSize
        self.timeout = timeout
        self.retries = retries
        self.tcpFallbackOnTruncation = tcpFallbackOnTruncation
    }
}

/// The result of one resolved query: the decoded response plus everything a
/// troubleshooter wants — which server answered, how it was reached, how long it
/// took, and the exact bytes on the wire.
public struct Answer: Sendable {
    public var question: Question
    public var server: ServerEndpoint
    public var transport: TransportKind
    public var message: Message
    public var latency: TimeInterval
    public var rawQuery: [UInt8]
    public var rawResponse: [UInt8]

    public var responseCode: ResponseCode { message.header.responseCode }
}

/// Stateless query engine. Build queries, send them to a chosen server, decode
/// the reply. Holds no caches and never consults the system resolver — every
/// query goes exactly where you point it.
public struct Resolver: Sendable {
    public var options: QueryOptions

    public init(options: QueryOptions = QueryOptions()) {
        self.options = options
    }

    /// Resolve one `name`/`type` against one `server`.
    public func query(
        name: DomainName,
        type: RecordType,
        server: ServerEndpoint,
        transport: TransportKind = .udp,
        recordClass: RecordClass = .internet
    ) async throws -> Answer {
        let edns: ResourceRecord? = options.ednsBufferSize == 0
            ? nil
            : .edns(udpPayloadSize: options.ednsBufferSize, dnssecOK: options.dnssecOK)

        let request = Message.query(
            name: name,
            type: type,
            recordClass: recordClass,
            recursionDesired: options.recursionDesired,
            edns: edns
        )
        let rawQuery = try request.encoded()

        let start = Date()
        var usedTransport = transport
        var raw = try await attempt(rawQuery, server: server, transport: transport)
        var response = try Message(decoding: raw)

        // Truncated UDP answer → retry over TCP for the full record set.
        if transport == .udp, response.header.truncated, options.tcpFallbackOnTruncation {
            usedTransport = .tcp
            raw = try await DNSTransport.exchange(query: rawQuery, server: server, kind: .tcp, timeout: options.timeout)
            response = try Message(decoding: raw)
        }

        return Answer(
            question: request.questions[0],
            server: server,
            transport: usedTransport,
            message: response,
            latency: Date().timeIntervalSince(start),
            rawQuery: rawQuery,
            rawResponse: raw
        )
    }

    /// Convenience: resolve a string name, accepting a textual or numeric type.
    public func query(
        name: String,
        type: RecordType,
        server: ServerEndpoint,
        transport: TransportKind = .udp
    ) async throws -> Answer {
        try await query(name: DomainName(name), type: type, server: server, transport: transport)
    }

    /// Run the same query against many servers concurrently. Results come back
    /// keyed by server, each a success or the error that server produced — this
    /// is the "why do these resolvers disagree?" primitive.
    public func queryAll(
        name: DomainName,
        type: RecordType,
        servers: [ServerEndpoint],
        transport: TransportKind = .udp
    ) async -> [(server: ServerEndpoint, result: Result<Answer, Error>)] {
        await withTaskGroup(of: (Int, ServerEndpoint, Result<Answer, Error>).self) { group in
            for (index, server) in servers.enumerated() {
                group.addTask {
                    do {
                        let answer = try await query(name: name, type: type, server: server, transport: transport)
                        return (index, server, .success(answer))
                    } catch {
                        return (index, server, .failure(error))
                    }
                }
            }
            // Preserve the caller's server ordering regardless of completion order.
            var collected: [(Int, ServerEndpoint, Result<Answer, Error>)] = []
            for await item in group { collected.append(item) }
            return collected.sorted { $0.0 < $1.0 }.map { ($0.1, $0.2) }
        }
    }

    /// One transport attempt with UDP retries on timeout.
    private func attempt(_ query: [UInt8], server: ServerEndpoint, transport: TransportKind) async throws -> [UInt8] {
        let totalAttempts = transport == .udp ? max(1, options.retries + 1) : 1
        var lastError: Error = DNSError.timeout
        for _ in 0..<totalAttempts {
            do {
                return try await DNSTransport.exchange(
                    query: query, server: server, kind: transport, timeout: options.timeout)
            } catch DNSError.timeout {
                lastError = DNSError.timeout
                continue
            }
        }
        throw lastError
    }
}
