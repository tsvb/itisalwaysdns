import Foundation
@preconcurrency import Network

/// Bridges `NWConnection`'s callback API to a single `async` request/response.
/// A `ContinuationBox` guarantees the continuation resumes exactly once no matter
/// which callback (ready / receive / fail / timeout) fires first.
enum DNSTransport {
    static func exchange(
        query: [UInt8],
        server: ServerEndpoint,
        kind: TransportKind,
        timeout: TimeInterval
    ) async throws -> [UInt8] {
        switch kind {
        case .udp: try await udp(query: query, server: server, timeout: timeout)
        case .tcp: try await tcp(query: query, server: server, timeout: timeout)
        }
    }

    private static func endpoint(_ server: ServerEndpoint) throws -> (NWEndpoint.Host, NWEndpoint.Port) {
        guard let port = NWEndpoint.Port(rawValue: server.port) else {
            throw DNSError.invalidArgument("bad port \(server.port)")
        }
        return (NWEndpoint.Host(server.host), port)
    }

    // MARK: UDP

    private static func udp(query: [UInt8], server: ServerEndpoint, timeout: TimeInterval) async throws -> [UInt8] {
        let (host, port) = try endpoint(server)
        let connection = NWConnection(host: host, port: port, using: .udp)
        let queue = DispatchQueue(label: "dnskit.udp")

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8], Error>) in
                let box = ContinuationBox(cont)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        connection.send(content: Data(query), completion: .contentProcessed { error in
                            if let error {
                                box.finish(.failure(DNSError.transport("send failed: \(error)")))
                                connection.cancel()
                            }
                        })
                        connection.receiveMessage { data, _, _, error in
                            if let data, !data.isEmpty {
                                box.finish(.success([UInt8](data)))
                            } else if let error {
                                box.finish(.failure(DNSError.transport("receive failed: \(error)")))
                            } else {
                                box.finish(.failure(DNSError.transport("empty UDP response")))
                            }
                            connection.cancel()
                        }
                    case .failed(let error):
                        box.finish(.failure(DNSError.transport("connection failed: \(error)")))
                        connection.cancel()
                    default:
                        break
                    }
                }
                queue.asyncAfter(deadline: .now() + timeout) {
                    box.finish(.failure(DNSError.timeout))
                    connection.cancel()
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    // MARK: TCP (length-prefixed, RFC 1035 §4.2.2)

    private static func tcp(query: [UInt8], server: ServerEndpoint, timeout: TimeInterval) async throws -> [UInt8] {
        guard query.count <= 0xFFFF else { throw DNSError.invalidArgument("query too large for TCP framing") }
        let (host, port) = try endpoint(server)
        let connection = NWConnection(host: host, port: port, using: .tcp)
        let queue = DispatchQueue(label: "dnskit.tcp")

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8], Error>) in
                let exchange = TCPExchange(connection: connection, query: query, box: ContinuationBox(cont))
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: exchange.begin()
                    case .failed(let error): exchange.fail("connection failed: \(error)")
                    default: break
                    }
                }
                queue.asyncAfter(deadline: .now() + timeout) { exchange.failTimeout() }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }
}

/// Drives a single DNS-over-TCP exchange: send the length-prefixed query, read
/// the 2-byte length, then read exactly that many body bytes (across as many
/// `receive` callbacks as it takes). Confined to the connection's serial queue,
/// hence `@unchecked Sendable`.
private final class TCPExchange: @unchecked Sendable {
    private let connection: NWConnection
    private let framed: [UInt8]
    private let box: ContinuationBox

    init(connection: NWConnection, query: [UInt8], box: ContinuationBox) {
        self.connection = connection
        self.framed = [UInt8(query.count >> 8), UInt8(query.count & 0xFF)] + query
        self.box = box
    }

    func begin() {
        connection.send(content: Data(framed), completion: .contentProcessed { [weak self] error in
            if let error { self?.fail("send failed: \(error)") }
        })
        readExactly(2, []) { [weak self] lengthBytes in
            guard let self else { return }
            let length = (Int(lengthBytes[0]) << 8) | Int(lengthBytes[1])
            guard length > 0 else { self.fail("zero-length TCP response"); return }
            self.readExactly(length, []) { [weak self] body in
                self?.box.finish(.success(body))
                self?.connection.cancel()
            }
        }
    }

    private func readExactly(_ count: Int, _ acc: [UInt8], _ done: @escaping @Sendable ([UInt8]) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - acc.count) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error { self.fail("receive failed: \(error)"); return }
            var acc = acc
            if let data { acc.append(contentsOf: data) }
            if acc.count >= count {
                done(acc)
            } else if isComplete {
                self.fail("connection closed mid-message")
            } else {
                self.readExactly(count, acc, done)
            }
        }
    }

    func fail(_ message: String) {
        box.finish(.failure(DNSError.transport(message)))
        connection.cancel()
    }

    func failTimeout() {
        box.finish(.failure(DNSError.timeout))
        connection.cancel()
    }
}

/// One-shot, thread-safe wrapper around a checked continuation.
private final class ContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[UInt8], Error>?

    init(_ continuation: CheckedContinuation<[UInt8], Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<[UInt8], Error>) {
        lock.lock()
        guard let cont = continuation else { lock.unlock(); return }
        continuation = nil
        lock.unlock()
        cont.resume(with: result)
    }
}
