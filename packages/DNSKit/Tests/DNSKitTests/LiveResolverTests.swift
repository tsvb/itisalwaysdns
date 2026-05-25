import Testing
import Foundation
import DNSKit

// Network-dependent tests. Off by default so `swift test` works offline; run with:
//   IIADNS_LIVE=1 swift test
@Suite("Live resolver", .enabled(if: ProcessInfo.processInfo.environment["IIADNS_LIVE"] == "1"))
struct LiveResolverTests {
    let resolver = Resolver(options: QueryOptions(timeout: 5))
    let cloudflare = ServerEndpoint(host: "1.1.1.1")

    @Test("Resolves a stable A record over UDP")
    func resolveAUDP() async throws {
        let answer = try await resolver.query(name: "one.one.one.one", type: .a, server: cloudflare)
        #expect(answer.responseCode == .noError)
        let addrs = answer.message.answers.compactMap { rr -> String? in
            if case .a(let b) = rr.data { IPAddress.ipv4String(b) } else { nil }
        }
        #expect(addrs.contains("1.1.1.1"))
    }

    @Test("Resolves the same record over TCP")
    func resolveATCP() async throws {
        let answer = try await resolver.query(name: "one.one.one.one", type: .a, server: cloudflare, transport: .tcp)
        #expect(answer.transport == .tcp)
        #expect(answer.responseCode == .noError)
        #expect(!answer.message.answers.isEmpty)
    }

    @Test("Reverse lookup resolves to a hostname")
    func reverseLookup() async throws {
        let ptr = try #require(DomainName.reversePointer(forIP: "8.8.8.8"))
        let answer = try await resolver.query(name: ptr, type: .ptr, server: cloudflare)
        #expect(answer.responseCode == .noError)
        let names = answer.message.answers.compactMap { rr -> String? in
            if case .ptr(let n) = rr.data { n.description } else { nil }
        }
        #expect(names.contains("dns.google."))
    }

    @Test("NXDOMAIN is reported, not thrown")
    func nxdomain() async throws {
        let answer = try await resolver.query(
            name: "this-name-should-not-exist-iiadns-\(UInt32.random(in: 0...UInt32.max)).example",
            type: .a, server: cloudflare)
        #expect(answer.responseCode == .nxDomain)
    }

    @Test("Multi-resolver fan-out returns one result per server")
    func fanOut() async throws {
        let servers = [ServerEndpoint(host: "1.1.1.1"), ServerEndpoint(host: "8.8.8.8"), ServerEndpoint(host: "9.9.9.9")]
        let results = await resolver.queryAll(name: "example.com", type: .a, servers: servers)
        #expect(results.count == 3)
        #expect(results.allSatisfy {
            if case .success(let a) = $0.result { a.responseCode == .noError } else { false }
        })
    }
}
