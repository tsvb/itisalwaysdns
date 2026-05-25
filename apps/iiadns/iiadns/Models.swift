import Foundation
import Observation
import DNSKit

/// The sections in the sidebar.
enum AppSection: String, CaseIterable, Identifiable, Hashable {
    case lookup = "Lookup"
    case leakTest = "Leak Test"
    case resolvers = "Resolvers"

    var id: String { rawValue }

    var systemImage: String {
        switch self {
        case .lookup: "magnifyingglass"
        case .leakTest: "drop.fill"
        case .resolvers: "server.rack"
        }
    }
}

/// App-wide state container.
@MainActor
@Observable
final class AppModel {
    var selection: AppSection? = .lookup
    var lookup = LookupModel()
    var systemDNS = SystemDNSModel()
}

/// Drives the Lookup (nslookup) feature against the DNS engine.
@MainActor
@Observable
final class LookupModel {
    var nameInput = "example.com"
    var selectedType: RecordType = .a
    var useSystemResolver = true
    var serverInput = "1.1.1.1"
    var transport: TransportKind = .udp
    var dnssec = false

    private(set) var isRunning = false
    private(set) var answer: Answer?
    private(set) var errorText: String?
    private(set) var rawHex = ""

    let allTypes: [RecordType] = [.a, .aaaa, .cname, .mx, .txt, .ns, .soa, .ptr, .srv, .caa, .any]

    /// The server that will actually be queried, given the current inputs.
    var effectiveServer: ServerEndpoint {
        if useSystemResolver {
            return SystemDNS.current().resolverEndpoints.first ?? ServerEndpoint(host: "1.1.1.1")
        }
        return parseServer(serverInput)
    }

    func run() async {
        guard !nameInput.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        isRunning = true
        errorText = nil
        defer { isRunning = false }

        let resolver = Resolver(options: QueryOptions(dnssecOK: dnssec, timeout: 5))
        let server = effectiveServer
        do {
            let result = try await resolver.query(
                name: DomainName(nameInput),
                type: selectedType,
                server: server,
                transport: transport
            )
            answer = result
            rawHex = hexDump(result.rawResponse)
        } catch {
            answer = nil
            rawHex = ""
            errorText = "\(error)"
        }
    }
}

/// Holds a snapshot of the system's DNS configuration.
@MainActor
@Observable
final class SystemDNSModel {
    private(set) var config = SystemDNS.current()

    func refresh() {
        config = SystemDNS.current()
    }
}
