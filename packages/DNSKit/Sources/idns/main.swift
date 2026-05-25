import DNSKit
import Foundation

// iiadns — a dig-style command-line front end for DNSKit. It exists both as a
// useful tool and as a headless harness for validating the engine against real
// resolvers (and cross-checking output against the system `dig`).

func printErr(_ s: String) {
    FileHandle.standardError.write(Data((s + "\n").utf8))
}

let usage = """
iiadns — DNS lookup tool (DNSKit)

USAGE:
  iiadns [@server] <name> [type] [options]
  iiadns -x <ip> [@server] [options]

ARGUMENTS:
  @server        Resolver to query as host or host#port (default: system resolver)
  name           Domain name to look up
  type           Record type: A AAAA CNAME MX TXT NS SOA PTR SRV CAA ANY (default: A)

OPTIONS:
  -x <ip>        Reverse lookup (PTR) for an IPv4/IPv6 address
  -t, --type T   Record type (alternative to positional)
  --tcp, +tcp    Use TCP instead of UDP
  +short         Print only the answer rdata
  +dnssec        Set the EDNS DO bit (request DNSSEC records)
  +norecurse     Clear the Recursion Desired flag
  --raw          Append a hex dump of the raw response
  --compare      Query system + Cloudflare/Google/Quad9 and compare answers
  --timeout S    Per-query timeout in seconds (default: 5)
  -h, --help     Show this help
"""

struct Options {
    var server: ServerEndpoint?
    var name: String?
    var type: RecordType?
    var reverseIP: String?
    var transport: TransportKind = .udp
    var short = false
    var dnssec = false
    var recurse = true
    var raw = false
    var compare = false
    var timeout: TimeInterval = 5
    var help = false
}

func parseServer(_ s: String) -> ServerEndpoint {
    if let hash = s.firstIndex(of: "#"), let port = UInt16(s[s.index(after: hash)...]) {
        return ServerEndpoint(host: String(s[..<hash]), port: port)
    }
    return ServerEndpoint(host: s)
}

func parse(_ args: [String]) throws -> Options {
    var o = Options()
    var i = 0
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "-h", "--help": o.help = true
        case "--tcp", "+tcp": o.transport = .tcp
        case "+short": o.short = true
        case "+dnssec": o.dnssec = true
        case "+norecurse": o.recurse = false
        case "--raw": o.raw = true
        case "--compare": o.compare = true
        case "-x":
            i += 1
            guard i < args.count else { throw DNSError.invalidArgument("-x needs an IP") }
            o.reverseIP = args[i]
        case "-t", "--type":
            i += 1
            guard i < args.count, let t = RecordType(name: args[i]) else {
                throw DNSError.invalidArgument("unknown type after \(arg)")
            }
            o.type = t
        case "--timeout":
            i += 1
            guard i < args.count, let s = Double(args[i]) else {
                throw DNSError.invalidArgument("--timeout needs a number")
            }
            o.timeout = s
        default:
            if arg.hasPrefix("@") {
                o.server = parseServer(String(arg.dropFirst()))
            } else if o.name == nil, o.reverseIP == nil {
                o.name = arg
            } else if o.type == nil, let t = RecordType(name: arg) {
                o.type = t
            } else {
                throw DNSError.invalidArgument("unexpected argument '\(arg)'")
            }
        }
        i += 1
    }
    return o
}

func defaultServer() -> ServerEndpoint {
    if let first = SystemDNS.current().resolvers.first {
        return ServerEndpoint(host: first)
    }
    return ServerEndpoint(host: "1.1.1.1")
}

func hexDump(_ bytes: [UInt8]) -> String {
    var lines: [String] = []
    var offset = 0
    while offset < bytes.count {
        let slice = Array(bytes[offset..<min(offset + 16, bytes.count)])
        let hex = slice.map { String(format: "%02x", $0) }
            .enumerated()
            .map { $0.offset == 8 ? " " + $0.element : $0.element }
            .joined(separator: " ")
        let ascii = slice.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
        lines.append(String(format: "%04x  %-49s  %@", offset, (hex as NSString).utf8String!, ascii as NSString))
        offset += 16
    }
    return lines.joined(separator: "\n")
}

func printRecord(_ rr: ResourceRecord) {
    print("\(rr.name)\t\(rr.ttl)\t\(rr.recordClass)\t\(rr.type)\t\(rr.data.presentation)")
}

func printAnswer(_ a: Answer, short: Bool, raw: Bool) {
    if short {
        for rr in a.message.answers { print(rr.data.presentation) }
        return
    }
    let h = a.message.header
    print("; <<>> iiadns <<>> \(a.question.name) \(a.question.type) @\(a.server) (\(a.transport.rawValue))")
    print(";; ->>HEADER<<- opcode: \(h.opcode), status: \(h.responseCode), id: \(h.id)")
    let counts = "QUERY: \(a.message.questions.count), ANSWER: \(a.message.answers.count), "
        + "AUTHORITY: \(a.message.authorities.count), ADDITIONAL: \(a.message.additionals.count)"
    print(";; flags: \(h.flagString); \(counts)")

    print("\n;; QUESTION SECTION:")
    for q in a.message.questions { print(";\(q.name)\t\t\(q.recordClass)\t\(q.type)") }

    if !a.message.answers.isEmpty {
        print("\n;; ANSWER SECTION:")
        a.message.answers.forEach(printRecord)
    }
    if !a.message.authorities.isEmpty {
        print("\n;; AUTHORITY SECTION:")
        a.message.authorities.forEach(printRecord)
    }
    let additional = a.message.additionals.filter { $0.type != .opt }
    if !additional.isEmpty {
        print("\n;; ADDITIONAL SECTION:")
        additional.forEach(printRecord)
    }

    print("\n;; Query time: \(Int(a.latency * 1000)) ms")
    print(";; SERVER: \(a.server) (\(a.transport.rawValue))")
    print(";; MSG SIZE  rcvd: \(a.rawResponse.count)")
    if raw {
        print("\n;; RAW RESPONSE (\(a.rawResponse.count) bytes):")
        print(hexDump(a.rawResponse))
    }
}

func runCompare(_ resolver: Resolver, name: DomainName, type: RecordType, transport: TransportKind) async -> Int32 {
    var targets: [(String, ServerEndpoint)] = [
        ("Cloudflare", ServerEndpoint(host: "1.1.1.1")),
        ("Google", ServerEndpoint(host: "8.8.8.8")),
        ("Quad9", ServerEndpoint(host: "9.9.9.9")),
    ]
    for (idx, ip) in SystemDNS.current().resolvers.prefix(2).enumerated() {
        targets.append((idx == 0 ? "system" : "system\(idx)", ServerEndpoint(host: ip)))
    }

    print("== \(name) \(type) ==\n")
    let results = await resolver.queryAll(name: name, type: type, servers: targets.map(\.1), transport: transport)
    let labels = Dictionary(targets.map { ($0.1, $0.0) }, uniquingKeysWith: { a, _ in a })

    for (server, result) in results {
        let label = labels[server] ?? server.description
        switch result {
        case .success(let a):
            let rdata = a.message.answers.map { $0.data.presentation }
            let summary = rdata.isEmpty ? "(no answer)" : rdata.joined(separator: ", ")
            print(String(format: "%-12@ %-9@ %4dms  %@",
                         label as NSString,
                         a.responseCode.description as NSString,
                         Int(a.latency * 1000),
                         summary as NSString))
        case .failure(let error):
            print(String(format: "%-12@ %@", label as NSString, "ERROR: \(error)" as NSString))
        }
    }
    return 0
}

func runCLI(_ args: [String]) async -> Int32 {
    let options: Options
    do {
        options = try parse(args)
    } catch {
        printErr("error: \(error)\n")
        printErr(usage)
        return 2
    }

    if options.help || (options.name == nil && options.reverseIP == nil) {
        print(usage)
        return options.help ? 0 : 2
    }

    // Resolve the query name + type, handling reverse lookups.
    let name: DomainName
    let type: RecordType
    if let ip = options.reverseIP {
        guard let ptr = DomainName.reversePointer(forIP: ip) else {
            printErr("error: '\(ip)' is not a valid IP address")
            return 2
        }
        name = ptr
        type = options.type ?? .ptr
    } else {
        name = DomainName(options.name!)
        type = options.type ?? .a
    }

    let resolver = Resolver(options: QueryOptions(
        recursionDesired: options.recurse,
        dnssecOK: options.dnssec,
        timeout: options.timeout
    ))

    if options.compare {
        return await runCompare(resolver, name: name, type: type, transport: options.transport)
    }

    let server = options.server ?? defaultServer()
    do {
        let answer = try await resolver.query(name: name, type: type, server: server, transport: options.transport)
        printAnswer(answer, short: options.short, raw: options.raw)
        return 0
    } catch {
        printErr("error querying \(server): \(error)")
        return 1
    }
}

let exitCode = await runCLI(Array(CommandLine.arguments.dropFirst()))
exit(exitCode)
