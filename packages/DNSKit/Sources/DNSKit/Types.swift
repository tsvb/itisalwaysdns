import Foundation

/// A DNS resource-record type. Modeled as a struct (not an enum) so unknown
/// types round-trip losslessly by their numeric code — a troubleshooting tool
/// must never silently drop a record it doesn't recognize.
public struct RecordType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let a = RecordType(rawValue: 1)
    public static let ns = RecordType(rawValue: 2)
    public static let cname = RecordType(rawValue: 5)
    public static let soa = RecordType(rawValue: 6)
    public static let ptr = RecordType(rawValue: 12)
    public static let mx = RecordType(rawValue: 15)
    public static let txt = RecordType(rawValue: 16)
    public static let aaaa = RecordType(rawValue: 28)
    public static let srv = RecordType(rawValue: 33)
    public static let opt = RecordType(rawValue: 41)
    public static let caa = RecordType(rawValue: 257)
    public static let any = RecordType(rawValue: 255)

    private static let names: [UInt16: String] = [
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 257: "CAA", 255: "ANY",
    ]

    public var name: String { Self.names[rawValue] ?? "TYPE\(rawValue)" }
    public var description: String { name }

    /// Parse a textual type ("A", "aaaa", "TYPE65") into a `RecordType`.
    public init?(name: String) {
        let upper = name.uppercased()
        if let match = Self.names.first(where: { $0.value == upper }) {
            self = RecordType(rawValue: match.key)
        } else if upper.hasPrefix("TYPE"), let n = UInt16(upper.dropFirst(4)) {
            self = RecordType(rawValue: n)
        } else {
            return nil
        }
    }
}

/// A DNS class. `IN` (internet) in essentially all real traffic.
public struct RecordClass: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let internet = RecordClass(rawValue: 1)
    public static let chaos = RecordClass(rawValue: 3)
    public static let hesiod = RecordClass(rawValue: 4)
    public static let any = RecordClass(rawValue: 255)

    public var description: String {
        switch rawValue {
        case 1: "IN"
        case 3: "CH"
        case 4: "HS"
        case 255: "ANY"
        default: "CLASS\(rawValue)"
        }
    }
}

/// DNS response code (RCODE). EDNS can extend this beyond 4 bits, hence `UInt16`.
public struct ResponseCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let noError = ResponseCode(rawValue: 0)
    public static let formErr = ResponseCode(rawValue: 1)
    public static let servFail = ResponseCode(rawValue: 2)
    public static let nxDomain = ResponseCode(rawValue: 3)
    public static let notImp = ResponseCode(rawValue: 4)
    public static let refused = ResponseCode(rawValue: 5)

    public var description: String {
        switch rawValue {
        case 0: "NOERROR"
        case 1: "FORMERR"
        case 2: "SERVFAIL"
        case 3: "NXDOMAIN"
        case 4: "NOTIMP"
        case 5: "REFUSED"
        case 6: "YXDOMAIN"
        case 7: "YXRRSET"
        case 8: "NXRRSET"
        case 9: "NOTAUTH"
        case 10: "NOTZONE"
        case 16: "BADVERS"
        default: "RCODE\(rawValue)"
        }
    }
}

/// DNS opcode (query kind). QUERY for everything this tool does.
public struct Opcode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let query = Opcode(rawValue: 0)
    public static let status = Opcode(rawValue: 2)
    public static let notify = Opcode(rawValue: 4)
    public static let update = Opcode(rawValue: 5)

    public var description: String {
        switch rawValue {
        case 0: "QUERY"
        case 2: "STATUS"
        case 4: "NOTIFY"
        case 5: "UPDATE"
        default: "OPCODE\(rawValue)"
        }
    }
}

/// A single EDNS0 option (TLV) carried in an OPT record's rdata.
public struct EDNSOption: Hashable, Sendable {
    public var code: UInt16
    public var data: [UInt8]
    public init(code: UInt16, data: [UInt8]) {
        self.code = code
        self.data = data
    }
}

/// How to reach a resolver on the wire.
public enum TransportKind: String, Sendable, CaseIterable {
    case udp
    case tcp
}

/// A resolver address. Port defaults to 53.
public struct ServerEndpoint: Sendable, Hashable, CustomStringConvertible {
    public var host: String
    public var port: UInt16
    public init(host: String, port: UInt16 = 53) {
        self.host = host
        self.port = port
    }
    public var description: String { port == 53 ? host : "\(host)#\(port)" }
}
