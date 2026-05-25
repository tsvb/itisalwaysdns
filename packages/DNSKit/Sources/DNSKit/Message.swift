import Foundation

/// The 12-byte DNS header, expanded into named fields.
public struct Header: Sendable, Hashable {
    public var id: UInt16
    public var isResponse: Bool          // QR
    public var opcode: Opcode
    public var authoritativeAnswer: Bool // AA
    public var truncated: Bool           // TC
    public var recursionDesired: Bool    // RD
    public var recursionAvailable: Bool  // RA
    public var authenticData: Bool       // AD
    public var checkingDisabled: Bool    // CD
    public var responseCode: ResponseCode

    public init(
        id: UInt16,
        isResponse: Bool = false,
        opcode: Opcode = .query,
        authoritativeAnswer: Bool = false,
        truncated: Bool = false,
        recursionDesired: Bool = true,
        recursionAvailable: Bool = false,
        authenticData: Bool = false,
        checkingDisabled: Bool = false,
        responseCode: ResponseCode = .noError
    ) {
        self.id = id
        self.isResponse = isResponse
        self.opcode = opcode
        self.authoritativeAnswer = authoritativeAnswer
        self.truncated = truncated
        self.recursionDesired = recursionDesired
        self.recursionAvailable = recursionAvailable
        self.authenticData = authenticData
        self.checkingDisabled = checkingDisabled
        self.responseCode = responseCode
    }

    /// dig-style flag string, e.g. "qr rd ra ad".
    public var flagString: String {
        var f: [String] = []
        if isResponse { f.append("qr") }
        if authoritativeAnswer { f.append("aa") }
        if truncated { f.append("tc") }
        if recursionDesired { f.append("rd") }
        if recursionAvailable { f.append("ra") }
        if authenticData { f.append("ad") }
        if checkingDisabled { f.append("cd") }
        return f.joined(separator: " ")
    }
}

public struct Question: Sendable, Hashable {
    public var name: DomainName
    public var type: RecordType
    public var recordClass: RecordClass
    public init(name: DomainName, type: RecordType, recordClass: RecordClass = .internet) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
    }
}

/// Typed record data. Unrecognized types fall through to `.raw`.
public enum RecordData: Sendable, Hashable {
    case a([UInt8])                                // 4 bytes
    case aaaa([UInt8])                             // 16 bytes
    case ns(DomainName)
    case cname(DomainName)
    case ptr(DomainName)
    case soa(mname: DomainName, rname: DomainName, serial: UInt32,
             refresh: Int32, retry: Int32, expire: Int32, minimum: UInt32)
    case mx(preference: UInt16, exchange: DomainName)
    case txt([String])
    case srv(priority: UInt16, weight: UInt16, port: UInt16, target: DomainName)
    case caa(flags: UInt8, tag: String, value: String)
    case opt(options: [EDNSOption])
    case raw(type: RecordType, bytes: [UInt8])
}

public struct ResourceRecord: Sendable, Hashable {
    public var name: DomainName
    public var type: RecordType
    public var recordClass: RecordClass
    public var ttl: UInt32
    public var data: RecordData

    public init(name: DomainName, type: RecordType, recordClass: RecordClass, ttl: UInt32, data: RecordData) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
        self.ttl = ttl
        self.data = data
    }

    /// Build an EDNS0 OPT pseudo-record. For OPT, the class field carries the
    /// advertised UDP payload size and the TTL field carries the flags
    /// (extended-rcode | version | DO bit).
    public static func edns(udpPayloadSize: UInt16 = 1232, dnssecOK: Bool = false) -> ResourceRecord {
        let flags: UInt32 = dnssecOK ? (1 << 15) : 0 // DO is bit 15 of the 32-bit TTL field
        return ResourceRecord(
            name: DomainName(labels: []),
            type: .opt,
            recordClass: RecordClass(rawValue: udpPayloadSize),
            ttl: flags,
            data: .opt(options: [])
        )
    }
}

public struct Message: Sendable, Hashable {
    public var header: Header
    public var questions: [Question]
    public var answers: [ResourceRecord]
    public var authorities: [ResourceRecord]
    public var additionals: [ResourceRecord]

    public init(
        header: Header,
        questions: [Question] = [],
        answers: [ResourceRecord] = [],
        authorities: [ResourceRecord] = [],
        additionals: [ResourceRecord] = []
    ) {
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals
    }

    /// Build a standard recursive query for `name`/`type`, with EDNS0 by default.
    public static func query(
        id: UInt16 = .random(in: 0...UInt16.max),
        name: DomainName,
        type: RecordType,
        recordClass: RecordClass = .internet,
        recursionDesired: Bool = true,
        edns: ResourceRecord? = .edns()
    ) -> Message {
        let header = Header(
            id: id,
            isResponse: false,
            opcode: .query,
            recursionDesired: recursionDesired
        )
        return Message(
            header: header,
            questions: [Question(name: name, type: type, recordClass: recordClass)],
            additionals: edns.map { [$0] } ?? []
        )
    }
}
