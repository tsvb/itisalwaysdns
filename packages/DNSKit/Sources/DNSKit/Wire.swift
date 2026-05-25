import Foundation

/// A forward-only reader over a DNS message buffer. Bounds-checked everywhere —
/// it is decoding bytes that arrived over the network, so it assumes hostility.
struct ByteReader {
    let bytes: [UInt8]
    var index: Int = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    mutating func u8() throws -> UInt8 {
        guard index < bytes.count else { throw DNSError.malformedMessage("read past end (u8)") }
        defer { index += 1 }
        return bytes[index]
    }

    mutating func u16() throws -> UInt16 {
        let hi = try u8(), lo = try u8()
        return (UInt16(hi) << 8) | UInt16(lo)
    }

    mutating func u32() throws -> UInt32 {
        var v: UInt32 = 0
        for _ in 0..<4 { v = (v << 8) | UInt32(try u8()) }
        return v
    }

    mutating func raw(_ count: Int) throws -> [UInt8] {
        guard count >= 0, index + count <= bytes.count else {
            throw DNSError.malformedMessage("read past end (\(count) bytes)")
        }
        defer { index += count }
        return Array(bytes[index..<index + count])
    }

    /// Read a domain name, following RFC 1035 compression pointers. Pointers must
    /// point strictly backward, and total jumps are capped, so malformed packets
    /// can't trap us in a loop. The main cursor advances only over bytes consumed
    /// before the first jump (pointer or terminator), exactly as the wire intends.
    mutating func name() throws -> DomainName {
        var labels: [String] = []
        var jumped = false
        var pos = index
        var hops = 0

        while true {
            guard pos < bytes.count else { throw DNSError.malformedMessage("name past end") }
            let length = bytes[pos]

            if length & 0xC0 == 0xC0 {
                guard pos + 1 < bytes.count else { throw DNSError.malformedMessage("pointer past end") }
                let pointer = (Int(length & 0x3F) << 8) | Int(bytes[pos + 1])
                if !jumped { index = pos + 2 }
                jumped = true
                hops += 1
                guard hops <= 128 else { throw DNSError.malformedMessage("compression loop") }
                guard pointer < pos else { throw DNSError.malformedMessage("non-backward pointer") }
                pos = pointer
            } else if length == 0 {
                if !jumped { index = pos + 1 }
                break
            } else {
                let n = Int(length)
                guard pos + 1 + n <= bytes.count else { throw DNSError.malformedMessage("label past end") }
                labels.append(String(decoding: bytes[pos + 1..<pos + 1 + n], as: UTF8.self))
                pos += 1 + n
                if !jumped { index = pos }
            }
        }
        return DomainName(labels: labels)
    }
}

/// A growable writer. Names are written uncompressed — legal, and far simpler to
/// reason about for the small queries we emit.
struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    mutating func u8(_ v: UInt8) { bytes.append(v) }
    mutating func u16(_ v: UInt16) { bytes.append(UInt8(v >> 8)); bytes.append(UInt8(v & 0xFF)) }
    mutating func u32(_ v: UInt32) {
        bytes.append(UInt8((v >> 24) & 0xFF))
        bytes.append(UInt8((v >> 16) & 0xFF))
        bytes.append(UInt8((v >> 8) & 0xFF))
        bytes.append(UInt8(v & 0xFF))
    }
    mutating func raw(_ b: [UInt8]) { bytes.append(contentsOf: b) }

    mutating func name(_ name: DomainName) throws {
        guard name.wireLength <= 255 else { throw DNSError.nameTooLong(name.description) }
        for label in name.labels {
            let octets = Array(label.utf8)
            guard !octets.isEmpty else { throw DNSError.invalidName("empty label in \(name)") }
            guard octets.count <= 63 else { throw DNSError.labelTooLong(label) }
            u8(UInt8(octets.count))
            raw(octets)
        }
        u8(0)
    }
}

// MARK: - Encoding

public extension Message {
    /// Serialize to DNS wire format.
    func encoded() throws -> [UInt8] {
        var w = ByteWriter()
        w.u16(header.id)

        var flags1: UInt8 = 0
        if header.isResponse { flags1 |= 0x80 }
        flags1 |= (header.opcode.rawValue & 0x0F) << 3
        if header.authoritativeAnswer { flags1 |= 0x04 }
        if header.truncated { flags1 |= 0x02 }
        if header.recursionDesired { flags1 |= 0x01 }

        var flags2: UInt8 = 0
        if header.recursionAvailable { flags2 |= 0x80 }
        if header.authenticData { flags2 |= 0x20 }
        if header.checkingDisabled { flags2 |= 0x10 }
        flags2 |= UInt8(header.responseCode.rawValue & 0x0F)

        w.u8(flags1)
        w.u8(flags2)
        w.u16(UInt16(questions.count))
        w.u16(UInt16(answers.count))
        w.u16(UInt16(authorities.count))
        w.u16(UInt16(additionals.count))

        for q in questions {
            try w.name(q.name)
            w.u16(q.type.rawValue)
            w.u16(q.recordClass.rawValue)
        }
        for rr in answers { try Self.encode(rr, into: &w) }
        for rr in authorities { try Self.encode(rr, into: &w) }
        for rr in additionals { try Self.encode(rr, into: &w) }

        return w.bytes
    }

    private static func encode(_ rr: ResourceRecord, into w: inout ByteWriter) throws {
        try w.name(rr.name)
        w.u16(rr.type.rawValue)
        w.u16(rr.recordClass.rawValue)
        w.u32(rr.ttl)
        let rdata = try rr.data.rdataBytes()
        w.u16(UInt16(rdata.count))
        w.raw(rdata)
    }
}

extension RecordData {
    /// Serialize just the rdata portion (no compression).
    func rdataBytes() throws -> [UInt8] {
        var w = ByteWriter()
        switch self {
        case .a(let b), .aaaa(let b):
            w.raw(b)
        case .ns(let n), .cname(let n), .ptr(let n):
            try w.name(n)
        case .soa(let mname, let rname, let serial, let refresh, let retry, let expire, let minimum):
            try w.name(mname)
            try w.name(rname)
            w.u32(serial)
            w.u32(UInt32(bitPattern: refresh))
            w.u32(UInt32(bitPattern: retry))
            w.u32(UInt32(bitPattern: expire))
            w.u32(minimum)
        case .mx(let preference, let exchange):
            w.u16(preference)
            try w.name(exchange)
        case .txt(let strings):
            for s in strings {
                let octets = Array(s.utf8)
                guard octets.count <= 255 else { throw DNSError.invalidArgument("TXT chunk > 255 bytes") }
                w.u8(UInt8(octets.count))
                w.raw(octets)
            }
        case .srv(let priority, let weight, let port, let target):
            w.u16(priority)
            w.u16(weight)
            w.u16(port)
            try w.name(target)
        case .caa(let flags, let tag, let value):
            w.u8(flags)
            let tagBytes = Array(tag.utf8)
            w.u8(UInt8(tagBytes.count))
            w.raw(tagBytes)
            w.raw(Array(value.utf8))
        case .opt(let options):
            for opt in options {
                w.u16(opt.code)
                w.u16(UInt16(opt.data.count))
                w.raw(opt.data)
            }
        case .raw(_, let bytes):
            w.raw(bytes)
        }
        return w.bytes
    }
}

// MARK: - Decoding

public extension Message {
    /// Parse a DNS message from wire format.
    init(decoding bytes: [UInt8]) throws {
        var r = ByteReader(bytes)
        let id = try r.u16()
        let flags1 = try r.u8()
        let flags2 = try r.u8()
        let qdCount = try r.u16()
        let anCount = try r.u16()
        let nsCount = try r.u16()
        let arCount = try r.u16()

        let header = Header(
            id: id,
            isResponse: flags1 & 0x80 != 0,
            opcode: Opcode(rawValue: (flags1 >> 3) & 0x0F),
            authoritativeAnswer: flags1 & 0x04 != 0,
            truncated: flags1 & 0x02 != 0,
            recursionDesired: flags1 & 0x01 != 0,
            recursionAvailable: flags2 & 0x80 != 0,
            authenticData: flags2 & 0x20 != 0,
            checkingDisabled: flags2 & 0x10 != 0,
            responseCode: ResponseCode(rawValue: UInt16(flags2 & 0x0F))
        )

        var questions: [Question] = []
        questions.reserveCapacity(Int(qdCount))
        for _ in 0..<qdCount {
            let name = try r.name()
            let type = RecordType(rawValue: try r.u16())
            let cls = RecordClass(rawValue: try r.u16())
            questions.append(Question(name: name, type: type, recordClass: cls))
        }

        func readRecords(_ count: UInt16) throws -> [ResourceRecord] {
            var records: [ResourceRecord] = []
            records.reserveCapacity(Int(count))
            for _ in 0..<count {
                let name = try r.name()
                let type = RecordType(rawValue: try r.u16())
                let cls = RecordClass(rawValue: try r.u16())
                let ttl = try r.u32()
                let rdlength = Int(try r.u16())
                let rdataStart = r.index
                let data = try RecordData(reading: &r, type: type, rdlength: rdlength)
                // Force the cursor to exactly end-of-rdata: name compression inside
                // rdata makes the consumed length ambiguous, so the wire-stated
                // rdlength is authoritative.
                r.index = rdataStart + rdlength
                records.append(ResourceRecord(name: name, type: type, recordClass: cls, ttl: ttl, data: data))
            }
            return records
        }

        let answers = try readRecords(anCount)
        let authorities = try readRecords(nsCount)
        let additionals = try readRecords(arCount)

        self.init(header: header, questions: questions, answers: answers,
                  authorities: authorities, additionals: additionals)
    }
}

extension RecordData {
    init(reading r: inout ByteReader, type: RecordType, rdlength: Int) throws {
        switch type {
        case .a:
            self = .a(try r.raw(4))
        case .aaaa:
            self = .aaaa(try r.raw(16))
        case .ns:
            self = .ns(try r.name())
        case .cname:
            self = .cname(try r.name())
        case .ptr:
            self = .ptr(try r.name())
        case .soa:
            let mname = try r.name()
            let rname = try r.name()
            let serial = try r.u32()
            let refresh = Int32(bitPattern: try r.u32())
            let retry = Int32(bitPattern: try r.u32())
            let expire = Int32(bitPattern: try r.u32())
            let minimum = try r.u32()
            self = .soa(mname: mname, rname: rname, serial: serial,
                        refresh: refresh, retry: retry, expire: expire, minimum: minimum)
        case .mx:
            let preference = try r.u16()
            self = .mx(preference: preference, exchange: try r.name())
        case .txt:
            var strings: [String] = []
            var consumed = 0
            while consumed < rdlength {
                let len = Int(try r.u8())
                consumed += 1
                strings.append(String(decoding: try r.raw(len), as: UTF8.self))
                consumed += len
            }
            self = .txt(strings)
        case .srv:
            let priority = try r.u16()
            let weight = try r.u16()
            let port = try r.u16()
            self = .srv(priority: priority, weight: weight, port: port, target: try r.name())
        case .caa:
            let flags = try r.u8()
            let tagLen = Int(try r.u8())
            let tag = String(decoding: try r.raw(tagLen), as: UTF8.self)
            let valueLen = max(0, rdlength - 2 - tagLen)
            let value = String(decoding: try r.raw(valueLen), as: UTF8.self)
            self = .caa(flags: flags, tag: tag, value: value)
        case .opt:
            var options: [EDNSOption] = []
            var consumed = 0
            while consumed + 4 <= rdlength {
                let code = try r.u16()
                let len = Int(try r.u16())
                consumed += 4
                options.append(EDNSOption(code: code, data: try r.raw(len)))
                consumed += len
            }
            self = .opt(options: options)
        default:
            self = .raw(type: type, bytes: try r.raw(rdlength))
        }
    }
}
