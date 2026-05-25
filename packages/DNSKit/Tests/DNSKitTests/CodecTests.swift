import Testing
@testable import DNSKit

// Pure codec tests — no network. Golden wire-format vectors plus round-trips and
// adversarial inputs. These are the regression net for the parser.

@Suite("Wire codec")
struct CodecTests {

    // MARK: Query encoding (golden vector)

    @Test("Encodes a minimal A query to exact bytes")
    func encodeQueryGolden() throws {
        // example.com A IN, id 0x1234, RD set, no EDNS.
        let query = Message.query(id: 0x1234, name: "example.com", type: .a, edns: nil)
        let bytes = try query.encoded()
        let expected: [UInt8] = [
            0x12, 0x34,             // id
            0x01, 0x00,             // flags: RD
            0x00, 0x01,             // QDCOUNT
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00,                   // root
            0x00, 0x01,             // QTYPE A
            0x00, 0x01,             // QCLASS IN
        ]
        #expect(bytes == expected)
    }

    @Test("EDNS OPT carries buffer size in class and DO bit in TTL")
    func ednsOptEncoding() throws {
        let opt = ResourceRecord.edns(udpPayloadSize: 1232, dnssecOK: true)
        #expect(opt.type == .opt)
        #expect(opt.recordClass.rawValue == 1232)
        #expect(opt.ttl == 0x0000_8000) // DO bit = bit 15 of the TTL field
        let query = Message.query(id: 1, name: "a.test", type: .a, edns: opt)
        let decoded = try Message(decoding: try query.encoded())
        #expect(decoded.additionals.count == 1)
        #expect(decoded.additionals[0].type == .opt)
        #expect(decoded.additionals[0].recordClass.rawValue == 1232)
    }

    // MARK: Compression (golden vector)

    @Test("Decodes a compression pointer in an answer name")
    func decodeCompressionPointer() throws {
        let bytes: [UInt8] = [
            0x12, 0x34,             // id
            0x81, 0x80,             // flags: qr rd ra
            0x00, 0x01,             // QDCOUNT
            0x00, 0x01,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            // Question at offset 12: foo.bar A IN
            0x03, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72, 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer: name is a pointer to offset 12, A IN ttl=60 rdata=1.2.3.4
            0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3c,
            0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        ]
        let msg = try Message(decoding: bytes)
        #expect(msg.header.id == 0x1234)
        #expect(msg.header.isResponse)
        #expect(msg.header.recursionAvailable)
        #expect(msg.questions.first?.name == DomainName("foo.bar"))
        let answer = try #require(msg.answers.first)
        #expect(answer.name == DomainName("foo.bar")) // resolved through the pointer
        #expect(answer.ttl == 60)
        #expect(answer.type == .a)
        #expect(answer.data == .a([1, 2, 3, 4]))
    }

    // MARK: rdata round-trips

    @Test("Round-trips one record of each common type")
    func rdataRoundTrip() throws {
        let records: [ResourceRecord] = [
            ResourceRecord(name: "h.example", type: .a, recordClass: .internet, ttl: 1, data: .a([192, 0, 2, 1])),
            ResourceRecord(name: "h.example", type: .aaaa, recordClass: .internet, ttl: 1,
                           data: .aaaa(IPAddress.ipv6Bytes("2001:db8::1")!)),
            ResourceRecord(name: "h.example", type: .cname, recordClass: .internet, ttl: 1, data: .cname("target.example")),
            ResourceRecord(name: "h.example", type: .mx, recordClass: .internet, ttl: 1,
                           data: .mx(preference: 10, exchange: "mail.example")),
            ResourceRecord(name: "h.example", type: .txt, recordClass: .internet, ttl: 1,
                           data: .txt(["v=spf1 -all", "second"])),
            ResourceRecord(name: "h.example", type: .srv, recordClass: .internet, ttl: 1,
                           data: .srv(priority: 1, weight: 2, port: 443, target: "svc.example")),
            ResourceRecord(name: "h.example", type: .caa, recordClass: .internet, ttl: 1,
                           data: .caa(flags: 0, tag: "issue", value: "letsencrypt.org")),
            ResourceRecord(name: "example", type: .soa, recordClass: .internet, ttl: 1,
                           data: .soa(mname: "ns.example", rname: "host.example",
                                      serial: 2024010101, refresh: 7200, retry: 3600,
                                      expire: 1209600, minimum: 3600)),
        ]
        for rr in records {
            // Wrap each record in a message, encode, decode, and compare the record back.
            var msg = Message(header: Header(id: 7, isResponse: true))
            msg.answers = [rr]
            let decoded = try Message(decoding: try msg.encoded())
            #expect(decoded.answers.count == 1, "\(rr.type)")
            #expect(decoded.answers[0] == rr, "round-trip mismatch for \(rr.type)")
        }
    }

    // MARK: Names

    @Test("Domain name parsing and presentation")
    func nameParsing() {
        #expect(DomainName("example.com").labels == ["example", "com"])
        #expect(DomainName("example.com.").labels == ["example", "com"])
        #expect(DomainName("").isRoot)
        #expect(DomainName(".").isRoot)
        #expect(DomainName("a.b.c").description == "a.b.c.")
        #expect(DomainName("EXAMPLE.com").matches(DomainName("example.COM")))
        #expect(!DomainName("a.b").matches(DomainName("a.c")))
    }

    @Test("Reverse pointer names")
    func reversePointers() {
        #expect(DomainName.reversePointer(forIP: "8.8.4.4") == DomainName("4.4.8.8.in-addr.arpa"))
        #expect(DomainName.reversePointer(forIP: "not-an-ip") == nil)
        let v6 = DomainName.reversePointer(forIP: "2001:db8::1")
        #expect(v6?.description.hasSuffix(".ip6.arpa.") == true)
        // 32 nibbles + "ip6" + "arpa"
        #expect(v6?.labels.count == 34)
    }

    @Test("IPv6 formatting uses :: compression")
    func ipv6Formatting() throws {
        let bytes = try #require(IPAddress.ipv6Bytes("2606:4700:4700::1111"))
        #expect(IPAddress.ipv6String(bytes) == "2606:4700:4700::1111")
        let loop = try #require(IPAddress.ipv6Bytes("::1"))
        #expect(IPAddress.ipv6String(loop) == "::1")
    }

    // MARK: Adversarial input

    @Test("Truncated message throws rather than crashing")
    func truncatedMessage() {
        #expect(throws: DNSError.self) { try Message(decoding: [0x12, 0x34]) }
        #expect(throws: DNSError.self) { try Message(decoding: []) }
    }

    @Test("Non-backward compression pointer is rejected")
    func compressionLoopRejected() {
        var reader = ByteReader([0xc0, 0x00]) // pointer at offset 0 -> offset 0
        #expect(throws: DNSError.self) { try reader.name() }
    }

    @Test("Over-long label is rejected on encode")
    func labelTooLong() {
        let longLabel = String(repeating: "a", count: 64)
        var writer = ByteWriter()
        #expect(throws: DNSError.self) { try writer.name(DomainName(labels: [longLabel])) }
    }

    @Test("Header flags pack and unpack symmetrically")
    func headerFlagRoundTrip() throws {
        let header = Header(id: 0xABCD, isResponse: true, opcode: .query,
                            authoritativeAnswer: true, truncated: false,
                            recursionDesired: true, recursionAvailable: true,
                            authenticData: true, checkingDisabled: false,
                            responseCode: .nxDomain)
        let msg = Message(header: header, questions: [Question(name: "x", type: .a)])
        let decoded = try Message(decoding: try msg.encoded())
        #expect(decoded.header.isResponse)
        #expect(decoded.header.authoritativeAnswer)
        #expect(decoded.header.recursionAvailable)
        #expect(decoded.header.authenticData)
        #expect(decoded.header.responseCode == .nxDomain)
        #expect(decoded.header.flagString == "qr aa rd ra ad")
    }
}
