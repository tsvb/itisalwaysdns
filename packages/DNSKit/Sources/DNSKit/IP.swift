import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// IP-address parsing and formatting backed by the system's `inet_pton`/`inet_ntop`,
/// so IPv6 compression (`::`) is handled exactly the way the OS does it.
public enum IPAddress {
    /// Parse a dotted-quad IPv4 string into 4 bytes.
    public static func ipv4Bytes(_ string: String) -> [UInt8]? {
        var addr = in_addr()
        guard string.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0.prefix(4)) }
    }

    /// Parse an IPv6 string into 16 bytes.
    public static func ipv6Bytes(_ string: String) -> [UInt8]? {
        var addr = in6_addr()
        guard string.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0.prefix(16)) }
    }

    /// Is this string any valid IP literal?
    public static func isLiteral(_ string: String) -> Bool {
        ipv4Bytes(string) != nil || ipv6Bytes(string) != nil
    }

    public static func ipv4String(_ bytes: [UInt8]) -> String {
        guard bytes.count >= 4 else { return "<invalid A>" }
        return bytes.prefix(4).map(String.init).joined(separator: ".")
    }

    public static func ipv6String(_ bytes: [UInt8]) -> String {
        guard bytes.count >= 16 else { return "<invalid AAAA>" }
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { raw in
            for i in 0..<16 { raw[i] = bytes[i] }
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return "<invalid AAAA>"
        }
        let utf8 = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: utf8, as: UTF8.self)
    }
}

public extension DomainName {
    /// Build the reverse-lookup (PTR) name for an IP literal:
    /// `8.8.4.4` → `4.4.8.8.in-addr.arpa.`, IPv6 → nibble-reversed `ip6.arpa.`.
    static func reversePointer(forIP string: String) -> DomainName? {
        if let v4 = IPAddress.ipv4Bytes(string) {
            return DomainName(labels: v4.reversed().map(String.init) + ["in-addr", "arpa"])
        }
        if let v6 = IPAddress.ipv6Bytes(string) {
            var nibbles: [String] = []
            for byte in v6.reversed() {
                nibbles.append(String(byte & 0x0F, radix: 16))
                nibbles.append(String((byte >> 4) & 0x0F, radix: 16))
            }
            return DomainName(labels: nibbles + ["ip6", "arpa"])
        }
        return nil
    }
}

public extension RecordData {
    /// Presentation form of the rdata, dig-style.
    var presentation: String {
        switch self {
        case .a(let b): IPAddress.ipv4String(b)
        case .aaaa(let b): IPAddress.ipv6String(b)
        case .ns(let n), .cname(let n), .ptr(let n): n.description
        case .soa(let mname, let rname, let serial, let refresh, let retry, let expire, let minimum):
            "\(mname) \(rname) \(serial) \(refresh) \(retry) \(expire) \(minimum)"
        case .mx(let preference, let exchange): "\(preference) \(exchange)"
        case .txt(let strings): strings.map { "\"\($0)\"" }.joined(separator: " ")
        case .srv(let priority, let weight, let port, let target): "\(priority) \(weight) \(port) \(target)"
        case .caa(let flags, let tag, let value): "\(flags) \(tag) \"\(value)\""
        case .opt(let options): "; EDNS: \(options.count) option(s)"
        case .raw(_, let bytes): "\\# \(bytes.count) " + bytes.map { String(format: "%02x", $0) }.joined()
        }
    }
}
