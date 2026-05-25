import Foundation

/// A domain name as an ordered list of labels (without the implicit root label).
/// `example.com` → `["example", "com"]`; the root is `[]`.
///
/// Equality is exact (case-preserving); use `matches(_:)` for the case-insensitive
/// comparison the DNS protocol actually mandates.
public struct DomainName: Sendable, Hashable, CustomStringConvertible, ExpressibleByStringLiteral {
    public var labels: [String]

    public init(labels: [String]) {
        self.labels = labels
    }

    /// Parse a presentation-form name. A trailing dot is optional and stripped.
    public init(_ string: String) {
        var s = string
        if s.hasSuffix(".") { s.removeLast() }
        if s.isEmpty {
            self.labels = []
        } else {
            self.labels = s.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        }
    }

    public init(stringLiteral value: String) {
        self.init(value)
    }

    public var isRoot: Bool { labels.isEmpty }

    /// Presentation form, always fully qualified with a trailing dot.
    public var description: String {
        labels.isEmpty ? "." : labels.joined(separator: ".") + "."
    }

    /// Case-insensitive comparison per RFC 4343.
    public func matches(_ other: DomainName) -> Bool {
        guard labels.count == other.labels.count else { return false }
        return zip(labels, other.labels).allSatisfy {
            $0.lowercased() == $1.lowercased()
        }
    }

    /// Total wire length (label-length octets + bytes + terminating root). Used
    /// to enforce the 255-octet ceiling.
    var wireLength: Int {
        labels.reduce(1) { $0 + 1 + $1.utf8.count }
    }
}
