import Foundation
import DNSKit

/// Parse a "host" or "host#port" resolver string.
func parseServer(_ string: String) -> ServerEndpoint {
    let trimmed = string.trimmingCharacters(in: .whitespaces)
    if let hash = trimmed.firstIndex(of: "#"), let port = UInt16(trimmed[trimmed.index(after: hash)...]) {
        return ServerEndpoint(host: String(trimmed[..<hash]), port: port)
    }
    return ServerEndpoint(host: trimmed)
}

/// Classic offset / hex / ASCII hexdump.
func hexDump(_ bytes: [UInt8]) -> String {
    var lines: [String] = []
    var offset = 0
    while offset < bytes.count {
        let chunk = Array(bytes[offset..<min(offset + 16, bytes.count)])
        let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
        let ascii = chunk.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
        let off = String(format: "%04x", offset)
        lines.append("\(off)  \(hex.padding(toLength: 47, withPad: " ", startingAt: 0))  \(ascii)")
        offset += 16
    }
    return lines.joined(separator: "\n")
}

/// A flattened, identifiable record row for the results table.
struct RecordRow: Identifiable {
    let id = UUID()
    let section: String
    let record: ResourceRecord
}

extension Answer {
    /// All returned records, flattened and tagged with their section, with the
    /// EDNS OPT pseudo-record filtered out (it isn't really an answer).
    var displayRows: [RecordRow] {
        var rows: [RecordRow] = []
        rows += message.answers.map { RecordRow(section: "Answer", record: $0) }
        rows += message.authorities.map { RecordRow(section: "Authority", record: $0) }
        rows += message.additionals
            .filter { $0.type != .opt }
            .map { RecordRow(section: "Additional", record: $0) }
        return rows
    }
}
