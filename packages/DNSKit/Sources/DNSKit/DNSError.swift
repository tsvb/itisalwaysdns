import Foundation

/// Errors surfaced by the DNS engine. Messages are intentionally human-readable
/// because this is a diagnostic tool — the error *is* part of the output.
public enum DNSError: Error, Sendable, CustomStringConvertible, Equatable {
    case malformedMessage(String)
    case nameTooLong(String)
    case labelTooLong(String)
    case invalidName(String)
    case invalidArgument(String)
    case transport(String)
    case timeout
    case noServers
    case cancelled

    public var description: String {
        switch self {
        case .malformedMessage(let s): "malformed DNS message: \(s)"
        case .nameTooLong(let s): "name too long: \(s)"
        case .labelTooLong(let s): "label too long: \(s)"
        case .invalidName(let s): "invalid name: \(s)"
        case .invalidArgument(let s): "invalid argument: \(s)"
        case .transport(let s): "transport error: \(s)"
        case .timeout: "timed out waiting for response"
        case .noServers: "no resolvers available"
        case .cancelled: "cancelled"
        }
    }
}
