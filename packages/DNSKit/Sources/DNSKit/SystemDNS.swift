import Foundation
#if canImport(SystemConfiguration)
import SystemConfiguration
#endif

/// Resolvers configured for one network service/scope.
public struct ScopedResolver: Sendable, Hashable {
    public var nameservers: [String]
    public var searchDomains: [String]
    public var supplementalMatchDomains: [String]
    public init(nameservers: [String], searchDomains: [String] = [], supplementalMatchDomains: [String] = []) {
        self.nameservers = nameservers
        self.searchDomains = searchDomains
        self.supplementalMatchDomains = supplementalMatchDomains
    }
}

/// A snapshot of the system's DNS configuration — what the OS *says* it will use,
/// as opposed to what a leak test later proves it *actually* uses.
public struct SystemDNSConfiguration: Sendable, Hashable {
    public var resolvers: [String]
    public var searchDomains: [String]
    public var primaryInterface: String?
    public var vpnActive: Bool
    public var scopedResolvers: [ScopedResolver]

    public init(
        resolvers: [String] = [],
        searchDomains: [String] = [],
        primaryInterface: String? = nil,
        vpnActive: Bool = false,
        scopedResolvers: [ScopedResolver] = []
    ) {
        self.resolvers = resolvers
        self.searchDomains = searchDomains
        self.primaryInterface = primaryInterface
        self.vpnActive = vpnActive
        self.scopedResolvers = scopedResolvers
    }

    /// Servers ready to query, as endpoints (defaulting to port 53).
    public var resolverEndpoints: [ServerEndpoint] {
        resolvers.map { ServerEndpoint(host: $0) }
    }
}

public enum SystemDNS {
    /// Read the live DNS configuration via SystemConfiguration's dynamic store —
    /// the same source `scutil --dns` reads.
    public static func current() -> SystemDNSConfiguration {
        #if canImport(SystemConfiguration)
        guard let store = SCDynamicStoreCreate(nil, "iiadns.SystemDNS" as CFString, nil, nil) else {
            return SystemDNSConfiguration()
        }

        var config = SystemDNSConfiguration()

        if let globalDNS = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
            config.resolvers = (globalDNS["ServerAddresses"] as? [String]) ?? []
            config.searchDomains = (globalDNS["SearchDomains"] as? [String]) ?? []
        }

        if let globalIPv4 = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any] {
            let primary = globalIPv4["PrimaryInterface"] as? String
            config.primaryInterface = primary
            // Tunnel interfaces backing a VPN/Personal-VPN/utun take the default route.
            if let primary {
                config.vpnActive = primary.hasPrefix("utun") || primary.hasPrefix("ppp") || primary.hasPrefix("ipsec")
            }
        }

        // Per-service scoped resolvers (split-DNS, VPN-pushed domains, etc.).
        if let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/DNS" as CFString) as? [String] {
            for key in keys {
                guard let dns = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] else { continue }
                let servers = (dns["ServerAddresses"] as? [String]) ?? []
                guard !servers.isEmpty else { continue }
                config.scopedResolvers.append(ScopedResolver(
                    nameservers: servers,
                    searchDomains: (dns["SearchDomains"] as? [String]) ?? [],
                    supplementalMatchDomains: (dns["SupplementalMatchDomains"] as? [String]) ?? []
                ))
            }
        }

        return config
        #else
        return SystemDNSConfiguration()
        #endif
    }
}
