import SwiftUI
import DNSKit

struct ResolversView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let config = model.systemDNS.config
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Status") {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("Primary interface", value: config.primaryInterface ?? "unknown")
                        LabeledContent("VPN active") {
                            Label(config.vpnActive ? "Yes" : "No",
                                  systemImage: config.vpnActive ? "checkmark.shield.fill" : "shield.slash")
                                .foregroundStyle(config.vpnActive ? .green : .secondary)
                        }
                    }
                    .padding(6)
                }

                GroupBox("Default resolvers") {
                    if config.resolvers.isEmpty {
                        Text("None reported").foregroundStyle(.secondary).padding(6)
                    } else {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(config.resolvers, id: \.self) { server in
                                Label(server, systemImage: "server.rack")
                                    .textSelection(.enabled)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                    }
                }

                if !config.searchDomains.isEmpty {
                    GroupBox("Search domains") {
                        Text(config.searchDomains.joined(separator: ", "))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                    }
                }

                if !config.scopedResolvers.isEmpty {
                    GroupBox("Scoped resolvers") {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(Array(config.scopedResolvers.enumerated()), id: \.offset) { _, scoped in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(scoped.nameservers.joined(separator: ", "))
                                        .font(.callout)
                                    if !scoped.supplementalMatchDomains.isEmpty {
                                        Text("matches: " + scoped.supplementalMatchDomains.joined(separator: ", "))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                    }
                }
            }
            .padding()
        }
        .navigationTitle("Resolvers")
        .toolbar {
            Button { model.systemDNS.refresh() } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
        }
    }
}
