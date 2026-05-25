import SwiftUI
import DNSKit

/// Leak-test screen. The verdict half depends on the self-hosted `leakd` backend
/// (authoritative zone + reporting API), which isn't wired in this foundation
/// build — so this shows the client-side half that already works (the resolvers
/// the OS *says* it will use) and explains what the full test adds.
struct LeakTestView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let config = model.systemDNS.config
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "drop.fill")
                            .font(.title)
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("DNS Leak Test").font(.headline)
                            Text("Compares the resolvers the OS reports against the ones that "
                                 + "actually answer queries, observed at our authoritative server.")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(6)
                }

                GroupBox("Configured resolvers (what the OS reports)") {
                    VStack(alignment: .leading, spacing: 4) {
                        if config.resolvers.isEmpty {
                            Text("None reported").foregroundStyle(.secondary)
                        } else {
                            ForEach(config.resolvers, id: \.self) { server in
                                Label(server, systemImage: "server.rack").textSelection(.enabled)
                            }
                        }
                        LabeledContent("VPN active", value: config.vpnActive ? "Yes" : "No")
                            .padding(.top, 4)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox("Observed resolvers (what actually answers)") {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Requires the leakd backend", systemImage: "wifi.exclamationmark")
                            .foregroundStyle(.secondary)
                        Text("The full test triggers lookups of unique random hostnames under a "
                             + "zone we control, then reports every recursive resolver that queried "
                             + "it — enriched with reverse DNS, ASN/org, and geo — and flags any that "
                             + "don't match your VPN.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                Button {
                    // Wired once the backend endpoint is configured.
                } label: {
                    Label("Run Leak Test", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(true)
                .help("Enabled once the leakd backend endpoint is configured.")
            }
            .padding()
        }
        .navigationTitle("Leak Test")
        .toolbar {
            Button { model.systemDNS.refresh() } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
        }
    }
}
