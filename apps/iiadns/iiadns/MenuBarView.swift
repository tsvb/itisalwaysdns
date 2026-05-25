import SwiftUI
import DNSKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let config = model.systemDNS.config
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "network")
                Text("iiadns").fontWeight(.semibold)
                Spacer()
            }
            Divider()

            LabeledContent("Resolver") {
                Text(config.resolvers.first ?? "unknown").foregroundStyle(.secondary)
            }
            LabeledContent("VPN") {
                Label(config.vpnActive ? "Active" : "Off",
                      systemImage: config.vpnActive ? "checkmark.shield.fill" : "shield.slash")
                    .foregroundStyle(config.vpnActive ? .green : .secondary)
                    .labelStyle(.titleAndIcon)
            }

            Divider()

            Button {
                model.selection = .lookup
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label("Open iiadns", systemImage: "macwindow")
            }

            Button {
                model.systemDNS.refresh()
            } label: {
                Label("Refresh status", systemImage: "arrow.clockwise")
            }

            Divider()

            Button {
                NSApp.terminate(nil)
            } label: {
                Label("Quit", systemImage: "power")
            }
        }
        .buttonStyle(.plain)
        .padding(12)
    }
}
