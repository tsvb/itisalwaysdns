import SwiftUI
import DNSKit

struct LookupView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        let lookup = model.lookup

        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $model.lookup.nameInput, prompt: Text("example.com"))
                        .onSubmit { Task { await lookup.run() } }

                    Picker("Type", selection: $model.lookup.selectedType) {
                        ForEach(lookup.allTypes, id: \.self) { Text($0.name).tag($0) }
                    }

                    Toggle("Use system resolver", isOn: $model.lookup.useSystemResolver)
                    if !lookup.useSystemResolver {
                        TextField("Server", text: $model.lookup.serverInput, prompt: Text("1.1.1.1 or 1.1.1.1#53"))
                    } else {
                        LabeledContent("Resolver", value: lookup.effectiveServer.description)
                    }

                    Picker("Transport", selection: $model.lookup.transport) {
                        ForEach(TransportKind.allCases, id: \.self) { Text($0.rawValue.uppercased()).tag($0) }
                    }
                    .pickerStyle(.segmented)

                    Toggle("Request DNSSEC (DO bit)", isOn: $model.lookup.dnssec)
                } header: {
                    Text("Query")
                }
            }
            .formStyle(.grouped)

            HStack {
                Button {
                    Task { await lookup.run() }
                } label: {
                    Label("Run", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(lookup.isRunning)

                if lookup.isRunning {
                    ProgressView().controlSize(.small)
                }
                Spacer()
            }
            .padding([.horizontal, .bottom])

            Divider()

            ResultsView(lookup: lookup)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("Lookup")
    }
}

private struct ResultsView: View {
    let lookup: LookupModel

    var body: some View {
        if let error = lookup.errorText {
            ContentUnavailableView {
                Label("Query failed", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error).textSelection(.enabled)
            }
        } else if let answer = lookup.answer {
            VStack(alignment: .leading, spacing: 0) {
                MetadataBar(answer: answer)
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                Divider()
                Table(answer.displayRows) {
                    TableColumn("Section") { Text($0.section).foregroundStyle(.secondary) }
                        .width(min: 70, ideal: 80)
                    TableColumn("Name") { Text($0.record.name.description).textSelection(.enabled) }
                    TableColumn("TTL") { Text("\($0.record.ttl)").monospacedDigit() }
                        .width(min: 50, ideal: 60)
                    TableColumn("Type") { Text($0.record.type.name) }
                        .width(min: 60, ideal: 70)
                    TableColumn("Data") { Text($0.record.data.presentation).textSelection(.enabled) }
                }

                DisclosureGroup("Raw response (\(answer.rawResponse.count) bytes)") {
                    ScrollView([.horizontal, .vertical]) {
                        Text(lookup.rawHex)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(height: 160)
                }
                .padding(.horizontal)
                .padding(.bottom, 8)
            }
        } else {
            ContentUnavailableView {
                Label("No results yet", systemImage: "magnifyingglass")
            } description: {
                Text("Run a query to see the records returned.")
            }
        }
    }
}

private struct MetadataBar: View {
    let answer: Answer

    var body: some View {
        HStack(spacing: 16) {
            badge("STATUS", answer.responseCode.description, tint: answer.responseCode == .noError ? .green : .orange)
            badge("FLAGS", answer.message.header.flagString.isEmpty ? "—" : answer.message.header.flagString)
            badge("TIME", "\(Int(answer.latency * 1000)) ms")
            badge("SERVER", "\(answer.server) · \(answer.transport.rawValue.uppercased())")
            Spacer()
        }
        .font(.callout)
    }

    private func badge(_ label: String, _ value: String, tint: Color = .secondary) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).foregroundStyle(tint == .secondary ? .primary : tint).fontWeight(.medium)
        }
    }
}
