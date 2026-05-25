import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                ForEach(AppSection.allCases) { section in
                    Label(section.rawValue, systemImage: section.systemImage)
                        .tag(section)
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
            .navigationTitle("iiadns")
        } detail: {
            switch model.selection ?? .lookup {
            case .lookup: LookupView()
            case .leakTest: LeakTestView()
            case .resolvers: ResolversView()
            }
        }
    }
}
