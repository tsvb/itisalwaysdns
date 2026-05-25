import SwiftUI

@main
struct IiadnsApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 840, minHeight: 540)
        }

        // Quick-glance menu bar item (rich popover via `.window` style).
        MenuBarExtra("iiadns", systemImage: "network") {
            MenuBarView()
                .environment(model)
                .frame(width: 320)
        }
        .menuBarExtraStyle(.window)
    }
}
