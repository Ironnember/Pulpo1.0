import SwiftUI

@main
struct PulpoOperatorApp: App {
    @StateObject private var model = OperatorModel()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                HomeView(model: model)
            }
        }
    }
}
