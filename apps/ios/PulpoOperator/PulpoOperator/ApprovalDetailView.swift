import SwiftUI

struct ApprovalDetailView: View {
    @ObservedObject var model: OperatorModel
    let approval: ApprovalRequestLink

    @State private var showingApproval = false

    var body: some View {
        List {
            Section("Status") {
                StatusBadge(status: model.status)

                switch model.status {
                case .pending:
                    Text("Ready to open the exact server-hosted approval ceremony.")
                case .approved:
                    Text("Reserved for authenticated authority evidence. v0 never creates this state locally.")
                case .unknown:
                    Text("The app does not know whether authority accepted the request. Do not treat this as success or retry authority.")
                }
            }

            Section("Exact object") {
                LabeledContent("Host", value: ApprovalURLValidator.authorityHost)
                LabeledContent("Request ID", value: approval.requestID)
                Text(approval.url.absoluteString)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }

            Section("Authority") {
                Button("Open governed approval ceremony") {
                    showingApproval = true
                }
                .disabled(model.status != .pending)

                Text("The approval page performs the existing WebAuthn challenge and assertion against Pulpo authority. This app does not receive a signing key or provider credential.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            if model.status == .unknown {
                Section("Fail closed") {
                    Text("The ceremony was dismissed without authenticated readback. v0 intentionally disables blind retry. Obtain fresh authority evidence or a fresh governed request instead.")
                        .font(.footnote)
                }
            }
        }
        .navigationTitle("Approval")
        .sheet(isPresented: $showingApproval, onDismiss: {
            model.approvalCeremonyWasDismissed()
        }) {
            SafariView(url: approval.url)
                .ignoresSafeArea()
        }
    }
}
