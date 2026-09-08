import SwiftUI
import UIKit

struct HomeView: View {
    @ObservedObject var model: OperatorModel

    var body: some View {
        Form {
            Section("Pulpo Operator") {
                Text("Review exact governed requests without giving the phone provider credentials or execution authority.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                StatusBadge(status: model.status)
            }

            Section("Approval link") {
                TextField("https://authority.pulpo.ai/human/approval/...", text: $model.approvalURLText, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)

                HStack {
                    Button("Paste") {
                        if let value = UIPasteboard.general.string {
                            model.approvalURLText = value
                        }
                    }

                    Spacer()

                    Button("Validate") {
                        model.loadApproval()
                    }
                    .buttonStyle(.borderedProminent)
                }

                if let error = model.errorMessage {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }

            if let approval = model.approval {
                Section("Exact request") {
                    LabeledContent("Authority", value: ApprovalURLValidator.authorityHost)
                    LabeledContent("Request ID", value: approval.requestID)

                    NavigationLink("Review approval") {
                        ApprovalDetailView(model: model, approval: approval)
                    }
                }
            }

            Section("Boundary") {
                Text("A tap in this app does not create authority. The server requires the existing Pulpo WebAuthn ceremony. The app does not mark an action approved without authenticated authority evidence.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Pulpo")
        .toolbar {
            if model.approval != nil || !model.approvalURLText.isEmpty {
                Button("Reset") {
                    model.reset()
                }
            }
        }
    }
}

struct StatusBadge: View {
    let status: ApprovalStatus

    var body: some View {
        Text(status.rawValue)
            .font(.caption.bold())
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(.thinMaterial, in: Capsule())
            .accessibilityLabel("Approval status \(status.rawValue)")
    }
}
