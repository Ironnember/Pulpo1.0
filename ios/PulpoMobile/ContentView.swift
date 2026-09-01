import SwiftUI

private struct DecisionRequest: Encodable {
    let principal: String
    let action: String
    let resource: String
    let cost: Int
}

private struct DecisionResponse: Decodable {
    let outcome: String
    let reason: String
    let permit: String?
}

struct ContentView: View {
    @AppStorage("pulpo.apiURL") private var apiURL = "https://api.example.com/api/decision"
    @AppStorage("pulpo.token") private var token = ""
    @AppStorage("pulpo.principal") private var principal = "agent:phone"
    @State private var action = "read"
    @State private var resource = "repo:docs"
    @State private var cost = 10
    @State private var result: DecisionResponse?
    @State private var errorMessage: String?
    @State private var isSubmitting = false

    private let actions = ["read", "write", "deploy"]

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    TextField("HTTPS API URL", text: $apiURL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Bearer token", text: $token)
                    TextField("Principal", text: $principal)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("Intent") {
                    Picker("Action", selection: $action) {
                        ForEach(actions, id: \.self, content: Text.init)
                    }
                    TextField("Resource", text: $resource)
                    Stepper("Cost: \(cost)", value: $cost, in: 0...100)
                }

                Section {
                    Button {
                        Task { await submit() }
                    } label: {
                        HStack {
                            Spacer()
                            if isSubmitting {
                                ProgressView()
                            } else {
                                Label("Check policy", systemImage: "checkmark.shield")
                            }
                            Spacer()
                        }
                    }
                    .disabled(isSubmitting || token.isEmpty)
                }

                if let result {
                    Section("Decision") {
                        LabeledContent("Outcome", value: result.outcome.uppercased())
                        LabeledContent("Reason", value: result.reason)
                        if result.permit != nil {
                            Label("One-use permit issued", systemImage: "key.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Pulpo")
        }
    }

    private func submit() async {
        guard let url = URL(string: apiURL), url.scheme == "https" else {
            errorMessage = "Use an HTTPS API URL."
            return
        }

        isSubmitting = true
        errorMessage = nil
        defer { isSubmitting = false }

        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            request.httpBody = try JSONEncoder().encode(
                DecisionRequest(principal: principal, action: action, resource: resource, cost: cost)
            )
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw URLError(.badServerResponse)
            }
            guard (200...299).contains(httpResponse.statusCode) else {
                throw NSError(domain: "Pulpo", code: httpResponse.statusCode,
                              userInfo: [NSLocalizedDescriptionKey: "API returned HTTP \(httpResponse.statusCode)"])
            }
            result = try JSONDecoder().decode(DecisionResponse.self, from: data)
        } catch {
            result = nil
            errorMessage = error.localizedDescription
        }
    }
}

#Preview {
    ContentView()
}
