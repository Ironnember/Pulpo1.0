import Foundation

@MainActor
final class OperatorModel: ObservableObject {
    @Published var approvalURLText = ""
    @Published private(set) var approval: ApprovalRequestLink?
    @Published private(set) var status: ApprovalStatus = .unknown
    @Published var errorMessage: String?

    func loadApproval() {
        do {
            let link = try ApprovalURLValidator.parse(approvalURLText)
            approval = link
            status = .pending
            errorMessage = nil
        } catch {
            approval = nil
            status = .unknown
            errorMessage = error.localizedDescription
        }
    }

    func approvalCeremonyWasDismissed() {
        guard status == .pending else { return }
        status = .unknown
    }

    func reset() {
        approvalURLText = ""
        approval = nil
        status = .unknown
        errorMessage = nil
    }
}

enum ApprovalStatus: String {
    case pending = "PENDING"
    case approved = "APPROVED"
    case unknown = "UNKNOWN"
}

struct ApprovalRequestLink: Hashable, Identifiable {
    let requestID: String
    let url: URL

    var id: String { requestID }
}

enum ApprovalLinkError: LocalizedError {
    case malformed
    case invalidScheme
    case invalidHost
    case invalidPort
    case credentialsNotAllowed
    case queryOrFragmentNotAllowed
    case invalidPath

    var errorDescription: String? {
        switch self {
        case .malformed:
            return "Enter a complete Pulpo approval URL."
        case .invalidScheme:
            return "Pulpo approvals require HTTPS."
        case .invalidHost:
            return "This is not an approved Pulpo authority host."
        case .invalidPort:
            return "Custom ports are not permitted for Pulpo approval links."
        case .credentialsNotAllowed:
            return "Credentials must not be embedded in approval links."
        case .queryOrFragmentNotAllowed:
            return "Pulpo approval links may not contain query strings or fragments."
        case .invalidPath:
            return "The URL is not an exact Pulpo human approval path."
        }
    }
}

enum ApprovalURLValidator {
    static let authorityHost = "authority.pulpo.ai"

    static func parse(_ input: String) throws -> ApprovalRequestLink {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed), let url = components.url else {
            throw ApprovalLinkError.malformed
        }
        guard components.scheme?.lowercased() == "https" else {
            throw ApprovalLinkError.invalidScheme
        }
        guard components.host?.lowercased() == authorityHost else {
            throw ApprovalLinkError.invalidHost
        }
        guard components.port == nil else {
            throw ApprovalLinkError.invalidPort
        }
        guard components.user == nil, components.password == nil else {
            throw ApprovalLinkError.credentialsNotAllowed
        }
        guard components.query == nil, components.fragment == nil else {
            throw ApprovalLinkError.queryOrFragmentNotAllowed
        }

        let parts = components.path.split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count == 3,
              parts[0] == "human",
              parts[1] == "approval",
              !parts[2].isEmpty,
              components.path == "/human/approval/\(parts[2])" else {
            throw ApprovalLinkError.invalidPath
        }

        return ApprovalRequestLink(requestID: String(parts[2]), url: url)
    }
}
