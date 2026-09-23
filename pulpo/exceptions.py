# pulpo/exceptions.py

from typing import Optional


class ServiceRejected(Exception):
    """Generic service-level rejection with an optional machine code."""

    def __init__(self, code: str, message: Optional[str] = None):
        self.code = code
        self.message = message or ""
        if self.message:
            super().__init__(f"{code}:{self.message}")
        else:
            super().__init__(code)


class ProposalCommitmentViolation(ServiceRejected):
    """Raised when a proposal commitment is invalid or cannot be created."""

    def __init__(self, code: str = "proposal_commitment_violation", message: Optional[str] = None):
        super().__init__(code, message)


class ProposalProvenanceRejected(ServiceRejected):
    """Raised when provenance-related checks reject a proposal (e.g., unknown commitment)."""

    def __init__(self, code: str = "proposal_provenance_rejected", message: Optional[str] = None):
        super().__init__(code, message)


class AuthorizationRejected(ServiceRejected):
    """Raised when an authorization attempt is rejected by custody logic."""

    def __init__(self, code: str = "authorization_rejected", message: Optional[str] = None):
        super().__init__(code, message)
