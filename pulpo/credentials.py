"""Portable agent-credential evidence that cannot create Pulpo authority.

Credentials represent demonstrated competence or conformance. They are an
input to policy/eligibility reasoning only: this module has no kernel, permit,
authority-client, executor, directive-state, or provider dependency.

A positive assessment means only that the presented credential satisfies the
requested qualification predicates at the supplied trusted time. It does not
mint authority, broaden scope, reserve budget, or authorize execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class AgentCredential:
    credential_id: str
    issuer_id: str
    subject_principal: str
    qualification: str
    scopes: tuple[str, ...]
    issued_at_ns: int
    expires_at_ns: int
    evidence_digest: str
    revocation_ref: str
    schema: str = "pulpo.agent-credential.v0"

    def __post_init__(self) -> None:
        if not all(
            (
                self.credential_id,
                self.issuer_id,
                self.subject_principal,
                self.qualification,
                self.evidence_digest,
                self.revocation_ref,
            )
        ):
            raise ValueError("credential identity and evidence fields must be non-empty")
        if not self.scopes or any(not scope for scope in self.scopes):
            raise ValueError("credential scope must be non-empty")
        if self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("credential validity bounds are invalid")
        if self.schema != "pulpo.agent-credential.v0":
            raise ValueError("unsupported credential schema")

    @property
    def credential_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class CredentialAssessment:
    eligible: bool
    reason: str
    credential_hash: str
    issuer_id: str
    subject_principal: str
    qualification: str


@dataclass(frozen=True)
class CredentialRequirement:
    qualification: str
    scope: str

    def __post_init__(self) -> None:
        if not self.qualification or not self.scope:
            raise ValueError("credential requirement must be non-empty")


class CredentialEvaluator:
    """Assess credential eligibility without creating authority.

    Trusted issuers and revocation state are supplied by the caller so this
    object cannot become a second canonical trust registry. The output is only
    an assessment artifact; consequential authorization remains in Pulpo's
    existing authority/policy/directive/permit path.
    """

    def __init__(
        self,
        *,
        trusted_issuer_ids: frozenset[str],
        revoked_credential_ids: frozenset[str] = frozenset(),
    ) -> None:
        self._trusted_issuer_ids = trusted_issuer_ids
        self._revoked_credential_ids = revoked_credential_ids

    @staticmethod
    def _result(
        credential: AgentCredential,
        eligible: bool,
        reason: str,
    ) -> CredentialAssessment:
        return CredentialAssessment(
            eligible=eligible,
            reason=reason,
            credential_hash=credential.credential_hash,
            issuer_id=credential.issuer_id,
            subject_principal=credential.subject_principal,
            qualification=credential.qualification,
        )

    def assess(
        self,
        credential: AgentCredential,
        *,
        principal: str,
        requirement: CredentialRequirement,
        now_ns: int,
    ) -> CredentialAssessment:
        if not principal:
            return self._result(credential, False, "credential_principal_required")
        if now_ns <= 0:
            return self._result(credential, False, "credential_clock_invalid")
        if credential.issuer_id not in self._trusted_issuer_ids:
            return self._result(credential, False, "credential_issuer_untrusted")
        if credential.credential_id in self._revoked_credential_ids:
            return self._result(credential, False, "credential_revoked")
        if now_ns < credential.issued_at_ns or now_ns >= credential.expires_at_ns:
            return self._result(credential, False, "credential_inactive")
        if credential.subject_principal != principal:
            return self._result(credential, False, "credential_subject_mismatch")
        if credential.qualification != requirement.qualification:
            return self._result(credential, False, "credential_qualification_mismatch")
        if requirement.scope not in credential.scopes:
            return self._result(credential, False, "credential_scope_mismatch")
        return self._result(credential, True, "credential_eligible")
