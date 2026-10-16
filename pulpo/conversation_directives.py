"""Non-authoritative conversation-to-directive candidate projection.

Conversation is provenance, not authority. This module can freeze one semantic
interpretation of conversational text into an immutable candidate and, when the
candidate is unambiguous, materialize it only as a narrowing child of an existing
Pulpo ``Directive``. It cannot activate directives, mint permits, mutate canonical
state, validate IAM, or execute provider effects.

The existing ``DirectiveAuthorityController`` remains the only canonical path in
this package for activating the resulting directive, including its independent
approval and live-parent checks.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json

from .directives import Directive


_CANDIDATE_SCHEMA = "pulpo.conversation-directive-candidate.v0"
_SOURCE_TYPE = "conversation"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name}_invalid")
    return value


def _require_digest(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if (
        len(text) != 64
        or text != text.lower()
        or any(character not in "0123456789abcdef" for character in text)
    ):
        raise ValueError(f"{field_name}_invalid")
    return text


def digest_conversation_source(source: str) -> str:
    """Digest the exact conversational source without making it authoritative."""

    if not isinstance(source, str) or not source:
        raise ValueError("conversation_source_invalid")
    return sha256(source.encode("utf-8")).hexdigest()


class ConversationDirectiveCandidateError(ValueError):
    """Raised when a candidate cannot become a narrowing directive proposal."""


@dataclass(frozen=True)
class ConversationDirectiveCandidate:
    """Immutable semantic proposal derived from conversation.

    ``identity_context_hash`` is provenance only. A caller may bind the candidate
    to an independently obtained identity/IAM context digest, but this module does
    not validate that context and never treats it as authority.

    A candidate can materialize only as a child of an existing ``Directive``.
    This intentionally reuses Pulpo's existing non-broadening derivation rules;
    it does not provide a chat-to-root-policy path.
    """

    candidate_id: str
    source_digest: str
    interpreter_id: str
    interpreter_version: str
    proposed_issuer_authority_id: str
    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int
    issued_at_ns: int
    expires_at_ns: int
    directive_version: int = 1
    identity_context_hash: str | None = None
    unresolved_references: tuple[str, ...] = ()
    schema: str = _CANDIDATE_SCHEMA
    source_type: str = field(init=False, default=_SOURCE_TYPE)
    authority_effect: str = field(init=False, default="none")
    canonical_state_mutation: bool = field(init=False, default=False)
    governed_effect: str = field(init=False, default="none")

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.candidate_id, "candidate_id"),
            (self.interpreter_id, "interpreter_id"),
            (self.interpreter_version, "interpreter_version"),
            (self.proposed_issuer_authority_id, "proposed_issuer_authority_id"),
            (self.principal, "principal"),
        ):
            _require_text(value, field_name)
        _require_digest(self.source_digest, "source_digest")
        if self.identity_context_hash is not None:
            _require_digest(self.identity_context_hash, "identity_context_hash")
        if self.schema != _CANDIDATE_SCHEMA:
            raise ValueError("candidate_schema_invalid")
        if isinstance(self.directive_version, bool) or not isinstance(self.directive_version, int):
            raise ValueError("directive_version_invalid")
        if self.directive_version <= 0:
            raise ValueError("directive_version_invalid")
        if isinstance(self.max_cost, bool) or not isinstance(self.max_cost, int) or self.max_cost < 0:
            raise ValueError("candidate_max_cost_invalid")
        if (
            isinstance(self.issued_at_ns, bool)
            or not isinstance(self.issued_at_ns, int)
            or isinstance(self.expires_at_ns, bool)
            or not isinstance(self.expires_at_ns, int)
            or self.issued_at_ns <= 0
            or self.expires_at_ns <= self.issued_at_ns
        ):
            raise ValueError("candidate_time_bounds_invalid")
        if not isinstance(self.allowed_actions, frozenset) or not self.allowed_actions:
            raise ValueError("candidate_actions_invalid")
        if any(
            not isinstance(action, str) or not action or action != action.strip()
            for action in self.allowed_actions
        ):
            raise ValueError("candidate_actions_invalid")
        if not isinstance(self.resource_prefixes, tuple) or not self.resource_prefixes:
            raise ValueError("candidate_resources_invalid")
        if any(
            not isinstance(prefix, str) or not prefix or prefix != prefix.strip()
            for prefix in self.resource_prefixes
        ):
            raise ValueError("candidate_resources_invalid")
        if not isinstance(self.unresolved_references, tuple):
            raise ValueError("candidate_unresolved_references_invalid")
        if any(
            not isinstance(reference, str) or not reference or reference != reference.strip()
            for reference in self.unresolved_references
        ):
            raise ValueError("candidate_unresolved_references_invalid")

        object.__setattr__(self, "resource_prefixes", tuple(sorted(set(self.resource_prefixes))))
        object.__setattr__(
            self,
            "unresolved_references",
            tuple(sorted(set(self.unresolved_references))),
        )

    @property
    def candidate_hash(self) -> str:
        payload = asdict(self)
        payload["allowed_actions"] = sorted(self.allowed_actions)
        return sha256(_canonical(payload)).hexdigest()

    @property
    def admissible(self) -> bool:
        return not self.unresolved_references

    @property
    def derived_directive_id(self) -> str:
        """Bind source/proposal provenance into the eventual directive identity."""

        return f"conversation:{self.candidate_id}:{self.candidate_hash}"

    def materialize_narrowed_directive(self, parent: Directive) -> Directive:
        """Return an exact child directive only when the candidate narrows parent.

        Materialization is not activation. The returned ``Directive`` is still
        non-authoritative until the existing ``DirectiveAuthorityController``
        separately admits it through Pulpo's canonical approval path.
        """

        if not isinstance(parent, Directive):
            raise TypeError("parent directive required")
        if self.unresolved_references:
            raise ConversationDirectiveCandidateError("candidate_ambiguity_unresolved")

        child = Directive(
            directive_id=self.derived_directive_id,
            version=self.directive_version,
            issuer_authority_id=self.proposed_issuer_authority_id,
            principal=self.principal,
            allowed_actions=self.allowed_actions,
            resource_prefixes=self.resource_prefixes,
            max_cost=self.max_cost,
            issued_at_ns=self.issued_at_ns,
            expires_at_ns=self.expires_at_ns,
            parent_directive_hash=parent.directive_hash,
        )
        failure = child.derivation_failure(parent)
        if failure is not None:
            raise ConversationDirectiveCandidateError(failure)
        return child
