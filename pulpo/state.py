"""Canonical kernel state backends.

The state backend persists replay guards, one-use permits, directives, and the
audit chain for the existing governance kernel. It is storage for that kernel,
not another router, policy engine, or evidence ledger.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from os import PathLike
import sqlite3
from threading import RLock
from typing import Any, Callable, Protocol
from urllib.parse import quote as _url_quote


# Reuse the unchanged encoder configuration; per-call state stays in encode().
_CANONICAL_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"))


def _canonical(value: Any) -> bytes:
    return _CANONICAL_ENCODER.encode(value).encode()


class AuditSigner:
    """HMAC-SHA256 signer/verifier for audit records (Phase 2, Item 1).

    One signer per deployment, keyed by a dedicated ``audit-secret``
    that is deliberately NOT the kernel secret: a single theft must not
    yield both permit minting and undetectable history forgery. The
    signature covers the record's own ``hash`` and is stored as a
    sibling field, excluded from the hashed body — the exact pattern
    ``AuditAnchor`` uses (``signing_payload()`` excludes ``signature``).
    The field is algorithm-agile: a future Ed25519 signer can replace
    this class behind the same record shape without changing the chain
    math. Verification is constant-time; a missing, non-string, or
    malformed signature never verifies.
    """

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("audit secret must be non-empty")
        self._secret = secret

    def sign(self, record_hash: str) -> str:
        if not isinstance(record_hash, str):
            raise TypeError("record hash must be a string")
        return hmac.new(self._secret, record_hash.encode("utf-8"), sha256).hexdigest()

    def verify(self, record_hash: str, signature: Any) -> bool:
        if not isinstance(signature, str) or not signature:
            return False
        try:
            expected = self.sign(record_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, signature)


def _audit_record(previous_hash: str, event: str, payload: dict[str, Any], timestamp_ns: int, signer: AuditSigner | None = None) -> dict[str, Any]:
    body = {"event": event, "payload": payload, "previous_hash": previous_hash, "timestamp_ns": timestamp_ns}
    record = {**body, "hash": sha256(_canonical(body)).hexdigest()}
    if signer is not None:
        # The signature is computed over the record hash and stored as a
        # sibling field: it is NOT part of the hashed body, so the
        # unkeyed chain math is unchanged and old verifiers recomputing
        # the body still agree on the hash. Verification of the
        # signature is the kernel's job (verify_audit), not this
        # constructor's.
        record["signature"] = signer.sign(record["hash"])
    return record


@dataclass(frozen=True)
class ApprovalUse:
    approval_id: str
    nonce: str
    audit_payload: dict[str, Any]
    ceremony_evidence_id: str | None = None


@dataclass(frozen=True)
class LeaseIssuance:
    """The governed facts of one kernel lease issuance.

    A lease (canonical Lease port, PR 1) is recorded atomically with
    its directive binding at issuance — unlike a permit, whose
    binding is a separate governed step, a lease's binding is
    intrinsic: the artifact authorizes bounded physical actuation
    under exactly one directive, and an unbound lease is precisely
    the Autonomous shape this port exists to retire. The store
    records the binding, the signed expiry, the command budget, the
    sequence floor, and the mandatory safe fallback in the same
    transition that records the issuance, so the consume-time checks
    below are computed from governed records, never from quantities
    a caller presents later.
    """

    lease_digest: str
    binding: DirectivePermitBinding
    expires_at_ns: int
    max_commands: int
    sequence_floor: int
    safe_fallback: str

    def audit_payload(self) -> dict[str, Any]:
        return {
            "lease_digest": self.lease_digest,
            **self.binding.audit_payload(),
            "expires_at_ns": self.expires_at_ns,
            "max_commands": self.max_commands,
            "sequence_floor": self.sequence_floor,
            "safe_fallback": self.safe_fallback,
        }


@dataclass
class _LeaseEntry:
    """Mutable consume-side counters for one issued lease (in-memory)."""

    lease_digest: str
    intent_hash: str
    binding: DirectivePermitBinding
    expires_at_ns: int
    max_commands: int
    sequence_floor: int
    safe_fallback: str
    commands_used: int = 0
    last_sequence: int | None = None


@dataclass(frozen=True)
class DirectivePermitBinding:
    directive_id: str
    version: int
    directive_hash: str
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None = None
    # Cumulative budget (kernel build item #1): when the governing
    # directive carries an aggregate budget, the projection records
    # the evaluated intent's budget facts on the binding at issuance.
    # The consume-time check-and-debit is computed from this governed
    # record — never from a quantity the caller presents at release
    # time. All three stay None for permits under budget-less
    # directives, and the audit payload below is then byte-identical
    # to the pre-budget shape.
    budget_principal: str | None = None
    budget_session_id: str | None = None
    budget_cost: int | None = None

    def audit_payload(self) -> dict[str, Any]:
        payload = {
            "directive_id": self.directive_id,
            "directive_version": self.version,
            "directive_hash": self.directive_hash,
            "directive_issued_at_ns": self.issued_at_ns,
            "directive_expires_at_ns": self.expires_at_ns,
        }
        if self.parent_directive_hash is not None:
            payload["parent_directive_hash"] = self.parent_directive_hash
        if self.budget_cost is not None:
            payload["budget_principal"] = self.budget_principal
            payload["budget_session_id"] = self.budget_session_id
            payload["budget_cost"] = self.budget_cost
        return payload


_BUDGET_SCOPE_COMPONENTS = frozenset({"directive", "principal", "session"})


@dataclass(frozen=True)
class DirectiveBudget:
    """One directive's aggregate (cumulative) budget policy.

    ``ceiling`` is the maximum total cost consumable under the
    budget, in the same units as ``Intent.cost``. ``scope`` names the
    bucket the total accumulates over: a non-empty combination of
    ``directive``, ``principal``, and ``session`` that always
    includes ``directive`` (a bucket is owned by exactly one
    directive definition, so its ceiling is never ambiguous).
    ``session_reset`` states whether opening a new session starts a
    fresh allowance: it must agree with the scope — a scope that
    includes ``session`` gives every session its own bucket, which
    IS a reset, and the policy says so; a scope without ``session``
    shares one bucket across sessions, which is no reset, and the
    policy says that too. A disagreement is a malformed policy and
    fails closed here, at construction, identically everywhere the
    policy is read. There is no silent reset.
    """

    ceiling: int
    scope: tuple[str, ...]
    session_reset: bool

    def __post_init__(self) -> None:
        if isinstance(self.ceiling, bool) or not isinstance(self.ceiling, int) or self.ceiling < 0:
            raise ValueError("directive budget ceiling is invalid")
        if not isinstance(self.session_reset, bool):
            raise ValueError("directive budget session_reset must be boolean")
        scope = tuple(self.scope)
        if (
            not scope
            or len(set(scope)) != len(scope)
            or not set(scope) <= _BUDGET_SCOPE_COMPONENTS
        ):
            raise ValueError("directive budget scope is invalid")
        if "directive" not in scope:
            raise ValueError("directive budget scope must include the directive")
        if ("session" in scope) != self.session_reset:
            raise ValueError("directive budget session reset must match its scope")
        object.__setattr__(self, "scope", scope)


def budget_scope_key(
    scope: tuple[str, ...],
    *,
    directive_id: str,
    version: int,
    principal: str,
    session_id: str,
) -> str:
    """The canonical ledger key for one budget bucket.

    Built as a hash of the canonical JSON of exactly the components
    the scope names, so caller-controlled principal/session strings
    cannot collide buckets through separator injection, and a
    component the scope does not name cannot split the bucket.
    """

    components: dict[str, Any] = {}
    for component in scope:
        if component == "directive":
            components["directive"] = f"{directive_id}:{version}"
        elif component == "principal":
            components["principal"] = principal
        elif component == "session":
            components["session"] = session_id
        else:
            raise ValueError("unknown budget scope component")
    return "budget:" + sha256(_canonical(components)).hexdigest()


def _binding_carries_budget_facts(binding: DirectivePermitBinding) -> bool:
    """Whether a binding claims any budget facts at all.

    The projection records all three facts together, and only for
    permits under a budgeted directive, so a binding carrying any
    of them was issued against a budget policy. If no policy is
    then found in the store at consume time, the policy is MISSING
    (deleted row, partial restore) — the consumption must fail
    closed with ``budget_policy_missing``, never spend against an
    unrecorded mandate.
    """

    return (
        binding.budget_cost is not None
        or binding.budget_principal is not None
        or binding.budget_session_id is not None
    )


def _budget_scope_key_for(
    budget: DirectiveBudget,
    binding: DirectivePermitBinding,
    *,
    directive_id: str | None = None,
    version: int | None = None,
) -> tuple[str | None, str | None]:
    """(failure_status, scope_key) for a bound permit's budget facts.

    Exactly one element of the pair is set: a failure status when
    the binding's recorded budget facts are missing or malformed —
    the consumption then fails closed, because a budgeted
    directive's permit may not spend against a debit the backend
    cannot compute — or the bucket key when the facts are usable.

    The bucket's directive component names the directive that OWNS
    the budget: by default the binding's own directive; for a
    budgeted ancestor reached through the lineage walk, the
    ancestor's identity is passed explicitly. The principal and
    session components always resolve from the permit's recorded
    facts — the ancestor's scope definition decides which of them
    name its bucket.
    """

    if (
        binding.budget_cost is None
        or binding.budget_principal is None
        or binding.budget_session_id is None
    ):
        return "budget_context_missing", None
    if (
        isinstance(binding.budget_cost, bool)
        or not isinstance(binding.budget_cost, int)
        or binding.budget_cost < 0
        or not isinstance(binding.budget_principal, str)
        or not binding.budget_principal
        or not isinstance(binding.budget_session_id, str)
        or not binding.budget_session_id
    ):
        return "budget_context_invalid", None
    return None, budget_scope_key(
        budget.scope,
        directive_id=binding.directive_id if directive_id is None else directive_id,
        version=binding.version if version is None else version,
        principal=binding.budget_principal,
        session_id=binding.budget_session_id,
    )


def _budget_lineage_ancestors(
    binding: DirectivePermitBinding,
    resolve_identity: Callable[[str], "tuple[str, int] | None"],
    parent_hash_of: Callable[[str, int], "str | None"],
) -> tuple[list[tuple[str, int]], bool]:
    """The derivation lineage above a bound permit's directive.

    Returns (ancestors, complete): the (directive_id, version) of
    every ancestor from the nearest parent upward, and whether the
    chain was followed all the way to a root. Activation requires
    the parent to pre-exist and directive records are immutable,
    so a governed store's chains are finite and acyclic; the walk
    still stops incomplete on a missing record or a cycle (the
    store was then written out of band), and the caller must not
    enforce a partial lineage as if it were whole.
    """

    ancestors: list[tuple[str, int]] = []
    seen = {binding.directive_hash}
    parent_hash = binding.parent_directive_hash
    while parent_hash is not None:
        if parent_hash in seen:
            return ancestors, False
        seen.add(parent_hash)
        identity = resolve_identity(parent_hash)
        if identity is None:
            return ancestors, False
        ancestors.append(identity)
        parent_hash = parent_hash_of(identity[0], identity[1])
    return ancestors, True


def _budget_from_row(ceiling: Any, scope_json: Any, session_reset: Any) -> DirectiveBudget | None:
    """Rebuild a stored budget policy, or None when the row is malformed.

    The SQLite backend stores the policy as (ceiling, scope JSON,
    reset flag); a row a direct store writer corrupted must not be
    guessed at — None here makes the consume path refuse with
    ``budget_policy_invalid``, failing closed.
    """

    try:
        scope = json.loads(scope_json)
        if not isinstance(scope, list) or session_reset not in (0, 1):
            return None
        return DirectiveBudget(
            ceiling=ceiling,
            scope=tuple(scope),
            session_reset=bool(session_reset),
        )
    except (TypeError, ValueError):
        return None


def _directive_budget(directive: Any) -> DirectiveBudget | None:
    """The budget policy a directive object carries, or None.

    Read through getattr so directive-shaped values without the
    budget fields keep their pre-budget behavior. A present but
    malformed policy raises (DirectiveBudget validation), so
    activation fails closed instead of recording a directive whose
    budget the backends would later have to guess at.
    """

    ceiling = getattr(directive, "aggregate_budget", None)
    if ceiling is None:
        return None
    return DirectiveBudget(
        ceiling=ceiling,
        scope=tuple(getattr(directive, "budget_scope", ("directive",))),
        session_reset=getattr(directive, "budget_session_reset", False),
    )


@dataclass(frozen=True)
class VerifiedAuthorityEvidence:
    """Typed record that directive authority was verified (Phase 2, Item 3A).

    Before Item 3A, ``activate_directive``/``revoke_directive`` accepted
    ``authority_evidence`` as an opaque dict, verified against nothing:
    any holder of the state handle could activate a directive with
    ``{"approver": "no-one", "evidence": "invented"}`` and the invented
    directive then gated real kernel spends (design repro 3, part B).
    The state layer now requires this exact type and cross-checks its
    binding fields against the directive being activated or revoked, so
    a bare dict — or a wrapper naming a different directive — is
    refused at the storage surface itself.

    In practice the only production construction site is
    ``DirectiveAuthorityController``, which builds this value only after
    the kernel has verified the approval envelope and consumed the
    one-use authority permit (the same discipline ``ApprovalUse``
    carries for permit issuance). Honest boundary: this is a library
    type, not a capability — a determined in-process caller can
    construct one with fabricated fields, exactly as it can construct
    a state backend directly. Item 3A makes fabrication a deliberate,
    greppable construction of a named type instead of an anonymous
    dict; process-boundary enforcement is Item 3B (Phase 3).
    """

    operation: str
    directive_id: str
    directive_version: int
    directive_hash: str
    parent_directive_hash: str | None
    authority_id: str
    approval_id: str
    envelope_hash: str
    intent_hash: str
    policy_hash: str

    def __post_init__(self) -> None:
        if self.operation not in ("activate_directive", "revoke_directive"):
            raise ValueError("authority evidence operation is unsupported")
        if not self.directive_id or self.directive_version <= 0:
            raise ValueError("authority evidence directive identity is invalid")
        for value in (
            self.directive_hash,
            self.authority_id,
            self.approval_id,
            self.envelope_hash,
            self.intent_hash,
            self.policy_hash,
        ):
            if not isinstance(value, str) or not value:
                raise ValueError("authority evidence fields must be non-empty")

    def audit_payload(self) -> dict[str, Any]:
        """The exact dict shape recorded in the audit chain.

        Byte-identical to the pre-3A evidence dict the controller
        built, so existing chains and their readers see no format
        change — only the surface that accepts it changed.
        """

        return {
            "operation": self.operation,
            "directive_id": self.directive_id,
            "directive_version": self.directive_version,
            "directive_hash": self.directive_hash,
            "parent_directive_hash": self.parent_directive_hash,
            "authority_id": self.authority_id,
            "approval_id": self.approval_id,
            "envelope_hash": self.envelope_hash,
            "intent_hash": self.intent_hash,
            "policy_hash": self.policy_hash,
        }


def _require_verified_evidence(
    authority_evidence: object,
    *,
    operation: str,
    directive_id: str,
    version: int,
    directive_hash: str,
    parent_directive_hash: str | None = None,
    check_parent: bool = False,
) -> VerifiedAuthorityEvidence:
    """Fail closed unless ``authority_evidence`` is verified-typed and bound.

    The type requirement is exact (``type(...) is``), following the
    repo's canonical-type precedent: a dict, a subclass, or any other
    mapping-shaped value is refused. The binding cross-checks are the
    ones the state layer can perform itself — the evidence must name
    the operation and the exact directive the call is mutating.
    """

    if type(authority_evidence) is not VerifiedAuthorityEvidence:
        raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")
    evidence = authority_evidence
    if (
        evidence.operation != operation
        or evidence.directive_id != directive_id
        or evidence.directive_version != version
        or evidence.directive_hash != directive_hash
        or (check_parent and evidence.parent_directive_hash != parent_directive_hash)
    ):
        raise ValueError("authority evidence does not match the directive")
    return evidence


class KernelState(Protocol):
    @property
    def audit(self) -> list[dict[str, Any]]: ...
    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None: ...
    def ceremony_replay_reason(self, evidence_id: str) -> str | None: ...
    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None, expires_at_ns: int | None = None) -> str | None: ...
    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None: ...
    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool: ...
    def issue_lease(self, lease: str, intent_hash: str, issuance: LeaseIssuance, timestamp_ns: int, approval: ApprovalUse | None = None, decision_reason: str = "policy_satisfied") -> str | None: ...
    def consume_lease_command(self, lease: str, lease_digest: str, intent_hash: str, sequence: int, timestamp_ns: int) -> bool: ...
    def budget_spent(self, scope_key: str) -> int: ...
    def activate_directive(self, directive: Any, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None: ...
    def revoke_directive(self, directive_id: str, version: int, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None: ...
    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str: ...
    def directive_hash_status(self, directive_hash: str) -> str: ...
    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None: ...
    def append_unique(self, event: str, identity_field: str, identity_value: Any, payload: dict[str, Any], timestamp_ns: int) -> dict[str, Any] | None: ...


class InMemoryKernelState:
    def __init__(self, audit_signer: AuditSigner | None = None, legacy_audit_records: int = 0) -> None:
        # Audit signing (Phase 2, Item 1): when a signer is supplied,
        # every appended record carries an HMAC over its hash. When no
        # signer is supplied the backend stays in legacy mode — records
        # are unsigned and verification is the unkeyed chain alone — so
        # direct construction keeps its exact pre-signing behavior.
        # ``legacy_audit_records`` is the count of leading records that
        # predate enablement: they verify legacy-style and are reported
        # as an unsigned prefix. The enablement itself is recorded in
        # deployment config outside the state file (ops), never here.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records
        self._issued: dict[str, str] = {}
        # Token v2 (Phase 2, Item 4): the expiry recorded at issuance,
        # re-checked at consume as the second layer behind the kernel's
        # signed-expiry check. Permits the kernel issues always record
        # one; the store enforces what was recorded. (The v1 cutover
        # itself is the kernel's format check — the store cannot
        # distinguish a v1-era row from a direct store issuance, and
        # store rows are writer-controlled in any case.)
        self._permit_expiry: dict[str, int] = {}
        self._spent: set[str] = set()
        self._approval_ids: set[str] = set()
        self._approval_nonces: set[str] = set()
        self._ceremony_evidence_ids: set[str] = set()
        self._directives: dict[tuple[str, int], tuple[str, bool]] = {}
        # Cumulative budget (kernel build item #1): the budget policy
        # recorded at directive activation, and the per-bucket totals
        # debited inside consume_permit's transition. Both live in
        # this backend's canonical store — there is no second ledger.
        self._directive_budgets: dict[tuple[str, int], DirectiveBudget] = {}
        self._budget_spent: dict[str, int] = {}
        # Derivation lineage (Codex P1(i) fix on PR #369): each
        # directive's parent link, recorded at activation, so
        # consume_permit can walk the lineage and charge budgeted
        # ancestors. Recorded for every activation (None for a
        # root); the directive records themselves stay immutable.
        self._directive_parents: dict[tuple[str, int], str | None] = {}
        self._permit_directives: dict[str, DirectivePermitBinding] = {}
        # Leases (canonical Lease port, PR 1): issued lease tokens and
        # their consume-side counters, recorded at issuance inside the
        # same locked transitions as permits — there is no second
        # ledger; the audit appends below are the evidence.
        self._leases: dict[str, _LeaseEntry] = {}
        self._audit: list[dict[str, Any]] = []
        self._audit_lock = RLock()

    @property
    def audit(self) -> list[dict[str, Any]]:
        # Return detached deep copies, copied under the audit lock, matching
        # the SQLite backend (which rebuilds fresh records from rows on every
        # read). Returning the live list let any holder of the kernel delete
        # records, append forged ones, or rewrite a record's payload in the
        # stored trail through the read path alone.
        # Regression: tests/test_inmemory_audit_detached_copies.py.
        with self._audit_lock:
            return deepcopy(self._audit)

    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None:
        if approval_id in self._approval_ids: return "approval_id_replayed"
        if nonce in self._approval_nonces: return "approval_nonce_replayed"
        return None

    def ceremony_replay_reason(self, evidence_id: str) -> str | None:
        if evidence_id in self._ceremony_evidence_ids: return "ceremony_evidence_replayed"
        return None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None, expires_at_ns: int | None = None) -> str | None:
        # Serialize the whole check-and-record transition under the audit
        # lock (an RLock; append() re-enters it). The SQLite backend gets
        # the same atomicity from its BEGIN IMMEDIATE transaction: without
        # it, two concurrent issuances can both observe an approval or a
        # ceremony evidence id as unconsumed before either records it,
        # voiding single-use. Regression: tests/test_inmemory_ceremony_concurrency.py.
        with self._audit_lock:
            if approval is not None:
                replay = self.approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self.ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._ceremony_evidence_ids.add(approval.ceremony_evidence_id)
                self._approval_ids.add(approval.approval_id); self._approval_nonces.add(approval.nonce)
                self.append("approval_verified", approval.audit_payload, timestamp_ns)
            self._issued[permit] = intent_hash
            if expires_at_ns is not None:
                self._permit_expiry[permit] = expires_at_ns
            self.append("decision", {"outcome": "allow", "reason": decision_reason, "intent_hash": intent_hash}, timestamp_ns)
            return None

    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None:
        # Serialized under the same lock as issue_permit/consume_permit:
        # the availability and directive-status checks must hold against
        # the same state the binding is recorded into.
        with self._audit_lock:
            if self._issued.get(permit) != intent_hash or permit in self._spent: raise ValueError("permit unavailable for directive binding")
            if permit in self._permit_directives: raise ValueError("permit directive binding is immutable")
            if self.directive_status(binding.directive_id, binding.version, binding.directive_hash) != "active": raise ValueError("directive is not active for permit binding")
            if binding.parent_directive_hash is not None and self.directive_hash_status(binding.parent_directive_hash) != "active": raise ValueError("parent directive is not active for permit binding")
            self._permit_directives[permit] = binding
            self.append("permit_bound_to_directive", {"intent_hash": intent_hash, **binding.audit_payload()}, timestamp_ns)

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        # Serialize the whole check-and-record transition under the audit
        # lock (an RLock; append() re-enters it), mirroring the SQLite
        # backend's BEGIN IMMEDIATE transaction and issue_permit above.
        # Without it, a revoke_directive completing mid-consume still
        # admitted against the pre-revocation status, and two concurrent
        # consumptions of one permit could both observe it unspent
        # before either recorded the spend, voiding single-use.
        # Regression: tests/test_inmemory_consume_concurrency.py.
        with self._audit_lock:
            valid = self._issued.get(permit) == intent_hash and permit not in self._spent
            binding = self._permit_directives.get(permit)
            payload: dict[str, Any] = {"intent_hash": intent_hash}
            if binding is not None:
                status = self.directive_status(binding.directive_id, binding.version, binding.directive_hash)
                if status == "active" and binding.parent_directive_hash is not None:
                    status = self.directive_hash_status(binding.parent_directive_hash)
                if status == "active" and not (binding.issued_at_ns <= timestamp_ns < binding.expires_at_ns): status = "directive_inactive"
                valid = valid and status == "active"
                payload.update(binding.audit_payload()); payload["directive_status"] = status
            if valid:
                # Token v2 second layer (Phase 2, Item 4): a recorded
                # expiry is re-checked here, so a caller holding the
                # state handle alone faces the same bound the kernel
                # enforces from the signed token.
                stored_expiry = self._permit_expiry.get(permit)
                if stored_expiry is not None and timestamp_ns >= stored_expiry:
                    valid = False
                    payload["permit_status"] = "permit_expired"
            # Cumulative budget (kernel build item #1): the decisive
            # check is HERE, inside the same locked transition that
            # spends the permit — an atomic check-and-debit. A
            # consumption that would cross the bucket's ceiling is
            # refused with the permit unspent and no debit taken; the
            # refusal is recorded in this same audit record under
            # budget_status, never as a bare silent False. Permits
            # under budget-less directives take none of this path and
            # their audit payloads are unchanged.
            #
            # Lineage (Codex P1(i) fix): derivation narrows a child
            # beneath its parent's ceiling, but the child's bucket
            # key names the child — without lineage charging, parent
            # and child each hold an independent allowance and the
            # lineage total multiplies past the ancestor's cap.
            # Every budgeted ancestor's bucket is therefore planned
            # against the same recorded facts and debited in this
            # same transition, all-or-nothing: every bucket is
            # checked before any is debited, and any failure — a
            # crossing bucket, an unresolvable scope, a lineage that
            # cannot be walked completely — refuses the whole
            # consumption with the permit unspent.
            budget_key: str | None = None
            budget_amount = 0
            budget_spent_before = 0
            lineage_entries: list[dict[str, Any]] = []
            lineage_debits: list[tuple[str, int]] = []
            if binding is not None:
                budget = self._directive_budgets.get((binding.directive_id, binding.version))
                facts = _binding_carries_budget_facts(binding)
                budget_failure: str | None = None
                if budget is None and facts:
                    # Codex P1(ii) fix: the binding carries budget
                    # facts but no policy is recorded for its
                    # directive (deleted entry, partial restore).
                    # A malformed policy already fails closed; a
                    # missing one must too — never spend against a
                    # mandate the backend cannot read.
                    budget_failure = "budget_policy_missing"
                if budget is not None:
                    payload["budget_scope"] = list(budget.scope)
                    payload["budget_ceiling"] = budget.ceiling
                    failure, key = _budget_scope_key_for(budget, binding)
                    if failure is not None:
                        budget_failure = failure
                    else:
                        budget_key = key
                        budget_amount = binding.budget_cost
                        budget_spent_before = self._budget_spent.get(budget_key, 0)
                        payload["budget_amount"] = budget_amount
                        payload["budget_spent_before"] = budget_spent_before
                ancestors, lineage_complete = _budget_lineage_ancestors(
                    binding,
                    self._directive_identity_for_hash,
                    lambda directive_id, version: self._directive_parents.get(
                        (directive_id, version)
                    ),
                )
                engaged = budget is not None or facts
                for ancestor_id, ancestor_version in ancestors:
                    ancestor_budget = self._directive_budgets.get(
                        (ancestor_id, ancestor_version)
                    )
                    if ancestor_budget is None:
                        continue
                    engaged = True
                    if budget_failure is not None:
                        continue
                    failure, key = _budget_scope_key_for(
                        ancestor_budget,
                        binding,
                        directive_id=ancestor_id,
                        version=ancestor_version,
                    )
                    if failure is not None:
                        budget_failure = failure
                        continue
                    spent_before = self._budget_spent.get(key, 0)
                    lineage_entries.append(
                        {
                            "directive_id": ancestor_id,
                            "directive_version": ancestor_version,
                            "budget_scope": list(ancestor_budget.scope),
                            "budget_ceiling": ancestor_budget.ceiling,
                            "budget_amount": binding.budget_cost,
                            "budget_spent_before": spent_before,
                        }
                    )
                    lineage_debits.append((key, spent_before))
                if not lineage_complete and engaged and budget_failure is None:
                    # A lineage that cannot be walked completely is
                    # never enforced partially: some ancestor above
                    # the break could carry a budget this consumption
                    # would silently escape.
                    budget_failure = "budget_lineage_unresolvable"
                if budget_failure is None:
                    if budget_key is not None and budget_spent_before + budget_amount > budget.ceiling:
                        budget_failure = "aggregate_budget_exceeded"
                    else:
                        for entry in lineage_entries:
                            if entry["budget_spent_before"] + entry["budget_amount"] > entry["budget_ceiling"]:
                                budget_failure = "aggregate_budget_exceeded"
                                break
                if lineage_entries:
                    payload["budget_lineage"] = lineage_entries
                if budget_failure is not None:
                    valid = False
                    payload["budget_status"] = budget_failure
                elif budget_key is not None:
                    payload["budget_status"] = "within_budget"
            if valid:
                self._spent.add(permit)
                if budget_key is not None:
                    self._budget_spent[budget_key] = budget_spent_before + budget_amount
                    payload["budget_spent"] = budget_spent_before + budget_amount
                for entry, (key, spent_before) in zip(lineage_entries, lineage_debits):
                    total = spent_before + entry["budget_amount"]
                    self._budget_spent[key] = total
                    entry["budget_spent"] = total
            self.append("permit_consumed" if valid else "permit_rejected", payload, timestamp_ns)
            return valid

    def issue_lease(self, lease: str, intent_hash: str, issuance: LeaseIssuance, timestamp_ns: int, approval: ApprovalUse | None = None, decision_reason: str = "policy_satisfied") -> str | None:
        # Mirrors issue_permit's locked transition: the approval
        # replay checks, the approval record, the lease record, and
        # the issuance audit record land atomically, so a lease can
        # never exist without its governed issuance record (and an
        # approval can never be spent twice minting leases).
        with self._audit_lock:
            if approval is not None:
                replay = self.approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self.ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._ceremony_evidence_ids.add(approval.ceremony_evidence_id)
                self._approval_ids.add(approval.approval_id); self._approval_nonces.add(approval.nonce)
                self.append("approval_verified", approval.audit_payload, timestamp_ns)
            if lease in self._leases: return "lease_token_replayed"
            self._leases[lease] = _LeaseEntry(
                lease_digest=issuance.lease_digest,
                intent_hash=intent_hash,
                binding=issuance.binding,
                expires_at_ns=issuance.expires_at_ns,
                max_commands=issuance.max_commands,
                sequence_floor=issuance.sequence_floor,
                safe_fallback=issuance.safe_fallback,
            )
            self.append("lease_issued", {"intent_hash": intent_hash, "reason": decision_reason, **issuance.audit_payload()}, timestamp_ns)
            return None

    def consume_lease_command(self, lease: str, lease_digest: str, intent_hash: str, sequence: int, timestamp_ns: int) -> bool:
        # The store layer of lease verification, serialized under the
        # same lock as consume_permit: the directive status, the
        # stored expiry (second layer behind the kernel's signed
        # expiry), the signed sequence floor and monotonicity, and
        # the command budget are checked and debited in one
        # transition, so two concurrent commands can never both
        # observe the same remaining budget or the same last
        # sequence. The kernel has already authenticated the token,
        # its signed expiry, the presenter, and the exact command
        # binding before this layer is consulted — but this surface
        # is itself a governed capability, reachable without the
        # kernel funnel, so the floor is enforced here too: a first
        # consume below the floor must not record consumption
        # evidence outside the lease's signed sequence bounds
        # (Codex P2 on PR #383).
        with self._audit_lock:
            entry = self._leases.get(lease)
            payload: dict[str, Any] = {"lease_digest": lease_digest, "intent_hash": intent_hash, "sequence": sequence}
            reason: str | None = None
            if entry is None:
                reason = "lease_not_issued"
            else:
                payload.update(entry.binding.audit_payload())
                if entry.lease_digest != lease_digest or entry.intent_hash != intent_hash:
                    reason = "lease_binding_mismatch"
                else:
                    status = self.directive_status(entry.binding.directive_id, entry.binding.version, entry.binding.directive_hash)
                    if status == "active" and entry.binding.parent_directive_hash is not None:
                        status = self.directive_hash_status(entry.binding.parent_directive_hash)
                    if status == "active" and not (entry.binding.issued_at_ns <= timestamp_ns < entry.binding.expires_at_ns):
                        status = "directive_inactive"
                    payload["directive_status"] = status
                    if status != "active":
                        reason = status
                    elif timestamp_ns >= entry.expires_at_ns:
                        reason = "lease_expired"
                        payload["lease_status"] = reason
                    elif sequence < entry.sequence_floor:
                        reason = "lease_sequence_below_floor"
                        payload["lease_status"] = reason
                    elif entry.last_sequence is not None and sequence <= entry.last_sequence:
                        reason = "lease_replayed"
                        payload["lease_status"] = reason
                    elif entry.commands_used >= entry.max_commands:
                        reason = "lease_budget_exhausted"
                        payload["lease_status"] = reason
            if reason is None:
                assert entry is not None
                entry.commands_used += 1
                entry.last_sequence = sequence
                payload["commands_used"] = entry.commands_used
                payload["commands_remaining"] = entry.max_commands - entry.commands_used
                self.append("lease_command_consumed", payload, timestamp_ns)
                return True
            payload["reason"] = reason
            self.append("lease_rejected", payload, timestamp_ns)
            if reason in ("lease_expired", "lease_budget_exhausted") and entry is not None:
                # Expiry and budget exhaustion terminate the lease
                # into its safe fallback (spec §6): the termination
                # is an actuation event, journaled here in the same
                # transition that refused the command — not a silent
                # lapse. Executing the fallback on a device is the
                # device layer's duty (PR 2); this record is the
                # governed evidence that termination was reached.
                self.append(
                    "lease_fallback",
                    {"lease_digest": lease_digest, "intent_hash": intent_hash, "safe_fallback": entry.safe_fallback, "cause": reason},
                    timestamp_ns,
                )
            return False

    def budget_spent(self, scope_key: str) -> int:
        with self._audit_lock:
            return self._budget_spent.get(scope_key, 0)

    def activate_directive(self, directive, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None:
        # Item 3A: the evidence gate runs before any mutation — a bare
        # dict or a wrapper bound to another directive never reaches
        # the immutability/parent checks, let alone the audit append.
        evidence = _require_verified_evidence(
            authority_evidence,
            operation="activate_directive",
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            parent_directive_hash=getattr(directive, "parent_directive_hash", None),
            check_parent=True,
        )
        # Cumulative budget: a malformed budget policy refuses the
        # activation here, before any mutation — the directive is
        # never recorded in a state whose budget the backends would
        # have to guess at.
        budget = _directive_budget(directive)
        # Serialized under the same lock: the immutability and parent
        # checks must hold against the state the activation records into.
        with self._audit_lock:
            key = (directive.directive_id, directive.version)
            if key in self._directives: raise ValueError("directive version is immutable")
            parent_hash = getattr(directive, "parent_directive_hash", None)
            if parent_hash is not None and self.directive_hash_status(parent_hash) != "active":
                raise ValueError("parent directive is not active for activation")
            self._directives[key] = (directive.directive_hash, False)
            self._directive_parents[key] = parent_hash
            if budget is not None:
                self._directive_budgets[key] = budget
            self.append("directive_activated", {"directive_id": directive.directive_id, "version": directive.version, "directive_hash": directive.directive_hash, "authority_evidence": evidence.audit_payload()}, timestamp_ns)

    def revoke_directive(self, directive_id: str, version: int, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None:
        # Item 3A: the type gate runs before any lookup or mutation.
        if type(authority_evidence) is not VerifiedAuthorityEvidence:
            raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")
        # Serialized under the same lock: the revocation mutation and its
        # audit append are one transition, atomic against consume_permit's
        # status read -- a revocation fully precedes or fully follows any
        # consumption, and never lands inside one.
        with self._audit_lock:
            key = (directive_id, version)
            if key not in self._directives: raise ValueError("directive version not found")
            digest, _ = self._directives[key]
            # The stored hash is known only after the lookup, so the
            # binding cross-check completes here, before the mutation.
            evidence = _require_verified_evidence(
                authority_evidence,
                operation="revoke_directive",
                directive_id=directive_id,
                version=version,
                directive_hash=digest,
            )
            self._directives[key] = (digest, True)
            self.append("directive_revoked", {"directive_id": directive_id, "version": version, "directive_hash": digest, "authority_evidence": evidence.audit_payload()}, timestamp_ns)

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        value = self._directives.get((directive_id, version))
        if value is None: return "directive_not_authorized"
        digest, revoked = value
        if digest != directive_hash: return "directive_version_mismatch"
        return "directive_revoked" if revoked else "active"

    def directive_hash_status(self, directive_hash: str) -> str:
        for digest, revoked in self._directives.values():
            if digest == directive_hash:
                return "directive_parent_revoked" if revoked else "active"
        return "directive_parent_not_authorized"

    def _directive_identity_for_hash(self, directive_hash: str) -> tuple[str, int] | None:
        # The (directive_id, version) a stored hash belongs to, for
        # the budget lineage walk. A directive hash binds its own
        # identity fields, so at most one record can match.
        for (directive_id, version), (digest, _revoked) in self._directives.items():
            if digest == directive_hash:
                return directive_id, version
        return None

    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        with self._audit_lock:
            previous = self._audit[-1]["hash"] if self._audit else "0" * 64
            # Detach the payload at write, matching the SQLite backend,
            # which serializes at write: embedding the caller's dict by
            # reference let a caller rewrite the stored record afterwards
            # by mutating its own dict, with no state call at all
            # (writer-custody Phase 1; diagnosis Repro C).
            # Regression: tests/test_writer_custody.py.
            self._audit.append(_audit_record(previous, event, deepcopy(payload), timestamp_ns, signer=self.audit_signer))

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        if not event or not identity_field or payload.get(identity_field) != identity_value:
            raise ValueError("unique audit identity invalid")
        with self._audit_lock:
            matches = [
                record["payload"]
                for record in self._audit
                if record.get("event") == event
                and isinstance(record.get("payload"), dict)
                and record["payload"].get(identity_field) == identity_value
            ]
            if len(matches) > 1:
                raise ValueError("unique audit identity ambiguous")
            if matches:
                # Detached copy, as on the SQLite backend (which returns a
                # freshly decoded payload): the caller must not be able to
                # rewrite the stored record through the returned payload.
                return deepcopy(matches[0])
            previous = self._audit[-1]["hash"] if self._audit else "0" * 64
            # Detached at write, as in append() above (diagnosis Repro C).
            self._audit.append(_audit_record(previous, event, deepcopy(payload), timestamp_ns, signer=self.audit_signer))
            return None


class SQLiteKernelState:
    def __init__(self, path: str | PathLike[str], audit_signer: AuditSigner | None = None, legacy_audit_records: int = 0, migrate_schema: bool = True) -> None:
        # Audit signing (Phase 2, Item 1): same contract as the
        # in-memory backend — a signer signs every appended record, no
        # signer means legacy unsigned mode. ``legacy_audit_records``
        # counts the leading pre-enablement records (see above).
        #
        # ``migrate_schema`` gates the schema migrations below. Mutating
        # opens take the default (True): a deployment created before a
        # column existed gains it on first mutating open. Read-only
        # projections MUST pass False: with it the state is opened
        # through a read-only connection and no DDL runs at all, so
        # inspecting a deployment can neither silently rewrite its
        # canonical state nor fail outright on a read-only mount (Codex
        # P1 on PR #357 — a projection open used to execute both ALTERs
        # below). The gate covers BOTH migrations, not just the new
        # signature column: the permit_directives migration is the
        # identical shape, and a pre-#355 deployment would fail
        # verification on a read-only mount through that ALTER alone.
        # The read path tolerates a missing signature column (see
        # ``audit``); permit_directives is never read by a projection,
        # and mutating opens always migrate before any read of it.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records
        self._migrate_schema = migrate_schema
        if migrate_schema:
            self._connection = sqlite3.connect(path)
        else:
            # mode=ro: the open itself must not require write access,
            # or a read-only mount fails before any statement runs.
            # The URI is quoted so deployment paths carrying "?" or "#"
            # cannot change the query string. A missing state file
            # fails to open here (fail closed) instead of being
            # silently created as an empty chain.
            self._connection = sqlite3.connect(
                f"file:{_url_quote(str(path), safe='/')}?mode=ro", uri=True
            )
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA synchronous = FULL")
        if migrate_schema:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)), expires_at_ns INTEGER);
                CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS ceremony_evidence (evidence_id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS directives (directive_id TEXT NOT NULL, version INTEGER NOT NULL, directive_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)), parent_directive_hash TEXT, PRIMARY KEY (directive_id, version));
                CREATE TABLE IF NOT EXISTS permit_directives (permit TEXT PRIMARY KEY REFERENCES permits(permit) ON DELETE CASCADE, directive_id TEXT NOT NULL, directive_version INTEGER NOT NULL, directive_hash TEXT NOT NULL, directive_issued_at_ns INTEGER NOT NULL, directive_expires_at_ns INTEGER NOT NULL, parent_directive_hash TEXT);
                CREATE TABLE IF NOT EXISTS directive_budgets (directive_id TEXT NOT NULL, version INTEGER NOT NULL, ceiling INTEGER NOT NULL, scope_json TEXT NOT NULL, session_reset INTEGER NOT NULL, PRIMARY KEY (directive_id, version));
                CREATE TABLE IF NOT EXISTS budget_spend (scope_key TEXT PRIMARY KEY, spent INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS leases (lease TEXT PRIMARY KEY, lease_digest TEXT NOT NULL, intent_hash TEXT NOT NULL, directive_id TEXT NOT NULL, directive_version INTEGER NOT NULL, directive_hash TEXT NOT NULL, directive_issued_at_ns INTEGER NOT NULL, directive_expires_at_ns INTEGER NOT NULL, parent_directive_hash TEXT, expires_at_ns INTEGER NOT NULL, max_commands INTEGER NOT NULL, commands_used INTEGER NOT NULL DEFAULT 0, sequence_floor INTEGER NOT NULL, last_sequence INTEGER, safe_fallback TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, hash TEXT NOT NULL, signature TEXT);
            """)
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permit_directives)").fetchall()}
            if "parent_directive_hash" not in columns:
                self._connection.execute("ALTER TABLE permit_directives ADD COLUMN parent_directive_hash TEXT")
            # The directives parent link (Codex P1(i) fix on PR
            # #369): same migration pattern. Existing directive rows
            # keep a NULL parent link — they predate lineage
            # recording, and no budgeted directive can exist among
            # them (budgets arrive with this build), so the consume
            # path's lineage walk ending at a NULL link is exact for
            # every lineage that can carry a budget.
            directive_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(directives)").fetchall()}
            if "parent_directive_hash" not in directive_columns:
                self._connection.execute("ALTER TABLE directives ADD COLUMN parent_directive_hash TEXT")
            # The permit_directives budget columns (kernel build item
            # #1): same migration pattern. Existing binding rows keep
            # NULL budget facts — they are permits bound under
            # budget-less directives (or before budgets existed), and
            # the consume path treats them accordingly.
            if "budget_cost" not in columns:
                self._connection.execute("ALTER TABLE permit_directives ADD COLUMN budget_principal TEXT")
                self._connection.execute("ALTER TABLE permit_directives ADD COLUMN budget_session_id TEXT")
                self._connection.execute("ALTER TABLE permit_directives ADD COLUMN budget_cost INTEGER")
            # The audit signature column (Phase 2, Item 1): deployments
            # created before it existed gain it on first mutating open,
            # following the permit_directives migration precedent above.
            # Existing records keep NULL signatures — they are the legacy
            # prefix, verified by hash alone until the deployment
            # enables signing.
            audit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(audit)").fetchall()}
            if "signature" not in audit_columns:
                self._connection.execute("ALTER TABLE audit ADD COLUMN signature TEXT")
            # The permits expiry column (Phase 2, Item 4): same migration
            # pattern. Existing permit rows keep a NULL expiry — they
            # are v1-era permits, refused at consume by the kernel's
            # format check (the cutover); the store enforces the expiry
            # recorded for v2 rows.
            permit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permits)").fetchall()}
            if "expires_at_ns" not in permit_columns:
                self._connection.execute("ALTER TABLE permits ADD COLUMN expires_at_ns INTEGER")
        # Whether the audit table carries a signature column, read once
        # at open: with migration it is always present; without it, a
        # legacy database reports False and the read/append paths below
        # adapt instead of assuming the column exists.
        audit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(audit)").fetchall()}
        self._audit_has_signature = "signature" in audit_columns
        # Same treatment for the permits expiry column: a legacy database
        # opened without migration reports False, and the consume path
        # then treats every permit as expiry-less — refused, never
        # admitted on a missing column.
        permit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permits)").fetchall()}
        self._permits_has_expiry = "expires_at_ns" in permit_columns
        # Same treatment for the budget surfaces (kernel build item
        # #1): a legacy database opened without migration has neither
        # the binding budget columns nor the budget tables. No
        # budgeted directive can exist in such a database — activation
        # under a budget requires a mutating open, which migrates —
        # so the consume path treats every permit there as
        # budget-less, exactly as it was before budgets existed.
        permit_directive_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permit_directives)").fetchall()}
        self._permit_directives_has_budget = "budget_cost" in permit_directive_columns
        # Same treatment for the directives parent link: a legacy
        # database opened without migration has no column, and the
        # lineage walk then ends at the binding's own parent —
        # exact for such a database, which holds no budgeted
        # directive (see the migration note above).
        directive_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(directives)").fetchall()}
        self._directives_has_parent = "parent_directive_hash" in directive_columns
        table_names = {row[0] for row in self._connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        self._has_budget_tables = "directive_budgets" in table_names and "budget_spend" in table_names
        # Same treatment for the leases table (canonical Lease port,
        # PR 1): a legacy database opened without migration has no
        # leases table. No lease can exist in such a database —
        # issuance requires a mutating open, which creates the
        # table — so the consume path treats every presented lease
        # there as not issued, exactly as it was before leases
        # existed, and issuance fails loudly (below).
        self._has_lease_table = "leases" in table_names

    @property
    def audit(self) -> list[dict[str, Any]]:
        # A legacy database opened without migration has no signature
        # column: read the records without it (signature None) rather
        # than failing the projection with "no such column".
        if self._audit_has_signature:
            rows = self._connection.execute("SELECT event, payload_json, previous_hash, timestamp_ns, hash, signature FROM audit ORDER BY sequence").fetchall()
        else:
            rows = self._connection.execute("SELECT event, payload_json, previous_hash, timestamp_ns, hash FROM audit ORDER BY sequence").fetchall()
            rows = [(event, payload_json, previous_hash, timestamp_ns, record_hash, None) for event, payload_json, previous_hash, timestamp_ns, record_hash in rows]
        records = []
        for event, payload_json, previous_hash, timestamp_ns, record_hash, signature in rows:
            record: dict[str, Any] = {"event": event, "payload": json.loads(payload_json), "previous_hash": previous_hash, "timestamp_ns": timestamp_ns, "hash": record_hash}
            if signature is not None:
                record["signature"] = signature
            records.append(record)
        return records

    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None: return self._approval_replay_reason(approval_id, nonce)
    def _approval_replay_reason(self, approval_id: str, nonce: str) -> str | None:
        row = self._connection.execute(
            """
            SELECT CASE
                WHEN EXISTS (SELECT 1 FROM approvals WHERE approval_id = ?) THEN 'approval_id_replayed'
                WHEN EXISTS (SELECT 1 FROM approvals WHERE nonce = ?) THEN 'approval_nonce_replayed'
                ELSE NULL
            END
            """,
            (approval_id, nonce),
        ).fetchone()
        return row[0] if row is not None else None

    def ceremony_replay_reason(self, evidence_id: str) -> str | None: return self._ceremony_replay_reason(evidence_id)
    def _ceremony_replay_reason(self, evidence_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM ceremony_evidence WHERE evidence_id = ?) THEN 'ceremony_evidence_replayed' ELSE NULL END",
            (evidence_id,),
        ).fetchone()
        return row[0] if row is not None else None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None, expires_at_ns: int | None = None) -> str | None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if approval is not None:
                replay = self._approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self._ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._connection.execute("INSERT INTO ceremony_evidence (evidence_id) VALUES (?)", (approval.ceremony_evidence_id,))
                self._connection.execute("INSERT INTO approvals (approval_id, nonce) VALUES (?, ?)", (approval.approval_id, approval.nonce))
            if expires_at_ns is not None and not self._permits_has_expiry:
                # Fail loudly rather than record a permit whose expiry
                # this schema cannot store (the Item 1 posture for a
                # signed append without the signature column). Mutating
                # opens always migrate, so this is reachable only on a
                # read-only open misused for issuance.
                raise RuntimeError("permits table has no expires_at_ns column; open with schema migration to issue permits")
            if self._permits_has_expiry:
                self._connection.execute("INSERT INTO permits (permit, intent_hash, expires_at_ns) VALUES (?, ?, ?)", (permit, intent_hash, expires_at_ns))
            else:
                self._connection.execute("INSERT INTO permits (permit, intent_hash) VALUES (?, ?)", (permit, intent_hash))
            if approval is not None: self._append("approval_verified", approval.audit_payload, timestamp_ns)
            self._append("decision", {"outcome": "allow", "reason": decision_reason, "intent_hash": intent_hash}, timestamp_ns)
        return None

    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute("SELECT intent_hash, spent FROM permits WHERE permit = ?", (permit,)).fetchone()
            if row is None or row[0] != intent_hash or row[1] != 0: raise ValueError("permit unavailable for directive binding")
            if self._connection.execute("SELECT 1 FROM permit_directives WHERE permit = ?", (permit,)).fetchone(): raise ValueError("permit directive binding is immutable")
            directive = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id = ? AND version = ?", (binding.directive_id, binding.version)).fetchone()
            if directive is None or directive[0] != binding.directive_hash or directive[1] != 0: raise ValueError("directive is not active for permit binding")
            if binding.parent_directive_hash is not None and self.directive_hash_status(binding.parent_directive_hash) != "active": raise ValueError("parent directive is not active for permit binding")
            if self._permit_directives_has_budget:
                self._connection.execute("INSERT INTO permit_directives (permit, directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash, budget_principal, budget_session_id, budget_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (permit, binding.directive_id, binding.version, binding.directive_hash, binding.issued_at_ns, binding.expires_at_ns, binding.parent_directive_hash, binding.budget_principal, binding.budget_session_id, binding.budget_cost))
            elif binding.budget_cost is not None:
                # Fail loudly rather than record a budgeted binding
                # whose facts this schema cannot store (the expiry
                # posture in issue_permit). Mutating opens always
                # migrate, so this is reachable only on a read-only
                # open misused for binding.
                raise RuntimeError("permit_directives table has no budget columns; open with schema migration to bind budgeted permits")
            else:
                self._connection.execute("INSERT INTO permit_directives (permit, directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash) VALUES (?, ?, ?, ?, ?, ?, ?)", (permit, binding.directive_id, binding.version, binding.directive_hash, binding.issued_at_ns, binding.expires_at_ns, binding.parent_directive_hash))
            self._append("permit_bound_to_directive", {"intent_hash": intent_hash, **binding.audit_payload()}, timestamp_ns)

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if self._permits_has_expiry:
                permit_row = self._connection.execute("SELECT intent_hash, spent, expires_at_ns FROM permits WHERE permit = ?", (permit,)).fetchone()
            else:
                # Unmigrated legacy schema: no expiry column exists, so
                # every row reads as carrying no recorded expiry.
                permit_row = self._connection.execute("SELECT intent_hash, spent FROM permits WHERE permit = ?", (permit,)).fetchone()
                if permit_row is not None:
                    permit_row = (permit_row[0], permit_row[1], None)
            valid = permit_row is not None and permit_row[0] == intent_hash and permit_row[1] == 0
            payload: dict[str, Any] = {"intent_hash": intent_hash}
            if self._permit_directives_has_budget:
                row = self._connection.execute("SELECT directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash, budget_principal, budget_session_id, budget_cost FROM permit_directives WHERE permit = ?", (permit,)).fetchone()
            else:
                # Unmigrated legacy schema: no budget columns exist,
                # so every binding reads as carrying no budget facts.
                row = self._connection.execute("SELECT directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash FROM permit_directives WHERE permit = ?", (permit,)).fetchone()
                if row is not None:
                    row = (row[0], row[1], row[2], row[3], row[4], row[5], None, None, None)
            budget_key: str | None = None
            budget_amount = 0
            budget_spent_before = 0
            lineage_entries: list[dict[str, Any]] = []
            lineage_debits: list[tuple[str, int]] = []
            if row is not None:
                binding = DirectivePermitBinding(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
                directive = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id = ? AND version = ?", (binding.directive_id, binding.version)).fetchone()
                if directive is None: status = "directive_not_authorized"
                elif directive[0] != binding.directive_hash: status = "directive_version_mismatch"
                elif directive[1] != 0: status = "directive_revoked"
                elif binding.parent_directive_hash is not None: status = self.directive_hash_status(binding.parent_directive_hash)
                else: status = "active"
                if status == "active" and not (binding.issued_at_ns <= timestamp_ns < binding.expires_at_ns): status = "directive_inactive"
                valid = valid and status == "active"
                payload.update(binding.audit_payload()); payload["directive_status"] = status
                # Cumulative budget (kernel build item #1): the
                # decisive check is HERE, inside the same BEGIN
                # IMMEDIATE transaction that spends the permit — an
                # atomic check-and-debit, mirroring the in-memory
                # backend. The debits themselves land below, only if
                # the spend lands, in this same transaction.
                #
                # Lineage (Codex P1(i) fix): every budgeted
                # ancestor's bucket is planned against the same
                # recorded facts and debited in this same
                # transaction, all-or-nothing — see the in-memory
                # backend for the full rationale.
                budget_failure: str | None = None
                facts = _binding_carries_budget_facts(binding)
                budget = None
                if self._has_budget_tables:
                    budget_row = self._connection.execute("SELECT ceiling, scope_json, session_reset FROM directive_budgets WHERE directive_id = ? AND version = ?", (binding.directive_id, binding.version)).fetchone()
                    if budget_row is not None:
                        budget = _budget_from_row(budget_row[0], budget_row[1], budget_row[2])
                        if budget is None:
                            budget_failure = "budget_policy_invalid"
                if budget is None and budget_failure is None and facts:
                    # Codex P1(ii) fix: the binding carries budget
                    # facts but no policy row is recorded for its
                    # directive (deleted row, partial restore). A
                    # malformed policy already fails closed; a
                    # missing one must too — never spend against a
                    # mandate the backend cannot read.
                    budget_failure = "budget_policy_missing"
                if budget is not None:
                    payload["budget_scope"] = list(budget.scope)
                    payload["budget_ceiling"] = budget.ceiling
                    failure, key = _budget_scope_key_for(budget, binding)
                    if failure is not None:
                        budget_failure = failure
                    else:
                        budget_key = key
                        budget_amount = binding.budget_cost
                        spent_row = self._connection.execute("SELECT spent FROM budget_spend WHERE scope_key = ?", (budget_key,)).fetchone()
                        budget_spent_before = spent_row[0] if spent_row is not None else 0
                        if isinstance(budget_spent_before, bool) or not isinstance(budget_spent_before, int) or budget_spent_before < 0:
                            # A corrupted ledger row is never
                            # guessed at: fail closed.
                            budget_key = None
                            budget_failure = "budget_ledger_invalid"
                        else:
                            payload["budget_amount"] = budget_amount
                            payload["budget_spent_before"] = budget_spent_before
                ancestors, lineage_complete = _budget_lineage_ancestors(
                    binding,
                    self._directive_identity_for_hash,
                    self._directive_parent_hash,
                )
                engaged = budget is not None or facts
                for ancestor_id, ancestor_version in ancestors:
                    ancestor_budget = None
                    if self._has_budget_tables:
                        ancestor_row = self._connection.execute("SELECT ceiling, scope_json, session_reset FROM directive_budgets WHERE directive_id = ? AND version = ?", (ancestor_id, ancestor_version)).fetchone()
                        if ancestor_row is None:
                            continue
                        engaged = True
                        ancestor_budget = _budget_from_row(ancestor_row[0], ancestor_row[1], ancestor_row[2])
                        if ancestor_budget is None:
                            if budget_failure is None:
                                budget_failure = "budget_policy_invalid"
                            continue
                    if ancestor_budget is None:
                        continue
                    engaged = True
                    if budget_failure is not None:
                        continue
                    failure, key = _budget_scope_key_for(
                        ancestor_budget,
                        binding,
                        directive_id=ancestor_id,
                        version=ancestor_version,
                    )
                    if failure is not None:
                        budget_failure = failure
                        continue
                    spent_row = self._connection.execute("SELECT spent FROM budget_spend WHERE scope_key = ?", (key,)).fetchone()
                    spent_before = spent_row[0] if spent_row is not None else 0
                    if isinstance(spent_before, bool) or not isinstance(spent_before, int) or spent_before < 0:
                        # A corrupted ledger row is never guessed
                        # at: fail closed, for an ancestor's bucket
                        # exactly as for the permit's own.
                        budget_failure = "budget_ledger_invalid"
                        continue
                    lineage_entries.append(
                        {
                            "directive_id": ancestor_id,
                            "directive_version": ancestor_version,
                            "budget_scope": list(ancestor_budget.scope),
                            "budget_ceiling": ancestor_budget.ceiling,
                            "budget_amount": binding.budget_cost,
                            "budget_spent_before": spent_before,
                        }
                    )
                    lineage_debits.append((key, spent_before))
                if not lineage_complete and engaged and budget_failure is None:
                    # A lineage that cannot be walked completely is
                    # never enforced partially: some ancestor above
                    # the break could carry a budget this consumption
                    # would silently escape.
                    budget_failure = "budget_lineage_unresolvable"
                if budget_failure is None:
                    if budget_key is not None and budget_spent_before + budget_amount > budget.ceiling:
                        budget_failure = "aggregate_budget_exceeded"
                    else:
                        for entry in lineage_entries:
                            if entry["budget_spent_before"] + entry["budget_amount"] > entry["budget_ceiling"]:
                                budget_failure = "aggregate_budget_exceeded"
                                break
                if lineage_entries:
                    payload["budget_lineage"] = lineage_entries
                if budget_failure is not None:
                    valid = False
                    payload["budget_status"] = budget_failure
                elif budget_key is not None:
                    payload["budget_status"] = "within_budget"
            if valid:
                # Token v2 second layer (Phase 2, Item 4): a recorded
                # expiry is re-checked here, mirroring the in-memory
                # backend.
                row_expiry = permit_row[2] if permit_row is not None else None
                if row_expiry is not None and timestamp_ns >= row_expiry:
                    valid = False
                    payload["permit_status"] = "permit_expired"
            if valid:
                cursor = self._connection.execute("UPDATE permits SET spent = 1 WHERE permit = ? AND intent_hash = ? AND spent = 0", (permit, intent_hash))
                valid = cursor.rowcount == 1
            if valid and budget_key is not None:
                self._connection.execute("INSERT INTO budget_spend (scope_key, spent) VALUES (?, ?) ON CONFLICT(scope_key) DO UPDATE SET spent = excluded.spent", (budget_key, budget_spent_before + budget_amount))
                payload["budget_spent"] = budget_spent_before + budget_amount
            if valid:
                # Lineage debits land in this same transaction, or
                # (when the consumption was refused above) none do.
                for entry, (key, spent_before) in zip(lineage_entries, lineage_debits):
                    total = spent_before + entry["budget_amount"]
                    self._connection.execute("INSERT INTO budget_spend (scope_key, spent) VALUES (?, ?) ON CONFLICT(scope_key) DO UPDATE SET spent = excluded.spent", (key, total))
                    entry["budget_spent"] = total
            self._append("permit_consumed" if valid else "permit_rejected", payload, timestamp_ns)
        return valid

    def issue_lease(self, lease: str, intent_hash: str, issuance: LeaseIssuance, timestamp_ns: int, approval: ApprovalUse | None = None, decision_reason: str = "policy_satisfied") -> str | None:
        if not self._has_lease_table:
            # Fail loudly rather than record a lease this schema
            # cannot store (the issue_permit expiry posture). Mutating
            # opens always create the table, so this is reachable only
            # on a read-only open misused for issuance.
            raise RuntimeError("leases table is missing; open with schema migration to issue leases")
        binding = issuance.binding
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if approval is not None:
                replay = self._approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self._ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._connection.execute("INSERT INTO ceremony_evidence (evidence_id) VALUES (?)", (approval.ceremony_evidence_id,))
                self._connection.execute("INSERT INTO approvals (approval_id, nonce) VALUES (?, ?)", (approval.approval_id, approval.nonce))
            existing = self._connection.execute("SELECT 1 FROM leases WHERE lease = ?", (lease,)).fetchone()
            if existing: return "lease_token_replayed"
            self._connection.execute(
                "INSERT INTO leases (lease, lease_digest, intent_hash, directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash, expires_at_ns, max_commands, commands_used, sequence_floor, last_sequence, safe_fallback) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, ?)",
                (lease, issuance.lease_digest, intent_hash, binding.directive_id, binding.version, binding.directive_hash, binding.issued_at_ns, binding.expires_at_ns, binding.parent_directive_hash, issuance.expires_at_ns, issuance.max_commands, issuance.sequence_floor, issuance.safe_fallback),
            )
            if approval is not None: self._append("approval_verified", approval.audit_payload, timestamp_ns)
            self._append("lease_issued", {"intent_hash": intent_hash, "reason": decision_reason, **issuance.audit_payload()}, timestamp_ns)
        return None

    def consume_lease_command(self, lease: str, lease_digest: str, intent_hash: str, sequence: int, timestamp_ns: int) -> bool:
        # Mirrors the in-memory backend inside one BEGIN IMMEDIATE
        # transaction: directive status, stored expiry, the signed
        # sequence floor and monotonicity, and the command-budget
        # check-and-debit are atomic against the row the debit lands
        # on. The floor is enforced at this surface for the same
        # reason as in the in-memory backend (Codex P2 on PR #383).
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = None
            if self._has_lease_table:
                row = self._connection.execute("SELECT lease_digest, intent_hash, directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash, expires_at_ns, max_commands, commands_used, sequence_floor, last_sequence, safe_fallback FROM leases WHERE lease = ?", (lease,)).fetchone()
            payload: dict[str, Any] = {"lease_digest": lease_digest, "intent_hash": intent_hash, "sequence": sequence}
            reason: str | None = None
            safe_fallback: str | None = None
            commands_used = 0
            max_commands = 0
            if row is None:
                reason = "lease_not_issued"
            else:
                (row_digest, row_intent_hash, d_id, d_version, d_hash, d_issued, d_expires, d_parent, row_expiry, max_commands, commands_used, sequence_floor, last_sequence, safe_fallback) = row
                binding = DirectivePermitBinding(d_id, d_version, d_hash, d_issued, d_expires, d_parent)
                payload.update(binding.audit_payload())
                if row_digest != lease_digest or row_intent_hash != intent_hash:
                    reason = "lease_binding_mismatch"
                else:
                    directive = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id = ? AND version = ?", (d_id, d_version)).fetchone()
                    if directive is None: status = "directive_not_authorized"
                    elif directive[0] != d_hash: status = "directive_version_mismatch"
                    elif directive[1] != 0: status = "directive_revoked"
                    elif d_parent is not None: status = self.directive_hash_status(d_parent)
                    else: status = "active"
                    if status == "active" and not (d_issued <= timestamp_ns < d_expires): status = "directive_inactive"
                    payload["directive_status"] = status
                    if status != "active":
                        reason = status
                    elif timestamp_ns >= row_expiry:
                        reason = "lease_expired"
                        payload["lease_status"] = reason
                    elif sequence < sequence_floor:
                        reason = "lease_sequence_below_floor"
                        payload["lease_status"] = reason
                    elif last_sequence is not None and sequence <= last_sequence:
                        reason = "lease_replayed"
                        payload["lease_status"] = reason
                    elif commands_used >= max_commands:
                        reason = "lease_budget_exhausted"
                        payload["lease_status"] = reason
            if reason is None:
                cursor = self._connection.execute("UPDATE leases SET commands_used = commands_used + 1, last_sequence = ? WHERE lease = ?", (sequence, lease))
                if cursor.rowcount != 1:
                    reason = "lease_not_issued"
                    payload["reason"] = reason
                    self._append("lease_rejected", payload, timestamp_ns)
                    return False
                payload["commands_used"] = commands_used + 1
                payload["commands_remaining"] = max_commands - (commands_used + 1)
                self._append("lease_command_consumed", payload, timestamp_ns)
                return True
            payload["reason"] = reason
            self._append("lease_rejected", payload, timestamp_ns)
            if reason in ("lease_expired", "lease_budget_exhausted") and safe_fallback is not None:
                # Spec §6 termination journaling, mirroring the
                # in-memory backend.
                self._append(
                    "lease_fallback",
                    {"lease_digest": lease_digest, "intent_hash": intent_hash, "safe_fallback": safe_fallback, "cause": reason},
                    timestamp_ns,
                )
            return False

    def budget_spent(self, scope_key: str) -> int:
        if not self._has_budget_tables:
            return 0
        row = self._connection.execute("SELECT spent FROM budget_spend WHERE scope_key = ?", (scope_key,)).fetchone()
        if row is None or isinstance(row[0], bool) or not isinstance(row[0], int):
            return 0
        return row[0]

    def activate_directive(self, directive, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None:
        # Item 3A: same evidence gate as the in-memory backend, before
        # the transaction opens — a refused activation writes nothing.
        evidence = _require_verified_evidence(
            authority_evidence,
            operation="activate_directive",
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            parent_directive_hash=getattr(directive, "parent_directive_hash", None),
            check_parent=True,
        )
        # Cumulative budget: same pre-mutation refusal as the
        # in-memory backend — a malformed policy writes nothing.
        budget = _directive_budget(directive)
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if self._connection.execute("SELECT 1 FROM directives WHERE directive_id=? AND version=?", (directive.directive_id, directive.version)).fetchone(): raise ValueError("directive version is immutable")
            parent_hash = getattr(directive, "parent_directive_hash", None)
            if parent_hash is not None:
                parent = self._connection.execute("SELECT revoked FROM directives WHERE directive_hash=?", (parent_hash,)).fetchone()
                if parent is None or parent[0] != 0:
                    raise ValueError("parent directive is not active for activation")
            if self._directives_has_parent:
                self._connection.execute("INSERT INTO directives (directive_id, version, directive_hash, parent_directive_hash) VALUES (?, ?, ?, ?)", (directive.directive_id, directive.version, directive.directive_hash, parent_hash))
            else:
                # Unmigrated legacy schema: no parent-link column
                # exists to record into (reachable only on a
                # read-only open misused for activation — mutating
                # opens always migrate).
                self._connection.execute("INSERT INTO directives (directive_id, version, directive_hash) VALUES (?, ?, ?)", (directive.directive_id, directive.version, directive.directive_hash))
            if budget is not None:
                self._connection.execute("INSERT INTO directive_budgets (directive_id, version, ceiling, scope_json, session_reset) VALUES (?, ?, ?, ?, ?)", (directive.directive_id, directive.version, budget.ceiling, _canonical(list(budget.scope)).decode(), 1 if budget.session_reset else 0))
            self._append("directive_activated", {"directive_id": directive.directive_id, "version": directive.version, "directive_hash": directive.directive_hash, "authority_evidence": evidence.audit_payload()}, timestamp_ns)

    def revoke_directive(self, directive_id: str, version: int, authority_evidence: VerifiedAuthorityEvidence, timestamp_ns: int) -> None:
        # Item 3A: the type gate runs before the transaction opens.
        if type(authority_evidence) is not VerifiedAuthorityEvidence:
            raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute("SELECT directive_hash FROM directives WHERE directive_id=? AND version=?", (directive_id, version)).fetchone()
            if row is None: raise ValueError("directive version not found")
            # Binding cross-check against the stored hash, before the
            # mutation (mirrors the in-memory backend).
            evidence = _require_verified_evidence(
                authority_evidence,
                operation="revoke_directive",
                directive_id=directive_id,
                version=version,
                directive_hash=row[0],
            )
            self._connection.execute("UPDATE directives SET revoked=1 WHERE directive_id=? AND version=?", (directive_id, version))
            self._append("directive_revoked", {"directive_id": directive_id, "version": version, "directive_hash": row[0], "authority_evidence": evidence.audit_payload()}, timestamp_ns)

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        row = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id=? AND version=?", (directive_id, version)).fetchone()
        if row is None: return "directive_not_authorized"
        if row[0] != directive_hash: return "directive_version_mismatch"
        return "directive_revoked" if row[1] else "active"

    def directive_hash_status(self, directive_hash: str) -> str:
        row = self._connection.execute("SELECT revoked FROM directives WHERE directive_hash=?", (directive_hash,)).fetchone()
        if row is None: return "directive_parent_not_authorized"
        return "directive_parent_revoked" if row[0] else "active"

    def _directive_identity_for_hash(self, directive_hash: str) -> tuple[str, int] | None:
        # The (directive_id, version) a stored hash belongs to, for
        # the budget lineage walk. A directive hash binds its own
        # identity fields, so at most one row can match.
        row = self._connection.execute("SELECT directive_id, version FROM directives WHERE directive_hash = ?", (directive_hash,)).fetchone()
        if row is None:
            return None
        return row[0], row[1]

    def _directive_parent_hash(self, directive_id: str, version: int) -> str | None:
        # The parent link recorded at activation, for the budget
        # lineage walk. A schema without the column (a legacy
        # database opened without migration) reports no link: the
        # walk ends there, which is exact for such a database
        # because it can hold no budgeted directive.
        if not self._directives_has_parent:
            return None
        row = self._connection.execute("SELECT parent_directive_hash FROM directives WHERE directive_id = ? AND version = ?", (directive_id, version)).fetchone()
        return row[0] if row is not None else None

    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        # A signer configured over a database without a signature column
        # (a read-only open over a legacy database) must never silently
        # append unsigned: fail loudly before the write is attempted.
        # See _append for the same guard on the direct path.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE"); self._append(event, payload, timestamp_ns)

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        if not event or not identity_field or payload.get(identity_field) != identity_value:
            raise ValueError("unique audit identity invalid")
        # Same loud failure as append(): a signer over a database
        # without a signature column never appends unsigned.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            rows = self._connection.execute(
                "SELECT payload_json FROM audit WHERE event = ? ORDER BY sequence",
                (event,),
            ).fetchall()
            matches: list[dict[str, Any]] = []
            for (encoded,) in rows:
                candidate = json.loads(str(encoded))
                if isinstance(candidate, dict) and candidate.get(identity_field) == identity_value:
                    matches.append(candidate)
            if len(matches) > 1:
                raise ValueError("unique audit identity ambiguous")
            if matches:
                return matches[0]
            self._append(event, payload, timestamp_ns)
            return None

    def _append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        row = self._connection.execute("SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone(); previous = row[0] if row else "0" * 64
        record = _audit_record(previous, event, payload, timestamp_ns, signer=self.audit_signer)
        if not self._audit_has_signature and self.audit_signer is not None:
            # Opened without migration over a legacy database: a signer
            # configured here must never silently append unsigned — the
            # record would be refused at the next boot, bricking the
            # deployment (Codex P1 on PR #357). Fail loudly instead; the
            # caller re-opens with migration to add the column first.
            # (The same guard sits in append()/append_unique() so the
            # precise error fires before the connection's own write
            # refusal; this one covers direct _append callers.)
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
        self._connection.execute("INSERT INTO audit (event, payload_json, previous_hash, timestamp_ns, hash, signature) VALUES (?, ?, ?, ?, ?, ?)", (record["event"], _canonical(record["payload"]).decode(), record["previous_hash"], record["timestamp_ns"], record["hash"], record.get("signature")))

    def close(self) -> None: self._connection.close()
