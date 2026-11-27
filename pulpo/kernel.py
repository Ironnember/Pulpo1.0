"""Small, deterministic governance kernel with no runtime dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any, Callable, Protocol

from .authority import (
    ApprovalEnvelope,
    ApprovalVerifier,
    AuthorityTrust,
    DualControlTrust,
    PolicyEnvelope,
    PolicyEnvelopeV2,
    PolicyVeto,
)
from .ceremony import CeremonyEvidence, CeremonyTrust, CeremonyVerifier
from .state import (
    ApprovalUse,
    AuditSigner,
    DirectivePermitBinding,
    InMemoryKernelState,
    KernelState,
    LeaseIssuance,
    SQLiteKernelState,
    VerifiedAuthorityEvidence,
)


# Reuse the unchanged encoder configuration; per-call state stays in encode().
_CANONICAL_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"))

# Permit lifetime bounds (Phase 2, Item 4 — token v2). Every permit is
# issued with a signed expiry; the policy's ``max_permit_ttl_ns`` is both
# the lifetime stamped at issuance and the cap no issuance may exceed,
# and policy construction refuses a cap above the absolute ceiling, so
# no configuration of this library mints a longer-lived permit. The
# defaults are on the order of hours: a leaked or dormant permit file is
# worthless after its TTL instead of being spendable forever (the
# bearer-token repro: a bare copied token consumed ten years later).
DEFAULT_MAX_PERMIT_TTL_NS = 4 * 3600 * 1_000_000_000  # 4 hours
PERMIT_TTL_CEILING_NS = 24 * 3600 * 1_000_000_000  # 24 hours

# Presenter binding (Phase 3, Item 4B — token v3). A permit may be
# bound at issuance to one presenter identity; the token's signed
# claims then carry the SHA-256 of that identity, and consumption
# requires a proof, signed by the presenter's key over the exact
# token and intent, that the kernel verifies against the presenter
# verifier registered for that identity at construction. An unbound
# permit carries the hash of the empty string as its presenter
# claim and remains a bearer <redacted> exactly as in token v2 —
# unless the policy requires binding, in which case unbound permits
# are neither minted nor spent. Token v2 strings fail closed at
# consume under this format (the Item 4 hard-cutover precedent).
PRESENTER_PROOF_SCHEMA = "pulpo.presenter-proof.v1"
UNBOUND_PRESENTER_HASH = sha256(b"").hexdigest()

# Leases (canonical Lease port, PR 1). A lease is the physical
# analogue of a permit: a kernel-issued authorization artifact for
# bounded physical actuation, minted only from an evaluated intent
# under an active directive and always bound to a named device
# presenter. Its token follows the v3 discipline — the signed claims
# are ``digest:nonce:issued_at_ns:expires_at_ns:presenter_hash:
# signature`` — except the digest is the lease digest, a hash over
# every lease claim, so no claim (budget, expiry, fallback, binding)
# can be altered without invalidating the artifact. This is the
# binding the Autonomous physical layer lacked: its leases were
# locally mintable dataclasses any caller could construct.
LEASE_SCHEMA = "pulpo.lease.v1"
LEASE_COMMAND_SCHEMA = "pulpo.lease-command.v1"
LEASE_PROOF_SCHEMA = "pulpo.lease-proof.v1"


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value.isascii()
        and all(char in "0123456789abcdef" for char in value)
    )


class PresenterVerifier(Protocol):
    """Verification-only adapter for one presenter's key.

    Structurally the approval verifier's shape: the presenter signs
    ``GovernanceKernel.presenter_proof_payload(...)`` bytes with its
    own key; the kernel holds only verification. A deployment
    registers one verifier per presenter identity at kernel
    construction; the registry is deployment configuration, never
    policy, and never enters the audit chain.
    """

    def verify(self, payload: bytes, signature: str) -> bool:
        """Return true only for a proof signed by this presenter."""
        ...


def _token_time_ns(raw: str) -> int | None:
    """Parse a token time field, or None when it is not well-formed.

    Well-formed means ASCII digits only, at most 20 of them: nanosecond
    timestamps fit in 19 digits for any plausible date, and the bound
    keeps ``int()`` far below Python's integer-conversion limit.
    Unicode digit characters pass ``str.isdigit()`` but ``int()``
    rejects some of them — and an over-long field trips the conversion
    limit — so without this guard a malformed bearer token made
    ``consume`` raise instead of failing closed through the recorded
    rejection path (Codex P2 on PR #358, reproduced before the fix).
    """

    if not raw or len(raw) > 20 or not raw.isascii() or not raw.isdigit():
        return None
    return int(raw)


def _canonical(value: Any) -> bytes:
    return _CANONICAL_ENCODER.encode(value).encode()


def _observe_artifact_file(path: str | Path) -> tuple[str, str, int]:
    """Hash one stable regular file through a descriptor-bound observation.

    The resolved path, descriptor identity, byte count, size, and metadata
    must remain stable for the whole observation. A writer racing the read
    therefore cannot produce completion evidence for a mixed or replaced
    artifact snapshot. This is the single implementation: the target
    reconciliation projection delegates here, and the kernel's
    ``record_target_completion`` verb observes through it, so a caller can
    never substitute a self-asserted hash for an observed one.
    """

    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("artifact_not_found") from exc

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except FileNotFoundError as exc:
        raise ValueError("artifact_changed_during_observation") from exc
    except OSError as exc:
        raise ValueError("artifact_unreadable") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("artifact_not_file")
        if before.st_size <= 0:
            raise ValueError("artifact_empty")

        digest = sha256()
        bytes_read = 0
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                bytes_read += len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            path_after = os.stat(resolved, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("artifact_changed_during_observation") from exc

        stable_descriptor = (
            before.st_dev == after.st_dev
            and before.st_ino == after.st_ino
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
        )
        stable_path = (
            after.st_dev == path_after.st_dev
            and after.st_ino == path_after.st_ino
            and after.st_size == path_after.st_size
        )
        if bytes_read != before.st_size or not stable_descriptor or not stable_path:
            raise ValueError("artifact_changed_during_observation")

        return str(resolved), digest.hexdigest(), bytes_read
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Intent:
    principal: str
    action: str
    resource: str
    cost: int = 0
    session_id: str = "default"


@dataclass(frozen=True)
class LockedTarget:
    """Immutable proposed consequence recorded before authority evaluation.

    Locking a target creates no permit and has no authority effect.  The target
    hash binds the exact intent plus target identity, version, and lock time so a
    later interface can resolve a short command such as ``fire`` to one durable
    object before asking the kernel for an authorization decision.
    """

    target_id: str
    version: int
    intent: Intent
    created_at_ns: int
    schema: str = "pulpo.target.v0"

    def __post_init__(self) -> None:
        if not self.target_id or self.version <= 0 or self.created_at_ns <= 0:
            raise ValueError("target identity, version, and lock time must be valid")
        if self.schema != "pulpo.target.v0":
            raise ValueError("unsupported target schema")

    @property
    def target_hash(self) -> str:
        return sha256(
            _canonical(
                {
                    "schema": self.schema,
                    "target_id": self.target_id,
                    "version": self.version,
                    "intent": asdict(self.intent),
                    "created_at_ns": self.created_at_ns,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class TargetResolution:
    outcome: str
    reason: str
    target_id: str
    version: int
    expected_target_hash: str
    target: LockedTarget | None = None


@dataclass(frozen=True)
class AgentGrant:
    """Least-authority limits for one agent principal.

    Resource prefixes are namespaces such as ``repo:`` or ``evidence:``.  They
    are evaluated by the same kernel as every other policy condition; this is
    not a second agent router.
    """

    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int

    def __post_init__(self) -> None:
        if not self.principal or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("agent grant fields must be non-empty")
        if any(not prefix for prefix in self.resource_prefixes):
            raise ValueError("resource prefixes must be non-empty")
        if self.max_cost < 0:
            raise ValueError("agent max_cost must be non-negative")


@dataclass(frozen=True)
class Policy:
    allowed_actions: frozenset[str]
    max_cost: int
    approval_actions: frozenset[str] = frozenset()
    agent_grants: tuple[AgentGrant, ...] = ()
    authority_trust: AuthorityTrust | None = None
    ceremony_actions: frozenset[str] = frozenset()
    ceremony_trust: CeremonyTrust | None = None
    # Token v2 (Phase 2, Item 4): the maximum lifetime of an issued
    # permit, in nanoseconds. The kernel stamps every permit with
    # ``issued_at + max_permit_ttl_ns`` as its signed expiry and refuses
    # consumption at or after it; no issuance path may exceed this cap.
    max_permit_ttl_ns: int = DEFAULT_MAX_PERMIT_TTL_NS
    # Presenter binding (Phase 3, Item 4B): when true, every permit
    # this policy issues must be bound to a registered presenter, and
    # unbound permits are refused at consume. Default false keeps the
    # token-v2 bearer posture for policies that do not opt in.
    require_presenter_binding: bool = False
    # Signed policy envelope (door-two ◆2, ported from Pulpo-Preview):
    # the policy's position in the authenticated version chain. Genesis
    # is version 1 with no previous hash; every later version names the
    # policy hash it succeeds. The chain position binds into the policy
    # hash only above genesis, so version 1 policies keep their exact
    # pre-envelope hash. There is no no-expiry form: a version is a
    # positive integer and a successor always names its predecessor
    # (door-two ◆1 — NULL-expiry rejected everywhere).
    version: int = 1
    previous_policy_hash: str | None = None
    # Envelope schema v2 (signer-custody decision, 2026-11-27): when a
    # dual-control trust is pinned, policy authority is held jointly --
    # two enrolled signer keys must both sign every envelope, a third key
    # holds the policy-layer veto, and a fourth (Operations Manager seat)
    # is the standing-veto fallback. The trust binds into the policy hash
    # only for policies that enroll it, so unenrolled policies keep their
    # exact pre-v2 hash and their v1 envelope era.
    dual_control_trust: DualControlTrust | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.require_presenter_binding, bool):
            raise ValueError("require_presenter_binding must be a bool")
        if (
            isinstance(self.max_permit_ttl_ns, bool)
            or not isinstance(self.max_permit_ttl_ns, int)
            or self.max_permit_ttl_ns <= 0
        ):
            raise ValueError("max_permit_ttl_ns must be positive")
        if self.max_permit_ttl_ns > PERMIT_TTL_CEILING_NS:
            raise ValueError("max_permit_ttl_ns exceeds the permit TTL ceiling")
        principals = [grant.principal for grant in self.agent_grants]
        if len(principals) != len(set(principals)):
            raise ValueError("agent principals must be unique")
        if any(not grant.allowed_actions.issubset(self.allowed_actions) for grant in self.agent_grants):
            raise ValueError("agent actions must be a subset of policy actions")
        if self.approval_actions and self.authority_trust is None:
            raise ValueError("approval actions require a pinned authority trust")
        if self.authority_trust is not None and not self.approval_actions:
            raise ValueError("authority trust requires at least one approval action")
        if not self.ceremony_actions.issubset(self.approval_actions):
            raise ValueError("ceremony actions must be a subset of approval actions")
        if self.ceremony_actions and self.ceremony_trust is None:
            raise ValueError("ceremony actions require a pinned ceremony trust")
        if self.ceremony_trust is not None and not self.ceremony_actions:
            raise ValueError("ceremony trust requires at least one ceremony action")
        if (
            self.authority_trust is not None
            and self.ceremony_trust is not None
            and self.ceremony_trust.key_fingerprint == self.authority_trust.key_fingerprint
        ):
            raise ValueError("ceremony trust key must be distinct from authority trust key")
        if self.dual_control_trust is not None and self.ceremony_trust is not None:
            dual = self.dual_control_trust
            enrolled = [key.key_fingerprint for key in (*dual.signers, dual.veto, dual.fallback)]
            if self.ceremony_trust.key_fingerprint in enrolled:
                raise ValueError(
                    "ceremony trust key must be distinct from dual-control signer, veto, and fallback keys"
                )
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("policy version must be a positive integer")
        if self.version == 1 and self.previous_policy_hash is not None:
            raise ValueError("genesis policy version must not carry a previous policy hash")
        if self.version > 1 and not _is_digest(self.previous_policy_hash):
            raise ValueError("policy version above genesis requires a previous policy hash")


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    intent_hash: str
    permit: str | None = None


@dataclass(frozen=True)
class Lease:
    """A kernel-issued authorization artifact for bounded actuation.

    The claims are the artifact: ``lease_digest`` hashes every field
    except the token, and the token's HMAC signs that digest together
    with the nonce, issue time, expiry, and presenter hash — so the
    object is self-authenticating in exactly the way a permit token
    is, extended to the full claim set a physical deployment needs
    (command budget, disconnected window, safe fallback, sequence
    floor, boot counter, directive binding). The dataclass has a
    public constructor, as ``ApprovalEnvelope`` does; what a local
    constructor cannot produce is a *valid* lease, because validity
    requires a token signed under the kernel secret and a governed
    issuance record in the kernel's state. A locally assembled lease
    fails verification at the signature step (acceptance test 1).
    """

    intent_hash: str
    principal: str
    action: str
    resource: str
    payload_digest: str
    directive_id: str
    directive_version: int
    directive_hash: str
    parent_directive_hash: str | None
    policy_hash: str
    deployment_id: str
    presenter: str
    session_id: str
    nonce: str
    max_commands: int
    max_disconnected_ns: int
    safe_fallback: str
    sequence_floor: int
    boot_counter: int
    issued_at_ns: int
    expires_at_ns: int
    token: str
    schema: str = LEASE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != LEASE_SCHEMA:
            raise ValueError("unsupported lease schema")
        if not _is_digest(self.intent_hash) or not _is_digest(self.payload_digest) or not _is_digest(self.directive_hash):
            raise ValueError("lease digests must be SHA-256 hex")
        if self.parent_directive_hash is not None and not _is_digest(self.parent_directive_hash):
            raise ValueError("lease parent directive hash must be SHA-256 hex")
        if not self.principal or not self.action or not self.resource or not self.deployment_id or not self.presenter or not self.session_id or not self.nonce or not self.token:
            raise ValueError("lease identity fields must be non-empty")
        if not self.directive_id or self.directive_version <= 0:
            raise ValueError("lease directive identity must be valid")
        if not self.safe_fallback:
            raise ValueError("lease safe fallback is mandatory")
        if isinstance(self.max_commands, bool) or not isinstance(self.max_commands, int) or self.max_commands <= 0:
            raise ValueError("lease command budget must be positive")
        if isinstance(self.max_disconnected_ns, bool) or not isinstance(self.max_disconnected_ns, int) or self.max_disconnected_ns <= 0:
            raise ValueError("lease disconnected window must be positive")
        if isinstance(self.sequence_floor, bool) or not isinstance(self.sequence_floor, int) or self.sequence_floor < 0:
            raise ValueError("lease sequence floor must be non-negative")
        if isinstance(self.boot_counter, bool) or not isinstance(self.boot_counter, int) or self.boot_counter < 0:
            raise ValueError("lease boot counter must be non-negative")
        if self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("lease validity window must be valid")

    def claims(self) -> dict[str, Any]:
        """Every claim the lease digest binds — all fields but the token."""

        payload = asdict(self)
        payload.pop("token")
        return payload

    @property
    def lease_digest(self) -> str:
        return sha256(_canonical(self.claims())).hexdigest()


@dataclass(frozen=True)
class LeaseCommand:
    """One actuation command presented under a lease.

    The command binds by exact equality to the lease's intent: the
    action, the target (resource), and the digest of the exact
    command payload. A substituted payload — same length, different
    bytes — has a different digest and is refused at verification
    (acceptance test 6, the #382 boundary lesson). ``sequence`` is
    the command's position under the lease: strictly increasing,
    at or above the lease's sequence floor.
    """

    action: str
    resource: str
    payload_digest: str
    sequence: int
    schema: str = LEASE_COMMAND_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != LEASE_COMMAND_SCHEMA:
            raise ValueError("unsupported lease command schema")
        if not self.action or not self.resource:
            raise ValueError("lease command identity fields must be non-empty")
        if not _is_digest(self.payload_digest):
            raise ValueError("lease command payload digest must be SHA-256 hex")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("lease command sequence must be non-negative")

    @property
    def command_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class LeaseDecision:
    outcome: str
    reason: str
    intent_hash: str
    lease: Lease | None = None


class StateIntegrityError(RuntimeError):
    """Raised when persisted audit state cannot be trusted at bootstrap."""


class AuthorityTrustError(RuntimeError):
    """Raised when a configured verifier does not match pinned policy trust."""


class PolicyEnvelopeError(RuntimeError):
    """Raised when a signed policy envelope is missing, invalid, or stale."""


class PolicyVetoError(RuntimeError):
    """Raised when a policy veto record is invalid, replayed, or out of scope."""


# The chained silence that must separate an Operations Manager fallback
# request from any fallback standing-veto act (signer-custody fallback
# clause, 2026-11-27): 24 hours of chain time with no veto-holder act
# chained after the request.
FALLBACK_SILENCE_NS = 24 * 60 * 60 * 1_000_000_000


def policy_hash_for(policy: Policy) -> str:
    """The policy hash for ``policy``; genesis policies hash as before."""
    grants = [
        {
            "principal": grant.principal,
            "allowed_actions": sorted(grant.allowed_actions),
            "resource_prefixes": sorted(grant.resource_prefixes),
            "max_cost": grant.max_cost,
        }
        for grant in sorted(policy.agent_grants, key=lambda item: item.principal)
    ]
    payload = {
        "schema": "pulpo.policy.v1",
        "allowed_actions": sorted(policy.allowed_actions),
        "max_cost": policy.max_cost,
        "approval_actions": sorted(policy.approval_actions),
        "agent_grants": grants,
        "authority_trust": asdict(policy.authority_trust) if policy.authority_trust else None,
    }
    if policy.ceremony_actions or policy.ceremony_trust is not None:
        # Opted-in policies bind their ceremony configuration into the
        # policy hash. Policies that never opted in keep the exact
        # pre-ceremony hash, so their envelopes and behavior are unchanged.
        payload["ceremony_actions"] = sorted(policy.ceremony_actions)
        payload["ceremony_trust"] = asdict(policy.ceremony_trust) if policy.ceremony_trust else None
    if policy.max_permit_ttl_ns != DEFAULT_MAX_PERMIT_TTL_NS:
        # A non-default permit TTL is an authority-relevant policy
        # choice (it widens or narrows the bearer window), so it binds
        # into the policy hash. Policies at the default keep the exact
        # pre-Item-4 hash, so their envelopes and behavior are unchanged.
        payload["max_permit_ttl_ns"] = policy.max_permit_ttl_ns
    if policy.require_presenter_binding:
        # Requiring presenter binding is an authority-relevant
        # policy choice (it retires the bearer posture), so it
        # binds into the policy hash. Policies that do not require
        # it keep the exact pre-Item-4B hash.
        payload["require_presenter_binding"] = True
    if policy.version != 1:
        # Versioned policies bind the head chain. Version 1 policies hash
        # exactly as before, so existing permits and audit records keep
        # their policy hash.
        payload["version"] = policy.version
        payload["previous_policy_hash"] = policy.previous_policy_hash
    if policy.dual_control_trust is not None:
        # Dual-control enrollment is authority-defining (it names who may
        # advance policy and who may halt it), so it binds into the hash.
        # Policies that never enroll keep their exact pre-v2 hash.
        payload["dual_control_trust"] = asdict(policy.dual_control_trust)
    return sha256(_canonical(payload)).hexdigest()


class GovernanceKernel:
    """Evaluates intent, issues one-use permits, and maintains an audit chain."""

    def __init__(
        self,
        policy: Policy,
        secret: bytes | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        clock: Callable[[], int] | None = None,
        state: KernelState | None = None,
        *,
        ceremony_verifier: CeremonyVerifier | None = None,
        audit_signer: AuditSigner | None = None,
        legacy_audit_records: int = 0,
        presenter_verifiers: dict[str, PresenterVerifier] | None = None,
        policy_envelope: PolicyEnvelope | None = None,
        policy_envelope_v2: PolicyEnvelopeV2 | None = None,
        policy_signer_verifiers: dict[str, ApprovalVerifier] | None = None,
        veto_verifier: ApprovalVerifier | None = None,
        fallback_verifier: ApprovalVerifier | None = None,
    ) -> None:
        self.policy = policy
        # Pin the exact policy this kernel was constructed under. Every
        # authority decision point re-verifies the live policy against this
        # hash and fails closed on drift, so reassigning kernel.policy can
        # no longer silently change decisions (writer-custody Phase 1;
        # diagnosis Repro D). The policy_hash property itself stays a live
        # computation: callers legitimately compare it against hashes they
        # captured earlier to detect exactly this drift.
        self._pinned_policy_hash = self.policy_hash
        self._secret = secret or secrets.token_bytes(32)
        self._approval_verifier = approval_verifier
        self._ceremony_verifier = ceremony_verifier
        # Presenter registry (Item 4B): presenter identity -> verifier.
        # Deployment configuration injected at construction, like the
        # approval verifier; copied so later mutation of the caller's
        # dict cannot change who this kernel will accept proofs from.
        self._presenter_verifiers: dict[str, PresenterVerifier] = dict(presenter_verifiers or {})
        self._clock = clock or time.time_ns
        if state is not None and (audit_signer is not None or legacy_audit_records):
            # The signer lives in the state layer (it signs at append);
            # a caller that hands in a state must have constructed that
            # state with its signer. Supplying both would leave two
            # sources of truth for which records must be signed, so
            # refuse rather than guess.
            raise ValueError("audit_signer/legacy_audit_records must be given on the state, not the kernel, when a state is supplied")
        self._state = state if state is not None else InMemoryKernelState(audit_signer=audit_signer, legacy_audit_records=legacy_audit_records)
        if self._approval_verifier is not None and not self._verifier_matches_trust(self._approval_verifier):
            raise AuthorityTrustError("approval verifier does not match pinned authority trust")
        if self._ceremony_verifier is not None and not self._ceremony_verifier_matches_trust(self._ceremony_verifier):
            raise AuthorityTrustError("ceremony verifier does not match pinned ceremony trust")
        # Signed versioned policy envelope (door-two ◆2; ported from
        # Pulpo-Preview, reconciled): an envelope supplied at construction
        # is verified against the pinned issuer trust, and its
        # version/previous-hash chain is the authenticated current policy
        # head, recorded in the audit chain at acceptance below. A policy
        # with no pinned trust has no issuer key, so an envelope for it is
        # unverifiable and refused; an envelope that cannot be verified
        # because no approval verifier is configured is likewise refused.
        # Reconciliation against the fork: the fork requires an envelope
        # whenever a pinned trust and an approval verifier coexist.
        # Canonical requires one exactly where a chain is claimed or
        # already exists -- a versioned policy (version > 1), or state
        # that already records a policy head -- so a genesis policy with
        # no recorded head keeps the exact pre-envelope construction
        # behavior (existing deployments, including the merge gate whose
        # production policy source is still configuration pending the
        # signer-custody decision, adopt envelopes by an explicit act,
        # after which an envelope cannot be silently dropped).
        self._policy_envelope: PolicyEnvelope | None = None
        # Envelope schema v2 (signer-custody decision, 2026-11-27): a
        # policy that pins a dual-control trust lives in the v2 era. Its
        # envelopes are dual-signed, its veto registry is active, and the
        # era is fixed by the first recorded head -- a v1 envelope offered
        # to a v2 policy (or vice versa) is an era mismatch, refused, so a
        # chain on v2 dual control can never silently downgrade to v1
        # single-signer rules. Signer/veto/fallback verifiers are
        # deployment configuration injected at construction, like the
        # approval verifier, and every one supplied must match the key it
        # claims to verify for in the enrolled trust.
        self._policy_signer_verifiers: dict[str, ApprovalVerifier] = dict(
            policy_signer_verifiers or {}
        )
        self._veto_verifier = veto_verifier
        self._fallback_verifier = fallback_verifier
        dual = self.policy.dual_control_trust
        if dual is not None:
            enrolled_signers = {key.key_id: key for key in dual.signers}
            for signer_key_id, signer_verifier in self._policy_signer_verifiers.items():
                binding = enrolled_signers.get(signer_key_id)
                if binding is None or not self._enrolled_verifier_matches(
                    signer_verifier, dual, binding
                ):
                    raise AuthorityTrustError(
                        "policy signer verifier does not match an enrolled signer key"
                    )
            if veto_verifier is not None and not self._enrolled_verifier_matches(
                veto_verifier, dual, dual.veto
            ):
                raise AuthorityTrustError("veto verifier does not match the enrolled veto key")
            if fallback_verifier is not None and not self._enrolled_verifier_matches(
                fallback_verifier, dual, dual.fallback
            ):
                raise AuthorityTrustError(
                    "fallback verifier does not match the enrolled fallback key"
                )
        else:
            if self._policy_signer_verifiers or veto_verifier is not None or fallback_verifier is not None:
                raise AuthorityTrustError(
                    "policy signer, veto, and fallback verifiers require a dual-control trust"
                )
        self._policy_envelope_v2: PolicyEnvelopeV2 | None = None
        if dual is not None:
            if policy_envelope is not None:
                raise PolicyEnvelopeError(
                    "policy envelope era mismatch: a dual-control policy requires an envelope v2"
                )
            if policy_envelope_v2 is not None:
                self._policy_envelope_v2 = self._verify_policy_envelope_v2(policy_envelope_v2)
        elif policy_envelope_v2 is not None:
            raise PolicyEnvelopeError("policy envelope v2 requires a dual-control trust")
        if self.policy.authority_trust is None:
            if policy_envelope is not None:
                raise PolicyEnvelopeError("policy envelope requires a pinned authority trust")
        elif policy_envelope is not None:
            if self._approval_verifier is None:
                raise PolicyEnvelopeError("policy envelope cannot be verified without an approval verifier")
            self._policy_envelope = self._verify_policy_envelope(policy_envelope, self._approval_verifier)
        try:
            audit_valid = self.verify_audit()
        except Exception as exc:
            raise StateIntegrityError("kernel state audit chain is invalid") from exc
        if not audit_valid:
            raise StateIntegrityError("kernel state audit chain is invalid")
        if self._policy_envelope_v2 is not None:
            self._accept_policy_head_v2()
        elif self._policy_envelope is not None:
            self._accept_policy_head()
        elif (
            dual is not None
            and len(self._policy_signer_verifiers) == 2
            and (self.policy.version > 1 or self._recorded_policy_head() is not None)
        ):
            raise PolicyEnvelopeError(
                "signed policy envelope v2 is required for a versioned dual-control policy or a recorded policy head"
            )
        elif (self.policy.authority_trust is not None and self.policy.version > 1) or (
            self._recorded_policy_head() is not None
        ):
            # The requirement does not depend on an approval verifier
            # being configured: omitting both the envelope and the
            # verifier must not silently disable envelope enforcement
            # where a chain is claimed (version > 1) or already exists
            # (a recorded policy head) (Codex P1 on PR #418).
            raise PolicyEnvelopeError(
                "signed policy envelope is required for a versioned policy or a recorded policy head"
            )

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._state.audit

    @staticmethod
    def intent_hash(intent: Intent) -> str:
        return sha256(_canonical(asdict(intent))).hexdigest()

    @property
    def policy_hash(self) -> str:
        return policy_hash_for(self.policy)

    @property
    def policy_head(self) -> dict[str, Any] | None:
        """The authenticated policy head accepted at construction, if any."""

        if self._policy_envelope_v2 is not None:
            envelope = self._policy_envelope_v2
            dual = self.policy.dual_control_trust
            assert dual is not None
            return {
                "policy_version": envelope.version,
                "policy_hash": envelope.policy_hash,
                "previous_policy_hash": envelope.previous_policy_hash,
                "envelope_hash": envelope.envelope_hash,
                "schema": envelope.schema,
                "signer_key_ids": sorted(entry.key_id for entry in envelope.signatures),
                "veto_key_id": dual.veto.key_id,
                "fallback_key_id": dual.fallback.key_id,
            }
        if self._policy_envelope is None:
            return None
        envelope = self._policy_envelope
        return {
            "policy_version": envelope.version,
            "policy_hash": envelope.policy_hash,
            "previous_policy_hash": envelope.previous_policy_hash,
            "envelope_hash": envelope.envelope_hash,
        }

    def lock_target(self, target_id: str, intent: Intent, *, version: int = 1) -> LockedTarget:
        """Record an exact proposed target without granting authority."""

        existing = self.get_locked_target(target_id, version=version)
        if existing is not None:
            if not hmac.compare_digest(self.intent_hash(existing.intent), self.intent_hash(intent)):
                raise ValueError("target version is immutable")
            return existing

        now_ns = self._trusted_now()
        if now_ns is None:
            raise RuntimeError("target_clock_invalid")
        target = LockedTarget(target_id, version, intent, now_ns)
        self._state.append(
            "target_locked",
            {
                "schema": target.schema,
                "target_id": target.target_id,
                "version": target.version,
                "target_hash": target.target_hash,
                "intent": asdict(target.intent),
                "intent_hash": self.intent_hash(target.intent),
                "created_at_ns": target.created_at_ns,
                "authority_effect": "none",
            },
            now_ns,
        )
        return target

    def get_locked_target(self, target_id: str, *, version: int = 1) -> LockedTarget | None:
        """Resolve a locked target from the canonical audit chain."""

        if not target_id or version <= 0:
            return None
        if not self.verify_audit():
            raise StateIntegrityError("kernel state audit chain is invalid")
        for record in reversed(self.audit):
            if record.get("event") != "target_locked":
                continue
            payload = record.get("payload", {})
            if payload.get("target_id") != target_id or payload.get("version") != version:
                continue
            try:
                intent_payload = payload["intent"]
                target = LockedTarget(
                    target_id=payload["target_id"],
                    version=payload["version"],
                    intent=Intent(**intent_payload),
                    created_at_ns=payload["created_at_ns"],
                    schema=payload["schema"],
                )
                stored_target_hash = payload["target_hash"]
                stored_intent_hash = payload["intent_hash"]
            except (KeyError, TypeError, ValueError) as exc:
                raise StateIntegrityError("locked target record is invalid") from exc
            if not hmac.compare_digest(target.target_hash, stored_target_hash):
                raise StateIntegrityError("locked target hash is invalid")
            if not hmac.compare_digest(self.intent_hash(target.intent), stored_intent_hash):
                raise StateIntegrityError("locked target intent hash is invalid")
            if payload.get("authority_effect") != "none":
                raise StateIntegrityError("locked target cannot carry authority")
            return target
        return None

    def resolve_locked_target(
        self,
        target_id: str,
        expected_target_hash: str,
        *,
        version: int = 1,
    ) -> TargetResolution:
        """Fail closed unless a caller references the exact durable target."""

        now_ns = self._trusted_now()
        if now_ns is None:
            return TargetResolution("deny", "target_clock_invalid", target_id, version, expected_target_hash)
        if not target_id or version <= 0 or not isinstance(expected_target_hash, str) or len(expected_target_hash) != 64:
            result = TargetResolution("deny", "target_reference_invalid", target_id, version, expected_target_hash)
        else:
            target = self.get_locked_target(target_id, version=version)
            if target is None:
                result = TargetResolution("deny", "target_not_locked", target_id, version, expected_target_hash)
            elif not hmac.compare_digest(target.target_hash, expected_target_hash):
                result = TargetResolution("deny", "target_hash_mismatch", target_id, version, expected_target_hash)
            else:
                result = TargetResolution("match", "target_exact_match", target_id, version, expected_target_hash, target)
        self._state.append(
            "target_resolution",
            {
                "outcome": result.outcome,
                "reason": result.reason,
                "target_id": target_id,
                "version": version,
                "expected_target_hash": expected_target_hash,
                "resolved_target_hash": result.target.target_hash if result.target else None,
                "authority_effect": "none",
            },
            now_ns,
        )
        return result

    def evaluate_locked_target(
        self,
        target_id: str,
        expected_target_hash: str,
        *,
        version: int = 1,
        presenter: str | None = None,
    ) -> tuple[TargetResolution, Decision | None]:
        """Resolve an exact target, then delegate authority to the normal evaluator."""

        resolution = self.resolve_locked_target(target_id, expected_target_hash, version=version)
        if resolution.outcome != "match" or resolution.target is None:
            return resolution, None
        return resolution, self.evaluate(resolution.target.intent, presenter=presenter)

    def evaluate(self, intent: Intent, *, presenter: str | None = None) -> Decision:
        self._require_pinned_policy()
        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._decide("deny", failure, digest)
        if intent.action in self.policy.approval_actions:
            return self._decide("require_approval", "approval_required", digest)

        return self._issue_permit(digest, presenter=presenter)

    def evaluate_with_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        *,
        ceremony_evidence: CeremonyEvidence | None = None,
        presenter: str | None = None,
    ) -> Decision:
        """Issue a permit only after verification by the configured authority.

        For actions the policy marks as ceremony-required, a verified
        envelope signature is not sufficient: the kernel additionally
        requires ceremony evidence, checked here in the evaluation path,
        that is signed under the separately pinned ceremony trust and bound
        to this exact approval context. Missing or invalid evidence fails
        closed. Actions that are not ceremony-required ignore the evidence
        parameter entirely and behave exactly as before.
        """

        return self._verify_approval(
            intent,
            envelope,
            ceremony_evidence,
            lambda approval, verified_at_ns: self._issue_permit(
                self.intent_hash(intent),
                reason="verified_approval",
                approval=approval,
                envelope=envelope,
                timestamp_ns=verified_at_ns,
                presenter=presenter,
            ),
        )

    def _verify_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        ceremony_evidence: CeremonyEvidence | None,
        finisher: Callable[[ApprovalUse, int], Any],
        *,
        approval_digest: str | None = None,
    ) -> Any:
        """The approval verification path, shared by permits and leases.

        Every check and every recorded denial below is the permit
        path's, unchanged: failures return the denial Decision
        produced by ``_approval_decide`` / ``_decide`` exactly as
        before. On success the verified ``ApprovalUse`` and the
        admission time (the completion of every required
        verification, ceremony included) are handed to ``finisher``,
        whose return value becomes the caller's: the permit path
        issues a permit, the lease path issues a lease (Lease port
        PR 1). One verification implementation — a second,
        lease-only copy would be a second authority plane in
        everything but name.

        ``approval_digest`` is the digest the envelope (and any
        ceremony evidence) must bind. For permits it is the intent
        hash itself. For lease issuance it is the lease approval
        hash (``lease_approval_hash``): the intent hash authenticates
        only the intent, but a lease's authority-bearing claims —
        payload digest, command budget, presenter, deployment,
        TTL — ride outside the Intent, so an approval binding only
        the intent would leave every one of them choosable by the
        caller after verification (Codex P1 on PR #383). Every
        check, denial, and audit record below then speaks about
        that one approval context, exactly as the permit path
        speaks about the intent.
        """

        self._require_pinned_policy()
        digest = self.intent_hash(intent) if approval_digest is None else approval_digest
        failure = self._policy_failure(intent)
        if failure:
            return self._decide("deny", failure, digest)
        if intent.action not in self.policy.approval_actions:
            if not isinstance(envelope, ApprovalEnvelope):
                return self._decide("deny", "approval_envelope_invalid", digest)
            return self._approval_decide("approval_not_required", digest, envelope)
        if not isinstance(envelope, ApprovalEnvelope):
            return self._decide("deny", "approval_envelope_invalid", digest)
        verifier = self._approval_verifier
        if verifier is None:
            return self._approval_decide("approval_verifier_unavailable", digest, envelope)
        if not self._verifier_matches_trust(verifier):
            return self._approval_decide("approval_verifier_untrusted", digest, envelope)
        if not envelope.signature:
            return self._approval_decide("approval_signature_missing", digest, envelope)
        trust = self.policy.authority_trust
        if trust is None:
            return self._approval_decide("approval_trust_unavailable", digest, envelope)
        if envelope.authority_id != trust.authority_id:
            return self._approval_decide("approval_authority_mismatch", digest, envelope)
        if envelope.verifier_id != trust.verifier_id:
            return self._approval_decide("approval_verifier_mismatch", digest, envelope)
        if envelope.key_id != trust.key_id:
            return self._approval_decide("approval_key_mismatch", digest, envelope)
        if envelope.deployment_id != trust.deployment_id:
            return self._approval_decide("approval_deployment_mismatch", digest, envelope)
        if envelope.trust_hash != trust.trust_hash:
            return self._approval_decide("approval_trust_mismatch", digest, envelope)
        if envelope.session_id != intent.session_id:
            return self._approval_decide("approval_session_mismatch", digest, envelope)
        if envelope.principal != intent.principal:
            return self._approval_decide("approval_principal_mismatch", digest, envelope)
        if envelope.intent_hash != digest:
            return self._approval_decide("approval_intent_mismatch", digest, envelope)
        if envelope.policy_hash != self.policy_hash:
            return self._approval_decide("approval_policy_mismatch", digest, envelope)
        now_ns = self._trusted_now()
        if now_ns is None:
            return self._approval_decide("approval_clock_invalid", digest, envelope, timestamp_ns=0)
        if now_ns < envelope.issued_at_ns:
            return self._approval_decide("approval_not_yet_valid", digest, envelope, timestamp_ns=now_ns)
        if envelope.expires_at_ns - envelope.issued_at_ns > trust.max_approval_ttl_ns:
            return self._approval_decide("approval_ttl_exceeded", digest, envelope, timestamp_ns=now_ns)
        if now_ns >= envelope.expires_at_ns:
            return self._approval_decide("approval_expired", digest, envelope)
        replay = self._state.approval_replay_reason(envelope.approval_id, envelope.nonce)
        if replay:
            return self._approval_decide(replay, digest, envelope)
        try:
            signature_valid = verifier.verify(envelope.signing_bytes(), envelope.signature)
        except Exception:
            return self._approval_decide("approval_verifier_failed", digest, envelope)
        if signature_valid is not True:
            return self._approval_decide("approval_signature_invalid", digest, envelope)
        verified_at_ns = self._trusted_now()
        if verified_at_ns is None:
            return self._approval_decide("approval_clock_invalid", digest, envelope, timestamp_ns=0)
        if verified_at_ns < now_ns:
            return self._approval_decide("approval_clock_rollback", digest, envelope, timestamp_ns=verified_at_ns)
        if verified_at_ns >= envelope.expires_at_ns:
            return self._approval_decide(
                "approval_expired_during_verification",
                digest,
                envelope,
                timestamp_ns=verified_at_ns,
            )

        ceremony_payload: dict[str, Any] = {}
        ceremony_evidence_id: str | None = None
        if intent.action in self.policy.ceremony_actions:
            ceremony_failure, ceremony_checked_at_ns = self._ceremony_failure(
                intent,
                envelope,
                ceremony_evidence,
                digest,
                verified_at_ns,
            )
            if ceremony_failure is not None:
                return self._approval_decide(
                    ceremony_failure,
                    digest,
                    envelope,
                    timestamp_ns=(
                        verified_at_ns
                        if ceremony_checked_at_ns is None
                        else ceremony_checked_at_ns
                    ),
                )
            if (
                not isinstance(ceremony_evidence, CeremonyEvidence)
                or self.policy.ceremony_trust is None
                or ceremony_checked_at_ns is None
            ):
                raise RuntimeError("ceremony gate passed without verified evidence")
            # Admission time is the completion of every required verification,
            # not the earlier moment at which envelope verification finished.
            verified_at_ns = ceremony_checked_at_ns
            ceremony_evidence_id = ceremony_evidence.evidence_id
            ceremony_payload = {
                "ceremony_evidence_id": ceremony_evidence.evidence_id,
                "ceremony_evidence_hash": ceremony_evidence.evidence_hash,
                "ceremony_signing_payload_hash": ceremony_evidence.signing_payload_hash,
                "ceremony_authority_id": ceremony_evidence.authority_id,
                "ceremony_verifier_id": ceremony_evidence.verifier_id,
                "ceremony_key_id": ceremony_evidence.key_id,
                "ceremony_algorithm": self.policy.ceremony_trust.algorithm,
                "ceremony_key_fingerprint": self.policy.ceremony_trust.key_fingerprint,
                "ceremony_method": ceremony_evidence.method,
                "ceremony_issued_at_ns": ceremony_evidence.issued_at_ns,
                "ceremony_expires_at_ns": ceremony_evidence.expires_at_ns,
            }

        approval = ApprovalUse(
            envelope.approval_id,
            envelope.nonce,
            {
                "approval_id": envelope.approval_id,
                "authority_id": envelope.authority_id,
                "verifier_id": envelope.verifier_id,
                "key_id": envelope.key_id,
                "algorithm": trust.algorithm,
                "key_fingerprint": trust.key_fingerprint,
                "deployment_id": envelope.deployment_id,
                "trust_hash": envelope.trust_hash,
                "envelope_hash": envelope.envelope_hash,
                "signing_payload_hash": envelope.signing_payload_hash,
                "intent_hash": digest,
                "policy_hash": self.policy_hash,
                "issued_at_ns": envelope.issued_at_ns,
                "expires_at_ns": envelope.expires_at_ns,
                "verified_at_ns": verified_at_ns,
                **ceremony_payload,
            },
            ceremony_evidence_id=ceremony_evidence_id,
        )
        return finisher(approval, verified_at_ns)

    def _verifier_matches_trust(self, verifier: ApprovalVerifier) -> bool:
        trust = self.policy.authority_trust
        if trust is None:
            return False
        try:
            actual = (
                verifier.authority_id,
                verifier.verifier_id,
                verifier.key_id,
                verifier.algorithm,
                verifier.key_fingerprint,
            )
        except Exception:
            return False
        expected = (
            trust.authority_id,
            trust.verifier_id,
            trust.key_id,
            trust.algorithm,
            trust.key_fingerprint,
        )
        return actual == expected

    def _ceremony_verifier_matches_trust(self, verifier: CeremonyVerifier) -> bool:
        trust = self.policy.ceremony_trust
        if trust is None:
            return False
        try:
            actual = (
                verifier.authority_id,
                verifier.verifier_id,
                verifier.key_id,
                verifier.algorithm,
                verifier.key_fingerprint,
            )
        except Exception:
            return False
        expected = (
            trust.authority_id,
            trust.verifier_id,
            trust.key_id,
            trust.algorithm,
            trust.key_fingerprint,
        )
        return actual == expected

    @staticmethod
    def _enrolled_verifier_matches(verifier: Any, dual: DualControlTrust, binding: Any) -> bool:
        """True when ``verifier`` is exactly the enrolled key ``binding`` names."""

        try:
            actual = (
                verifier.authority_id,
                verifier.verifier_id,
                verifier.key_id,
                verifier.algorithm,
                verifier.key_fingerprint,
            )
        except Exception:
            return False
        expected = (
            dual.authority_id,
            dual.verifier_id,
            binding.key_id,
            binding.algorithm,
            binding.key_fingerprint,
        )
        return actual == expected

    def _verify_policy_envelope(
        self, envelope: PolicyEnvelope | None, verifier: ApprovalVerifier
    ) -> PolicyEnvelope:
        """Verify a signed envelope against the pinned issuer trust."""

        if not isinstance(envelope, PolicyEnvelope):
            raise PolicyEnvelopeError(
                "signed policy envelope is required for a policy with pinned authority trust"
            )
        trust = self.policy.authority_trust
        assert trust is not None
        bindings = (
            (envelope.authority_id, trust.authority_id, "policy envelope authority mismatch"),
            (envelope.verifier_id, trust.verifier_id, "policy envelope verifier mismatch"),
            (envelope.key_id, trust.key_id, "policy envelope key mismatch"),
            (envelope.deployment_id, trust.deployment_id, "policy envelope deployment mismatch"),
            (envelope.trust_hash, trust.trust_hash, "policy envelope trust mismatch"),
        )
        for actual, expected, message in bindings:
            if actual != expected:
                raise PolicyEnvelopeError(message)
        if envelope.version != self.policy.version:
            raise PolicyEnvelopeError("policy envelope version mismatch")
        if envelope.previous_policy_hash != self.policy.previous_policy_hash:
            raise PolicyEnvelopeError("policy envelope previous-hash mismatch")
        if not hmac.compare_digest(envelope.policy_hash, self.policy_hash):
            raise PolicyEnvelopeError("policy envelope policy-hash mismatch")
        if not envelope.signature:
            raise PolicyEnvelopeError("policy envelope signature missing")
        try:
            signature_valid = verifier.verify(envelope.signing_bytes(), envelope.signature)
        except Exception as exc:
            raise PolicyEnvelopeError("policy envelope verifier failed") from exc
        if signature_valid is not True:
            raise PolicyEnvelopeError("policy envelope signature invalid")
        return envelope

    def _recorded_policy_head(self) -> dict[str, Any] | None:
        """Latest policy head recorded in the canonical audit chain, if any.

        Execution-time revalidation (see _require_current_policy_head)
        consults this on every consequential transition, so the common
        path is the state layer's targeted tail read -- reading the
        whole chain per call (the audit property rebuilds/deep-copies
        every record) made governed operation quadratic in the chain
        length and pushed the test suite past its CI job timeout. A
        malformed latest head record falls back to the full scan below,
        which skips malformed records exactly as the original lookup
        did; a state without the targeted read gets the full scan too.
        """

        latest_record = getattr(self._state, "latest_record", None)
        if latest_record is not None:
            record = latest_record("policy_head_accepted")
            if record is None:
                return None
            payload = record.get("payload", {})
            if (
                isinstance(payload, dict)
                and type(payload.get("policy_version")) is int
                and _is_digest(payload.get("policy_hash"))
            ):
                return payload
        head: dict[str, Any] | None = None
        for record in self.audit:
            if record.get("event") != "policy_head_accepted":
                continue
            payload = record.get("payload", {})
            if not isinstance(payload, dict):
                continue
            if type(payload.get("policy_version")) is not int:
                continue
            if not _is_digest(payload.get("policy_hash")):
                continue
            head = payload
        return head

    def _accept_policy_head(self) -> None:
        """Refuse a stale or forked policy head; record an advancing head.

        The recorded head lives in the canonical audit chain (existing
        ``append`` path, canonical columns only), so a stale kernel reopening
        the same state is refused instead of governing indefinitely under an
        older policy. Reopening with the identical head is a restart, not an
        advance, and records nothing new.
        """

        envelope = self._policy_envelope
        assert envelope is not None
        head = self._recorded_policy_head()
        if head is not None and head.get("schema") == "pulpo.policy-envelope.v2":
            raise PolicyEnvelopeError(
                "policy envelope era mismatch: the recorded policy head is an envelope v2 head"
            )
        if head is None:
            self._append_policy_head(envelope)
            return
        recorded_version = head["policy_version"]
        recorded_hash = head["policy_hash"]
        if envelope.version < recorded_version:
            raise PolicyEnvelopeError(
                "stale policy envelope: version is older than the recorded policy head"
            )
        if envelope.version == recorded_version:
            if not hmac.compare_digest(envelope.policy_hash, recorded_hash):
                raise PolicyEnvelopeError(
                    "policy envelope conflicts with the recorded policy head"
                )
            return
        if envelope.previous_policy_hash != recorded_hash:
            raise PolicyEnvelopeError(
                "policy envelope chain is broken: previous hash does not match the recorded policy head"
            )
        self._append_policy_head(envelope)

    def _append_policy_head(self, envelope: PolicyEnvelope) -> None:
        timestamp = self._trusted_now()
        payload = {
            "policy_version": envelope.version,
            "policy_hash": envelope.policy_hash,
            "previous_policy_hash": envelope.previous_policy_hash,
            "envelope_hash": envelope.envelope_hash,
            "authority_id": envelope.authority_id,
            "verifier_id": envelope.verifier_id,
            "key_id": envelope.key_id,
            "deployment_id": envelope.deployment_id,
            "trust_hash": envelope.trust_hash,
        }
        # Admission must be atomic: the check in _accept_policy_head()
        # reads the recorded head, so the append goes through the state
        # layer's compare-and-append primitive keyed on the policy
        # version. Two concurrent constructors advancing from the same
        # predecessor cannot both land a head for the same version --
        # the loser is handed the head that won and refuses here if it
        # is not its own envelope (Codex P1 on PR #418).
        existing = self._state.append_unique(
            "policy_head_accepted",
            "policy_version",
            envelope.version,
            payload,
            timestamp if timestamp is not None else 0,
        )
        if existing is not None and not hmac.compare_digest(
            str(existing.get("policy_hash", "")), envelope.policy_hash
        ):
            raise PolicyEnvelopeError(
                "policy envelope conflicts with the recorded policy head"
            )

    def _verify_policy_envelope_v2(self, envelope: PolicyEnvelopeV2) -> PolicyEnvelopeV2:
        """Verify a dual-signed envelope against the dual-control trust.

        Both enrolled signer keys must have signed the exact payload --
        which itself binds the signer key-id set -- and each signature is
        verified with the verifier enrolled for that key. One signature,
        an unenrolled key, or a signature from the wrong key all refuse:
        neither signer alone can advance policy.
        """

        dual = self.policy.dual_control_trust
        assert dual is not None
        if not isinstance(envelope, PolicyEnvelopeV2):
            raise PolicyEnvelopeError("signed policy envelope v2 is required")
        bindings = (
            (envelope.authority_id, dual.authority_id, "policy envelope authority mismatch"),
            (envelope.verifier_id, dual.verifier_id, "policy envelope verifier mismatch"),
            (envelope.deployment_id, dual.deployment_id, "policy envelope deployment mismatch"),
            (envelope.trust_hash, dual.trust_hash, "policy envelope trust mismatch"),
        )
        for actual, expected, message in bindings:
            if actual != expected:
                raise PolicyEnvelopeError(message)
        if envelope.version != self.policy.version:
            raise PolicyEnvelopeError("policy envelope version mismatch")
        if envelope.previous_policy_hash != self.policy.previous_policy_hash:
            raise PolicyEnvelopeError("policy envelope previous-hash mismatch")
        if not hmac.compare_digest(envelope.policy_hash, self.policy_hash):
            raise PolicyEnvelopeError("policy envelope policy-hash mismatch")
        enrolled = {key.key_id: key for key in dual.signers}
        presented = {entry.key_id: entry.signature for entry in envelope.signatures}
        if set(presented) != set(enrolled):
            raise PolicyEnvelopeError(
                "policy envelope v2 requires signatures from both enrolled signer keys"
            )
        for key_id, binding in enrolled.items():
            signature = presented[key_id]
            if not signature:
                raise PolicyEnvelopeError("policy envelope signature missing")
            verifier = self._policy_signer_verifiers.get(key_id)
            if verifier is None:
                raise PolicyEnvelopeError(
                    "policy envelope v2 cannot be verified without both signer verifiers"
                )
            if not self._enrolled_verifier_matches(verifier, dual, binding):
                raise PolicyEnvelopeError("policy envelope signer verifier mismatch")
            try:
                signature_valid = verifier.verify(envelope.signing_bytes(), signature)
            except Exception as exc:
                raise PolicyEnvelopeError("policy envelope verifier failed") from exc
            if signature_valid is not True:
                raise PolicyEnvelopeError("policy envelope signature invalid")
        return envelope

    def _accept_policy_head_v2(self) -> None:
        """Refuse a stale, forked, cross-era, or vetoed v2 head; record an advance.

        The veto registry is consulted before any append: an acceptance is
        the only moment a head enters the chain, so it is the governed
        boundary the veto guards. Reopening with the identical head
        appends nothing and is a restart, not an advance -- the veto halts
        advances, not governance under an already-accepted head.
        """

        envelope = self._policy_envelope_v2
        assert envelope is not None
        head = self._recorded_policy_head()
        if head is not None and head.get("schema") != "pulpo.policy-envelope.v2":
            raise PolicyEnvelopeError(
                "policy envelope era mismatch: the recorded policy head is an envelope v1 head"
            )
        if head is None:
            self._refuse_if_vetoed(envelope)
            self._append_policy_head_v2(envelope)
            return
        recorded_version = head["policy_version"]
        recorded_hash = head["policy_hash"]
        if envelope.version < recorded_version:
            raise PolicyEnvelopeError(
                "stale policy envelope: version is older than the recorded policy head"
            )
        if envelope.version == recorded_version:
            if not hmac.compare_digest(envelope.policy_hash, recorded_hash):
                raise PolicyEnvelopeError(
                    "policy envelope conflicts with the recorded policy head"
                )
            return
        if envelope.previous_policy_hash != recorded_hash:
            raise PolicyEnvelopeError(
                "policy envelope chain is broken: previous hash does not match the recorded policy head"
            )
        self._refuse_if_vetoed(envelope)
        self._append_policy_head_v2(envelope)

    def _append_policy_head_v2(self, envelope: PolicyEnvelopeV2) -> None:
        dual = self.policy.dual_control_trust
        assert dual is not None
        timestamp = self._trusted_now()
        self._state.append(
            "policy_head_accepted",
            {
                "schema": envelope.schema,
                "policy_version": envelope.version,
                "policy_hash": envelope.policy_hash,
                "previous_policy_hash": envelope.previous_policy_hash,
                "envelope_hash": envelope.envelope_hash,
                "authority_id": envelope.authority_id,
                "verifier_id": envelope.verifier_id,
                "deployment_id": envelope.deployment_id,
                "trust_hash": envelope.trust_hash,
                "signer_key_ids": sorted(entry.key_id for entry in envelope.signatures),
                "veto_key_id": dual.veto.key_id,
                "fallback_key_id": dual.fallback.key_id,
            },
            timestamp if timestamp is not None else 0,
        )

    # -- Policy veto registry (signer-custody decision, 2026-11-27) -----
    #
    # Veto records enter canonical state only through ``record_policy_veto``
    # -- a governed intake that verifies the record's signature against the
    # enrolled veto or fallback key before appending it to the audit chain.
    # Registry state is derived from the chain in order, never stored
    # separately: the latest standing act in chain order is the standing
    # state (so the veto holder's acts supersede fallback acts whenever
    # they land), and targeted kills accumulate permanently.

    _VETO_EVENTS = {
        "targeted": "policy_veto_targeted",
        "standing": "policy_veto_standing_set",
        "standing_renewal": "policy_veto_standing_renewed",
        "standing_lift": "policy_veto_standing_lifted",
        "fallback_request": "policy_veto_fallback_requested",
    }

    def _policy_veto_state(self) -> dict[str, Any]:
        """Derive the veto registry from the audit chain, in chain order."""

        targeted: set[str] = set()
        standing_expires_at_ns: int | None = None
        seen_veto_hashes: set[str] = set()
        seen_nonces: set[tuple[str, str]] = set()
        operative_request: dict[str, Any] | None = None
        veto_act_after_request = False
        dual = self.policy.dual_control_trust
        veto_key_id = dual.veto.key_id if dual is not None else None
        for record in self.audit:
            event = record.get("event")
            payload = record.get("payload", {})
            if not isinstance(payload, dict):
                continue
            if event == "policy_veto_targeted":
                if isinstance(payload.get("envelope_hash"), str):
                    targeted.add(payload["envelope_hash"])
            elif event == "policy_veto_standing_set" or event == "policy_veto_standing_renewed":
                expires = payload.get("expires_at_ns")
                standing_expires_at_ns = expires if type(expires) is int else None
            elif event == "policy_veto_standing_lifted":
                standing_expires_at_ns = None
            elif event == "policy_veto_fallback_requested":
                operative_request = {"timestamp_ns": record.get("timestamp_ns")}
                veto_act_after_request = False
            else:
                continue
            if isinstance(payload.get("veto_hash"), str):
                seen_veto_hashes.add(payload["veto_hash"])
            key_id = payload.get("key_id")
            nonce = payload.get("nonce")
            if isinstance(key_id, str) and isinstance(nonce, str):
                seen_nonces.add((key_id, nonce))
            if (
                operative_request is not None
                and event != "policy_veto_fallback_requested"
                and key_id == veto_key_id
            ):
                veto_act_after_request = True
        return {
            "targeted": targeted,
            "standing_expires_at_ns": standing_expires_at_ns,
            "seen_veto_hashes": seen_veto_hashes,
            "seen_nonces": seen_nonces,
            "operative_request": operative_request,
            "veto_act_after_request": veto_act_after_request,
        }

    def _refuse_if_vetoed(self, envelope: PolicyEnvelopeV2) -> None:
        """Refuse an advancing head the veto registry bars.

        A targeted kill names this exact envelope and is permanent. A
        standing veto bars every advance while active -- including an
        advance whose effect would alter the veto arrangement itself, so
        a live veto cannot be routed around by the signers.
        """

        state = self._policy_veto_state()
        if not state["seen_veto_hashes"] and not state["targeted"]:
            return
        if envelope.envelope_hash in state["targeted"]:
            raise PolicyEnvelopeError(
                "policy envelope is permanently vetoed by a targeted veto"
            )
        standing_expires = state["standing_expires_at_ns"]
        if standing_expires is not None:
            now_ns = self._trusted_now()
            if now_ns is None:
                raise PolicyEnvelopeError(
                    "policy veto state cannot be judged without a trusted clock"
                )
            if now_ns < standing_expires:
                raise PolicyEnvelopeError(
                    "policy advances are halted by a standing veto"
                )

    def _standing_veto_active(self, state: dict[str, Any], now_ns: int) -> bool:
        expires = state["standing_expires_at_ns"]
        return expires is not None and now_ns < expires

    def _fallback_trigger_satisfied(self, state: dict[str, Any], now_ns: int) -> bool:
        """The chained fallback trigger: request, 24h of silence, no veto act.

        The operative (latest) fallback request starts the clock; the
        release requires at least ``FALLBACK_SILENCE_NS`` of chain time
        since that request's chained timestamp and no veto-holder act
        chained after it. Nothing is self-certified: the request, the
        silence, and the release are all records in the same chain.
        """

        request = state["operative_request"]
        if request is None or state["veto_act_after_request"]:
            return False
        requested_at = request["timestamp_ns"]
        if type(requested_at) is not int:
            return False
        return now_ns - requested_at >= FALLBACK_SILENCE_NS

    def _veto_record_authorized(
        self, veto: PolicyVeto, state: dict[str, Any], now_ns: int
    ) -> tuple[Any, Any]:
        """Resolve a veto record's actor to its enrolled binding and verifier.

        This is the single authority seam for the whole registry. The veto
        key may perform any act at any time. The fallback key may perform
        standing acts only, and only behind the chained 24-hour trigger;
        targeted acts never delegate. Lift authority is decided here and
        nowhere else.
        """

        dual = self.policy.dual_control_trust
        assert dual is not None
        if veto.key_id == dual.veto.key_id:
            return dual.veto, self._veto_verifier
        if veto.key_id == dual.fallback.key_id:
            if veto.kind == "targeted":
                raise PolicyVetoError("targeted policy vetoes never delegate to the fallback key")
            if veto.kind == "fallback_request":
                return dual.fallback, self._fallback_verifier
            if not self._fallback_trigger_satisfied(state, now_ns):
                raise PolicyVetoError(
                    "fallback standing-veto act requires a chained request and 24 hours without a veto-holder act"
                )
            return dual.fallback, self._fallback_verifier
        raise PolicyVetoError("policy veto record is signed by an unenrolled key")

    def record_policy_veto(self, veto: PolicyVeto) -> dict[str, Any]:
        """Verify and chain a signed veto-registry record.

        The governed intake for the registry: bindings are checked against
        the enrolled dual-control trust, the signature is verified with
        the actor's enrolled verifier, replays are refused, and the
        registry's state machine (no double standing set, renewals only
        extend an active veto, lifts only clear one) is enforced at
        intake. Returns the chained audit payload.
        """

        dual = self.policy.dual_control_trust
        if dual is None:
            raise PolicyVetoError("policy vetoes require a dual-control trust")
        if not isinstance(veto, PolicyVeto):
            raise PolicyVetoError("policy veto record is required")
        bindings = (
            (veto.authority_id, dual.authority_id, "policy veto authority mismatch"),
            (veto.verifier_id, dual.verifier_id, "policy veto verifier mismatch"),
            (veto.deployment_id, dual.deployment_id, "policy veto deployment mismatch"),
            (veto.trust_hash, dual.trust_hash, "policy veto trust mismatch"),
        )
        for actual, expected, message in bindings:
            if actual != expected:
                raise PolicyVetoError(message)
        now_ns = self._trusted_now()
        if now_ns is None:
            raise PolicyVetoError("policy veto intake requires a trusted clock")
        state = self._policy_veto_state()
        binding, verifier = self._veto_record_authorized(veto, state, now_ns)
        if verifier is None:
            raise PolicyVetoError("policy veto cannot be verified without the actor's verifier")
        if not self._enrolled_verifier_matches(verifier, dual, binding):
            raise PolicyVetoError("policy veto verifier does not match the enrolled key")
        if not veto.signature:
            raise PolicyVetoError("policy veto signature missing")
        try:
            signature_valid = verifier.verify(veto.signing_bytes(), veto.signature)
        except Exception as exc:
            raise PolicyVetoError("policy veto verifier failed") from exc
        if signature_valid is not True:
            raise PolicyVetoError("policy veto signature invalid")
        if veto.veto_hash in state["seen_veto_hashes"] or (veto.key_id, veto.nonce) in state["seen_nonces"]:
            raise PolicyVetoError("policy veto record replayed")
        active = self._standing_veto_active(state, now_ns)
        if veto.kind == "targeted":
            if veto.envelope_hash in state["targeted"]:
                raise PolicyVetoError("policy envelope is already under a targeted veto")
        elif veto.kind == "standing":
            if active:
                raise PolicyVetoError("a standing veto is already active; renew or lift it instead")
            assert veto.expires_at_ns is not None
            if veto.expires_at_ns <= now_ns:
                raise PolicyVetoError("standing policy veto expiry must be in the future")
        elif veto.kind == "standing_renewal":
            if not active:
                raise PolicyVetoError("no active standing veto to renew")
            assert veto.expires_at_ns is not None
            if veto.expires_at_ns <= state["standing_expires_at_ns"]:
                raise PolicyVetoError("standing policy veto renewal must extend the current expiry")
        elif veto.kind == "standing_lift":
            if not active:
                raise PolicyVetoError("no active standing veto to lift")
        payload = {
            "kind": veto.kind,
            "authority_id": veto.authority_id,
            "verifier_id": veto.verifier_id,
            "deployment_id": veto.deployment_id,
            "trust_hash": veto.trust_hash,
            "key_id": veto.key_id,
            "nonce": veto.nonce,
            "issued_at_ns": veto.issued_at_ns,
            "envelope_hash": veto.envelope_hash,
            "expires_at_ns": veto.expires_at_ns,
            "veto_hash": veto.veto_hash,
        }
        self._state.append(self._VETO_EVENTS[veto.kind], payload, now_ns)
        return payload

    def _ceremony_failure(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        evidence: CeremonyEvidence | None,
        digest: str,
        now_ns: int,
    ) -> tuple[str | None, int | None]:
        """Return a deny reason and the ceremony completion time, if reached.

        Runs only for ceremony-required actions, and only after the approval
        envelope itself has verified: an invalid envelope denies before any
        ceremony check, so ceremony verification is never an oracle for
        holders of invalid envelopes. Signature verification can itself take
        time, so the trusted clock is read again after it succeeds; expiry
        and rollback are judged at that completion time, not at the earlier
        envelope-verification time.
        """

        if evidence is None:
            return "ceremony_evidence_missing", None
        if not isinstance(evidence, CeremonyEvidence):
            return "ceremony_evidence_invalid", None
        trust = self.policy.ceremony_trust
        if trust is None:
            return "ceremony_trust_unavailable", None
        verifier = self._ceremony_verifier
        if verifier is None:
            return "ceremony_verifier_unavailable", None
        if not self._ceremony_verifier_matches_trust(verifier):
            return "ceremony_verifier_untrusted", None
        if evidence.authority_id != trust.authority_id:
            return "ceremony_authority_mismatch", None
        if evidence.verifier_id != trust.verifier_id:
            return "ceremony_verifier_mismatch", None
        if evidence.key_id != trust.key_id:
            return "ceremony_key_mismatch", None
        if evidence.method != trust.method:
            return "ceremony_method_mismatch", None
        if evidence.trust_hash != trust.trust_hash:
            return "ceremony_trust_mismatch", None
        if not evidence.signature:
            return "ceremony_signature_missing", None
        if evidence.approval_id != envelope.approval_id:
            return "ceremony_approval_mismatch", None
        if evidence.envelope_hash != envelope.envelope_hash:
            return "ceremony_envelope_mismatch", None
        if evidence.intent_hash != digest:
            return "ceremony_intent_mismatch", None
        if evidence.policy_hash != self.policy_hash:
            return "ceremony_policy_mismatch", None
        if evidence.principal != intent.principal:
            return "ceremony_principal_mismatch", None
        if evidence.session_id != intent.session_id:
            return "ceremony_session_mismatch", None
        if evidence.approval_nonce != envelope.nonce:
            return "ceremony_nonce_mismatch", None
        if now_ns < evidence.issued_at_ns:
            return "ceremony_not_yet_valid", None
        if evidence.expires_at_ns - evidence.issued_at_ns > trust.max_evidence_ttl_ns:
            return "ceremony_ttl_exceeded", None
        if now_ns >= evidence.expires_at_ns:
            return "ceremony_expired", None
        replay = self._state.ceremony_replay_reason(evidence.evidence_id)
        if replay:
            return replay, None
        try:
            signature_valid = verifier.verify(evidence.signing_bytes(), evidence.signature)
        except Exception:
            return "ceremony_verifier_failed", None
        if signature_valid is not True:
            return "ceremony_signature_invalid", None
        ceremony_checked_at_ns = self._trusted_now()
        if ceremony_checked_at_ns is None:
            return "ceremony_clock_invalid", 0
        if ceremony_checked_at_ns < now_ns:
            return "ceremony_clock_rollback", ceremony_checked_at_ns
        if ceremony_checked_at_ns >= evidence.expires_at_ns:
            return "ceremony_expired_during_verification", ceremony_checked_at_ns
        if ceremony_checked_at_ns >= envelope.expires_at_ns:
            return "approval_expired_during_ceremony_verification", ceremony_checked_at_ns
        return None, ceremony_checked_at_ns

    def _trusted_now(self) -> int | None:
        try:
            value = self._clock()
        except Exception:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        return value

    def _policy_failure(self, intent: Intent) -> str | None:
        if not intent.principal or not intent.session_id or not intent.action or not intent.resource:
            return "incomplete_intent"
        if intent.cost < 0 or intent.cost > self.policy.max_cost:
            return "budget_exceeded"
        if intent.action not in self.policy.allowed_actions:
            return "action_not_allowed"
        if self.policy.agent_grants:
            grant = next((item for item in self.policy.agent_grants if item.principal == intent.principal), None)
            if grant is None:
                return "unknown_principal"
            if intent.action not in grant.allowed_actions:
                return "agent_action_not_allowed"
            if not any(intent.resource.startswith(prefix) for prefix in grant.resource_prefixes):
                return "agent_resource_not_allowed"
            if intent.cost > grant.max_cost:
                return "agent_budget_exceeded"
        return None

    def _issue_permit(
        self,
        digest: str,
        *,
        reason: str = "policy_satisfied",
        approval: ApprovalUse | None = None,
        envelope: ApprovalEnvelope | None = None,
        timestamp_ns: int | None = None,
        presenter: str | None = None,
    ) -> Decision:
        # The issuance funnel re-checks the pin itself: no permit is minted
        # under a drifted policy regardless of which entry path reached here.
        self._require_pinned_policy()
        # Presenter binding (Phase 3, Item 4B) is enforced in this
        # funnel so every issuance path inherits it: a policy that
        # requires binding mints no unbound permit, and a permit is
        # never bound to a presenter this kernel could not verify a
        # proof from at consume time — such a permit would be
        # unspendable by construction, so it is not minted.
        if presenter is None and self.policy.require_presenter_binding:
            return self._decide("deny", "presenter_binding_required", digest)
        if presenter is not None:
            if not isinstance(presenter, str) or not presenter:
                return self._decide("deny", "presenter_invalid", digest)
            if presenter not in self._presenter_verifiers:
                return self._decide("deny", "presenter_not_registered", digest)
        issued_at_ns = self._clock() if timestamp_ns is None else timestamp_ns
        # Token v2 (Phase 2, Item 4): the expiry is inside the signed
        # payload, so it cannot be extended without the kernel secret.
        # The lifetime is the policy's TTL cap itself — no issuance path
        # stamps a longer one, and policy construction refuses a cap
        # above the absolute ceiling (see Policy.__post_init__).
        expires_at_ns = issued_at_ns + self.policy.max_permit_ttl_ns
        nonce = secrets.token_hex(16)
        # Token v3 (Item 4B): the presenter claim — the SHA-256 of the
        # bound presenter identity, or of the empty string for an
        # unbound (bearer) permit — is inside the signed payload too,
        # so the binding cannot be stripped or swapped without the
        # kernel secret.
        presenter_hash = (
            UNBOUND_PRESENTER_HASH if presenter is None else sha256(presenter.encode()).hexdigest()
        )
        payload = f"{digest}:{nonce}:{issued_at_ns}:{expires_at_ns}:{presenter_hash}"
        signature = hmac.new(self._secret, payload.encode(), sha256).hexdigest()
        permit = f"{payload}:{signature}"
        replay = self._state.issue_permit(
            permit, digest, reason, issued_at_ns, approval, expires_at_ns=expires_at_ns
        )
        if replay:
            if envelope is None:
                raise RuntimeError("state rejected an approval-free permit")
            return self._approval_decide(replay, digest, envelope)
        return Decision("allow", reason, digest, permit)

    def _approval_decide(
        self,
        reason: str,
        digest: str,
        envelope: ApprovalEnvelope,
        *,
        timestamp_ns: int | None = None,
    ) -> Decision:
        if timestamp_ns is None:
            trusted_time = self._trusted_now()
            rejection_time = 0 if trusted_time is None else trusted_time
        else:
            rejection_time = timestamp_ns
        self._state.append(
            "approval_rejected",
            {
                "approval_id": envelope.approval_id,
                "authority_id": envelope.authority_id,
                "verifier_id": envelope.verifier_id,
                "key_id": envelope.key_id,
                "deployment_id": envelope.deployment_id,
                "trust_hash": envelope.trust_hash,
                "envelope_hash": envelope.envelope_hash,
                "signing_payload_hash": envelope.signing_payload_hash,
                "intent_hash": digest,
                "policy_hash": self.policy_hash,
                "reason": reason,
            },
            rejection_time,
        )
        decision = Decision("deny", reason, digest)
        self._state.append(
            "decision",
            {"outcome": "deny", "reason": reason, "intent_hash": digest},
            rejection_time,
        )
        return decision

    def _require_pinned_policy(self) -> None:
        """Fail closed if the live policy has drifted from the pinned one.

        Policy is set once, at construction. Reassigning ``kernel.policy``
        afterwards (diagnosis Repro D) previously swapped the evaluation
        policy silently, with no audit record; now every authority decision
        point refuses to decide under a policy other than the pinned one.
        """

        if not hmac.compare_digest(self.policy_hash, self._pinned_policy_hash):
            raise StateIntegrityError(
                "kernel policy does not match the policy pinned at construction"
            )
        self._require_current_policy_head()

    def _require_current_policy_head(self) -> None:
        """Fail closed if the recorded policy head has moved past this kernel.

        The pinned-hash check above compares the kernel against its own
        construction-time policy; it cannot see another kernel sharing
        the same state advancing the recorded policy head afterwards.
        Every consequential transition therefore re-reads the recorded
        head at execution time: a kernel whose signed envelope is no
        longer the recorded head refuses instead of issuing or consuming
        under the superseded policy, and a kernel holding no envelope at
        all refuses once a head has been recorded by someone else
        (Codex P1 on PR #418).
        """

        head = self._recorded_policy_head()
        envelope = self._policy_envelope
        if envelope is None:
            if head is not None:
                raise PolicyEnvelopeError(
                    "a policy head is recorded in state but this kernel holds no signed policy envelope"
                )
            return
        if head is None:
            raise PolicyEnvelopeError(
                "this kernel's signed policy head is missing from the recorded policy chain"
            )
        if head["policy_version"] != envelope.version or not hmac.compare_digest(
            head["policy_hash"], envelope.policy_hash
        ):
            raise PolicyEnvelopeError(
                "stale policy: this kernel's policy head has been superseded by the recorded policy head"
            )

    def _permit_token_claims(self, permit: object) -> tuple[str, int, int, str] | None:
        """Authenticate a v3 permit token and return its signed claims.

        Tokens are minted in ``_issue_permit`` as
        ``digest:nonce:issued_at_ns:expires_at_ns:presenter_hash:signature``
        with the signature an HMAC of the first five fields under the
        kernel secret. Verification recomputes that HMAC over the
        token's own presented fields and compares in constant time: it
        proves the token was minted under this kernel's secret and is
        unaltered — including its expiry, which therefore cannot be
        extended by a holder, and its presenter claim (Item 4B), which
        therefore cannot be stripped or swapped by a holder. Returns
        ``(intent_digest, issued_at_ns, expires_at_ns, presenter_hash)``
        for an authentic v3 token, else None.

        v1 tokens (``digest:nonce:signature``) and v2 tokens (no
        presenter field) fail closed here: this is the cutover. An
        outstanding pre-v3 permit is refused at consume, never
        silently accepted — the Phase 1 (#355) precedent for
        outstanding tokens at a format change, applied at Item 4 for
        v1 and here for v2. Malformed tokens and tokens minted under
        any other secret fail closed the same way.
        """

        if not isinstance(permit, str):
            return None
        parts = permit.split(":")
        if len(parts) != 6:
            return None
        token_digest, nonce, issued_raw, expires_raw, presenter_hash, signature = parts
        issued_at_ns = _token_time_ns(issued_raw)
        expires_at_ns = _token_time_ns(expires_raw)
        if issued_at_ns is None or expires_at_ns is None:
            return None
        if expires_at_ns <= issued_at_ns:
            return None
        if len(presenter_hash) != 64 or not presenter_hash.isascii() or not all(
            char in "0123456789abcdef" for char in presenter_hash
        ):
            return None
        expected = hmac.new(
            self._secret,
            f"{token_digest}:{nonce}:{issued_raw}:{expires_raw}:{presenter_hash}".encode(),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return None
        return token_digest, issued_at_ns, expires_at_ns, presenter_hash

    @staticmethod
    def presenter_proof_payload(permit: str, intent_digest: str, presenter: str) -> bytes:
        """The exact bytes a presenter signs to prove a consumption.

        One canonical construction, shared by presenters and the
        kernel: the proof binds the presenter identity to the exact
        permit token and the exact intent digest, so a proof captured
        for one permit or intent verifies for no other. The permit's
        own single-use semantics bound replay of a valid proof.
        """

        return _canonical(
            {
                "schema": PRESENTER_PROOF_SCHEMA,
                "permit": permit,
                "intent_hash": intent_digest,
                "presenter": presenter,
            }
        )

    def _presenter_refusal(
        self,
        claims: tuple[str, int, int, str],
        digest: str,
        permit: str,
        presenter: str | None,
        presenter_proof: str | None,
    ) -> str | None:
        """The Item 4B consume gate: a refusal reason, or None to proceed.

        Runs after the token is authenticated and bound to the
        presented intent, before the store is consulted — so a
        refusal here never burns the permit, and the bound presenter
        can still spend it. An unbound permit proceeds exactly as a
        token-v2 bearer <redacted> unless the pinned policy requires
        binding. A bound permit requires the named presenter's valid
        proof under the verifier registered for that identity; every
        failure mode is a distinct recorded reason. Verification
        follows the approval path's discipline: only the literal
        ``True`` is a verdict in favor — a verifier that raises, or
        that returns anything other than a bool, has not verified
        (``permit_presenter_unverifiable``); a verifier that returns
        ``False`` has verified and refused the proof
        (``permit_presenter_mismatch``).
        """

        presenter_hash = claims[3]
        if presenter_hash == UNBOUND_PRESENTER_HASH:
            if self.policy.require_presenter_binding:
                return "permit_presenter_unbound"
            return None
        if presenter is None or presenter_proof is None:
            return "permit_presenter_proof_required"
        if not isinstance(presenter, str) or not isinstance(presenter_proof, str):
            return "permit_presenter_mismatch"
        if not hmac.compare_digest(sha256(presenter.encode()).hexdigest(), presenter_hash):
            return "permit_presenter_mismatch"
        verifier = self._presenter_verifiers.get(presenter)
        if verifier is None:
            return "permit_presenter_unverifiable"
        payload = self.presenter_proof_payload(permit, digest, presenter)
        try:
            verified = verifier.verify(payload, presenter_proof)
        except Exception:
            return "permit_presenter_unverifiable"
        if verified is True:
            return None
        if verified is False:
            return "permit_presenter_mismatch"
        return "permit_presenter_unverifiable"

    def _permit_token_valid(self, permit: object) -> bool:
        """Whether ``permit`` is an authentic v3 token (see _permit_token_claims).

        On its own this authenticates provenance only, but ``consume``
        no longer stops there: since the 2026-11-13 layering change it
        also binds the authenticated token to the presented intent at
        this layer, and since token v2 it enforces the signed expiry
        at this layer too (see ``consume``). Single-use, store-side
        expiry, and directive-revocation checks remain the store's
        ``consume_permit`` checks, exactly as before.
        """

        return self._permit_token_claims(permit) is not None

    def consume(
        self,
        permit: str,
        intent: Intent,
        *,
        presenter: str | None = None,
        presenter_proof: str | None = None,
    ) -> bool:
        self._require_pinned_policy()
        digest = self.intent_hash(intent)
        claims = self._permit_token_claims(permit)
        if claims is None:
            # A permit the kernel cannot authenticate is refused before the
            # store is consulted. Rows written directly into the store --
            # state.issue_permit with approval=None (diagnosis Repro A) or
            # raw state-file inserts (Repro B) -- carry no valid token
            # signature and can no longer be spent through the kernel. The
            # refusal is recorded under the same event the store uses for
            # its own rejections, with the reason, so the attempt itself
            # stays in evidence. Single-use and directive-revocation checks
            # for authentic tokens remain the store's, unchanged. v1
            # tokens land here too: the cutover refuses them with the
            # same recorded reason rather than accepting an
            # unsigned-expiry format.
            self._state.append(
                "permit_rejected",
                {"intent_hash": digest, "reason": "permit_signature_invalid"},
                self._clock(),
            )
            return False
        _token_digest, _issued_at_ns, expires_at_ns, _presenter_hash = claims
        now_ns = self._clock()
        if now_ns >= expires_at_ns:
            # Token v2 (Phase 2, Item 4): the signed expiry is enforced
            # HERE, at consume time, before the store is consulted — an
            # expired permit fails closed exactly as a revoked one does.
            # The expiry was authenticated with the token, so no store
            # row and no holder edit can extend it. The store re-checks
            # the expiry recorded at issuance as the second layer.
            self._state.append(
                "permit_rejected",
                {"intent_hash": digest, "reason": "permit_expired"},
                now_ns,
            )
            return False
        # Layering change (2026-11-13, superseding Phase 1's
        # provenance-only layering): the authenticated token is also
        # bound to the presented intent HERE, before the store is
        # consulted. Phase 1 left that binding to the store's check
        # against the permit row's stored intent hash -- a column the
        # state-file writer controls, outside the audit chain. A writer
        # holding any genuine token could therefore rewrite its row's
        # intent hash (and reset spent) and spend the token for an
        # intent the kernel never authorized, with the chain still
        # verifying (Codex P1 on PR #355, independently reproduced).
        # The token's own authenticated digest is the one statement of
        # the authorized intent the writer cannot alter, so it is the
        # one the presented intent is compared against. The store's
        # binding check remains in place as the second layer, and
        # single-use and directive-revocation checks remain the store's.
        embedded_digest = claims[0]
        if not hmac.compare_digest(embedded_digest.encode(), digest.encode()):
            self._state.append(
                "permit_rejected",
                {"intent_hash": digest, "reason": "permit_intent_mismatch"},
                self._clock(),
            )
            return False
        # Presenter binding (Phase 3, Item 4B): the authenticated
        # token's presenter claim is enforced HERE, at the same layer
        # as the expiry and intent bindings — the claim lives in the
        # signed token, not in any store row a writer could edit. A
        # refusal is recorded and the store is never consulted, so a
        # failed presenter attempt does not burn the permit.
        refusal = self._presenter_refusal(claims, digest, permit, presenter, presenter_proof)
        if refusal is not None:
            self._state.append(
                "permit_rejected",
                {"intent_hash": digest, "reason": refusal},
                self._clock(),
            )
            return False
        return self._state.consume_permit(permit, digest, now_ns)

    # ------------------------------------------------------------------
    # Leases (canonical Lease port, PR 1)
    #
    # A lease is a permit's physical analogue: minted only here, from
    # an evaluated intent under an active directive, always bound to
    # a named device presenter, and verified in the spec's §4 order —
    # token signature, signed expiry, presenter proof, exact command
    # binding — at this layer, before the store's directive, expiry,
    # sequence, and budget transition. PR 1 is the binding itself:
    # the offline state machine, consumption records, and
    # reconciliation are PR 2; bounded intake, boot attestation, and
    # domain-safety composition are PR 3.
    # ------------------------------------------------------------------

    def _lease_decide(self, outcome: str, reason: str, digest: str) -> LeaseDecision:
        decision = LeaseDecision(outcome, reason, digest)
        self._append("decision", {"outcome": outcome, "reason": reason, "intent_hash": digest})
        return decision

    def _lease_directive_failure(self, intent: Intent, directive: Any) -> str | None:
        """The directive gate for lease issuance: a deny reason or None.

        Mirrors ``GovernedDirectiveProjection.evaluate``'s checks —
        the directive is active, its parent (if any) is active, and
        its mandate permits the intent — with one lease-specific
        refusal: a directive carrying an aggregate budget cannot
        govern a lease in PR 1, because lease commands debit the
        lease's own command budget and never the directive's
        cumulative ceiling; issuing anyway would let actuation escape
        the ceiling entirely (the Amplify pass). Budgeted-directive
        leases are a PR 2 reconciliation design question, refused
        here rather than silently unaccounted.
        """

        status = self.directive_status(directive.directive_id, directive.version, directive.directive_hash)
        if status != "active":
            return status
        if directive.parent_directive_hash is not None:
            parent_status = self.directive_hash_status(directive.parent_directive_hash)
            if parent_status != "active":
                return parent_status
        if directive.aggregate_budget is not None:
            return "lease_directive_budget_unsupported"
        now_ns = self._trusted_now()
        if now_ns is None:
            return "directive_clock_invalid"
        return directive.permits(intent, now_ns)

    def _record_lease_directive_denial(self, intent: Intent, directive: Any, digest: str, reason: str) -> LeaseDecision:
        self.record_directive_denial(
            intent,
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            reason=reason,
        )
        return LeaseDecision("deny", reason, digest)

    @staticmethod
    def lease_approval_hash(
        intent: Intent,
        directive: Any,
        *,
        presenter: str | None,
        payload_digest: str,
        max_commands: int,
        max_disconnected_ns: int,
        safe_fallback: str,
        deployment_id: str,
        boot_counter: int,
        sequence_floor: int = 0,
        ttl_ns: int | None = None,
    ) -> str:
        """The approval context digest for one lease issuance.

        The hash an approval envelope must bind (in its
        ``intent_hash`` field) before ``issue_lease_with_approval``
        will mint. It covers the intent and every authority-bearing
        claim the issued lease will carry: the governing directive's
        identity, the payload digest, the command budget, the
        disconnected window, the safe fallback, the deployment, the
        bound presenter, the boot counter, the sequence floor, and
        the requested TTL — the issued expiry is the admission time
        plus that TTL, clamped by the policy cap, and the clamp only
        ever narrows what was approved. The kernel-minted claims
        (nonce, issue time) are not approval material and are not
        covered. Computing the digest is public and harmless: the
        authority is the external signature over an envelope binding
        it, exactly as the intent hash is for permits.
        """

        return sha256(
            _canonical(
                {
                    "schema": "pulpo.lease-approval.v1",
                    "intent_hash": GovernanceKernel.intent_hash(intent),
                    "directive_id": directive.directive_id,
                    "directive_version": directive.version,
                    "directive_hash": directive.directive_hash,
                    "parent_directive_hash": directive.parent_directive_hash,
                    "presenter": presenter,
                    "payload_digest": payload_digest,
                    "max_commands": max_commands,
                    "max_disconnected_ns": max_disconnected_ns,
                    "safe_fallback": safe_fallback,
                    "deployment_id": deployment_id,
                    "boot_counter": boot_counter,
                    "sequence_floor": sequence_floor,
                    "ttl_ns": ttl_ns,
                }
            )
        ).hexdigest()

    def issue_lease(
        self,
        intent: Intent,
        directive: Any,
        *,
        presenter: str | None = None,
        payload_digest: str,
        max_commands: int,
        max_disconnected_ns: int,
        safe_fallback: str,
        deployment_id: str,
        boot_counter: int,
        sequence_floor: int = 0,
        ttl_ns: int | None = None,
    ) -> LeaseDecision:
        """Mint a lease for an intent under an active directive.

        The non-approval issuance path, mirroring ``evaluate``: the
        pinned-policy check, the policy failure check, the directive
        gate (denials recorded through ``record_directive_denial``,
        the projection's evidence shape), and the approval gate —
        an approval action returns ``require_approval`` here and is
        minted only through ``issue_lease_with_approval``.
        """

        self._require_pinned_policy()
        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._lease_decide("deny", failure, digest)
        directive_failure = self._lease_directive_failure(intent, directive)
        if directive_failure is not None:
            return self._record_lease_directive_denial(intent, directive, digest, directive_failure)
        if intent.action in self.policy.approval_actions:
            return self._lease_decide("require_approval", "approval_required", digest)
        return self._mint_lease(
            intent,
            directive,
            digest,
            presenter=presenter,
            payload_digest=payload_digest,
            max_commands=max_commands,
            max_disconnected_ns=max_disconnected_ns,
            safe_fallback=safe_fallback,
            deployment_id=deployment_id,
            boot_counter=boot_counter,
            sequence_floor=sequence_floor,
            ttl_ns=ttl_ns,
        )

    def issue_lease_with_approval(
        self,
        intent: Intent,
        directive: Any,
        envelope: ApprovalEnvelope,
        *,
        ceremony_evidence: CeremonyEvidence | None = None,
        presenter: str | None = None,
        payload_digest: str,
        max_commands: int,
        max_disconnected_ns: int,
        safe_fallback: str,
        deployment_id: str,
        boot_counter: int,
        sequence_floor: int = 0,
        ttl_ns: int | None = None,
    ) -> LeaseDecision:
        """Mint a lease only after the approval path verifies.

        The envelope (and, for ceremony actions, the ceremony
        evidence) is verified by the same ``_verify_approval`` the
        permit path uses — ceremony-gated actions require the
        ceremony path for lease issuance exactly as for permits
        (spec §3). The directive gate runs first, as it does in the
        projection's composition.

        The envelope must bind the lease approval hash of the exact
        claim set requested here (``lease_approval_hash``), not the
        bare intent hash: the approval authenticates the claims, so
        a caller holding a valid approval cannot substitute a
        different payload digest, command budget, presenter,
        deployment, or TTL after verification (Codex P1 on PR #383).
        """

        self._require_pinned_policy()
        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._lease_decide("deny", failure, digest)
        directive_failure = self._lease_directive_failure(intent, directive)
        if directive_failure is not None:
            return self._record_lease_directive_denial(intent, directive, digest, directive_failure)
        approval_digest = self.lease_approval_hash(
            intent,
            directive,
            presenter=presenter,
            payload_digest=payload_digest,
            max_commands=max_commands,
            max_disconnected_ns=max_disconnected_ns,
            safe_fallback=safe_fallback,
            deployment_id=deployment_id,
            boot_counter=boot_counter,
            sequence_floor=sequence_floor,
            ttl_ns=ttl_ns,
        )
        result = self._verify_approval(
            intent,
            envelope,
            ceremony_evidence,
            lambda approval, verified_at_ns: self._mint_lease(
                intent,
                directive,
                digest,
                reason="verified_approval",
                approval=approval,
                envelope=envelope,
                timestamp_ns=verified_at_ns,
                presenter=presenter,
                payload_digest=payload_digest,
                max_commands=max_commands,
                max_disconnected_ns=max_disconnected_ns,
                safe_fallback=safe_fallback,
                deployment_id=deployment_id,
                boot_counter=boot_counter,
                sequence_floor=sequence_floor,
                ttl_ns=ttl_ns,
            ),
            approval_digest=approval_digest,
        )
        if isinstance(result, Decision):
            return LeaseDecision(result.outcome, result.reason, digest)
        return result

    def _mint_lease(
        self,
        intent: Intent,
        directive: Any,
        digest: str,
        *,
        reason: str = "policy_satisfied",
        approval: ApprovalUse | None = None,
        envelope: ApprovalEnvelope | None = None,
        timestamp_ns: int | None = None,
        presenter: str | None,
        payload_digest: str,
        max_commands: int,
        max_disconnected_ns: int,
        safe_fallback: str,
        deployment_id: str,
        boot_counter: int,
        sequence_floor: int,
        ttl_ns: int | None,
    ) -> LeaseDecision:
        # The issuance funnel, mirroring _issue_permit: the pin is
        # re-checked, and every lease parameter is validated here so
        # no entry path mints a malformed artifact. Presenter binding
        # is mandatory for leases (spec §3): a lease is never a
        # bearer artifact, and never bound to a presenter this kernel
        # could not verify a proof from — such a lease would be
        # unspendable by construction, so it is not minted.
        self._require_pinned_policy()
        if presenter is None:
            return self._lease_decide("deny", "presenter_binding_required", digest)
        if not isinstance(presenter, str) or not presenter:
            return self._lease_decide("deny", "presenter_invalid", digest)
        if presenter not in self._presenter_verifiers:
            return self._lease_decide("deny", "presenter_not_registered", digest)
        if not _is_digest(payload_digest):
            return self._lease_decide("deny", "lease_payload_digest_invalid", digest)
        if isinstance(max_commands, bool) or not isinstance(max_commands, int) or max_commands <= 0:
            return self._lease_decide("deny", "lease_command_budget_invalid", digest)
        if isinstance(max_disconnected_ns, bool) or not isinstance(max_disconnected_ns, int) or max_disconnected_ns <= 0:
            return self._lease_decide("deny", "lease_disconnected_window_invalid", digest)
        if not isinstance(safe_fallback, str) or not safe_fallback:
            return self._lease_decide("deny", "lease_safe_fallback_required", digest)
        if not isinstance(deployment_id, str) or not deployment_id:
            return self._lease_decide("deny", "lease_deployment_invalid", digest)
        if isinstance(boot_counter, bool) or not isinstance(boot_counter, int) or boot_counter < 0:
            return self._lease_decide("deny", "lease_boot_counter_invalid", digest)
        if isinstance(sequence_floor, bool) or not isinstance(sequence_floor, int) or sequence_floor < 0:
            return self._lease_decide("deny", "lease_sequence_floor_invalid", digest)
        if ttl_ns is not None and (isinstance(ttl_ns, bool) or not isinstance(ttl_ns, int) or ttl_ns <= 0):
            return self._lease_decide("deny", "lease_ttl_invalid", digest)
        issued_at_ns = self._clock() if timestamp_ns is None else timestamp_ns
        # The requested lifetime is clamped by the policy's permit TTL
        # cap (spec §2): no issuance path stamps a longer one, and the
        # expiry sits inside the signed token, so it cannot be
        # extended by a holder.
        ttl = self.policy.max_permit_ttl_ns if ttl_ns is None else min(ttl_ns, self.policy.max_permit_ttl_ns)
        expires_at_ns = issued_at_ns + ttl
        nonce = secrets.token_hex(16)
        presenter_hash = sha256(presenter.encode()).hexdigest()
        fields: dict[str, Any] = {
            "intent_hash": digest,
            "principal": intent.principal,
            "action": intent.action,
            "resource": intent.resource,
            "payload_digest": payload_digest,
            "directive_id": directive.directive_id,
            "directive_version": directive.version,
            "directive_hash": directive.directive_hash,
            "parent_directive_hash": directive.parent_directive_hash,
            "policy_hash": self.policy_hash,
            "deployment_id": deployment_id,
            "presenter": presenter,
            "session_id": intent.session_id,
            "nonce": nonce,
            "max_commands": max_commands,
            "max_disconnected_ns": max_disconnected_ns,
            "safe_fallback": safe_fallback,
            "sequence_floor": sequence_floor,
            "boot_counter": boot_counter,
            "issued_at_ns": issued_at_ns,
            "expires_at_ns": expires_at_ns,
        }
        probe = Lease(token="probe", **fields)
        lease_digest = probe.lease_digest
        payload = f"{lease_digest}:{nonce}:{issued_at_ns}:{expires_at_ns}:{presenter_hash}"
        signature = hmac.new(self._secret, payload.encode(), sha256).hexdigest()
        token = f"{payload}:{signature}"
        lease = Lease(token=token, **fields)
        if not hmac.compare_digest(lease.lease_digest, lease_digest):
            raise RuntimeError("lease digest does not match its claims")
        issuance = LeaseIssuance(
            lease_digest=lease_digest,
            binding=directive.permit_binding,
            expires_at_ns=expires_at_ns,
            max_commands=max_commands,
            sequence_floor=sequence_floor,
            safe_fallback=safe_fallback,
        )
        replay = self._state.issue_lease(
            token, digest, issuance, issued_at_ns, approval=approval, decision_reason=reason
        )
        if replay:
            if envelope is None:
                raise RuntimeError("state rejected an approval-free lease")
            decision = self._approval_decide(replay, digest, envelope)
            return LeaseDecision(decision.outcome, decision.reason, digest)
        return LeaseDecision("allow", reason, digest, lease)

    @staticmethod
    def lease_proof_payload(lease_token: str, command_hash: str, presenter: str, sequence: int) -> bytes:
        """The exact bytes a device presenter signs to prove a lease command.

        The lease analogue of ``presenter_proof_payload``: the proof
        binds the presenter identity to the exact lease token and the
        exact command hash — which itself binds the action, target,
        payload digest, and sequence — so a proof captured for one
        command verifies for no other.
        """

        return _canonical(
            {
                "schema": LEASE_PROOF_SCHEMA,
                "lease": lease_token,
                "command_hash": command_hash,
                "presenter": presenter,
                "sequence": sequence,
            }
        )

    def _lease_token_claims(self, lease: Lease) -> tuple[str, int, int, str] | None:
        """Authenticate a lease token and cross-check its claims.

        Follows ``_permit_token_claims``: the HMAC recomputed over
        the token's own fields proves the token was minted under
        this kernel's secret and is unaltered. For a lease the signed
        digest is the lease digest — a hash over every claim — so
        authentication extends to the full claim set: the recomputed
        digest of the presented object must equal the token's digest,
        and the token's nonce, times, and presenter hash must equal
        the object's fields. Altering one field of a genuine lease
        (its budget, its expiry) without re-signing therefore fails
        here (acceptance test 11), as does a locally assembled lease
        whose token this kernel never signed (acceptance test 1).
        A lease token is never unbound: an empty-presenter claim
        fails closed like a malformed one.
        """

        token = lease.token
        if not isinstance(token, str):
            return None
        parts = token.split(":")
        if len(parts) != 6:
            return None
        token_digest, nonce, issued_raw, expires_raw, presenter_hash, signature = parts
        issued_at_ns = _token_time_ns(issued_raw)
        expires_at_ns = _token_time_ns(expires_raw)
        if issued_at_ns is None or expires_at_ns is None:
            return None
        if expires_at_ns <= issued_at_ns:
            return None
        if not _is_digest(presenter_hash) or presenter_hash == UNBOUND_PRESENTER_HASH:
            return None
        expected = hmac.new(
            self._secret,
            f"{token_digest}:{nonce}:{issued_raw}:{expires_raw}:{presenter_hash}".encode(),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return None
        try:
            presented_digest = lease.lease_digest
        except Exception:
            return None
        if not hmac.compare_digest(token_digest.encode(), presented_digest.encode()):
            return None
        if nonce != lease.nonce or issued_at_ns != lease.issued_at_ns or expires_at_ns != lease.expires_at_ns:
            return None
        if not hmac.compare_digest(presenter_hash, sha256(lease.presenter.encode()).hexdigest()):
            return None
        return token_digest, issued_at_ns, expires_at_ns, presenter_hash

    def _lease_presenter_refusal(
        self,
        lease: Lease,
        command: LeaseCommand,
        presenter: str | None,
        presenter_proof: str | None,
    ) -> str | None:
        """The presenter gate for lease commands (spec §4 step 3).

        The lease analogue of ``_presenter_refusal``, stricter in one
        respect: a lease is always bound, so there is no bearer path
        to fall through to — a missing or wrong presenter is always a
        refusal (acceptance test 12). Runs after the token is
        authenticated and its expiry enforced, before the store is
        consulted, so a failed presenter attempt never debits the
        command budget. Only the literal ``True`` from the verifier
        is a verdict in favor, as on the permit path.
        """

        if presenter is None or presenter_proof is None:
            return "lease_presenter_proof_required"
        if not isinstance(presenter, str) or not isinstance(presenter_proof, str):
            return "lease_presenter_mismatch"
        if not hmac.compare_digest(presenter.encode(), lease.presenter.encode()):
            return "lease_presenter_mismatch"
        verifier = self._presenter_verifiers.get(presenter)
        if verifier is None:
            return "lease_presenter_unverifiable"
        payload = self.lease_proof_payload(lease.token, command.command_hash, presenter, command.sequence)
        try:
            verified = verifier.verify(payload, presenter_proof)
        except Exception:
            return "lease_presenter_unverifiable"
        if verified is True:
            return None
        if verified is False:
            return "lease_presenter_mismatch"
        return "lease_presenter_unverifiable"

    def _append_lease_rejection(self, lease_digest: str | None, intent_hash: str | None, sequence: int | None, reason: str) -> None:
        self._state.append(
            "lease_rejected",
            {"lease_digest": lease_digest, "intent_hash": intent_hash, "sequence": sequence, "reason": reason},
            self._clock(),
        )

    def consume_lease_command(
        self,
        lease: Lease,
        command: LeaseCommand,
        *,
        presenter: str | None = None,
        presenter_proof: str | None = None,
    ) -> bool:
        """Verify one command under a lease, in spec §4 order.

        (1) The token signature and full-claim binding; (2) the
        signed expiry, enforced here before the store is consulted —
        expiry terminates the lease into its safe fallback, journaled
        with the refusal (spec §6); (3) the named presenter's proof;
        (4) exact intent binding of the command (action, target,
        payload digest — a same-length swap fails), plus the signed
        sequence floor; (5) the store's transition: directive status
        and revocation, stored expiry, sequence monotonicity, and
        the command-budget check-and-debit. Every refusal is recorded
        as ``lease_rejected`` with its reason; kernel-layer refusals
        never debit the budget.
        """

        self._require_pinned_policy()
        if not isinstance(lease, Lease) or not isinstance(command, LeaseCommand):
            self._append_lease_rejection(None, None, None, "lease_invalid")
            return False
        claims = self._lease_token_claims(lease)
        if claims is None:
            self._append_lease_rejection(lease.lease_digest, lease.intent_hash, command.sequence, "lease_signature_invalid")
            return False
        lease_digest, _issued_at_ns, expires_at_ns, _presenter_hash = claims
        now_ns = self._clock()
        if now_ns >= expires_at_ns:
            self._append_lease_rejection(lease_digest, lease.intent_hash, command.sequence, "lease_expired")
            self._state.append(
                "lease_fallback",
                {
                    "lease_digest": lease_digest,
                    "intent_hash": lease.intent_hash,
                    "safe_fallback": lease.safe_fallback,
                    "cause": "lease_expired",
                },
                now_ns,
            )
            return False
        refusal = self._lease_presenter_refusal(lease, command, presenter, presenter_proof)
        if refusal is not None:
            self._append_lease_rejection(lease_digest, lease.intent_hash, command.sequence, refusal)
            return False
        if not (
            hmac.compare_digest(command.action.encode(), lease.action.encode())
            and hmac.compare_digest(command.resource.encode(), lease.resource.encode())
            and hmac.compare_digest(command.payload_digest.encode(), lease.payload_digest.encode())
        ):
            self._append_lease_rejection(lease_digest, lease.intent_hash, command.sequence, "lease_command_mismatch")
            return False
        if command.sequence < lease.sequence_floor:
            self._append_lease_rejection(lease_digest, lease.intent_hash, command.sequence, "lease_sequence_below_floor")
            return False
        return self._state.consume_lease_command(
            lease.token, lease_digest, lease.intent_hash, command.sequence, self._clock()
        )

    def verify_audit_report(self) -> dict[str, Any]:
        """Verify the audit chain and report its signing coverage.

        Returns ``ok`` plus, for every record, whether it was accepted
        as signed or as legacy. The signature field is excluded from
        the hashed body (it is a sibling of ``hash``, not part of it),
        so the unkeyed chain math is identical to before signing
        existed. When the state carries no signer, every record
        verifies legacy-style and ``signing_enabled`` is False — the
        exact pre-signing behavior. When a signer is configured,
        every record at or after the legacy prefix must carry a valid
        signature: a missing one fails as ``audit_signature_missing``,
        a present-but-wrong one as ``audit_signature_invalid``. A
        signature that is present anywhere must verify, including on
        legacy-prefix records — a record carries no signature it cannot
        prove. Malformed records fail as ``audit_record_malformed``
        instead of raising, so callers that treat verification as a
        boolean (boot included) fail closed the same way.
        """

        signer = getattr(self._state, "audit_signer", None)
        try:
            legacy_records = int(getattr(self._state, "legacy_audit_records", 0) or 0)
        except (TypeError, ValueError):
            legacy_records = 0
        report: dict[str, Any] = {
            "ok": True,
            "reason": None,
            "total_records": 0,
            "signed_records": 0,
            "unsigned_records": 0,
            "legacy_records": legacy_records,
            "signing_enabled": signer is not None,
            "failed_record": None,
        }
        previous = "0" * 64
        try:
            records = self.audit
        except Exception:
            report.update({"ok": False, "reason": "audit_record_malformed"})
            return report
        for index, record in enumerate(records):
            report["total_records"] = index + 1
            try:
                body = {key: value for key, value in record.items() if key not in ("hash", "signature")}
                if body["previous_hash"] != previous:
                    report.update({"ok": False, "reason": "audit_previous_hash_mismatch", "failed_record": index})
                    return report
                expected = sha256(_canonical(body)).hexdigest()
                if not hmac.compare_digest(str(record["hash"]), expected):
                    report.update({"ok": False, "reason": "audit_hash_mismatch", "failed_record": index})
                    return report
            except (AttributeError, KeyError, TypeError, ValueError):
                report.update({"ok": False, "reason": "audit_record_malformed", "failed_record": index})
                return report
            signature = record.get("signature") if isinstance(record, dict) else None
            if signature is not None:
                if signer is None or not signer.verify(record["hash"], signature):
                    # With no signer configured there is nothing a
                    # signature could be verified against, so a present
                    # signature on an unsigned chain is itself a
                    # forgery-shaped anomaly: fail rather than ignore.
                    report.update({"ok": False, "reason": "audit_signature_invalid", "failed_record": index})
                    return report
                report["signed_records"] += 1
            elif signer is not None and index >= legacy_records:
                report.update({"ok": False, "reason": "audit_signature_missing", "failed_record": index})
                return report
            else:
                report["unsigned_records"] += 1
            previous = record["hash"]
        return report

    def verify_audit(self) -> bool:
        return bool(self.verify_audit_report()["ok"])

    # ------------------------------------------------------------------
    # Capability facade (Phase 2, Item 3A)
    #
    # The verbs below are the governed write/read surface sibling
    # modules use instead of reaching ``kernel._state`` directly.
    # Before Item 3A, production code held the state handle around the
    # kernel: directives.py activated/revoked/bound through it,
    # custody_reconcile.py appended outcome memory through it,
    # target_reconcile.py appended completions through it, and
    # incident_channel.py read the backend object itself. Every one of
    # those writes now flows through a kernel method with a fixed
    # event schema, and a structural regression test pins production
    # modules at zero ``_state`` reach-through.
    #
    # Honest scope (ruling Q5): the facade is discipline + evidence,
    # NOT in-process enforcement. The state object still exists inside
    # this process, and a determined in-process caller can construct a
    # backend directly and write around every verb here. What 3A
    # proves is narrower and checkable: no production module possesses
    # the ungoverned handle, every production write has one reviewable
    # governed path, and directive mutation additionally requires the
    # typed VerifiedAuthorityEvidence at the state surface itself.
    # Process-boundary enforcement is Item 3B, the Phase 3 program.
    # ------------------------------------------------------------------

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        """Facade read: the recorded status of one exact directive version."""

        return self._state.directive_status(directive_id, version, directive_hash)

    def directive_hash_status(self, directive_hash: str) -> str:
        """Facade read: the recorded status of a directive by its hash."""

        return self._state.directive_hash_status(directive_hash)

    def budget_spent(self, scope_key: str) -> int:
        """Facade read: total cost already debited under one budget bucket.

        Read-only and advisory: the directive projection consults it
        as an issuance-time early check. The decisive budget check is
        the atomic check-and-debit inside the state backend's consume
        transition, never this read.
        """

        return self._state.budget_spent(scope_key)

    def activate_directive(
        self,
        directive: Any,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: record a verified directive activation.

        The only production caller is ``DirectiveAuthorityController``,
        after envelope verification and the one-use authority-permit
        consume. The state layer requires the typed evidence and
        cross-checks its binding, so the fabricated-bare-dict
        activation from design repro 3 (part B) fails at this surface.
        """

        self._state.activate_directive(directive, authority_evidence, timestamp_ns)

    def revoke_directive(
        self,
        directive_id: str,
        version: int,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: record a verified directive revocation."""

        self._state.revoke_directive(directive_id, version, authority_evidence, timestamp_ns)

    def bind_permit_to_directive(
        self,
        permit: str,
        intent_hash: str,
        binding: DirectivePermitBinding,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: bind an issued permit to its live directive."""

        self._state.bind_permit_to_directive(permit, intent_hash, binding, timestamp_ns)

    def record_directive_denial(
        self,
        intent: Intent,
        *,
        directive_id: str,
        version: int,
        directive_hash: str,
        reason: str,
    ) -> None:
        """Facade verb: record a directive-scope denial in the audit.

        Kernel build item #2: the directive projection returns its
        directive-scope denials (directive not active, parent not
        active, mandate failure, aggregate-budget early check)
        without a kernel evaluation, so before this verb those
        denials appended nothing — a refused attempt was invisible
        to the canonical audit and to reconciliation, unlike
        kernel-reached denials (``decision``) and consume denials
        (``permit_rejected``), which append exactly one record each.
        The projection reports each of its denials through this verb
        instead. The schema is fixed: the caller supplies the intent,
        the directive's identity, and the reason it already computed;
        the kernel derives the intent hash and appends exactly one
        ``directive_denial`` record with ``authority_effect=none``.
        Recording a denial grants nothing, spends nothing, and
        changes no directive state.

        Clock posture (Codex P2 on PR #372): the projection computes
        its status denials before any trusted-time check, and those
        paths returned their fail-closed Decision without touching
        the clock before this verb existed — so the record must
        never let an unavailable clock change the outcome. The
        record time is resolved through ``_trusted_now`` (the
        ``approval_rejected`` precedent in ``_approval_decide``);
        an unavailable clock stamps 0, the same visible sentinel
        approval rejections carry, instead of propagating the
        clock's exception, writing an invalid ``None`` timestamp
        into the in-memory chain, or tripping the SQLite backend's
        NOT NULL timestamp constraint. The denial is still recorded
        exactly once; only its timestamp degrades.
        """

        trusted_time = self._trusted_now()
        record_time = 0 if trusted_time is None else trusted_time
        self._state.append(
            "directive_denial",
            {
                "schema": "pulpo.directive-denial.v0",
                "directive_id": directive_id,
                "version": version,
                "directive_hash": directive_hash,
                "intent_hash": self.intent_hash(intent),
                "principal": intent.principal,
                "action": intent.action,
                "resource": intent.resource,
                "cost": intent.cost,
                "session_id": intent.session_id,
                "reason": reason,
                "authority_effect": "none",
            },
            record_time,
        )

    def record_target_completion(
        self,
        *,
        target_id: str,
        version: int,
        target_hash: str,
        intent_hash: str,
        artifact_path: str | Path,
        timestamp_ns: int,
    ) -> dict[str, Any]:
        """Facade verb: observe an artifact and append its completion record.

        Fixed schema, verified at the append surface (Codex P1 fix on
        PR #359): the verb takes an artifact *path*, never a
        caller-supplied completion dict or hash. It resolves the
        locked target, cross-checks the exact target and intent
        hashes, and observes the file itself through
        ``_observe_artifact_file`` — the same descriptor-bound stable
        observation the governed projection performs — so evidence
        naming a nonexistent or unobserved file cannot be recorded.
        Returns the completion dict exactly as recorded.
        """

        target = self.get_locked_target(target_id, version=version)
        if target is None:
            raise ValueError("target_not_locked")
        if not isinstance(target_hash, str):
            raise ValueError("target_hash_mismatch")
        if not hmac.compare_digest(target.target_hash, target_hash):
            raise ValueError("target_hash_mismatch")
        expected_intent_hash = self.intent_hash(target.intent)
        if not isinstance(intent_hash, str):
            raise ValueError("target_intent_mismatch")
        if not hmac.compare_digest(expected_intent_hash, intent_hash):
            raise ValueError("target_intent_mismatch")
        if timestamp_ns < target.created_at_ns:
            raise RuntimeError("artifact_observed_before_target")

        resolved_path, artifact_sha256, size_bytes = _observe_artifact_file(artifact_path)
        completion: dict[str, Any] = {
            "target_id": target.target_id,
            "version": target.version,
            "target_hash": target.target_hash,
            "intent_hash": expected_intent_hash,
            "artifact_path": resolved_path,
            "artifact_sha256": artifact_sha256,
            "size_bytes": size_bytes,
            "observed_at_ns": timestamp_ns,
            "schema": "pulpo.target-artifact-completion.v0",
        }
        completion_hash = sha256(_canonical(completion)).hexdigest()
        self._state.append(
            "target_completed",
            {
                "target_id": target.target_id,
                "version": target.version,
                "target_hash": target.target_hash,
                "intent_hash": expected_intent_hash,
                "completion": completion,
                "completion_hash": completion_hash,
                "authority_effect": "none",
            },
            timestamp_ns,
        )
        return completion

    def record_domain_outcome_memory(
        self,
        *,
        reconciliation_transition_hash: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        """Facade verb: verify, then append-once, a domain outcome-memory record.

        Fixed schema: the ``domain_outcome_memory`` event, unique on
        ``reconciliation_transition_hash``. Returns the existing
        payload when a record with that identity already exists (the
        state layer's ``append_unique`` contract), else None.

        Verified at the append surface (Codex P1 fix on PR #359): a
        self-asserted payload is refused — with a distinct
        ``outcome_memory_*`` ``ValueError`` and nothing appended —
        unless its identity hash recomputes, its policy hash is this
        kernel's, exactly one projected custody-transition evidence
        record backs its transition hash with a receipt bound to its
        order hash and epoch, its classification is consistent with
        that receipt's transition type, and exactly one locked target
        in the audit carries its target and intent hashes. The kernel
        cannot re-derive the custody layer's observation/budget
        checks; those remain the projection's authority (see the
        change record).
        """

        if not isinstance(payload, dict):
            raise ValueError("outcome_memory_payload_invalid")
        if payload.get("reconciliation_transition_hash") != reconciliation_transition_hash:
            raise ValueError("outcome_memory_transition_hash_mismatch")
        if payload.get("schema") != "pulpo.domain-outcome-memory.v0":
            raise ValueError("outcome_memory_schema_mismatch")
        if payload.get("authority_effect") != "none":
            raise ValueError("outcome_memory_authority_effect_mismatch")
        if payload.get("governed_effect") != "canonical_outcome_memory":
            raise ValueError("outcome_memory_governed_effect_mismatch")

        identity = {
            "schema": "pulpo.domain-outcome-memory.v0",
            "attempt_id": payload.get("attempt_id"),
            "order_hash": payload.get("order_hash"),
            "target_hash": payload.get("target_hash"),
            "intent_hash": payload.get("intent_hash"),
            "policy_hash": payload.get("policy_hash"),
            "observation_hash": payload.get("observation_hash"),
            "reconciliation_transition_hash": payload.get("reconciliation_transition_hash"),
            "reconciliation_epoch": payload.get("reconciliation_epoch"),
            "reconciliation_outcome": payload.get("reconciliation_outcome"),
            "classification": payload.get("classification"),
            "reason": payload.get("reason"),
            "reusable": payload.get("reusable"),
            "authority_effect": "none",
            "governed_effect": "canonical_outcome_memory",
        }
        expected_memory_id = sha256(_canonical(identity)).hexdigest()
        memory_id = payload.get("memory_id")
        if not isinstance(memory_id, str):
            raise ValueError("outcome_memory_memory_id_mismatch")
        if not hmac.compare_digest(expected_memory_id, memory_id):
            raise ValueError("outcome_memory_memory_id_mismatch")

        if payload.get("policy_hash") != self.policy_hash:
            raise ValueError("outcome_memory_policy_hash_mismatch")

        custody_matches: list[dict[str, Any]] = []
        for record in self.audit:
            if record.get("event") != "custody_transition":
                continue
            record_payload = record.get("payload")
            if not isinstance(record_payload, dict):
                continue
            if record_payload.get("transition_hash") == reconciliation_transition_hash:
                custody_matches.append(record_payload)
        if len(custody_matches) != 1:
            if not custody_matches:
                raise ValueError("outcome_memory_custody_evidence_missing")
            raise ValueError("outcome_memory_custody_evidence_ambiguous")
        evidence = custody_matches[0]
        receipt = evidence.get("receipt")
        if (
            evidence.get("schema") != "pulpo.custody-evidence-projection.v0"
            or not isinstance(receipt, dict)
            or receipt.get("transition_hash") != reconciliation_transition_hash
            or receipt.get("object_hash") != payload.get("order_hash")
            or receipt.get("epoch") != payload.get("reconciliation_epoch")
        ):
            raise ValueError("outcome_memory_custody_evidence_mismatch")

        transition_type = receipt.get("transition_type")
        outcome = payload.get("reconciliation_outcome")
        classification = payload.get("classification")
        reusable = payload.get("reusable")
        if transition_type == "reconciled_success":
            consistent = (
                outcome == "success"
                and classification == "SUCCESS_VERIFIED"
                and reusable is True
            )
        elif transition_type == "reconciled_failure":
            consistent = (
                outcome == "failure"
                and classification in {"RECONCILIATION_FAILURE", "RECONCILIATION_MISMATCH"}
                and reusable is False
            )
        elif transition_type == "unresolved":
            consistent = (
                outcome == "unresolved"
                and classification == "EVIDENCE_FAILURE"
                and reusable is False
            )
        else:
            raise ValueError("outcome_memory_custody_transition_type_invalid")
        if not consistent:
            raise ValueError("outcome_memory_classification_mismatch")

        target_matches: list[dict[str, Any]] = []
        for record in self.audit:
            if record.get("event") != "target_locked":
                continue
            record_payload = record.get("payload")
            if not isinstance(record_payload, dict):
                continue
            if record_payload.get("target_hash") == payload.get("target_hash"):
                target_matches.append(record_payload)
        if len(target_matches) != 1:
            if not target_matches:
                raise ValueError("outcome_memory_target_missing")
            raise ValueError("outcome_memory_target_ambiguous")
        if target_matches[0].get("intent_hash") != payload.get("intent_hash"):
            raise ValueError("outcome_memory_target_intent_mismatch")

        return self._state.append_unique(
            "domain_outcome_memory",
            "reconciliation_transition_hash",
            reconciliation_transition_hash,
            payload,
            timestamp_ns,
        )

    def state_source_id(self) -> str:
        """Opaque process-scoped identifier for this kernel's backend.

        Read-only identification for evidence derivation (the incident
        channel stamps its reports with which backend instance they
        were derived from). Exposing an identifier is not exposing the
        handle: callers learn a stable name for the backend in this
        process, never the object. A SQLite backend whose connection
        carries an ``activity_id`` reports that id, as before.
        """

        backend = self._state
        source_id = sha256(f"{os.getpid()}:{id(backend)}".encode()).hexdigest()[:32]
        if type(backend) is SQLiteKernelState:
            activity_id = getattr(backend._connection, "activity_id", None)
            if type(activity_id) is str and activity_id:
                source_id = activity_id
        return source_id

    def _decide(self, outcome: str, reason: str, digest: str, permit: str | None = None) -> Decision:
        decision = Decision(outcome, reason, digest, permit)
        self._append("decision", {"outcome": outcome, "reason": reason, "intent_hash": digest})
        return decision

    def _append(self, event: str, payload: dict[str, Any]) -> None:
        self._state.append(event, payload, self._clock())
