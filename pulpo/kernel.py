"""Small, deterministic governance kernel with no runtime dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import secrets
import time
from typing import Any, Callable

from .authority import ApprovalEnvelope, ApprovalVerifier, AuthorityTrust
from .ceremony import CeremonyEvidence, CeremonyTrust, CeremonyVerifier
from .state import ApprovalUse, InMemoryKernelState, KernelState


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


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

    def __post_init__(self) -> None:
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


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    intent_hash: str
    permit: str | None = None


class StateIntegrityError(RuntimeError):
    """Raised when persisted audit state cannot be trusted at bootstrap."""


class AuthorityTrustError(RuntimeError):
    """Raised when a configured verifier does not match pinned policy trust."""


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
    ) -> None:
        self.policy = policy
        self._secret = secret or secrets.token_bytes(32)
        self._approval_verifier = approval_verifier
        self._ceremony_verifier = ceremony_verifier
        self._clock = clock or time.time_ns
        self._state = state if state is not None else InMemoryKernelState()
        if self._approval_verifier is not None and not self._verifier_matches_trust(self._approval_verifier):
            raise AuthorityTrustError("approval verifier does not match pinned authority trust")
        if self._ceremony_verifier is not None and not self._ceremony_verifier_matches_trust(self._ceremony_verifier):
            raise AuthorityTrustError("ceremony verifier does not match pinned ceremony trust")
        try:
            audit_valid = self.verify_audit()
        except Exception as exc:
            raise StateIntegrityError("kernel state audit chain is invalid") from exc
        if not audit_valid:
            raise StateIntegrityError("kernel state audit chain is invalid")

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._state.audit

    @staticmethod
    def intent_hash(intent: Intent) -> str:
        return sha256(_canonical(asdict(intent))).hexdigest()

    @property
    def policy_hash(self) -> str:
        grants = [
            {
                "principal": grant.principal,
                "allowed_actions": sorted(grant.allowed_actions),
                "resource_prefixes": sorted(grant.resource_prefixes),
                "max_cost": grant.max_cost,
            }
            for grant in sorted(self.policy.agent_grants, key=lambda item: item.principal)
        ]
        payload = {
            "schema": "pulpo.policy.v1",
            "allowed_actions": sorted(self.policy.allowed_actions),
            "max_cost": self.policy.max_cost,
            "approval_actions": sorted(self.policy.approval_actions),
            "agent_grants": grants,
            "authority_trust": asdict(self.policy.authority_trust) if self.policy.authority_trust else None,
        }
        if self.policy.ceremony_actions or self.policy.ceremony_trust is not None:
            # Opted-in policies bind their ceremony configuration into the
            # policy hash. Policies that never opted in keep the exact
            # pre-ceremony hash, so their envelopes and behavior are unchanged.
            payload["ceremony_actions"] = sorted(self.policy.ceremony_actions)
            payload["ceremony_trust"] = asdict(self.policy.ceremony_trust) if self.policy.ceremony_trust else None
        return sha256(_canonical(payload)).hexdigest()

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
    ) -> tuple[TargetResolution, Decision | None]:
        """Resolve an exact target, then delegate authority to the normal evaluator."""

        resolution = self.resolve_locked_target(target_id, expected_target_hash, version=version)
        if resolution.outcome != "match" or resolution.target is None:
            return resolution, None
        return resolution, self.evaluate(resolution.target.intent)

    def evaluate(self, intent: Intent) -> Decision:
        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._decide("deny", failure, digest)
        if intent.action in self.policy.approval_actions:
            return self._decide("require_approval", "approval_required", digest)

        return self._issue_permit(digest)

    def evaluate_with_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        *,
        ceremony_evidence: CeremonyEvidence | None = None,
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

        digest = self.intent_hash(intent)
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
        return self._issue_permit(
            digest,
            reason="verified_approval",
            approval=approval,
            envelope=envelope,
            timestamp_ns=verified_at_ns,
        )

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
    ) -> Decision:
        nonce = secrets.token_hex(16)
        payload = f"{digest}:{nonce}"
        signature = hmac.new(self._secret, payload.encode(), sha256).hexdigest()
        permit = f"{payload}:{signature}"
        issued_at_ns = self._clock() if timestamp_ns is None else timestamp_ns
        replay = self._state.issue_permit(permit, digest, reason, issued_at_ns, approval)
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

    def consume(self, permit: str, intent: Intent) -> bool:
        digest = self.intent_hash(intent)
        return self._state.consume_permit(permit, digest, self._clock())

    def verify_audit(self) -> bool:
        previous = "0" * 64
        for record in self.audit:
            body = {key: value for key, value in record.items() if key != "hash"}
            if body["previous_hash"] != previous:
                return False
            expected = sha256(_canonical(body)).hexdigest()
            if not hmac.compare_digest(record["hash"], expected):
                return False
            previous = record["hash"]
        return True

    def _decide(self, outcome: str, reason: str, digest: str, permit: str | None = None) -> Decision:
        decision = Decision(outcome, reason, digest, permit)
        self._append("decision", {"outcome": outcome, "reason": reason, "intent_hash": digest})
        return decision

    def _append(self, event: str, payload: dict[str, Any]) -> None:
        self._state.append(event, payload, self._clock())
