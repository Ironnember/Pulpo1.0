"""Fail-closed developer gate over the one Pulpo governance kernel.

These helpers are the integration surface a developer wraps around a
consequential action so the action runs only behind a consumed permit.
They delegate every authority decision to ``GovernanceKernel``: they
mint nothing, alter no policy, hold no signing material, and create no
second router, executor, or evidence path. What they add is discipline
at the call site:

- approval is never inferred — the action runs only after ``evaluate``
  returns the literal outcome ``"allow"`` with a permit AND ``consume``
  returns the literal ``True`` for that permit and the exact intent;
- every other outcome — ``deny``, ``require_approval``, a missing
  permit, a refused consume, a malformed decision, or any exception
  raised by the kernel or its state backend — raises
  :class:`PermitRefused` and the action does not run;
- a refusal is a record, not an obstacle: the kernel has already
  appended its decision / ``permit_rejected`` entries to the audit
  chain, and this module never retries, re-mints, or routes around one.

Presenter binding: when a presenter is configured, the permit is bound
to that presenter at issuance and the consume requires that presenter's
proof. The proof is produced by a caller-supplied ``proof_provider``
callback — the presenter's signing key stays with the presenter (or its
signing service); this module only carries the finished proof string
to ``consume``, exactly as the kernel's own API expects. A gate
configured with a presenter but no proof provider refuses locally
rather than presenting an unprovable consumption.

Approval-required actions are out of this helper's scope by design:
``evaluate`` answers ``require_approval`` for them and the gate raises.
Minting those permits is the governed approval path
(``GovernanceKernel.evaluate_with_approval`` with an envelope from the
authority service); a permit obtained that way can still be spent
through :func:`spend_permit` / :meth:`PermitGate.run_with_permit`.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from .kernel import Decision, GovernanceKernel, Intent

# The proof a presenter presents for one consumption, produced by the
# presenter's own signer from the exact permit, intent, and presenter
# identity (see ``GovernanceKernel.presenter_proof_payload``).
ProofProvider = Callable[[str, Intent, str], str]


class PermitRefused(RuntimeError):
    """The gate refused to let the action run.

    Carries the kernel's own verdict where one exists: ``outcome`` and
    ``reason`` from the ``Decision`` for an evaluation refusal, or the
    gate's own outcome labels (``consume_refused``, ``kernel_error``,
    ``presenter_proof_unavailable``) for refusals past evaluation. The
    kernel's audit chain holds the durable record either way.
    """

    def __init__(self, outcome: str, reason: str, intent_hash: str | None = None) -> None:
        super().__init__(f"permit refused: outcome={outcome} reason={reason}")
        self.outcome = outcome
        self.reason = reason
        self.intent_hash = intent_hash


def _proof_for(
    proof_provider: ProofProvider | None,
    permit: str,
    intent: Intent,
    presenter: str | None,
    intent_hash: str | None,
) -> str | None:
    if presenter is None:
        return None
    if proof_provider is None:
        raise PermitRefused(
            "presenter_proof_unavailable",
            "a presenter is configured but no proof provider was supplied",
            intent_hash,
        )
    try:
        return proof_provider(permit, intent, presenter)
    except PermitRefused:
        raise
    except Exception as exc:
        raise PermitRefused(
            "kernel_error",
            f"presenter proof provider failed: {exc}",
            intent_hash,
        ) from exc


def spend_permit(
    kernel: GovernanceKernel,
    permit: str,
    intent: Intent,
    *,
    presenter: str | None = None,
    presenter_proof: str | None = None,
) -> None:
    """Consume ``permit`` for the exact ``intent``, or raise.

    For permits minted outside this call (an approval flow, a standing
    directive): the action may proceed only when the kernel's
    ``consume`` returns the literal ``True``. Expiry, intent mismatch,
    presenter refusal, replay, and revocation all surface as
    :class:`PermitRefused` — the kernel records the specific reason in
    the audit chain (a ``permit_rejected`` entry) and this helper
    deliberately does not invent a more specific one.
    """

    try:
        digest = kernel.intent_hash(intent)
    except Exception as exc:
        raise PermitRefused("kernel_error", f"intent hashing failed: {exc}") from exc
    try:
        consumed = kernel.consume(
            permit,
            intent,
            presenter=presenter,
            presenter_proof=presenter_proof,
        )
    except Exception as exc:
        raise PermitRefused("kernel_error", f"kernel consume failed: {exc}", digest) from exc
    if consumed is not True:
        raise PermitRefused(
            "consume_refused",
            "kernel consume did not return True; the specific refusal reason is recorded in the audit chain",
            digest,
        )


def require_permit(
    kernel: GovernanceKernel,
    intent: Intent,
    *,
    presenter: str | None = None,
    proof_provider: ProofProvider | None = None,
) -> Decision:
    """Evaluate ``intent`` and consume its permit, or raise.

    Returns the kernel's ``allow`` Decision after its permit has been
    consumed for the exact intent. The caller may run the consequential
    action only after this returns; if it raises, the action must not
    run. Consumption happens here, before the action, because a Pulpo
    permit is spent at the moment of the act it authorizes — an action
    that runs first and consumes later is not governed by the permit.
    """

    try:
        decision = kernel.evaluate(intent, presenter=presenter)
    except Exception as exc:
        raise PermitRefused("kernel_error", f"kernel evaluate failed: {exc}") from exc
    outcome = getattr(decision, "outcome", None)
    reason = getattr(decision, "reason", "decision_malformed")
    digest = getattr(decision, "intent_hash", None)
    permit = getattr(decision, "permit", None)
    if outcome != "allow" or not isinstance(permit, str) or not permit:
        # A non-allow outcome, or an "allow" carrying no permit, is a
        # refusal. Approval is the permit, never the absence of an error.
        raise PermitRefused(str(outcome), str(reason), digest)
    proof = _proof_for(proof_provider, permit, intent, presenter, digest)
    spend_permit(kernel, permit, intent, presenter=presenter, presenter_proof=proof)
    return decision


class PermitGate:
    """A kernel plus its presenter configuration, as one gate object.

    Construct one gate per integration (one kernel, one presenter
    identity) and route every consequential action through it.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        *,
        presenter: str | None = None,
        proof_provider: ProofProvider | None = None,
    ) -> None:
        self._kernel = kernel
        self._presenter = presenter
        self._proof_provider = proof_provider

    def require(self, intent: Intent) -> Decision:
        """Evaluate and consume a permit for ``intent``, or raise."""

        return require_permit(
            self._kernel,
            intent,
            presenter=self._presenter,
            proof_provider=self._proof_provider,
        )

    def run(self, intent: Intent, action: Callable[[], Any]) -> Any:
        """Run ``action`` only behind a freshly consumed permit."""

        self.require(intent)
        return action()

    def run_with_permit(self, permit: str, intent: Intent, action: Callable[[], Any]) -> Any:
        """Run ``action`` only behind the successful spend of ``permit``.

        For permits minted outside this gate (approval or directive
        flows). The presenter proof, when this gate's presenter is
        bound to the permit, is produced by the gate's proof provider
        for this exact permit and intent.
        """

        proof = _proof_for(self._proof_provider, permit, intent, self._presenter, None)
        spend_permit(
            self._kernel,
            permit,
            intent,
            presenter=self._presenter,
            presenter_proof=proof,
        )
        return action()

    @contextmanager
    def guard(self, intent: Intent) -> Iterator[Decision]:
        """``with gate.guard(intent):`` — the body runs post-consume.

        The permit is consumed on entry; if the gate raises, the body
        never runs. An exception inside the body propagates — the
        permit stays consumed, because consumption precedes the act.
        """

        decision = self.require(intent)
        yield decision
