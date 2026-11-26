"""Scenario test: the November 2026 Microsoft ``agent-framework``
PyPI compromise, modeled against the canonical kernel API.

Incident (graded from the two primary analyses — StepSecurity's
static analysis of both quarantined wheels, corroborated by Wiz):

- **Verified** (StepSecurity's analysis of the wheels it downloaded
  from the PyPI file host; Wiz's independent analysis converges):
  on 2026-11-17, two malicious releases of Microsoft's official
  ``agent-framework`` Python package were published to PyPI —
  1.26.1 (uploaded 20:35:20 UTC, quarantined 21:06:16 UTC, about
  31 minutes later) and 1.26.2 (uploaded 21:08:39 UTC, about two
  minutes AFTER the first quarantine, itself quarantined at
  21:16:44 UTC). Both wheels carried a credential stealer
  installed as a ``.pth`` startup hook (``agent_framework_meta.pth``
  in 1.26.1; ``af_runtime_diag.pth`` in 1.26.2), so the payload
  executed at Python interpreter startup whenever the interpreter
  processed the affected site-packages — no import of the package
  required. The payload harvested environment variables and
  credential files, scraped other processes' environments via
  ``/proc/*/environ``, minted fresh identity tokens from GitHub
  Actions OIDC, Azure DevOps OIDC, and Azure managed-identity
  endpoints, and exfiltrated everything to a public webhook
  endpoint. Both malicious wheels were wheel-only and carried NO
  provenance attestation, unlike the clean 1.26.0 release
  (2026-11-12, wheel + sdist). Quarantining 1.26.1 did not stop
  1.26.2: the uploader retained publishing access, so the
  artifact-level response never reached the publisher's
  authority.
- **Recorded** (Wiz): of the requests captured at the attacker's
  public webhook, seventeen represented three unique, successful
  cases of victim-data exfiltration.
- **Inferred** (Wiz's account, NOT confirmed by Microsoft): the
  attacker appears to have compromised a client certificate and
  private key for Microsoft's ESRP release pipeline and published
  through it. This scenario does not state that mechanism as
  fact; it models the class — release-pipeline credentials are
  not the reviewer authority — which holds whichever access
  story is true.
- **Unknown**: the initial access vector and the uploader's
  identity. StepSecurity states its evidence establishes neither,
  and Wiz states how the credentials were obtained is not yet
  known. Not modeled.

This module does NOT reproduce agent-framework, the payload, or
any part of the stealer. The malicious "wheels" below are
synthetic byte strings that merely NAME the hook files from the
incident; no payload code exists in this file, and the credential
store holds synthetic placeholder strings, never real secrets.
The "publisher" is this harness holding intents; the only route
from intent to a published or installed release is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash, and the intent names the package, the version, the
exact wheel bytes by SHA-256, AND the provenance attestation by
hash — the permit binds the act, not the channel it arrived on.

The distinct contributions of this scenario, against the
existing incident battery (WPPConnect covers provenance without
authorization on npm; OPTIMJACK covers trusted-CDN content
substitution):

1. **Execution decoupled from install.** The ``.pth`` hook makes
   interpreter startup itself a consequential act, repeated at
   every launch, that no install authorization ever named.
   Step 4 treats startup execution as its own governed act and
   shows it has no permit to spend.
2. **Quarantine is not revocation** (the signature case, step
   6). PyPI's quarantine of 1.26.1 was the correct artifact-level
   response and it did not stop 1.26.2 two minutes later,
   because the publisher's authority was never revoked. Setup B
   tests both states honestly: with the artifact quarantined but
   the publisher directive still active, the second upload still
   executes (the counterfactual); with the directive revoked,
   the second upload is refused and previously issued,
   unconsumed permits die at consume.

Setup A (approval path): each publish and install requires the
reviewer authority's approval of the exact wheel bytes and
attestation. The incident's acts are then attempted: a publish
with no permit, the hooked wheel substituted under the clean
release's permit, a permit-less startup-hook execution, an
unattested release presented for evaluation (including under an
envelope signed by the release pipeline's own key — the
ESRP-analog), replay of a spent install permit, and
reconciliation of the index-side observer's records against the
kernel audit in both directions, including a provenance-history
rewrite attempt checked against submission-time audit order.

Setup B (directive path): publishes and installs flow under the
publisher's standing directive, scoped to the package. The
compromise plays out inside that scope (the directive delegates
the acts; it does not review content), incident response then
acts — first artifact quarantine alone (insufficient, tested as
the counterfactual), then revocation of the directive (the
second upload refused; an unconsumed install permit for the
quarantined release dies at consume with the directive recorded
as revoked).

Boundary: this proves kernel behavior at this commit for this
action class (Verified, executable evidence). It proves nothing
about PyPI, Microsoft, or ESRP themselves; it does not model how
publishing access was obtained (Unknown in the sources) or the
payload's behavior, and it models only the main package — the
satellite ``agent-framework-*`` packages are further acts of the
same class, not separately modeled. A pipeline or index that
does not route its publishes and installs through the gate is
governed by nothing here: a control not on the execution path
governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's pull
request per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only — exactly the authority-approved publishes, installs, and
executions are permitted, and any non-kernel publish, install,
or execution path (the known direct-writer class) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): each denied attempt that reaches the
kernel appends exactly one audit record — a governed effect
(evidence production), bounded at one record per attempt,
append-only, ``authority_effect=none``. The refusals that never
reach the kernel are the index double's own pre-consumption
checks (an intent/presentation mismatch, and the artifact
quarantine of a specific version): internally inconsistent or
artifact-blocked presentations, refused before consumption,
appending nothing — stated here rather than claimed away.
"Consequence" below means governed external consequence — a
release actually recorded by the index, bytes actually
installed, or data actually exfiltrated — never audit growth.
"""

from __future__ import annotations

import hashlib
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, directive


NOW = 3_000_000
AGENT = "agent:release-pipeline"
SESSION = "ms-agent-framework-2026-11"

PACKAGE = "agent-framework"
V_CLEAN = "1.26.0"
V_BAD1 = "1.26.1"
V_BAD2 = "1.26.2"

# Synthetic byte strings standing in for wheels. Only their hashes
# enter intents; the malicious wheels merely NAME the hook files
# from the incident — they contain no payload code. The clean
# wheel names no .pth file.
CLEAN_WHEEL = (
    b"agent-framework 1.26.0 wheel | agent_framework_meta/__init__.py"
    b" (clean release) | wheel + sdist, provenance attested"
)
HOOKED_WHEEL_1 = (
    b"agent-framework 1.26.1 wheel | agent_framework_meta.pth +"
    b" agent_framework_meta/_telemetry.py | wheel only, no provenance"
)
HOOKED_WHEEL_2 = (
    b"agent-framework 1.26.2 wheel | af_runtime_diag.pth +"
    b" af_runtime_diag.py | wheel only, no provenance"
)

# The clean release's provenance attestation, as a synthetic
# reference string; only its hash enters intents. The malicious
# wheels carried no attestation (None).
CLEAN_ATTESTATION = "provenance:attested:agent-framework@1.26.0"

ACTIONS = frozenset({"publish_release", "install_release", "execute_startup_hook"})


def wheel_hash(wheel: bytes) -> str:
    return hashlib.sha256(wheel).hexdigest()


def attestation_hash(attestation: str | None) -> str:
    if attestation is None:
        return "none"
    return hashlib.sha256(attestation.encode()).hexdigest()


def release_target(version: str, wheel: bytes, attestation: str | None) -> str:
    """The target names the package, the version, the exact wheel
    bytes by hash, AND the provenance attestation by hash."""
    return (
        f"pypi:{PACKAGE}@{version}"
        f"#wheel={wheel_hash(wheel)}#att={attestation_hash(attestation)}"
    )


def publish_intent(version: str, wheel: bytes, attestation: str | None) -> Intent:
    return Intent(
        AGENT,
        "publish_release",
        release_target(version, wheel, attestation),
        len(wheel),
        SESSION,
    )


def install_intent(version: str, wheel: bytes, attestation: str | None) -> Intent:
    return Intent(
        AGENT,
        "install_release",
        release_target(version, wheel, attestation),
        len(wheel),
        SESSION,
    )


def execute_intent(version: str, wheel: bytes) -> Intent:
    """Interpreter startup executing an installed .pth hook is its
    own act — one no install authorization ever named."""
    return Intent(
        AGENT,
        "execute_startup_hook",
        f"pypi:{PACKAGE}@{version}#wheel={wheel_hash(wheel)}",
        len(wheel),
        SESSION,
    )


class ReleasePipelineTestVerifier(HmacTestVerifier):
    """Test-only double for the release pipeline's own signing
    key — the ESRP analog. A genuine, working signer with its own
    identity and key; it is simply not the reviewer authority.
    Its signatures verify under its own key; they authorize
    nothing here. (Wiz's account of the incident has the attacker
    publishing through the pipeline's own credentials — Inferred,
    unconfirmed by Microsoft; the class this double models —
    pipeline credentials are not reviewer authority — holds
    whichever access story is true.)"""

    authority_id = "authority:release-pipeline"
    verifier_id = "verifier:release-pipeline"
    key_id = "key:release-pipeline:v1"
    key_fingerprint = hashlib.sha256(b"pulpo-test-release-pipeline-key").hexdigest()

    def __init__(self, secret=b"release-pipeline-key"):
        super().__init__(secret)


class PackageIndex:
    """What the package index actually published, and the gate its
    publishes and installs pass through — the consequence surface.
    A release is recorded, and bytes are installed, only through a
    successful consume."""

    def __init__(self) -> None:
        self.published: dict[tuple[str, str], tuple[str, str]] = {}
        # The observer's submission log: (version, wheel hash,
        # attestation hash) in the order releases were submitted —
        # what an index-side observer recorded at submission time.
        self.submission_log: list[tuple[str, str, str]] = []
        # Artifact-level quarantine: versions the index has pulled.
        # Quarantine blocks installs of that version; it is not a
        # revocation of the publisher's authority and blocks no
        # publish.
        self.quarantined: set[str] = set()

    def publish(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        version: str,
        wheel: bytes,
        attestation: str | None,
    ) -> bool:
        # The published bytes and attestation are bound to the
        # consumed intent: the presented intent must be exactly
        # the intent for THESE bytes and THIS attestation. A
        # caller pairing an approved intent with different bytes —
        # or with the attestation stripped — is refused BEFORE
        # consumption: the permit is not spent and nothing is
        # recorded (the fixed Wave 1 pattern; see PR #367).
        if kernel.intent_hash(intent) != kernel.intent_hash(
            publish_intent(version, wheel, attestation)
        ):
            return False
        if permit is None:
            # No permit was issued for this publish. The attempt
            # is routed through the canonical kernel with a
            # sentinel permit rather than short-circuited here, so
            # the kernel's own rejection path is exercised and the
            # refusal lands in the audit as exactly one
            # permit_rejected record (the fixed Wave 1 pattern).
            kernel.consume("no-permit-issued", intent)
            return False
        if not kernel.consume(permit, intent):
            return False
        record = (wheel_hash(wheel), attestation_hash(attestation))
        self.published[(PACKAGE, version)] = record
        self.submission_log.append((version, *record))
        return True

    def install(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        version: str,
        wheel: bytes,
        attestation: str | None,
        environment: "Environment",
    ) -> bool:
        # Same binding discipline as publish: the installed bytes
        # and attestation must be exactly the consumed intent's.
        if kernel.intent_hash(intent) != kernel.intent_hash(
            install_intent(version, wheel, attestation)
        ):
            return False
        if version in self.quarantined:
            # Artifact quarantine: this version cannot be
            # installed. Refused before consumption — an
            # index-local, artifact-level block (see the module
            # docstring's audit-growth classification).
            return False
        if permit is None:
            kernel.consume("no-permit-issued", intent)
            return False
        if not kernel.consume(permit, intent):
            return False
        environment.install(version, wheel, attestation)
        return True


class Environment:
    """A Python environment: the wheels installed into it, and the
    credential store the incident's payload would have read. The
    store holds synthetic placeholder strings only."""

    def __init__(self) -> None:
        self.installed: dict[str, tuple[bytes, str | None]] = {}
        self.credential_store = {
            "AZURE_CLIENT_SECRET": "synthetic-placeholder-not-a-secret",
            "SYSTEM_ACCESSTOKEN": "synthetic-placeholder-not-a-token",
        }
        self.credential_reads = 0
        self.exfiltrated: list[bytes] = []

    def install(self, version: str, wheel: bytes, attestation: str | None) -> None:
        self.installed[version] = (wheel, attestation)

    def startup(self, kernel: GovernanceKernel) -> bool:
        """Interpreter startup. If an installed wheel carries a
        .pth hook (the synthetic wheel bytes name their files; a
        .pth name marks a startup hook), the hook's execution is
        attempted as its own governed act. No install
        authorization names it, so the attempt is routed through
        the canonical kernel with a sentinel permit. The payload
        effects — credential reads and exfiltration — are gated
        on the consume RESULT: they occur if and only if consume
        returns True. Under the canonical kernel the sentinel is
        refused, so no credential is read and nothing is
        exfiltrated; under a kernel whose consume accepts (the
        negative control's defective double), the hook executes
        and the effects occur — the gate is the consume result,
        not this harness's construction."""
        for version, (wheel, _attestation) in sorted(self.installed.items()):
            if b".pth" in wheel:
                if not kernel.consume(
                    "no-permit-issued", execute_intent(version, wheel)
                ):
                    return False
                # Consume succeeded — possible only under an
                # unguarded or defective kernel. The hook
                # executes: it reads the credential store and
                # exfiltrates its contents (synthetic
                # placeholders only).
                self.credential_reads += len(self.credential_store)
                self.exfiltrated.append(
                    "\n".join(
                        f"{name}={value}"
                        for name, value in sorted(self.credential_store.items())
                    ).encode()
                )
                return True
        return True


def observe_environment(environment: Environment) -> set[tuple[str, str, str]]:
    """The independent observer: reads the environment's installed
    wheels directly, hashes them, and never consults the kernel or
    the index's claims."""
    return {
        (version, wheel_hash(wheel), attestation_hash(attestation))
        for version, (wheel, attestation) in sorted(environment.installed.items())
    }


def _audit_supported(
    kernel: GovernanceKernel,
    intent_for,
    candidates: list[tuple[str, bytes, str | None]],
) -> list[tuple[str, str, str]]:
    """The (version, wheel hash, attestation hash) triples the
    kernel audit actually consumed intents for — restricted to the
    intent class ``intent_for`` builds, derived solely from the
    audit record, in audit (submission-time) order. Provenance is
    read as it was bound at submission, from the audit, never
    from a later index-side rewrite."""
    by_hash = {
        kernel.intent_hash(intent_for(version, wheel, attestation)): (
            version,
            wheel_hash(wheel),
            attestation_hash(attestation),
        )
        for version, wheel, attestation in candidates
    }
    supported = []
    for record in kernel.audit:
        if record["event"] == "permit_consumed":
            triple = by_hash.get(record["payload"]["intent_hash"])
            if triple is not None:
                supported.append(triple)
    return supported


def audit_supported_publishes(
    kernel: GovernanceKernel, candidates: list[tuple[str, bytes, str | None]]
) -> list[tuple[str, str, str]]:
    return _audit_supported(kernel, publish_intent, candidates)


def audit_supported_installs(
    kernel: GovernanceKernel, candidates: list[tuple[str, bytes, str | None]]
) -> list[tuple[str, str, str]]:
    return _audit_supported(kernel, install_intent, candidates)


def reconcile_installs(
    claims: set[tuple[str, str, str]],
    observed: set[tuple[str, str, str]],
    supported: set[tuple[str, str, str]],
) -> dict:
    """Test-level reconciliation, both directions stated
    explicitly (the PR #362 lesson): ``rejected_claims`` is claims
    minus audit-consumed installs — a claim with no consumed
    install behind it is a phantom claim and is rejected;
    ``unreported_claims`` is audit-consumed installs missing from
    the claims — an omitted claim is reported, and ``ok``
    requires the claims to equal the supported set exactly (a
    subset check would let an omitted install claim pass
    silently); ``unaccounted_effects`` is observed installs minus
    audit-consumed installs — bytes installed that no consumed
    install accounts for, the incident's condition;
    ``missing_effects`` is audit-consumed installs the observer
    does not see."""
    return {
        "ok": claims == supported and observed == supported,
        "rejected_claims": claims - supported,
        "unreported_claims": supported - claims,
        "unaccounted_effects": observed - supported,
        "missing_effects": supported - observed,
    }


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control (see
    the canonical incident scenarios): its consume ignores the
    intent binding, so the substituted publish must EXECUTE under
    it, proving the scenario's denials come from the kernel's
    binding."""

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = permit in self._issued and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self.append(
            "permit_consumed" if valid else "permit_rejected",
            {"intent_hash": intent_hash},
            timestamp_ns,
        )
        return valid


class _UnguardedConsumeKernel(GovernanceKernel):
    """Deliberately unguarded kernel double for the negative control."""

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


class _SentinelAcceptingState(InMemoryKernelState):
    """Defective state double for the startup negative control:
    its consume accepts any permit string, modeling a kernel
    whose rejection path is broken. Used to prove that
    startup's payload effects are gated on the consume RESULT —
    under this double the hook executes."""

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        self.append("permit_consumed", {"intent_hash": intent_hash}, timestamp_ns)
        return True


CANDIDATES: list[tuple[str, bytes, str | None]] = [
    (V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
    (V_BAD1, HOOKED_WHEEL_1, None),
    (V_BAD2, HOOKED_WHEEL_2, None),
]


class MsAgentFrameworkApprovalPathTests(unittest.TestCase):
    """Setup A: every publish and install requires the reviewer
    authority's approval of the exact wheel bytes and attestation."""

    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.index = PackageIndex()
        self.environment = Environment()

    def _kernel(self, state=None, *, kernel_class=GovernanceKernel) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"ms-agent-framework-scenario-kernel-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _issue(self, kernel: GovernanceKernel, intent: Intent) -> str:
        self._issue_count = getattr(self, "_issue_count", 0) + 1
        n = self._issue_count
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=f"approval-{n}",
            nonce=f"approval-nonce-{n}",
        )
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- beat 1: positive control ------------------------------------------

    def test_positive_control_attested_release_publishes_and_installs_once(self) -> None:
        publish_permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            self.index.publish(
                self.kernel,
                publish_permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        clean_record = (wheel_hash(CLEAN_WHEEL), attestation_hash(CLEAN_ATTESTATION))
        self.assertEqual({(PACKAGE, V_CLEAN): clean_record}, self.index.published)

        install_permit = self._issue(
            self.kernel, install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            self.index.install(
                self.kernel,
                install_permit,
                install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
                self.environment,
            )
        )
        clean_triple = (V_CLEAN, *clean_record)
        # The observer records exactly that release — no more, no less.
        self.assertEqual({clean_triple}, observe_environment(self.environment))
        self.assertEqual(
            [clean_triple], audit_supported_installs(self.kernel, CANDIDATES)
        )
        self.assertEqual(
            [clean_triple], audit_supported_publishes(self.kernel, CANDIDATES)
        )
        self.assertEqual([clean_triple], self.index.submission_log)
        # The clean wheel carries no hook: startup is unremarkable.
        self.assertTrue(self.environment.startup(self.kernel))
        self.assertEqual([], self.environment.exfiltrated)
        self.assertTrue(self.kernel.verify_audit())

    # -- beat 2: byte substitution ------------------------------------------

    def test_step2_byte_substitution_under_clean_permit_denied(self) -> None:
        permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        # The hooked 1.26.1 wheel presented under the clean
        # release's permit: a different intent, denied at consume.
        self.assertFalse(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1,
                HOOKED_WHEEL_1,
                None,
            )
        )
        self.assertEqual({}, self.index.published)
        # The denial consumed nothing: the clean release still
        # publishes on the same permit.
        self.assertTrue(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        self.assertTrue(self.kernel.verify_audit())

    def test_step2b_approved_intent_with_hooked_bytes_refused(self) -> None:
        permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        # The caller pairs the CLEAN release's approved intent
        # with the HOOKED wheel's bytes. The index refuses the
        # mismatch before consumption: the bytes published must be
        # the consumed intent's bytes (the fixed Wave 1 pattern).
        audit_before = len(self.kernel.audit)
        self.assertFalse(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                HOOKED_WHEEL_1,
                CLEAN_ATTESTATION,
            )
        )
        self.assertEqual({}, self.index.published)
        # The refusal happened before the kernel: no audit growth,
        # and the permit is unspent.
        self.assertEqual(audit_before, len(self.kernel.audit))
        self.assertTrue(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- beat 3: unauthorized publish ----------------------------------------

    def test_step3_publish_without_permit_refused(self) -> None:
        intent = publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        # Channel access is not authority: the attempt reaches the
        # index with no permit and is routed through the canonical
        # kernel with a sentinel permit, so the refusal lands in
        # the audit as exactly one permit_rejected record.
        audit_before = len(self.kernel.audit)
        self.assertFalse(
            self.index.publish(
                self.kernel, None, intent, V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION
            )
        )
        self.assertEqual({}, self.index.published)
        self.assertEqual(audit_before + 1, len(self.kernel.audit))
        rejected = [r for r in self.kernel.audit if r["event"] == "permit_rejected"]
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(intent), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        self.assertTrue(self.kernel.verify_audit())

    # -- beat 4: permit-less startup-hook execution ---------------------------

    def test_step4_permitless_startup_hook_execution_refused(self) -> None:
        # The incident's post-install state, modeled directly: the
        # hooked wheel's files are present in the environment (how
        # they got there is the install question, settled in the
        # other steps; the execution question is this step's).
        self.environment.installed[V_BAD1] = (HOOKED_WHEEL_1, None)
        intent = execute_intent(V_BAD1, HOOKED_WHEEL_1)
        # Interpreter startup fires the hook. The execution is a
        # consequential act no install authorization named; it is
        # routed through the kernel with a sentinel permit and
        # refused — exactly one permit_rejected record, and the
        # payload's effects never occur.
        self.assertFalse(self.environment.startup(self.kernel))
        self.assertEqual([], self.environment.exfiltrated)
        self.assertEqual(0, self.environment.credential_reads)
        rejected = [r for r in self.kernel.audit if r["event"] == "permit_rejected"]
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(intent), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        self.assertTrue(self.kernel.verify_audit())

    # -- beat 5: the pipeline's key is not the reviewer authority -------------
    #
    # What this beat proves, stated precisely (narrowed in the
    # fix pass — the original text claimed "missing provenance
    # fails closed at evaluation"): (i) an approval envelope for
    # the unattested hooked release signed by the release
    # pipeline's OWN key mints nothing, because the pipeline is
    # not the reviewer authority the policy pins — a
    # wrong-authority rejection. Provenance absence is NOT what
    # denies it: the attestation state is bound into the intent
    # (att = hash-of-None), no policy constraint in this setup
    # requires an attestation, and step 5b shows the SAME
    # unattested intent allowing when the reviewer authority
    # signs it. (ii) The attestation cannot be stripped
    # downstream of approval: the clean release's permit
    # presented with the attestation removed is a different
    # intent, refused before consumption.

    def test_step5_pipeline_key_envelope_is_not_reviewer_authority(self) -> None:
        intent = publish_intent(V_BAD1, HOOKED_WHEEL_1, None)
        # (i) The release pipeline's OWN key signs an approval
        # envelope for the unattested hooked release — genuine
        # pipeline credentials, the ESRP-analog. The signature
        # verifies under the pipeline key; the pipeline is not the
        # reviewer authority, so no permit is minted.
        pipeline = ReleasePipelineTestVerifier()
        pipeline_trust = trust_for(pipeline)
        envelope = signed_envelope(
            self.kernel,
            intent,
            pipeline,
            now_ns=NOW,
            approval_id="pipeline-approval-1",
            nonce="pipeline-nonce-1",
            authority_id=pipeline_trust.authority_id,
            verifier_id=pipeline_trust.verifier_id,
            key_id=pipeline_trust.key_id,
            deployment_id=pipeline_trust.deployment_id,
            trust_hash=pipeline_trust.trust_hash,
        )
        self.assertTrue(pipeline.verify(envelope.signing_bytes(), envelope.signature))
        decision = self.kernel.evaluate_with_approval(intent, envelope)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual({}, self.index.published)

        # (ii) Provenance cannot be stripped downstream of
        # approval either: the clean release's permit presented
        # with the same bytes but NO attestation is a different
        # intent, refused before consumption, permit unspent.
        permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        audit_before = len(self.kernel.audit)
        self.assertFalse(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                None,
            )
        )
        self.assertEqual({}, self.index.published)
        self.assertEqual(audit_before, len(self.kernel.audit))
        self.assertTrue(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        self.assertTrue(self.kernel.verify_audit())

    def test_step5b_reviewer_approval_of_unattested_intent_allows(self) -> None:
        # The boundary of step 5's evidence: the SAME unattested
        # hooked intent, signed by the reviewer authority the
        # policy pins, evaluates to allow and publishes. Step
        # 5(i)'s denial is therefore a wrong-authority rejection
        # — the pipeline key is not the reviewer — not a
        # provenance check. Provenance is enforced only as part
        # of the exact intent the reviewer approves: an approval
        # for the attested release does not cover the unattested
        # one (step 2/5(ii) territory), and an approval for the
        # unattested one is the reviewer's own act to answer for.
        permit = self._issue(
            self.kernel, publish_intent(V_BAD1, HOOKED_WHEEL_1, None)
        )
        self.assertTrue(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1,
                HOOKED_WHEEL_1,
                None,
            )
        )
        self.assertIn((PACKAGE, V_BAD1), self.index.published)
        self.assertTrue(self.kernel.verify_audit())

    # -- single-use ------------------------------------------------------------

    def test_step6_replay_of_spent_install_permit_denied(self) -> None:
        permit = self._issue(
            self.kernel, install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        intent = install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        self.assertTrue(
            self.index.install(
                self.kernel,
                permit,
                intent,
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
                self.environment,
            )
        )
        self.assertFalse(
            self.index.install(
                self.kernel,
                permit,
                intent,
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
                self.environment,
            )
        )
        self.assertEqual(
            {(V_CLEAN, *(
                wheel_hash(CLEAN_WHEEL), attestation_hash(CLEAN_ATTESTATION)
            ))},
            observe_environment(self.environment),
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- beat 7: reconciliation -------------------------------------------------

    def test_step7_reconciliation_both_directions(self) -> None:
        publish_permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            self.index.publish(
                self.kernel,
                publish_permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        install_permit = self._issue(
            self.kernel, install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            self.index.install(
                self.kernel,
                install_permit,
                install_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
                self.environment,
            )
        )
        clean_triple = (
            V_CLEAN,
            wheel_hash(CLEAN_WHEEL),
            attestation_hash(CLEAN_ATTESTATION),
        )
        hooked_triple = (V_BAD1, wheel_hash(HOOKED_WHEEL_1), attestation_hash(None))
        supported = set(audit_supported_installs(self.kernel, CANDIDATES))
        self.assertEqual({clean_triple}, supported)
        observed = observe_environment(self.environment)

        # Governed run: claims, observed installs, and the audit
        # agree exactly.
        result = reconcile_installs({clean_triple}, observed, supported)
        self.assertTrue(result["ok"])

        # An omitted claim is reported, not silently reconciled:
        # empty claims against a supported install fail, with the
        # install named as unreported. (A subset check —
        # claims <= supported — would have passed this.)
        result = reconcile_installs(set(), observed, supported)
        self.assertFalse(result["ok"])
        self.assertEqual({clean_triple}, result["unreported_claims"])
        self.assertEqual(set(), result["rejected_claims"])

        # A claim for an install that never executed — the index
        # page asserting 1.26.1 was installed — is a phantom
        # claim: claimed but never authorized, rejected.
        result = reconcile_installs({clean_triple, hooked_triple}, observed, supported)
        self.assertFalse(result["ok"])
        self.assertEqual({hooked_triple}, result["rejected_claims"])
        self.assertEqual(set(), result["unaccounted_effects"])

        # The incident's detection condition: the hooked wheel IS
        # installed somewhere the governed path never wrote —
        # observed bytes no consumed install accounts for.
        incident_env = Environment()
        incident_env.installed[V_BAD1] = (HOOKED_WHEEL_1, None)
        result = reconcile_installs(
            {clean_triple}, observe_environment(incident_env), supported
        )
        self.assertFalse(result["ok"])
        self.assertEqual({hooked_triple}, result["unaccounted_effects"])
        self.assertTrue(self.kernel.verify_audit())

    def test_step7b_provenance_rewrite_flagged_against_audit_order(self) -> None:
        permit = self._issue(
            self.kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            self.index.publish(
                self.kernel,
                permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN,
                CLEAN_WHEEL,
                CLEAN_ATTESTATION,
            )
        )
        clean_triple = (
            V_CLEAN,
            wheel_hash(CLEAN_WHEEL),
            attestation_hash(CLEAN_ATTESTATION),
        )
        # The observer's submission log, read in order, equals the
        # audit-derived supported set: provenance as bound at
        # submission time.
        self.assertEqual([clean_triple], self.index.submission_log)
        self.assertEqual(
            [clean_triple], audit_supported_publishes(self.kernel, CANDIDATES)
        )

        # The rewrite attempt: the index-side record is edited
        # after the fact to claim a different attestation for the
        # release. The audit — append-only, kernel-held — does not
        # move, so the rewritten log now diverges from the
        # submission-time record instead of replacing it.
        self.index.submission_log[0] = (V_CLEAN, wheel_hash(CLEAN_WHEEL), "0" * 64)
        self.assertNotEqual(
            self.index.submission_log,
            audit_supported_publishes(self.kernel, CANDIDATES),
        )
        self.assertEqual(
            [clean_triple], audit_supported_publishes(self.kernel, CANDIDATES)
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ---------------------------------------------------

    def test_negative_control_unguarded_kernel_publishes_hooked_wheel(self) -> None:
        kernel = self._kernel(_IntentBlindState(), kernel_class=_UnguardedConsumeKernel)
        index = PackageIndex()
        permit = self._issue(
            kernel, publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION)
        )
        self.assertTrue(
            index.publish(
                kernel,
                permit,
                publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1,
                HOOKED_WHEEL_1,
                None,
            )
        )
        self.assertEqual(
            {(PACKAGE, V_BAD1): (wheel_hash(HOOKED_WHEEL_1), attestation_hash(None))},
            index.published,
        )

    def test_negative_control_startup_effects_follow_consume_result(self) -> None:
        # The startup gate is the consume RESULT, not the
        # harness's construction: under a defective kernel whose
        # consume accepts the sentinel permit, the same startup
        # attempt EXECUTES the hook — the credential store is read
        # and its contents exfiltrated. Step 4's effect-free
        # startup under the canonical kernel is therefore
        # evidence about the kernel's refusal, not about a
        # harness that never performs effects.
        kernel = self._kernel(
            _SentinelAcceptingState(), kernel_class=_UnguardedConsumeKernel
        )
        environment = Environment()
        environment.installed[V_BAD1] = (HOOKED_WHEEL_1, None)
        self.assertTrue(environment.startup(kernel))
        self.assertEqual(
            len(environment.credential_store), environment.credential_reads
        )
        self.assertEqual(1, len(environment.exfiltrated))


class MsAgentFrameworkRevocationTests(unittest.TestCase):
    """Setup B: publishes and installs flow under the publisher's
    standing directive, scoped to the package. The directive
    delegates the acts within its scope; it does not review
    content — so the compromise plays out inside the scope, and
    the incident-response levers are tested in order: artifact
    quarantine alone (insufficient), then revocation of the
    publisher's authority (decisive).

    The activation/revocation scaffolding mirrors DirectiveProofTests
    (tests/test_directives.py) by composition of the same public
    helpers, with the kernel policy's action set covering this
    scenario's actions; it does not inherit that suite.
    """

    def _governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset(
                {"publish_release", "install_release", "activate_directive", "revoke_directive"}
            ),
            10_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"ms-agent-framework-directive-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def _directive(self):
        return directive(
            directive_id="ms-agent-framework-publisher",
            principal=AGENT,
            allowed_actions=frozenset({"publish_release", "install_release"}),
            # The trailing "@" delimits the package name: the
            # kernel's directive check is a prefix match, so an
            # undelimited "pypi:agent-framework" would also scope
            # in look-alike packages (pypi:agent-framework-evil@…)
            # — broader than the package-scoped authority this
            # setup documents. Delimited, the scope is exactly
            # this package.
            resource_prefixes=(f"pypi:{PACKAGE}@",),
            max_cost=10_000,
            issued_at_ns=1_000_000,
            expires_at_ns=9_000_000,
        )

    def _approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation, d, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def _activate(self, state, d):
        kernel, verifier = self._governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(
            kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def _revoke(self, kernel, verifier, controller, d):
        envelope = self._approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        decision = controller.revoke(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    def _publish_under_directive(self, kernel, d, version, wheel, attestation, index):
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(publish_intent(version, wheel, attestation), d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- beat 6, counterfactual: quarantine is not revocation ----------------

    def test_quarantine_alone_does_not_revoke_publisher_authority(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        index = PackageIndex()
        environment = Environment()
        projection = GovernedDirectiveProjection(kernel)

        # The compromise plays out inside the directive's scope:
        # 1.26.1 publishes and installs under the publisher's
        # standing authority. The record binds exactly what was
        # authorized — hooked bytes, no attestation — which the
        # incident's index never could say.
        permit = self._publish_under_directive(
            kernel, d, V_BAD1, HOOKED_WHEEL_1, None, index
        )
        self.assertTrue(
            index.publish(
                kernel, permit, publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None,
            )
        )
        install_decision = projection.evaluate(
            install_intent(V_BAD1, HOOKED_WHEEL_1, None), d
        )
        self.assertEqual("allow", install_decision.outcome)
        self.assertTrue(
            index.install(
                kernel, install_decision.permit,
                install_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None, environment,
            )
        )
        self.assertIn(V_BAD1, environment.installed)

        # Incident response, artifact level only: the index
        # quarantines 1.26.1. Installs of THAT version now stop.
        index.quarantined.add(V_BAD1)
        install_decision = projection.evaluate(
            install_intent(V_BAD1, HOOKED_WHEEL_1, None), d
        )
        self.assertEqual("allow", install_decision.outcome)
        self.assertFalse(
            index.install(
                kernel, install_decision.permit,
                install_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None, Environment(),
            )
        )

        # But the publisher's authority was never revoked — so the
        # second upload, 1.26.2, still executes. This is the
        # incident's signature failure, reproduced: quarantine
        # reached the artifact, not the authority.
        permit = self._publish_under_directive(
            kernel, d, V_BAD2, HOOKED_WHEEL_2, None, index
        )
        self.assertTrue(
            index.publish(
                kernel, permit, publish_intent(V_BAD2, HOOKED_WHEEL_2, None),
                V_BAD2, HOOKED_WHEEL_2, None,
            )
        )
        self.assertIn((PACKAGE, V_BAD2), index.published)
        self.assertTrue(kernel.verify_audit())

    # -- beat 6a: revocation kills the unconsumed install permit --------------

    def test_revocation_kills_unconsumed_install_permit_at_consume(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        index = PackageIndex()
        environment = Environment()
        projection = GovernedDirectiveProjection(kernel)

        permit = self._publish_under_directive(
            kernel, d, V_BAD1, HOOKED_WHEEL_1, None, index
        )
        self.assertTrue(
            index.publish(
                kernel, permit, publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None,
            )
        )
        # An install permit for the (about to be quarantined)
        # release is issued but not yet consumed.
        install_decision = projection.evaluate(
            install_intent(V_BAD1, HOOKED_WHEEL_1, None), d
        )
        self.assertEqual("allow", install_decision.outcome)
        self.assertIsNotNone(install_decision.permit)

        # Incident response done at the authority level: the
        # publisher directive is revoked.
        self._revoke(kernel, verifier, controller, d)

        # The install attempt now fails closed AT CONSUME — not
        # because the artifact is quarantined (the index never
        # quarantined it in this test) but because the authority
        # behind the permit is gone.
        self.assertFalse(
            index.install(
                kernel, install_decision.permit,
                install_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None, environment,
            )
        )
        self.assertEqual({}, environment.installed)
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])
        self.assertTrue(kernel.verify_audit())

    # -- beat 6b: the second upload after revocation ---------------------------

    def test_second_upload_refused_after_revocation(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        index = PackageIndex()
        projection = GovernedDirectiveProjection(kernel)

        # A publish permit for the second upload is issued while
        # the directive is still active, but not yet consumed —
        # the attacker's staged next release.
        staged = projection.evaluate(publish_intent(V_BAD2, HOOKED_WHEEL_2, None), d)
        self.assertEqual("allow", staged.outcome)
        self.assertIsNotNone(staged.permit)

        self._revoke(kernel, verifier, controller, d)

        # The staged permit is dead at consume.
        self.assertFalse(
            index.publish(
                kernel, staged.permit, publish_intent(V_BAD2, HOOKED_WHEEL_2, None),
                V_BAD2, HOOKED_WHEEL_2, None,
            )
        )
        self.assertEqual({}, index.published)
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])

        # And no fresh permit issues under the revoked directive:
        # revocation reaches the publisher's authority itself, so
        # there is no 1.26.2 — the outcome the incident's
        # quarantine could not produce.
        fresh = projection.evaluate(publish_intent(V_BAD2, HOOKED_WHEEL_2, None), d)
        self.assertEqual("deny", fresh.outcome)
        self.assertEqual("directive_revoked", fresh.reason)
        self.assertIsNone(fresh.permit)
        self.assertEqual({}, index.published)
        self.assertTrue(kernel.verify_audit())

    # -- directive permit does not spend on a substituted wheel -----------------

    def test_directive_permit_does_not_spend_on_substituted_wheel(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        index = PackageIndex()
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(
            publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION), d
        )
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        self.assertFalse(
            index.publish(
                kernel, decision.permit,
                publish_intent(V_BAD1, HOOKED_WHEEL_1, None),
                V_BAD1, HOOKED_WHEEL_1, None,
            )
        )
        self.assertEqual({}, index.published)
        self.assertTrue(
            index.publish(
                kernel, decision.permit,
                publish_intent(V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION),
                V_CLEAN, CLEAN_WHEEL, CLEAN_ATTESTATION,
            )
        )
        self.assertEqual(
            {(PACKAGE, V_CLEAN): (wheel_hash(CLEAN_WHEEL), attestation_hash(CLEAN_ATTESTATION))},
            index.published,
        )
        self.assertTrue(kernel.verify_audit())

    # -- directive scope is delimited to the package ---------------------------

    def test_directive_scope_excludes_adjacent_package(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        # A look-alike package: the directive's delimited prefix
        # (pypi:agent-framework@) does not cover
        # pypi:agent-framework-evil@…, so no permit issues for it
        # under the publisher's directive. (With the undelimited
        # prefix the kernel's prefix match would have scoped it
        # in — broader than the documented package scope.)
        evil = Intent(
            AGENT,
            "publish_release",
            f"pypi:{PACKAGE}-evil@9.9.9"
            f"#wheel={wheel_hash(HOOKED_WHEEL_1)}#att={attestation_hash(None)}",
            len(HOOKED_WHEEL_1),
            SESSION,
        )
        decision = projection.evaluate(evil, d)
        self.assertEqual(
            ("deny", "directive_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()
