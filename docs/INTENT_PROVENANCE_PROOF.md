# Exact Intent Provenance Proof

## Purpose

This proof addresses a boundary observed in a real conversational AI failure trace:
human language was interpreted, a bounded alternative was proposed and accepted,
and a later transcription error changed `pin-up territory` to `penetratory`.
The lesson is not specific to image generation. It is that a transformed
representation must not silently inherit authority from the human-approved
object it replaced.

Pulpo remains outside semantic interpretation. Intelligence and interface layers
may transcribe, interpret, summarize, and propose. Pulpo receives one exact
object binding and governs only that exact object.

## Invariants

```text
DERIVED_REPRESENTATION != HUMAN_AUTHORITY
TRANSCRIPTION_DRIFT != APPROVED_OBJECT
INTERPRETATION_DRIFT != APPROVED_OBJECT
APPROVAL(A) != APPROVAL(B)
NO_EXACT_OBJECT_BINDING -> NO_PERMIT_FOR_EXACT_OBJECT_ACTION
OBJECT_HASH + INTENT + POLICY -> ONE APPROVAL BINDING
```

The existing constitutional rule remains unchanged:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

## Design

`IntentProvenance` is a non-authoritative, hash-only chain:

```text
human source
  -> optional transcript
  -> interpretation
  -> proposal
  -> object_hash
  -> canonical Intent
  -> intent_hash
  -> external approval
  -> one-use permit
```

Each stage hash binds the prior stage. Any changed transcript, interpretation, or
proposal therefore produces a different `object_hash`. For policy-selected
`exact_object_actions`, Pulpo denies an intent that omits that binding.

The independent authority request carries the same optional `object_hash`,
recomputes the displayed intent hash including it, and displays the object hash
during the human approval ceremony. The approval envelope continues to bind the
canonical `intent_hash`; no second authority format or ledger is introduced.

Legacy intents with no `object_hash` preserve their prior canonical hash bytes.
The stronger requirement is opt-in per policy action.

## Adversarial case

The executable case uses the same source and same final structured action while
changing only the transcript:

```text
approved transcript:  "pin-up territory"
corrupted transcript: "penetratory"
```

Because later provenance stages are chained to the transcript, the two
`object_hash` values differ even if the downstream interpretation and proposal
strings are held constant.

Acceptance requires:

1. the exact-object action without `object_hash` is denied;
2. approval signed for the approved provenance is denied against the corrupted provenance;
3. that denial does not consume or widen the original approval;
4. the original approved intent can still receive one permit;
5. the permit cannot execute the drifted intent;
6. the permit executes the approved intent once only;
7. replay remains denied after SQLite restart;
8. future equivalent work still requires fresh approval;
9. the capability-stripped MCP proposal may carry the hash but cannot mint authority or mutate canonical state;
10. legacy unbound intent hashing remains byte-for-byte stable.

The authority-service test separately proves that the service rejects a request
whose `object_hash` no longer matches the submitted `intent_hash`, displays the
bound hash, signs the resulting envelope, and produces a kernel-usable approval.

## Claim classification

- **Verified only after exact-head CI passes:** deterministic provenance hashing,
  optional exact-object policy enforcement, authority-request recomputation,
  approval binding, permit mismatch/replay denial, restart behavior, MCP
  non-authority, and legacy hash compatibility under the tested software
  boundary.
- **Recorded:** the motivating screenshots and conversation are field evidence,
  not canonical executable proof.
- **Inferred:** the same class of representation drift can occur at speech,
  summarization, retrieval, translation, model-routing, or tool-adapter
  boundaries.
- **Unknown:** whether any third-party AI product exposes enough internal
  provenance to bind its complete production pipeline this way.
- **Not proved:** semantic correctness, user comprehension of a hash, live model
  containment, external-provider containment, hostile-host containment, or a
  production human-readable provenance viewer.

## Architectural boundary

This change does not make Pulpo a semantic router, transcription service, model
judge, conversational memory system, or second policy engine. Stage content is
formed outside governance. Pulpo receives the resulting exact object binding and
applies its existing authority, policy, approval, permit, evidence, and replay
semantics.
