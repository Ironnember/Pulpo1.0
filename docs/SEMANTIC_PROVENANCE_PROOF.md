# Semantic Provenance Binding Proof

## Purpose

Prove that a human-approved consequential proposal cannot silently transfer its
authority to a semantically drifted representation produced by transcription,
interpretation, summarization, or another intelligence-layer transformation.

This extends the existing exact-intent authority seam. It does not create a
semantic router, policy engine, authority source, memory system, or evidence ledger.

## Field case

**Recorded:** A ChatGPT interaction supplied by the founder showed a compact
semantic-drift sequence:

- an ambiguous colloquial request ("make it sexier") was interpreted more literally
  than intended;
- a safe, fully clothed alternative was proposed and accepted by the human;
- downstream generation still rejected the attempt;
- during later reconciliation, a spoken reference to "pin-up territory" was
  transcribed as "penetratory";
- the corrupted transcription was then temporarily reasoned about as though it
  represented the user's intended concept.

The screenshots and screen recording are external field evidence. They are not
canonical executable proof and are not imported as authority.

**Unknown:** The exact internal platform payloads, routing, moderation transforms,
and image-generation request objects are not observable from the supplied evidence.
No claim is made about which internal component introduced any specific drift.

## Constitutional invariant

```text
DERIVED_REPRESENTATION != HUMAN_AUTHORIZATION
TRANSCRIPTION_DRIFT != AUTHORIZED_INTENT
INTERPRETATION_CONFIDENCE != AUTHORITY
APPROVAL_BINDS_EXACT_INTENT_AND_PROVENANCE
PROVENANCE_CHANGE -> NEW_INTENT_HASH -> FRESH_AUTHORITY_REQUIRED
```

Semantic retrieval or model reasoning may help form a proposal. Neither may
increase its authority. A provenance record is evidence only.

## Architecture

`SemanticProvenance` stores hashes of the source evidence, optional transcription,
interpretation, and exact proposed representation. Its deterministic `chain_hash`
can be attached to an `Intent` as `provenance_hash`.

When present, that provenance hash becomes part of the existing canonical intent
hash. Existing approval envelopes and one-use permits therefore bind the proposal
lineage without adding a second approval mechanism.

When provenance is absent, legacy intent serialization and intent hashes remain
unchanged.

The MCP projection may carry a provenance hash as non-authoritative proposal data.
It still cannot mutate canonical state, issue a permit, or grant authority.

## Executable proof

`tests/test_semantic_provenance_binding.py` covers:

1. positive control: exact provenance receives a valid approval and permit;
2. transcription drift: `pin-up territory` -> `penetratory` changes the provenance
   hash and exact intent hash even when action and resource remain identical;
3. the prior approval fails closed with `approval_intent_mismatch` for the drifted
   intent;
4. the prior permit cannot execute the drifted intent;
5. invalid provenance digests fail closed;
6. MCP can project provenance without gaining canonical mutation or authority;
7. legacy intent hashes remain stable when no provenance is supplied.

## Boundary

This is a local software proof. It does not prove live model correctness, speech
transcription accuracy, image-generation policy behavior, production platform
containment, or that an external AI platform exposes enough provenance to enforce
this contract end to end.

The proof establishes only the Pulpo-side invariant: once a provenance-bound exact
intent is the authorized object, a different provenance chain cannot silently reuse
that authority.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
