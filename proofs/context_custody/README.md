# Context Custody V0

Issue: #298

This proof asks whether model-visible context formation can be treated as a
governed capability without turning retrieval/routing into a second authority
system.

## Boundary

The candidate routing surface is authority-neutral.  It can propose fragment
identities and relevance scores.  The existing Pulpo `GovernanceKernel`
authorizes the exact context-projection object and issues the one-use permit.

```text
candidate ranking
      |
      v
exact fragment set + source digests
      |
      v
Pulpo project_context intent
      |
      v
one-use permit
      |
      v
model-visible synthetic context
```

V0 intentionally uses synthetic data only.

## Executable properties

The tests prove, within this in-process object/API harness:

- exact admitted projections release only selected fragment content;
- source provenance is bound into the exact projection hash;
- relevance scores do not contribute authority;
- a maximum relevance score cannot authorize an excluded fragment;
- individually admissible fragments can be denied when their composition crosses
  a stronger disclosure boundary;
- split adversarial fragments are re-evaluated at assembly;
- projection permits are exact and one-use;
- object substitution does not consume the original valid permit;
- a stale policy version cannot release a prepared projection;
- the authority-neutral candidate schema has no raw-content or generated-summary
  field.

## Explicit nonclaims

V0 does **not** prove:

- hostile same-process isolation;
- operating-system or network isolation from the raw store;
- production storage or provider containment;
- semantic detection of arbitrary prompt injection;
- that fragmentation itself provides confidentiality;
- end-to-end efficiency improvement;
- novelty.

The next custody proof, if V0 survives review, must move the raw store behind a
separate process/capability boundary and demonstrate that hostile intelligence
cannot reach it except through the governed projection path.

`RETRIEVAL_SCORE != AUTHORITY`

`FRAGMENTATION != CAPABILITY_CUSTODY`

`FRAGMENT_ALLOWED_X_N != COMPOSITE_CONTEXT_ALLOWED`
