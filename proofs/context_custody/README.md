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
 + projection policy contents + kernel policy hash
      |
      v
Pulpo project_context intent
      |
      v
one-use permit
      |
      v
canonical possible-disclosure reservation + aggregate check
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
- individually admissible fragments are denied when their composition crosses
  a stronger disclosure boundary, including separate releases across sessions
  and service recreation;
- split adversarial fragments are re-evaluated at assembly;
- projection permits are exact and one-use;
- object substitution does not consume the original valid permit;
- changes to projection policy contents or the kernel policy invalidate a
  prepared projection, even when the projection version string is unchanged;
- release returns the immutable source snapshot it validated, without a second
  raw-store read;
- malformed requests, invalid audit evidence, and unavailable reservation storage
  return denials without exposing source exception text;
- SQLite restart retains reservations and spent permits;
- concurrently reserved complementary fragments cannot both be released;
- the authority-neutral candidate schema has no raw-content or generated-summary
  field.

## Disclosure history and failure semantics

After consuming the exact `project_context` permit, the harness records a
`context_projection_reserved` event through the existing canonical state's
`append_unique` operation. It creates no separate disclosure database, authority
ledger, or router. The existing canonical audit is verified before admission and
release, and again after reservation. This proof uses the kernel's private state
interface; it is not a proposed production API.

Reservations count as **possible disclosure**, not evidence that content actually
reached a recipient. Their fragment identities are accumulated for the same
principal across sessions, purposes, and policy versions in this synthetic
namespace. Current blocked groups are checked against that accumulated set.
Changing the session, recreating the service, or reopening the same SQLite state
does not erase it. Fragment identities must remain stable in this namespace.

A known aggregate denial leaves its permit unconsumed. After consumption, any
failure leaves the permit spent; an appended reservation remains conservative
history even if output was denied. A race may deny both complementary requests.
Unrelated benign fragments can still be released. Availability is deliberately
secondary to preventing a prohibited composite disclosure.

This does not prove protection against restoring an older complete database
snapshot, colluding principals, arbitrary host mutation, or policy revocation at
every possible instruction boundary. It does test policy changes before release
and during permit consumption. A production boundary needs stronger transaction
and recipient/identity guarantees.

## Gladiator regression

The frozen PR head for the reproduction is
`4da545442dc4c8c51992c0ebf95c07247d32e80c` (PR #299). The original nine tests
passed while the first expanded attack set reproduced eleven failures. The final
thirty-check suite produced sixteen failures against the frozen harness and
passed all thirty after the fix. The
regression suite adds twenty-one tests for cumulative disclosure, snapshot drift,
policy rebinding, audit tamper, storage failure, malformed requests, replay,
forgery, provenance substitution, concurrent composition, and conservative
restart behavior. A stacked case combines score inflation, session rotation,
service recreation, replay, and complementary disclosure. Cooperative requests
are included to detect indiscriminate denial.

Run the bounded custody tests with:

```text
python -m pytest tests/test_context_custody_v0.py tests/test_context_custody_gladiator.py -q
```

Passing these tests supports only this object/API proof. It does not recover the
missing reviewer comment or establish that every originally reported attack has
been reproduced.

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
