# Exact custody attempt handles

Custody execute and reconcile requests must carry the original issuance handle.
The service compares its order/target hashes against the canonical attempt and
its reservation ID/amount against the existing durable budget record. Unknown
handle schemas, altered issuance labels and non-integer amounts fail closed.
Executor references are derived from those protected records rather than copied
from worker fields.

These checks run before evidence projection or provider/observer entry. Invalid
handles therefore cannot flush a pending canonical evidence obligation merely
by reaching a route. Valid requests keep the existing projection-before-effect
ordering. No canonical mutation or second execution/authority plane is added.

The handle's `state` is the original `attempt_authorized` issuance label, not a
claim that the current custody state is still authorized. The same exact handle
can cross legitimate claim/execution/reconciliation transitions; canonical
custody state still denies replay. The budget lookup reads the original
reservation even after settlement without reopening it or granting a new right.

## Regression evidence and boundary

The tests alter six fields (target hash, order hash, reservation ID, reserved
amount, schema and issuance state) across execute/reconcile, with and without a
pending evidence obligation. All 24 rejection subcases require HTTP 409,
byte-equivalent SQLite table rows and zero provider/observer calls. The original
handle must then execute once and reconcile successfully, including recovery
of an already claimed attempt and projection of its pending evidence.

The added tests were first run with unmodified upstream source at
`d674dbb7a00b471d69bcca84d2f034cf74705e1a`: the two added methods failed, including
acceptance of an altered target hash. With this candidate, 24 selected service,
custody, executor, evidence and concurrency tests and three external P3
target/reservation/amount probes passed locally on Windows. Windows fixture
cleanup collected unreachable SQLite cycles before unlink callbacks; no runtime
connection or security assertion was replaced. A wider 41-test selection had
zero assertion failures and five Windows commerce cleanup errors, also reproduced
by the same 17 commerce tests on pristine upstream source. Linux CI runs the
repository harness without that local cleanup accommodation.

Tests use fake providers, public synthetic signing fixtures and temporary state.
This repairs supplied-handle validation, not a demonstrated arbitrary-domain
execution: the previous accepted target-hash mutation still executed the
original canonical order. It does not prove host containment, independent human
authority, hostile-store resistance or production P3 integration. Batching is
outside this change. Claim-before-approval proposal consumption is unchanged.

## Adversarial transformation and change record

Purpose: reject altered handles before consequential owner operations.
Authority boundary: the existing trusted custody owner, canonical attempt,
protected budget and original executor/observer. Acceptance is narrowed; no new
approval or execution right is granted. The added reservation lookup is read-only.

- **Flip:** a hostile worker alters each field; owner checks reject it before
  adapter entry without relying on worker cooperation.
- **Reverse:** canonical attempt/order/reservation reads precede projection,
  claiming, transmission and observation.
- **Invert:** a correct purchase through an altered supplied handle no longer
  satisfies the handle contract merely because its outcome was correct.
- **Inside-Out:** the custodian and stores remain trusted. Same-store reads
  do not establish resistance to arbitrary hostile-custodian replacement.
- **Darken:** invalid calls with a pending obligation must preserve every row,
  not just avoid a purchase. Regressions enforce this stricter boundary.
- **Lighten:** the previous finding is unchecked handle metadata, not proof of
  arbitrary target execution or a P3 framing exploit.
- **Amplify:** valid handles remain usable through later transitions while
  existing custody replay/concurrency controls remain in force.
- **Negate:** validate against the existing stores; add no new ledger, router,
  authority plane, schema, canonical writer or alternate provider route.

Stop/continue: baseline behavior was reproduced and source reconciled; selected
candidate assertions passed. Broader Linux validation is delegated to CI, with
Windows baseline cleanup limits explicitly recorded rather than hidden.
Smallest next proof: maintainer review and CI at the exact PR head before merge.

Classification: local assertions are **Verified** on the stated source/runtime;
test counts and platform limits are **Recorded**; deployment behavior is
**Unknown**; upstream admission remains **Proposed** until reviewed.
Canonical mutations introduced/exposed: none. Existing valid projection,
claim/transmission/reconciliation transitions keep their governed owner.
Legacy disposition: reuse current canonical budget/custody/evidence/executor
paths; no historical control path is imported. Baseline/candidate evidence is
bound to the current pinned upstream base, not transferred from the dirty local
checkout. No additional historical-checkpoint or general temporal-transfer
proof is claimed.
