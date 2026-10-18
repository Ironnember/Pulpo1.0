# Combined custody, renewal and budget cleanup candidate

Status: local unreviewed candidate. No publication, merge, production activation,
credential use, registrar contact or financial consequence is authorized here.
Canonical base: `d674dbb7a00b471d69bcca84d2f034cf74705e1a`.

## Exact public source components

- Custody handle validation: closed/unmerged #307 at
  `0f6ea3a357cce911e0480e1e1cee5bc2b05dcf34`.
- Registrar renewal semantics: closed/unmerged #266 at
  `8c45b9d9df9748ee9d2922a6732b4dc861bbebc1`.
- SQLite budget connection lifecycle: open #308 at
  `faeeffc36f050027546964b7ef7d351a85f369b8`.

Apply each exact main-to-component Git delta in that order. Three-way application
was clean, including overlapping commerce code and API/commerce fixtures.
The #266 description contains older source identities; the component above is
the observed current PR head, not an assertion that old reviews/authority carry
forward. Closure of #266/#307 is not admission. Preview, accelerator code,
response-projection experiments and unpublished MCP regressions are excluded.

## Resulting behavior

The existing custody service validates the supplied issuance handle against
protected attempt/order/reservation state before canonical evidence projection,
provider execution or observation. It derives executor references from that
state, not unchecked worker fields. Valid issuance handles survive legitimate
custody state transitions; existing canonical replay checks still apply.

The exact purchase request/order includes strict boolean auto-renew state.
Name.com V0 supports only disabled renewal, checks it before provider entry and
transmits that exact value. The independent observation path reads provider
renewal state; missing observation is unresolved, mismatched state is failure.
An older persisted proposal cannot silently acquire a new action meaning through
the defaulted field. It stays inert and requires fresh legitimate proposal work.

Budget operation connections close after success, denial and setup failure.
The added protected reservation lookup is read-only and closes its connection.
It reads settled issuance values without reviving an execution right.

## Required change record

1. **Invariants:** supplied handles cannot self-attest; provider defaults cannot
   enlarge the exact authorized consequence; budget connections close on all
   tested paths. Missing information is not proof of successful consequence.
2. **Authority:** acceptance narrows; no new approval, credential, budget ceiling,
   provider route or runtime writer is granted. Tests use synthetic authorities
   and fake providers. The existing custodian remains trusted.
3. **Canonical mutations:** no new mutation interface/table/ledger. Existing
   valid authorization, reservation, permit consumption, custody transition,
   evidence projection and reconciliation remain on their governed owners.
   Invalid handle/reservation requests must leave all canonical table rows
   unchanged, including pending evidence. Renewal fields change canonical
   hashes and constrain the existing reconciliation classification.
4. **Evidence:** fresh candidate-written regressions over exact-main runtime
   reproduce #307's two failing methods (26 assertion failures across methods),
   #266's five tests (four failures/four errors from absent semantic fields), and
   #308's three failing closure tests. Baseline runtime hashes are unchanged.
   Combined initial full run: 384 core/28 custody pass; authority 63 run/59 pass,
   four live-PostgreSQL skips. No observed Warning occurrences; -W error enabled.
   Three new integration methods exercise missing renewal then exact readback,
   renewal substitution without repeat purchase, and unavailable reservation
   state with pending evidence followed by legitimate recovery. The external
   evidence package binds final runs and mutation results to the final tree.
5. **Unproven:** live registrar behavior, production credential/OS/network
   custody, hostile store replacement, rollback/power-loss durability,
   independently deployed human authority, live PostgreSQL, native installed
   Windows/Mac behavior and external-person acceptance are not established.
   This combines selected known repairs, not every security or admission issue.
6. **Claims:** stated local reproductions are Verified; source PR descriptions
   and prior platform counts are Recorded; readiness/admission is Proposed;
   production containment and independent-person validation remain Unknown.
7. **Legacy:** reuse current canonical owners. No Preview router, accelerator,
   alternative authority service, policy truth or ledger is copied.
8. **Temporal:** exact unchanged-main versus candidate regression comparisons
   establish a bounded source delta. The older semantic-proposal fixture checks
   migration rejection, not general historical transfer. Existing core temporal
   tests do not certify this candidate for other releases. No historical
   credential, approval or policy authority is imported.

## Eight analytical passes

| Pass | Finding / disposition |
| --- | --- |
| Flip | Hostile supplied metadata is challenged against existing protected records; trusted-store compromise remains outside proof. |
| Reverse | Validation precedes evidence projection and adapter/observer entry. |
| Invert | Correct original-order purchase cannot justify accepting an altered handle; missing renewal cannot become accepted delivery. |
| Inside-Out | Custodian and backend retain governed capability; no model or worker authenticates itself. |
| Darken | Pending evidence is consequential state; denied requests must not flush it. Renewal drift can create future exposure. |
| Lighten | Baseline showed unchecked metadata and omitted semantics, not a demonstrated production exploit or arbitrary-domain purchase. |
| Amplify | Existing replay/restart/concurrency tests and combined recovery controls apply; repeated purchase after unknown observation is denied. |
| Negate | Extend existing reads, hashes and lifecycle cleanup; add no parallel executor or governor. |

## Admission and next proof

Review this exact combined source independently, reproduce its baseline/candidate
evidence, and run hosted exact-source checks before legitimate admission. Passing
local tests do not authorize a merge or revive closed-PR approvals. Preserve
signature/review protections. The local review commit is unsigned and must not
be treated as canonical admission.

Then demonstrate a separately authorized low-risk external workflow with
distinct authority, executor and observer custody. Keep unresolved consequences
explicit and never infer retry rights. The sales offer remains a scoped evidence
assessment; this candidate is not certification or a turnkey production promise.
