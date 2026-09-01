# Commerce Auto-Renew Governed-Effect Gap V0

Status: **RED PROOF / PROCESS HOLD / DO NOT MERGE**

`authority_effect=none`

## Finding

A domain registration can create provider-side auto-renew state that later causes a renewal charge. That state is therefore a governed effect/capability, not incidental metadata.

Canonical Pulpo currently binds purchase price, renewal price, registrar, owner, privacy, prohibited upsells, credential reference, and expiry into the domain purchase order. It does **not** bind an explicit auto-renew decision into:

- `DomainPurchaseRequest`;
- `DomainPurchaseOrder` / `order_hash` / permit resource;
- `VerificationEvidence`;
- `IndependentDomainObservation` and external reconciliation.

The current Name.com adapter happens to create `autorenewEnabled: false`, but that provider-specific implementation choice is not part of the governed order object and is not independently verified during reconciliation.

GoDaddy documentation made the defect consequentially visible because its registration flow enables auto-renew by default. The defect is provider-independent: a future renewal capability must be explicitly authorized and independently observed regardless of provider defaults.

## Red proof

`tests/test_commerce_autorenew_boundary.py` requires the four canonical schemas above to contain `auto_renew_enabled`.

On the current canonical base `ca3636680ca50356406519a5722444c0742afb39`, these tests are expected to fail. A failing hosted CI run is the intended executable evidence that the governed-effect object is incomplete.

## Corrective acceptance boundary

A future fix is claim-eligible only if it proves all of the following:

1. request policy explicitly binds auto-renew, with fail-safe default `false` for the bounded pilot;
2. exact `DomainPurchaseOrder.order_hash` changes when auto-renew changes, so permit substitution is denied;
3. each registrar adapter fails closed if it cannot honor the exact requested state;
4. independent provider observation records actual auto-renew state;
5. reconciliation refuses success when observed auto-renew differs from the authorized order or is unavailable;
6. existing replay, restart, budget, custody, and provider-unknown semantics remain intact.

## Nonclaims

This red proof does not implement the fix, authorize a registrar account, create a provider credential, or execute any external registration. It must not be merged while red.

Doctrine:

`CANONICAL_ACTION_OMISSION != AUTHORIZED_PROVIDER_DEFAULT`
