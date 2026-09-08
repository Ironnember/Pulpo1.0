# Authenticated Name.com Ceremony V0

Status: **PROPOSED / EXECUTION BLOCKED**.

`authority_effect=none`

## Purpose

Freeze the smallest real-provider consequence ceremony that can prove Pulpo governs an authenticated external action through the existing custody path.

This object does not authorize a provider transmission merely by existing or passing CI.

## Inherited evidence object

This branch intentionally composes two already-evaluated held objects without claiming either is canonical:

- external Name.com route-custody head: `29e2da6ef2f68f51cac6d67778047e09b839d101`;
- auto-renew exact-action binding head: `e0149836eef97d79bfbb395aaf329c000dea94a5`.

The first integration commit is `b3b3874c5f380b1dd57bc429a823e717dbfceb66`.

Historical/held evidence is evaluation input only. It is not admission authority.

## Frozen provider boundary

- provider: Name.com CORE API;
- environment: sandbox only;
- origin: `https://api.dev.name.com`;
- purchase type: registration only;
- duration: one year;
- hard Pulpo purchase ceiling: 3,000 cents;
- domain: chosen only through custody-side live discovery for one normalized, non-premium, currently purchasable domain;
- exact observed purchase and renewal prices become part of the request, quote, order, commitment and permit-bound resource;
- registrar: `name.com` only;
- privacy: required;
- auto-renew: explicitly `false` and independently observed after execution;
- prohibited upsells: hosting, email, SSL;
- production endpoint selection: unavailable in the custody runtime.

## Credential custody

The ceremony requires three independent credential/authority surfaces:

1. independent Pulpo human authority capable of issuing the exact signed approval envelope;
2. Name.com sandbox executor credential retained only by custody;
3. distinct Name.com sandbox observer credential retained only by custody.

The hostile worker must receive none of those credentials.

Provider credentials must never be pasted into ChatGPT, committed to GitHub, embedded in a PR body, logged by CI, or returned through the hostile-worker API.

The runtime must continue to require:

- sandbox username ending in `-test`;
- distinct executor and observer tokens;
- pinned independent authority public trust;
- exact approval TTL and deployment identity;
- an opaque `owner://` reference rather than private owner data in the worker surface.

## Required authority sequence

The only admissible execution sequence is:

`domain-only proposal -> custody live discovery/quote -> ProposalCommitment -> custody-generated approval challenge -> independent authority request -> independently signed approval envelope -> authorization by commitment reference -> one-use permit/budget consumption -> one provider transmission -> independent provider observation -> reconciliation -> canonical evidence projection -> governed outcome memory`

No direct-order submission and no test-signer fallback count.

## Required denial matrix

Before any allowed transmission is attempted, the same exact ceremony substrate must demonstrate:

1. missing approval -> zero provider write calls;
2. invalid/substituted approval -> zero provider write calls;
3. substituted proposal/order hash -> zero provider write calls;
4. expired approval -> zero provider write calls;
5. revoked directive/authority before permit consumption -> zero provider write calls;
6. price or renewal-price drift at live preflight -> zero provider write calls;
7. auto-renew substitution -> zero provider write calls;
8. permit replay -> zero additional provider write calls;
9. restart after spent authority -> zero additional provider write calls;
10. hostile-worker direct provider route -> blocked;
11. hostile-worker provider/governance credential possession -> absent.

## Single allowed transmission

Only after every prerequisite and denial control passes may the exact approved object produce one registration transmission.

The executor must:

- re-run live read-only preflight immediately before release;
- require exact purchase and renewal prices to match the frozen order;
- require `auto_renew_enabled is False`;
- derive the provider idempotency key from the custody attempt identity;
- release at most one network transmission right;
- treat transport ambiguity after release as `unknown`, never as permission to retry.

Provider success is a claim, not verified consequence.

## Independent reconciliation

Success requires an independent observer credential to read provider state and bind the observation to the same attempt/order.

The observer must establish the exact domain registration plus the material governed properties, including owner reference attribution where the adapter supports it, charge/order evidence, privacy state, DNS/registration state and `autorenewEnabled == false`.

Missing observation remains unresolved. Substitution is failure. Executor success alone is not success.

## Hard blockers before FIRE

Real execution is forbidden until all of the following are true:

1. the auto-renew correction represented by held PR #169 has received substantive review and legitimate admission into current canonical `main`, or an equivalent current-main correction is admitted;
2. the capability-custody route isolation represented by held PRs #170/#171 has received substantive review and legitimate admission, or equivalent current-main containment is admitted;
3. Issue #90 (`authority.pulpo.ai`) has passed independent deployment/acceptance proof; test/local signers cannot substitute;
4. exact current canonical main and exact ceremony implementation are reconciled after those admissions;
5. separately retained Name.com sandbox executor and observer credentials exist and are proven distinct without revealing them to ChatGPT or the worker;
6. the exact disposable sandbox domain is discovered from live provider truth inside custody and remains below the hard budget;
7. a fresh independent approval envelope exists for that exact commitment and has not expired;
8. the user separately authorizes FIRE against that exact frozen object after seeing the domain, prices, hashes, expiry and nonclaims.

`PASSING_CI != FIRE_AUTHORITY`

`CREDENTIAL_PRESENT != AUTHORITY`

`PROVIDER_SUCCESS != VERIFIED_CONSEQUENCE`

## Current claim boundary

At creation of this contract, external route custody and auto-renew binding have passing held-branch evidence, but neither is canonical admission evidence for this ceremony. Independent deployed authority acceptance is also still open. Therefore the authenticated provider transmission remains **BLOCKED**.
