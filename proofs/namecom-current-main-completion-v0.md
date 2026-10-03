# Name.com Current-Main Completion V0

Status: **DRAFT / PROCESS HOLD / DO NOT MERGE / DO NOT FIRE**

`authority_effect=none`
`governed_effect=none`
`provider_effect=none`

## Purpose

Collapse the previously stacked Name.com proof work onto the current protected `main` without importing the historical proof branch wholesale. This branch is a current-main-derived admission candidate only. It does not contact Name.com, deploy authority infrastructure, create approval authority, or authorize registration.

## Canonical base

Base: `b44dcd40a1ad2bd5413756bd413807f54f9283da`

The completion candidate restages only the already-tested controls needed for the external ceremony:

1. auto-renew state is part of the exact domain order/commitment/reconciliation object and sandbox registration requires it to remain disabled;
2. a successful executor response must be converted into the provider-native Name.com order identity before positive reconciliation is possible;
3. missing or lost provider-native identity leaves the consequence `UNKNOWN` and never recreates retry authority;
4. independent observation reads the exact provider order by provider-native ID and then performs exact-domain readback;
5. authenticated sandbox discovery is read-only, hard-fails when `PULPO_NAMECOM_FIRE != 0`, records no secrets, and does not claim distinct executor/observer credentials where Name.com exposes only one Development/Test token surface.

## Provenance

The code/test blobs were reconciled from the held Name.com proof lineage that previously passed exact-head CI. Restaging them on current `main` is not equivalent to admission: this new exact head requires fresh CI and independent review.

The read-only discovery runner is taken from the exact held discovery head `0f10cb6f071e3617fbf342d45a9b7908fea61e30`. Its allowed provider calls are only:

- `GET /core/v1/hello`
- `POST /core/v1/domains:checkAvailability`

It contains no Create Domain call.

## Required gates before merge

- fresh exact-head CI on this current-main-derived branch;
- fresh constitutional/admission checks;
- substantive independent review of exact-object binding, provider-native attribution, unknown/no-retry semantics, and secret handling;
- no regression to the trusted frozen MCP snapshot exporter already present on `main`.

## Required gates before authenticated discovery

Authenticated discovery may run only on a private credential-bearing operator surface. The Development/Test token must not be pasted into ChatGPT, committed, supplied through PR inputs, or placed in ordinary GitHub Actions.

A successful discovery produces only a sanitized candidate/price artifact and does **not** create purchase authority.

## Required gates before consequential FIRE

A provider registration remains blocked until all of the following are independently satisfied:

- accepted deployment of the selected independent `authority.pulpo.ai` boundary;
- acceptable execution/observation independence despite Name.com's single sandbox-token limitation;
- successful live read-only discovery of one exact disposable domain and prices;
- exact ProposalCommitment/order/policy/budget object with auto-renew disabled;
- fresh approval envelope for that exact object;
- one-use permit and budget reservation;
- separate explicit FIRE after the exact object is shown;
- one bounded provider transmission;
- provider-native order-ID capture;
- independent exact-order plus exact-domain observation;
- reconciliation and replay/restart denial evidence.

## Claim boundary

- `Verified`: this branch is derived directly from protected current `main` rather than the old stacked proof base.
- `Recorded`: the restaged controls previously passed their historical exact-head proof CI.
- `Unknown`: whether the combined current-main candidate passes fresh exact-head CI until GitHub Actions completes.
- `Unknown`: live Name.com authentication and candidate/prices until private discovery succeeds.
- `Not proven`: accepted independent authority deployment, provider write containment, registration, independent provider observation, or end-to-end external consequence governance.

`RESTAGED_PROOF != CANONICAL_ADMISSION`

`PASSING_CI != FIRE_AUTHORITY`

`READ_ONLY_PROVIDER_TRUTH != EXECUTION_AUTHORITY`

`PROVIDER_RESPONSE != VERIFIED_CONSEQUENCE`

`MISSING_PROVIDER_IDENTITY => UNKNOWN + NO_RETRY`
