# Name.com Live Sandbox Discovery V0

Status: **PROPOSED / READ-ONLY PROVIDER CONTACT ONLY / FIRE BLOCKED**

`authority_effect=none`

## Purpose

Advance the authenticated Name.com ceremony to the first real provider-backed step without creating a provider-side consequence. This proof authenticates the single Development/Test credential surface currently exposed by Name.com to this account, performs provider-native domain availability/pricing discovery, and freezes one disposable non-premium candidate below Pulpo's $30 purchase ceiling.

This proof does **not** register a domain and does **not** claim executor/observer provider-credential separation.

## Provider boundary

- provider: Name.com CORE API;
- environment: sandbox only;
- origin: `https://api.dev.name.com`;
- authentication: HTTP Basic Auth;
- sandbox username must end `-test`;
- provider credential mode observed by the operator: one Development/Test token surface;
- discovery endpoint: `POST /core/v1/domains:checkAvailability`;
- purchase type: `registration` only;
- maximum candidate batch: 30 domains;
- accepted candidate must be purchasable, non-premium, and <= 3,000 cents purchase price.

Name.com documents the sandbox as a separate testing environment that does not affect real domains or incur real charges. Sandbox data is not synchronized with production.

## Secret custody

Provider credentials must not be pasted into ChatGPT, committed, written to GitHub Actions logs, or passed as command-line arguments.

The intended operator path is:

```bash
bash scripts/run_namecom_sandbox_discovery_v0.sh
```

The runner reads the username and one Development/Test token interactively, with token echo disabled, exports them only to the child process, then unsets them on exit.

The sanitized artifact contains no secret values or secret-derived hashes.

## Allowed provider calls

The discovery script is intentionally limited to these authenticated calls:

1. `GET /core/v1/hello` using the sandbox credential;
2. `POST /core/v1/domains:checkAvailability` using the same sandbox credential.

It contains no Create Domain call and fails immediately if `PULPO_NAMECOM_FIRE` is anything other than `0`.

## Sanitized output

On success, `.pulpo-artifacts/namecom-sandbox-discovery.json` records only:

- provider/environment/origin;
- exact source Git head;
- purchase ceiling;
- boolean proving the sandbox credential authenticated;
- `credential_mode=single_sandbox_token`;
- `executor_observer_distinct=false`;
- `distinct_credential_separation_claimed=false`;
- selected disposable domain;
- purchase and renewal prices in cents;
- purchase type and premium flag;
- candidate/acceptable counts;
- `provider_write_attempted=false`;
- `fire_authorized=false`;
- a SHA-256 evidence hash over the sanitized object.

## Transition to consequential FIRE

A successful discovery result is **not** purchase authority. It becomes input to the existing ceremony only after the exact selected domain and prices are bound into the request, quote, order, ProposalCommitment, independent approval envelope, one-use permit, budget reservation, and custody attempt.

The provider write remains blocked until the hard blockers in `proofs/namecom-authenticated-ceremony-v0.md` are satisfied, including accepted independent `authority.pulpo.ai`, current-main reconciliation, exact provider-native transaction attribution, independently controlled execution/observation trust boundaries, exact commitment approval, and a separate explicit FIRE authorization after the user sees the final object.

The single provider sandbox credential means this discovery step can prove live provider authentication and read-only discovery, but **cannot** prove independent executor/observer credential custody at the provider boundary. That limitation must remain explicit rather than being simulated by duplicating the same token under different labels.

## Provider-native observation requirement

The live write proof must not rely on local `provider_request_id` as transaction identity. Create Domain returns a provider-native numeric order identifier. That identifier must be durably captured inside existing custody state before success can be reconciled, and the observer must use it only as a locator for `GET /core/v1/orders/{id}` plus exact Get Domain readback.

Until provider-native attribution and an acceptable observer independence boundary are implemented and independently reviewed, authenticated read-only discovery may proceed but the domain-registration FIRE remains blocked.

## Claim boundary

If this proof succeeds:

- `Verified`: the single Name.com sandbox credential authenticated against the real sandbox endpoint;
- `Verified`: one exact provider-returned disposable domain/price candidate was discovered under the frozen ceiling;
- `Verified`: this script attempted no provider write;
- `Verified`: this proof did not claim distinct executor/observer provider credentials;
- `Not proven`: independent provider-credential custody, independent authority acceptance, provider write containment, exact provider-order attribution, registration success, reconciliation, or external consequence governance.

`READ_ONLY_PROVIDER_TRUTH != EXECUTION_AUTHORITY`

`SINGLE_PROVIDER_CREDENTIAL != INDEPENDENT_OBSERVER_CUSTODY`

`DISCOVERED_OBJECT != AUTHORIZED_OBJECT`

`PROVIDER_CREDENTIAL_PRESENT != FIRE_AUTHORITY`
