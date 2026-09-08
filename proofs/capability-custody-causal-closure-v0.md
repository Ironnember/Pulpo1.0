# Capability Custody Causal Closure Proof V0

Status: PROPOSED until exact-head executable evidence says otherwise.

Parent proof: PR #170, `proof/capability-custody-route-v0` at `d817e8234664072bc3be0c7306f9f2455874f8b4`.

Related red-team contract: Issue #189.

## Purpose

Attack the strongest current capability-custody claim from the indirect path rather than the direct provider route.

The parent proof establishes, within its Docker topology, that the hostile worker can reach Pulpo custody but cannot reach the provider stub directly by provider DNS name or raw provider-network IP.

This proof asks the next question:

> Can the worker still cause the protected provider effect through a reachable helper, token broker, metadata relay, webhook relay, signed-request broker, SSRF primitive, or other confused deputy even though its own provider route is blocked?

Core invariant:

`NO_DIRECT_PROVIDER_ROUTE != NO_UNGOVERNED_CAUSAL_PATH_TO_EFFECT`

## Claim under test

Within this proof topology:

1. the hostile worker may reach Pulpo custody;
2. the hostile worker may reach deliberately dangerous relay/helper surfaces;
3. the hostile worker may know the provider DNS name and raw provider-network IP;
4. the worker and relay surfaces possess no provider/governance secret;
5. no worker-facing relay other than Pulpo custody spans the provider-facing network;
6. triggering relay classes must produce zero provider effects;
7. adding a worker-facing relay that also spans the provider network must be detected by the causal-closure sentinel before it can count as a valid topology;
8. Pulpo custody retains a positive-control route to the provider.

## Proof topology

```text
hostile worker
   |\
   | +--> metadata/token relay ----X----> provider
   | +--> signed-request relay ----X----> provider
   | +--> webhook/event relay -----X----> provider
   | +--> SSRF relay --------------X----> provider
   | +--> ambient-helper relay ----X----> provider
   |
   +----> Pulpo custody ----------------> provider
```

Both worker-facing and provider-facing Docker networks remain `--internal`.

The provider records exact local proof effects. No external provider is used.

## Relay classes

The helper surface exposes proof-only operations shaped like common confused-deputy paths:

- metadata/token retrieval;
- delegated/signed request creation;
- asynchronous webhook/event trigger;
- caller-supplied SSRF target;
- ambient-credential execution helper.

These surfaces are intentionally reachable from the hostile worker. They are not allowed to possess the provider credential or a provider-network route.

## Causal-closure sentinel

The test must inspect the live Docker topology and fail if any worker-network peer other than canonical Pulpo custody spans more than the worker-facing network.

A deliberate mutant helper is then temporarily attached to both worker and provider networks. The sentinel must reject that topology. The mutant is removed before the normal proof continues and is never used to create a provider effect.

This is a mutation test for the topology invariant, not an authorized alternate execution path.

## Required success and denial evidence

The same exact-head workflow must establish:

1. parent custody-domain exact permit/revocation/restart/budget tests still pass;
2. parent custody-service denial/replay/tamper tests still pass;
3. worker reaches custody health;
4. custody reaches provider positive control;
5. worker cannot reach provider DNS or raw IP directly;
6. worker reaches each proof relay;
7. worker and relay contain none of the tested provider/governance secrets;
8. metadata/token relay cannot produce provider effect;
9. signed-request relay cannot produce provider effect;
10. webhook/event relay cannot produce provider effect;
11. SSRF relay cannot produce provider effect by provider DNS or raw IP;
12. ambient-helper relay cannot produce provider effect;
13. provider effect count remains zero after every hostile relay attempt;
14. deliberate cross-network relay mutation is detected by the causal-closure sentinel;
15. custody positive control can create exactly one local proof effect after all hostile attempts remain at zero;
16. custody/provider remain unexposed by host ports in the proof topology.

## Failure condition

The proof fails if:

- any hostile worker or helper causes a provider effect;
- a worker-facing helper holds a tested provider/governance secret;
- a worker-facing helper silently spans the provider network;
- direct worker/provider reachability appears;
- the mutation sentinel accepts a deliberately cross-network relay;
- the provider positive control is unreachable.

## Scope boundary

A PASS is bounded to this exact Docker proof topology and tested relay classes.

It does **not** prove:

- arbitrary causal closure across the Internet;
- OpenAI/ChatGPT backend containment;
- hostile-host or hostile-custodian containment;
- absence of every possible metadata/workload-identity/token-exchange path;
- provider-side delegation correctness;
- production VPC/IAM correctness;
- real Name.com or Telegram custody;
- semantic correctness of a permitted action;
- provider atomicity or TOCTOU safety;
- cold third-party reproduction.

The correct claim after a PASS is:

> Within the exact tested Docker topology, direct provider isolation survives the tested indirect relay classes because every hostile worker-facing relay lacks both provider capability and provider-network reachability, and a deliberate cross-network relay mutation is detected before the topology is accepted.

Do not shorten this to `general capability custody proven`.

## Authority and admission

`authority_effect=none`

`governed_effect=none`

`provider_effect=local_stub_only`

This proof does not authorize merge of itself or PR #170, external provider execution, new credentials, policy change, or production deployment.

Passing evidence is not admission authority.
