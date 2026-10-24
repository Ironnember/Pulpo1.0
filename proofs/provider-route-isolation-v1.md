# Provider Route Isolation Proof V1

Status: PROPOSED until CI evidence on the exact branch head completes successfully.

## Purpose

Prove a narrow capability-custody property using the existing Pulpo custody service and existing CI admission path.

## Frozen claim

Within the tested Docker topology:

- the hostile worker can reach the Pulpo custody HTTP surface;
- custody can reach the protected provider stub;
- the hostile worker has neither the tested Pulpo/provider secrets nor a direct route to the provider stub by Docker DNS name or raw provider-network IP;
- custody and provider publish no host ports.

This is a route-isolation proof, not a claim of universal external containment.

## Topology

`hostile worker -> internal worker network -> custody -> internal provider network -> provider stub`

The hostile worker is attached only to the worker-facing internal network. The provider is attached only to the provider-facing internal network. Custody spans both.

## Required positive controls

1. Custody becomes healthy.
2. The hostile worker can reach custody `/health`.
3. Custody can reach the provider stub and receive the expected probe response.

A worker denial without the custody-to-provider positive control does not prove exclusive routing.

## Required negative controls

1. The hostile worker lacks the tested kernel, custody, authority, executor-token, and observer-token environment variables.
2. The hostile worker lacks the custody state mount.
3. The hostile worker lacks the Docker socket.
4. The hostile worker cannot reach the provider by Docker DNS name.
5. The hostile worker cannot reach the provider by raw provider-network IP.
6. Custody and provider publish no host ports.
7. Both proof networks are Docker internal networks.

## Admission path

The proof runs as an additional step inside the existing `hostile-worker-container-isolation` CI job. That job already feeds the protected `test` admission context. This change therefore does not create a second workflow, authority service, executor, policy engine, or admission mechanism.

## Scope boundary

A PASS verifies only the exact Docker topology and exact commit executed by CI. It does not establish:

- OpenAI or ChatGPT backend containment;
- host-compromise resistance;
- production cloud isolation;
- real Name.com provider containment;
- universal prevention of every possible alternate execution route.

Those require separate external proofs.

## Doctrine

Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.
