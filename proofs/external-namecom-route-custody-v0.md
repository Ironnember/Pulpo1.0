# External Name.com Route Custody Proof V0

Status: PROPOSED until exact-head executable workflow evidence says otherwise.

## Purpose

Extend the already-proved hostile-worker capability-custody topology from an internal provider stub to the real Name.com development network **without using a real provider credential or sending an authenticated API request**.

## External target

Official Name.com development/test API host:

`api.dev.name.com:443`

Name.com support documents a separate Development/Test Environment, and the public v4 API examples use `https://api.dev.name.com/...`.

## Frozen claim

Within this proof topology:

1. the canonical Pulpo custody container can resolve and complete a TLS handshake to `api.dev.name.com:443`;
2. the hostile worker can reach Pulpo custody `/health`;
3. the hostile worker has no Name.com or Pulpo governance secrets;
4. the hostile worker cannot connect to `api.dev.name.com:443` by hostname;
5. the hostile worker cannot connect to the exact IPv4 address resolved by custody for that host;
6. custody publishes no host port;
7. the worker is attached only to an internal Docker network;
8. no authenticated Name.com request, domain availability call, registration call, or provider mutation occurs.

## Topology

`hostile worker -> internal worker network -> custody -> egress network -> api.dev.name.com:443`

The worker receives no egress-capable network. Custody spans the worker network and a separate egress-capable Docker bridge. Provider credentials in this proof are explicit non-secret sentinel placeholders required only to satisfy local custody configuration; they are not valid Name.com credentials and are never transmitted.

## Positive control

Custody must complete certificate-validated TLS to the real Name.com development host. A worker denial without this positive control is not evidence of external route separation.

## Negative controls

- worker contains none of the tested Pulpo or Name.com secret variables;
- worker cannot connect to Name.com by DNS name;
- worker cannot connect to the custody-resolved raw provider IPv4;
- worker has exactly one Docker network and it is internal;
- custody publishes no host port.

## Pass condition

All positive and negative controls pass in one workflow execution on the exact branch head.

## Failure condition

Any worker connection to the external Name.com host or raw provider IP, any real provider credential in the proof, inability of custody to complete the TLS positive control, or any authenticated provider request invalidates the proof.

## Scope boundary

A PASS proves external **network-route custody** for this GitHub-hosted Docker topology and the observed Name.com development endpoint at test time. It does not prove authenticated Name.com capability custody, production cloud isolation, OpenAI/ChatGPT containment, host-compromise resistance, provider correctness, or a real domain consequence.
