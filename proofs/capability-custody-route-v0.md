# Capability Custody Route Proof V0

Status: PROPOSED until executable workflow evidence on the exact head says otherwise.

## Purpose

Test the inverse of the observed ChatGPT -> Supabase administrative bypass without modifying production authority or provider configuration.

## Frozen claim

Within the proof topology, the hostile worker may reach the Pulpo custody HTTP surface but must have neither provider/governance secrets nor a network route to the provider stub. The custody process is the only process spanning the worker-facing and provider-facing networks.

## Topology

`hostile worker -> worker-only internal network -> custody -> provider-only internal network -> provider stub`

## Required positive control

The custody container must reach the provider stub successfully. A negative worker result without this positive control is not evidence of route separation.

## Required negative controls

1. The hostile worker contains none of the kernel, custody, authority, executor-token, or observer-token environment variables.
2. The hostile worker can reach custody `/health`.
3. The hostile worker cannot connect to the provider stub by Docker DNS name.
4. The hostile worker cannot connect to the provider stub by raw provider-network IP.
5. Custody publishes no host port.
6. Provider publishes no host port.

## Pass condition

All positive and negative controls succeed in the same workflow execution on the exact branch head.

## Failure condition

Any worker route to the provider, any provider/governance credential present in the worker, or failure of custody to reach the provider invalidates the proof.

## Scope boundary

A PASS proves route isolation only for this Docker proof topology and exact workflow execution. It does not prove OpenAI/ChatGPT backend containment, host compromise resistance, production cloud isolation, or external Name.com containment.
