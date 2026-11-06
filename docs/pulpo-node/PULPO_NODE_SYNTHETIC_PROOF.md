# Pulpo Node synthetic virtual-lamp proof

This proof makes the Pulpo Node virtual-lamp result reproducible from source while preserving the canonical Pulpo governance path.

It intentionally remains synthetic: the lamp is a virtual audit event, not GPIO. The authority signer is the repository's existing test-only verifier from `tests/authority_support.py`, not production authority. The proof uses `GovernanceKernel` and `SQLiteKernelState` for authority verification, approval replay rejection, one-use permit issuance, permit consumption, restart replay denial, and audit/evidence integrity.

## Boundary

This artifact does not authorize or exercise GPIO, Raspberry Pi credentials, network changes, relays, motors, cameras, microphones, persistent daemons, Pulpo production credentials, external provider writes, or physical device custody.

It validates selected synthetic governance behavior through the canonical kernel/state path:

- valid exact target + verified approval -> one virtual signal;
- no permit -> no signal;
- forged approval -> no signal;
- target substitution -> no authority evaluation and no signal;
- approval replay -> no second permit;
- permit replay -> no additional signal;
- restart replay -> no additional signal after reopening canonical SQLite state;
- independent observation -> exact virtual signal reconciled from audit;
- tampered observation -> not reconciled;
- expired approval -> no signal;
- wrong actor -> no signal;
- permit object mismatch -> no signal;
- canonical approval/permit/audit evidence recorded;
- machine-readable summary available.

## Run

```bash
python3 proofs/pulpo-node/virtual_lamp_proof.py --output /tmp/pulpo-node-virtual-lamp-result.json
python3 -m unittest discover -s tests -p 'test_pulpo_node_virtual_lamp.py' -v
python3 scripts/run_gladiator_ultra_tournament.py --repo . --expected-revision "$(git rev-parse HEAD)" --output /tmp/gladiator-ultra-candidate
```

## Claim class

A passing run is `Verified` only for the synthetic virtual-lamp fixture routed through Pulpo's canonical kernel/state path. Physical GPIO custody, Raspberry Pi hardware behavior, deployed runtime containment, production authority, external-provider containment, and no-alternate-route enforcement remain `Unknown` until separately proven.
