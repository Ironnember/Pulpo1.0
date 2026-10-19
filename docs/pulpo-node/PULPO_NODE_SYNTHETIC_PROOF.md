# Pulpo Node synthetic virtual-lamp proof

This proof makes the recorded Pulpo Node virtual-lamp result reproducible from source. It intentionally remains synthetic. The signer is a test fixture, the state store is SQLite, and the lamp is a temporary virtual effect.

## Boundary

This artifact does not authorize or exercise GPIO, Raspberry Pi credentials, network changes, relays, motors, cameras, microphones, persistent daemons, Pulpo production credentials, or physical device custody.

It validates selected governance behavior only:

- valid permit -> one virtual signal;
- no permit -> no signal;
- forged approval -> no signal;
- target substitution -> no signal;
- permit replay -> no additional signal;
- restart replay -> no additional signal;
- independent observation -> reconciled to the exact virtual signal.

## Run

```bash
python3 proofs/pulpo-node/virtual_lamp_proof.py --output /tmp/pulpo-node-virtual-lamp-result.json
python3 -m unittest discover -s tests -p 'test_pulpo_node_virtual_lamp.py' -v
python3 scripts/run_gladiator_ultra_tournament.py --repo . --expected-revision "$(git rev-parse HEAD)" --output /tmp/gladiator-ultra-candidate
```

## Claim class

A passing run is `Verified` for the synthetic virtual-lamp fixture only. Physical GPIO custody, Raspberry Pi hardware behavior, deployed runtime containment, and no-alternate-route enforcement remain `Unknown` until separately proven.
