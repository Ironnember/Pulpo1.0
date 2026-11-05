# Synthetic governed incident-response proof

This proof models governed incident response without inspecting or changing a real host.

The process table is a synthetic fixture. The investigator receives bounded read-only metadata. Remediation is a synthetic consequence sink that records one audit observation after canonical permit consumption.

## Boundary

This artifact does not claim or perform:

- real malware detection;
- real XMRig detection or removal;
- process termination on the host;
- file deletion;
- launch-agent or startup modification;
- sensitive path/environment capture;
- production authority;
- Mac EDR/antivirus capability.

## Canonical path

The proof routes remediation authority through:

- `GovernanceKernel`;
- `SQLiteKernelState`;
- canonical target locking and exact-target resolution;
- canonical approval verification;
- canonical approval replay denial;
- canonical one-use permit issuance;
- canonical permit consumption;
- canonical audit events.

The synthetic incident fixture is only the consequence sink.

## Run

```bash
python3 proofs/incident-response/synthetic_incident_response_proof.py --output /tmp/pulpo-synthetic-incident-response-result.json
python3 -m unittest discover -s tests -p 'test_synthetic_incident_response.py' -v
```

## Covered cases

- read-only inspection is bounded and redacted;
- no permit -> no remediation;
- forged approval -> no remediation;
- target substitution -> no authority evaluation and no remediation;
- valid exact approval -> exactly one remediation;
- approval replay -> no second permit;
- permit replay -> no second remediation;
- restart replay -> no second remediation;
- stale PID / changed identity -> no remediation;
- expired approval -> no remediation;
- wrong actor -> no remediation;
- post-action observation reconciles exact target;
- UNKNOWN outcome records no automatic retry authority;
- machine-readable summary is produced.

## Claim class

A passing run is `Verified` for the synthetic fixture only. Real malware response, real host process control, production authority, and endpoint protection remain `Unknown` until separately proven and authorized.
