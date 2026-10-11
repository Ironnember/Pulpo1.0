"""Environment-gated authority signer for one exact GitHub Actions run."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pulpo import ApprovalEnvelope
from proofs.github_actions_custody.common import (
    AUTHORITY_ID,
    DEPLOYMENT_ID,
    KEY_ID,
    TTL_NS,
    VERIFIER_ID,
    b64,
    build_action,
    build_kernel,
    envelope_json,
)


def main() -> int:
    private_pem = os.environ["PULPO_PROOF_ED25519_PRIVATE_KEY_PEM"].encode()
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("authority key is not Ed25519")

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pinned = bytes.fromhex(Path("proofs/github_actions_custody/public_key.hex").read_text().strip())
    if public_key != pinned:
        raise RuntimeError("authority private key does not match pinned public key")

    intent, artifact_name, payload = build_action(
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_REF"],
        os.environ["GITHUB_SHA"],
        os.environ["GITHUB_RUN_ID"],
        os.environ["GITHUB_RUN_ATTEMPT"],
    )
    if os.environ["GITHUB_REF"] != "refs/heads/main":
        raise RuntimeError("authority only signs protected main")

    now_ns = time.time_ns()
    kernel, trust = build_kernel(public_key, now_ns)
    unsigned = ApprovalEnvelope(
        approval_id=f"approval:github-actions:{os.environ['GITHUB_RUN_ID']}:{os.environ['GITHUB_RUN_ATTEMPT']}",
        authority_id=AUTHORITY_ID,
        verifier_id=VERIFIER_ID,
        key_id=KEY_ID,
        deployment_id=DEPLOYMENT_ID,
        trust_hash=trust.trust_hash,
        session_id=intent.session_id,
        principal=intent.principal,
        intent_hash=kernel.intent_hash(intent),
        policy_hash=kernel.policy_hash,
        nonce=secrets.token_hex(16),
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + TTL_NS,
        signature="",
    )
    envelope = replace(unsigned, signature=private_key.sign(unsigned.signing_bytes()).hex())

    outputs = {
        "approval_b64": b64(envelope_json(envelope)),
        "payload_b64": b64(payload),
        "artifact_name": artifact_name,
    }
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    with output_path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")

    print(json.dumps({
        "authority_effect": "one_exact_run_approval",
        "artifact_name": artifact_name,
        "intent_hash": envelope.intent_hash,
        "envelope_hash": envelope.envelope_hash,
        "private_key_exposed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
