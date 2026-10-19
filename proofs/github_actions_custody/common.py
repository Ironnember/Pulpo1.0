"""Shared exact-action construction for the GitHub Actions custody proof."""

from __future__ import annotations

import base64
from dataclasses import asdict
from hashlib import sha256
import json

from pulpo import AuthorityTrust, Ed25519ApprovalVerifier, GovernanceKernel, Intent, Policy

ACTION = "create_proof_artifact"
PRINCIPAL = "github-actions:executor"
AUTHORITY_ID = "authority:github-environment-owner"
VERIFIER_ID = "verifier:github-actions-ed25519"
KEY_ID = "key:github-actions-custody:v1"
DEPLOYMENT_ID = "deployment:github-actions-custody:v1"
TTL_NS = 300_000_000_000


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build_action(repository: str, ref: str, sha: str, run_id: str, run_attempt: str):
    artifact_name = f"pulpo-custody-{run_id}-{run_attempt}"
    receipt = {
        "schema": "pulpo.github-actions-custody.receipt.v1",
        "repository": repository,
        "ref": ref,
        "sha": sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "artifact_name": artifact_name,
    }
    payload = canonical(receipt)
    payload_hash = sha256(payload).hexdigest()
    session_id = f"github-run:{run_id}:{run_attempt}"
    resource = ":".join(
        ("github-actions-artifact", repository, sha, run_id, run_attempt, artifact_name, payload_hash)
    )
    return Intent(PRINCIPAL, ACTION, resource, 0, session_id), artifact_name, payload


def build_kernel(public_key: bytes, now_ns: int):
    verifier = Ed25519ApprovalVerifier(
        authority_id=AUTHORITY_ID,
        verifier_id=VERIFIER_ID,
        key_id=KEY_ID,
        public_key=public_key,
    )
    trust = AuthorityTrust(
        authority_id=AUTHORITY_ID,
        verifier_id=VERIFIER_ID,
        key_id=KEY_ID,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        deployment_id=DEPLOYMENT_ID,
        max_approval_ttl_ns=TTL_NS,
    )
    policy = Policy(frozenset({ACTION}), 0, frozenset({ACTION}), authority_trust=trust)
    return GovernanceKernel(policy, approval_verifier=verifier, clock=lambda: now_ns), trust


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode(), validate=True)


def envelope_json(envelope) -> bytes:
    return canonical(asdict(envelope))
