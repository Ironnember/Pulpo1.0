"""Permit-only executor for the GitHub Actions custody proof."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import time

from pulpo import ApprovalEnvelope
from proofs.github_actions_custody.common import build_action, build_kernel, unb64


def decode_envelope(value: str) -> ApprovalEnvelope:
    data = json.loads(unb64(value))
    return ApprovalEnvelope(**data)


def main() -> int:
    expect_deny = os.environ.get("PULPO_EXPECT_DENY") == "1"
    tamper = os.environ.get("PULPO_TAMPER", "")

    public_key = bytes.fromhex(
        Path("proofs/github_actions_custody/public_key.hex").read_text().strip()
    )
    intent, artifact_name, expected_payload = build_action(
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_REF"],
        os.environ["GITHUB_SHA"],
        os.environ["GITHUB_RUN_ID"],
        os.environ["GITHUB_RUN_ATTEMPT"],
    )

    if os.environ["GITHUB_REF"] != "refs/heads/main":
        raise RuntimeError("executor only runs on protected main")

    approval_b64 = os.environ.get("PULPO_APPROVAL_B64", "")
    payload_b64 = os.environ.get("PULPO_PAYLOAD_B64", "")

    if not approval_b64:
        if expect_deny:
            print("DENY: approval_missing")
            return 0
        raise RuntimeError("approval_missing")

    try:
        envelope = decode_envelope(approval_b64)
    except Exception as exc:
        if expect_deny:
            print(f"DENY: approval_malformed:{type(exc).__name__}")
            return 0
        raise

    if tamper == "artifact":
        intent = replace(intent, resource=intent.resource + ":tampered")
    elif tamper == "signature":
        envelope = replace(envelope, signature="00" * 64)

    now_ns = time.time_ns()
    kernel, _ = build_kernel(public_key, now_ns)
    decision = kernel.evaluate_with_approval(intent, envelope)

    if decision.outcome != "allow" or decision.permit is None:
        if expect_deny:
            print(f"DENY: {decision.reason}")
            return 0
        raise RuntimeError(f"permit_denied:{decision.reason}")

    if expect_deny:
        raise RuntimeError("expected denial but permit was issued")

    if not payload_b64:
        raise RuntimeError("payload_missing")
    payload = unb64(payload_b64)
    if payload != expected_payload:
        raise RuntimeError("payload_exact_object_mismatch")

    if not kernel.consume(decision.permit, intent):
        raise RuntimeError("permit_consume_failed")
    if kernel.consume(decision.permit, intent):
        raise RuntimeError("permit_replay_succeeded")

    out_dir = Path("build/github-actions-custody")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{artifact_name}.json"
    out_path.write_bytes(payload)

    print(json.dumps({
        "artifact_name": artifact_name,
        "consequence": "artifact_payload_materialized",
        "permit_consumed_once": True,
        "permit_replay": False,
        "receipt_path": str(out_path),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
