#!/usr/bin/env python3
"""Run the PR #83 Hostile Worker V0 admission path through deployed services.

This script owns no registrar credentials, prices, budget state, permit, policy,
or signing key. It acts only as the hostile worker:

    domain
    -> custody proposal commitment + exact authority request
    -> authenticated request/poll to independent authority service
    -> custody authorization by proposal reference
    -> one execution request
    -> independent reconciliation

The custody runtime is separately hard-pinned to Name.com sandbox. This client
has no production-provider switch and no direct-order fallback.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pulpo.authority_client import AuthorityApprovalRequest, AuthorityClient


MAX_RESPONSE_BYTES = 1_048_576
MAX_WORKER_TOKEN_BYTES = 16_000


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CeremonyBlocked(RuntimeError):
    pass


def _origin(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CeremonyBlocked("custody URL must be an HTTP(S) origin")
    return value.rstrip("/")


def _worker_authorization_provider(environment_name: str):
    if not environment_name or environment_name != environment_name.strip():
        raise CeremonyBlocked("worker token environment variable name is invalid")
    token = os.environ.get(environment_name, "")
    if (
        not token
        or token != token.strip()
        or any(character.isspace() for character in token)
        or len(token.encode()) > MAX_WORKER_TOKEN_BYTES
    ):
        raise CeremonyBlocked(
            f"authenticated authority worker token is unavailable in {environment_name}"
        )
    return lambda: f"Bearer {token}"


def _request_json(
    opener,
    base_url: str,
    method: str,
    path: str,
    body: dict[str, object] | None = None,
) -> dict[str, Any]:
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = Request(
        f"{base_url}{path}",
        data=encoded,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise CeremonyBlocked(f"custody returned HTTP {response.status}")
            final = urlparse(response.geturl())
            if f"{final.scheme}://{final.netloc}" != base_url:
                raise CeremonyBlocked("custody response crossed the pinned origin")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise CeremonyBlocked(f"custody rejected {method} {path}: HTTP {exc.code}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CeremonyBlocked("custody response exceeded size limit")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CeremonyBlocked("custody returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise CeremonyBlocked("custody returned a non-object response")
    return value


def _approval(
    authority: AuthorityClient,
    request_value: dict[str, object],
    *,
    poll_attempts: int,
    poll_delay_seconds: float,
):
    request = AuthorityApprovalRequest(**request_value)
    request_id, approval_url = authority.request_approval(request)
    print(f"independent approval required: {approval_url}", file=sys.stderr)
    for index in range(poll_attempts):
        poll = authority.poll_approval(request_id)
        if poll.status == "approved":
            assert poll.envelope is not None
            return request_id, approval_url, poll.envelope
        if poll.status in {"denied", "expired"}:
            raise CeremonyBlocked(f"independent authority returned {poll.status}: {poll.reason}")
        if index + 1 < poll_attempts:
            time.sleep(poll_delay_seconds)
    raise CeremonyBlocked("independent approval remained pending")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, help="normalized Name.com sandbox domain")
    parser.add_argument("--custody-url", default="http://127.0.0.1:8080")
    parser.add_argument("--authority-url", required=True, help="pinned HTTPS authority origin")
    parser.add_argument(
        "--authority-worker-token-env",
        default="PULPO_AUTHORITY_WORKER_TOKEN",
        help="environment variable containing the raw bearer token for authority request/poll",
    )
    parser.add_argument("--approval-poll-attempts", type=int, default=60)
    parser.add_argument("--approval-poll-delay-seconds", type=float, default=2.0)
    parser.add_argument("--reconcile-attempts", type=int, default=10)
    parser.add_argument("--reconcile-delay-seconds", type=float, default=2.0)
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()

    if args.domain != args.domain.strip().lower() or "." not in args.domain:
        raise CeremonyBlocked("domain must be normalized lowercase")
    if args.approval_poll_attempts < 1 or args.reconcile_attempts < 1:
        raise CeremonyBlocked("poll attempt counts must be positive")
    if args.approval_poll_delay_seconds < 0 or args.reconcile_delay_seconds < 0:
        raise CeremonyBlocked("poll delays must be non-negative")

    custody_url = _origin(args.custody_url)
    opener = build_opener(_NoRedirect())
    authority = AuthorityClient(
        args.authority_url,
        authorization_provider=_worker_authorization_provider(args.authority_worker_token_env),
    )

    proposal = _request_json(
        opener,
        custody_url,
        "POST",
        "/v1/domain-proposals",
        {"domain": args.domain},
    )
    commitment = proposal.get("proposal_commitment")
    challenge = proposal.get("approval_challenge")
    if not isinstance(commitment, dict) or not isinstance(challenge, dict):
        raise CeremonyBlocked("custody proposal omitted commitment or approval challenge")
    commitment_id = commitment.get("commitment_id")
    authority_request = challenge.get("authority_request")
    if not isinstance(commitment_id, str) or not commitment_id:
        raise CeremonyBlocked("custody proposal returned invalid commitment reference")
    if not isinstance(authority_request, dict):
        raise CeremonyBlocked("custody proposal did not require external authority")

    authority_request_id, approval_url, envelope = _approval(
        authority,
        authority_request,
        poll_attempts=args.approval_poll_attempts,
        poll_delay_seconds=args.approval_poll_delay_seconds,
    )

    handle = _request_json(
        opener,
        custody_url,
        "POST",
        "/v1/domain-attempts",
        {
            "proposal_commitment_id": commitment_id,
            "approval": asdict(envelope),
        },
    )
    attempt_id = handle.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise CeremonyBlocked("custody returned invalid attempt handle")

    operation = {"handle": handle}
    execution = _request_json(
        opener,
        custody_url,
        "POST",
        f"/v1/domain-attempts/{attempt_id}/execute",
        operation,
    )
    if execution.get("status") not in {"provider_claim_recorded", "reconciliation_required"}:
        raise CeremonyBlocked("custody returned unexpected execution classification")

    # A copied handle must not create a second provider transmission.
    replay_denied = False
    try:
        _request_json(
            opener,
            custody_url,
            "POST",
            f"/v1/domain-attempts/{attempt_id}/execute",
            operation,
        )
    except CeremonyBlocked as exc:
        if "HTTP 409" in str(exc):
            replay_denied = True
        else:
            raise
    if not replay_denied:
        raise CeremonyBlocked("copied attempt handle unexpectedly remained executable")

    reconciliation = None
    for index in range(args.reconcile_attempts):
        reconciliation = _request_json(
            opener,
            custody_url,
            "POST",
            f"/v1/domain-attempts/{attempt_id}/reconcile",
            operation,
        )
        if reconciliation.get("outcome") in {"success", "failure"}:
            break
        if index + 1 < args.reconcile_attempts:
            time.sleep(args.reconcile_delay_seconds)

    status = _request_json(
        opener,
        custody_url,
        "GET",
        f"/v1/domain-attempts/{attempt_id}",
    )
    evidence = {
        "schema": "pulpo.hostile-worker-namecom-ceremony.v0",
        "domain": args.domain,
        "proposal_commitment": commitment,
        "availability_hash": proposal.get("availability_hash"),
        "approval_request_id": authority_request_id,
        "approval_url": approval_url,
        "approval_id": envelope.approval_id,
        "trust_hash": envelope.trust_hash,
        "intent_hash": envelope.intent_hash,
        "policy_hash": envelope.policy_hash,
        "attempt_handle": handle,
        "execution": execution,
        "copied_handle_replay_denied": replay_denied,
        "reconciliation": reconciliation,
        "final_status": status,
        "authority_effect": "none_beyond_exact_sandbox_attempt",
    }
    encoded = json.dumps(evidence, sort_keys=True, indent=2)
    if args.evidence_out is not None:
        args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_out.write_text(encoded + "\n")
    print(encoded)
    return 0 if reconciliation and reconciliation.get("outcome") == "success" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CeremonyBlocked as exc:
        print(f"hostile-worker ceremony blocked: {exc}", file=sys.stderr)
        raise SystemExit(2)
