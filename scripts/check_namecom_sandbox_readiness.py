#!/usr/bin/env python3
"""Read-only Name.com sandbox readiness proof.

This probe intentionally performs no registrar write. It verifies that the
sandbox executor and observer credentials can each perform the same live
availability check, then lets the observer credential construct one bounded
Pulpo proposal. A transport guard rejects every provider request except the
sandbox checkAvailability endpoint.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
import secrets
import sys
from typing import Any

from pulpo.namecom_core import (
    NameComCoreClient,
    NameComCoreConfig,
    NameComResponse,
    NameComViolation,
    UrllibNameComTransport,
)
from pulpo.namecom_proposal import NameComProposalViolation, NameComSandboxProposalBuilder


READ_ONLY_URL = "https://api.dev.name.com/core/v1/domains:checkAvailability"


class ReadinessBlocked(RuntimeError):
    pass


class ReadOnlyNameComTransport:
    """Fail closed before network I/O unless the request is availability-only."""

    def __init__(self, delegate=None) -> None:
        self.delegate = delegate or UrllibNameComTransport()
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, headers, body) -> NameComResponse:
        if method != "POST" or url != READ_ONLY_URL:
            raise NameComViolation("readiness_transport_forbids_provider_write")
        if body is None:
            raise NameComViolation("readiness_availability_body_required")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NameComViolation("readiness_availability_body_invalid") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"domainNames", "purchaseType"}
            or payload.get("purchaseType") != "registration"
            or not isinstance(payload.get("domainNames"), list)
            or len(payload["domainNames"]) != 1
            or not isinstance(payload["domainNames"][0], str)
        ):
            raise NameComViolation("readiness_availability_scope_invalid")
        if "X-Idempotency-Key" in headers:
            raise NameComViolation("readiness_write_header_forbidden")
        self.calls.append((method, url))
        return self.delegate.request(method, url, headers, body)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value != value.strip():
        raise ReadinessBlocked(f"missing required sandbox credential: {name}")
    return value


def _candidate(run_id: str, suffix: str, tld: str) -> str:
    digest = sha256(f"{run_id}:{suffix}:{secrets.token_hex(4)}".encode()).hexdigest()[:14]
    return f"pulpo-proof-{digest}.{tld}"


def _matching_result(response: dict[str, Any], domain: str) -> dict[str, Any]:
    results = response.get("results")
    if not isinstance(results, list):
        raise ReadinessBlocked("name.com sandbox returned invalid results")
    matches = [item for item in results if isinstance(item, dict) and item.get("domainName") == domain]
    if len(matches) != 1:
        raise ReadinessBlocked("name.com sandbox returned ambiguous domain result")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--owner-ref", default="owner://iron-ember/namecom-readiness-v0")
    args = parser.parse_args()

    username = _required("NAMECOM_SANDBOX_USERNAME")
    executor_token = _required("NAMECOM_SANDBOX_EXECUTOR_TOKEN")
    observer_token = _required("NAMECOM_SANDBOX_OBSERVER_TOKEN")
    if not username.endswith("-test"):
        raise ReadinessBlocked("sandbox username must end in -test")
    if executor_token == observer_token:
        raise ReadinessBlocked("executor and observer sandbox tokens must be distinct")

    executor_transport = ReadOnlyNameComTransport()
    observer_transport = ReadOnlyNameComTransport()
    executor = NameComCoreClient(
        NameComCoreConfig(username, executor_token, environment="sandbox"),
        transport=executor_transport,
    )
    observer = NameComCoreClient(
        NameComCoreConfig(username, observer_token, environment="sandbox"),
        transport=observer_transport,
    )
    builder = NameComSandboxProposalBuilder(
        observer,
        principal="agent:hostile-worker-sandbox-v0",
        owner_ref=args.owner_ref,
    )

    selected = None
    errors: list[str] = []
    for index, tld in enumerate(("com", "net", "org", "info", "xyz"), start=1):
        domain = _candidate(args.run_id, str(index), tld)
        try:
            observer_response = observer.check_availability(domain)
            executor_response = executor.check_availability(domain)
            observer_result = _matching_result(observer_response, domain)
            executor_result = _matching_result(executor_response, domain)
            comparable_fields = (
                "domainName",
                "purchasable",
                "purchaseType",
                "premium",
                "purchasePrice",
                "renewalPrice",
            )
            observer_view = {field: observer_result.get(field) for field in comparable_fields}
            executor_view = {field: executor_result.get(field) for field in comparable_fields}
            if observer_view != executor_view:
                raise ReadinessBlocked("executor/observer live availability views diverged")
            if observer_result.get("purchasable") is not True or observer_result.get("premium") is True:
                continue
            proposal = builder.propose(domain)
            selected = {
                "schema": "pulpo.namecom-sandbox-readiness.v0",
                "environment": "sandbox",
                "provider_origin": observer.config.base_url,
                "domain": domain,
                "availability_hash": proposal.availability_hash,
                "observed_at_ns": proposal.observed_at_ns,
                "expires_at_ns": proposal.expires_at_ns,
                "request": asdict(proposal.request),
                "quote": asdict(proposal.quote),
                "order_hash": proposal.order.order_hash,
                "observer_executor_views_match": True,
                "credential_separation_verified": True,
                "read_only_endpoint_enforced": True,
                "executor_read_calls": len(executor_transport.calls),
                "observer_read_calls": len(observer_transport.calls),
                "provider_write_attempted": False,
                "permit_issued": False,
                "authority_effect": "none",
            }
            break
        except (NameComViolation, NameComProposalViolation, ReadinessBlocked) as exc:
            errors.append(f"{domain}:{exc}")

    if selected is None:
        raise ReadinessBlocked("no bounded live sandbox proposal could be constructed: " + " | ".join(errors))

    print(json.dumps(selected, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReadinessBlocked as exc:
        print(f"name.com sandbox readiness blocked: {exc}", file=sys.stderr)
        raise SystemExit(2)
