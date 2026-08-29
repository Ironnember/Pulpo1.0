#!/usr/bin/env python3
"""Read-only Name.com sandbox readiness proof.

This probe intentionally performs no registrar write. It verifies that the
sandbox executor and observer credentials can each perform the same live
availability check, then lets the observer credential construct one bounded
Pulpo proposal. It never calls Create Domain, issues no permit, reserves no
budget, and grants no authority.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
import secrets
from typing import Any

from pulpo.namecom_core import NameComCoreClient, NameComCoreConfig, NameComViolation
from pulpo.namecom_proposal import NameComProposalViolation, NameComSandboxProposalBuilder


class ReadinessBlocked(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value != value.strip():
        raise ReadinessBlocked(f"missing required sandbox credential: {name}")
    return value


def _candidate(run_id: str, suffix: str, tld: str) -> str:
    digest = sha256(f"{run_id}:{suffix}:{secrets.token_hex(4)}".encode()).hexdigest()[:14]
    return f"pulpo-proof-{digest}.{tld}"


def _matching_result(response: dict[str, Any], domain: str) -> dict[str, Any] | None:
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

    executor = NameComCoreClient(NameComCoreConfig(username, executor_token, environment="sandbox"))
    observer = NameComCoreClient(NameComCoreConfig(username, observer_token, environment="sandbox"))
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
        print(f"name.com sandbox readiness blocked: {exc}", file=os.sys.stderr)
        raise SystemExit(2)
