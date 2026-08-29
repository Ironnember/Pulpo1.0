#!/usr/bin/env python3
"""Run the external Hostile Worker V0 path against name.com CORE sandbox.

This harness is intentionally SANDBOX ONLY. It cannot select the production
base URL and NameComCoreConfig independently rejects production unless enabled.
Sandbox mirrors production API shapes but does not create live domains or real
charges.

Required environment variables:
  NAMECOM_SANDBOX_USERNAME       username ending in -test
  NAMECOM_SANDBOX_EXECUTOR_TOKEN
  NAMECOM_SANDBOX_OBSERVER_TOKEN  separate read-back token
  PULPO_KERNEL_SECRET_HEX          >= 32 bytes encoded as hex
  PULPO_CUSTODY_SECRET_HEX         >= 32 bytes encoded as hex

The harness never prints tokens or secrets.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import time

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_executor import ExternalConsequenceUnknown, TrustedDomainExecutor
from pulpo.custody_reconcile import IndependentDomainReconciler
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.namecom_core import (
    NameComCoreClient,
    NameComCoreConfig,
    NameComCoreRegistrarAdapter,
    NameComViolation,
)
from pulpo.namecom_observer import NameComCoreObserver
from pulpo.state import SQLiteKernelState


PILOT_MAX_PURCHASE_CENTS = 3_000


def _secret_from_env(name: str) -> bytes:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be hex") from exc
    if len(raw) < 32:
        raise RuntimeError(f"{name} must encode at least 32 bytes")
    return raw


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def _usd_to_cents(value) -> int:
    from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise RuntimeError("sandbox returned invalid price") from exc
    return int(amount * 100)


def _default_domain(tld: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    nonce = secrets.token_hex(3)
    return f"pulpo-hw-v0-{stamp}-{nonce}.{tld}".lower()


def _availability(client: NameComCoreClient, domain: str) -> tuple[int, int]:
    decoded = client.check_availability(domain)
    results = decoded.get("results")
    if not isinstance(results, list):
        raise RuntimeError("sandbox availability response missing results")
    matches = [
        item
        for item in results
        if isinstance(item, dict) and item.get("domainName") == domain
    ]
    if len(matches) != 1:
        raise RuntimeError("sandbox did not return exactly one target result")
    result = matches[0]
    if result.get("purchasable") is not True:
        raise RuntimeError("sandbox target is not currently purchasable")
    if result.get("purchaseType") not in {None, "registration"}:
        raise RuntimeError("sandbox target is not standard registration inventory")
    purchase_cents = _usd_to_cents(result.get("purchasePrice"))
    renewal_cents = _usd_to_cents(result.get("renewalPrice"))
    if not 0 <= purchase_cents <= PILOT_MAX_PURCHASE_CENTS:
        raise RuntimeError("sandbox purchase price exceeds frozen $30 pilot ceiling")
    if renewal_cents < 0:
        raise RuntimeError("sandbox renewal price invalid")
    return purchase_cents, renewal_cents


def _safe_summary(
    *,
    domain: str,
    state_path: Path,
    order,
    governed,
    provider_claim,
    reconciliation,
    custody,
    budget,
    execution_unknown: bool,
) -> dict[str, object]:
    attempt = custody.attempt(governed.attempt_id)
    return {
        "schema": "pulpo.hostile-worker-namecom-sandbox.v0",
        "environment": "namecom-sandbox",
        "live_production_effect": False,
        "real_money_charged": False,
        "domain": domain,
        "state_path": str(state_path),
        "order_hash": order.order_hash,
        "attempt_id": governed.attempt_id,
        "governance_epoch": custody.snapshot().epoch,
        "governance_state_root": custody.snapshot().state_root,
        "attempt_state": attempt.state if attempt else None,
        "provider_claim_hash": provider_claim.claim_hash if provider_claim else None,
        "provider_response_lost_or_unknown": execution_unknown,
        "reconciliation_outcome": reconciliation.outcome if reconciliation else None,
        "reconciliation_reason": reconciliation.reason if reconciliation else None,
        "observation_hash": reconciliation.observation_hash if reconciliation else None,
        "budget_spent_cents": budget.spent_cents,
        "budget_reserved_cents": budget.reserved_cents,
        "budget_available_cents": budget.available_cents,
        "authority_effect": "none_beyond_frozen_sandbox_attempt",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", help="unique sandbox-only domain; generated when omitted")
    parser.add_argument("--tld", default="com", help="TLD for generated sandbox target")
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(".pulpo-hostile-worker-v0-sandbox.sqlite3"),
        help="persistent local proof state path",
    )
    parser.add_argument("--observe-attempts", type=int, default=5)
    parser.add_argument("--observe-delay-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if args.observe_attempts < 1:
        raise RuntimeError("observe-attempts must be positive")
    if args.observe_delay_seconds < 0:
        raise RuntimeError("observe delay must be non-negative")

    username = _env("NAMECOM_SANDBOX_USERNAME")
    executor_token = _env("NAMECOM_SANDBOX_EXECUTOR_TOKEN")
    observer_token = _env("NAMECOM_SANDBOX_OBSERVER_TOKEN")
    if executor_token == observer_token:
        raise RuntimeError("executor and observer sandbox tokens must be distinct")
    kernel_secret = _secret_from_env("PULPO_KERNEL_SECRET_HEX")
    custody_secret = _secret_from_env("PULPO_CUSTODY_SECRET_HEX")

    domain = (args.domain or _default_domain(args.tld)).lower()
    args.state.parent.mkdir(parents=True, exist_ok=True)

    executor_client = NameComCoreClient(
        NameComCoreConfig(username, executor_token, environment="sandbox")
    )
    observer_client = NameComCoreClient(
        NameComCoreConfig(username, observer_token, environment="sandbox")
    )

    # Discovery is read-only and happens before any Pulpo authority is consumed.
    purchase_cents, renewal_cents = _availability(executor_client, domain)
    now_ns = time.time_ns()
    request = DomainPurchaseRequest(
        request_id=f"sandbox:{secrets.token_hex(8)}",
        principal="agent:commerce-sandbox-v0",
        acceptable_domains=(domain,),
        max_purchase_cents=PILOT_MAX_PURCHASE_CENTS,
        max_renewal_cents=renewal_cents,
        approved_registrar="name.com",
        owner_ref="owner://iron-ember/namecom-sandbox",
        privacy_required=True,
        prohibited_upsells=("hosting", "email", "ssl"),
        expires_at_ns=now_ns + 15 * 60 * 1_000_000_000,
    )
    quote = DomainQuote(
        quote_id=f"namecom-sandbox:{secrets.token_hex(8)}",
        domain=domain,
        registrar="name.com",
        purchase_price_cents=purchase_cents,
        renewal_price_cents=renewal_cents,
        owner_ref=request.owner_ref,
        privacy_enabled=True,
        upsells=(),
        expires_at_ns=now_ns + 10 * 60 * 1_000_000_000,
    )
    assessment = assess_quote(
        request,
        quote,
        credential_ref="credential://name-com/sandbox-executor",
        now_ns=now_ns,
    )
    if assessment.outcome != "allow" or assessment.order is None:
        raise RuntimeError(f"sandbox quote denied: {assessment.reason}")
    order = assessment.order

    state = SQLiteKernelState(args.state)
    try:
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), PILOT_MAX_PURCHASE_CENTS),
            secret=kernel_secret,
            clock=time.time_ns,
            state=state,
        )
        custody = SQLiteGovernanceCustody(
            args.state,
            signing_secret=custody_secret,
            clock=time.time_ns,
        )
        budget = SQLiteBudgetAccount(args.state, ceiling_cents=PILOT_MAX_PURCHASE_CENTS)
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)

        intent = purchase_intent(order)
        target = kernel.lock_target(f"sandbox-domain:{order.order_hash}", intent)
        decision = kernel.evaluate(intent)
        if decision.outcome != "allow" or decision.permit is None:
            raise RuntimeError(f"sandbox kernel denied: {decision.reason}")
        reservation = coordinator.reserve(order)
        governed = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
            reservation_id=reservation.reservation_id,
        )

        provider_claim = None
        execution_unknown = False
        try:
            provider_claim = TrustedDomainExecutor(
                custody,
                executor_id="executor:namecom-sandbox-v0",
            ).execute(
                governed,
                order,
                NameComCoreRegistrarAdapter(executor_client),
            )
        except ExternalConsequenceUnknown:
            execution_unknown = True

        observer = NameComCoreObserver(
            custody,
            observer_client,
            owner_ref=order.owner_ref,
            observation_id_prefix="namecom-sandbox-readback",
        )
        reconciler = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-sandbox-readback",
        )
        reconciliation = None
        for index in range(args.observe_attempts):
            observation = observer.observe(governed, order)
            reconciliation = reconciler.reconcile(governed, order, observation)
            if reconciliation.outcome in {"success", "failure"}:
                break
            if index + 1 < args.observe_attempts:
                time.sleep(args.observe_delay_seconds)

        print(
            json.dumps(
                _safe_summary(
                    domain=domain,
                    state_path=args.state,
                    order=order,
                    governed=governed,
                    provider_claim=provider_claim,
                    reconciliation=reconciliation,
                    custody=custody,
                    budget=budget,
                    execution_unknown=execution_unknown,
                ),
                sort_keys=True,
                indent=2,
            )
        )
        return 0 if reconciliation and reconciliation.outcome == "success" else 2
    finally:
        state.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, NameComViolation) as exc:
        print(f"hostile-worker sandbox proof blocked: {exc}", file=sys.stderr)
        raise SystemExit(2)
