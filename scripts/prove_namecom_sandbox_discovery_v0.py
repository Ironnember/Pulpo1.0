"""Authenticated read-only Name.com sandbox discovery for Pulpo ceremony V0.

This proof intentionally cannot register a domain. It verifies separately
retained sandbox credentials, performs provider-native discovery only, freezes
one disposable non-premium registration candidate below Pulpo's $30 purchase
ceiling, and emits a sanitized evidence object for later exact-object approval.

No credential value or credential-derived hash is written to stdout/artifacts.
"""

from __future__ import annotations

from base64 import b64encode
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "https://api.dev.name.com"
PURCHASE_CEILING_CENTS = 3_000
ARTIFACT_PATH = Path(".pulpo-artifacts/namecom-sandbox-discovery.json")


class DiscoveryViolation(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _usd_to_cents(value: Any) -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise DiscoveryViolation("price_invalid") from exc
    if amount < 0:
        raise DiscoveryViolation("price_negative")
    return int(amount * 100)


def _auth_header(username: str, token: str) -> str:
    encoded = b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {encoded}"


def _request_json(
    method: str,
    path: str,
    *,
    username: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not path.startswith("/core/v1/"):
        raise DiscoveryViolation("path_outside_core_v1")
    headers = {
        "Authorization": _auth_header(username, token),
        "Accept": "application/json",
    }
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = _canonical(payload)
    request = Request(BASE_URL + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read()
            status = int(response.status)
    except HTTPError as exc:
        # Never include the Authorization header or token in an error.
        raise DiscoveryViolation(f"namecom_http_{int(exc.code)}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise DiscoveryViolation("namecom_transport_unavailable") from exc
    if not 200 <= status < 300:
        raise DiscoveryViolation(f"namecom_http_{status}")
    try:
        decoded = json.loads(raw.decode()) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryViolation("namecom_response_not_json") from exc
    if not isinstance(decoded, dict):
        raise DiscoveryViolation("namecom_response_shape_invalid")
    return decoded


def _require_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DiscoveryViolation(f"{name.lower()}_unavailable")
    return value


def _candidates(head: str) -> list[str]:
    suffix = head[:10].lower()
    if len(suffix) != 10 or any(c not in "0123456789abcdef" for c in suffix):
        raise DiscoveryViolation("github_sha_invalid")
    tlds = ("com", "net", "org", "info", "xyz", "site", "online", "cloud", "dev", "io")
    values: list[str] = []
    for sequence in range(1, 4):
        for tld in tlds:
            values.append(f"pulpo-rwe-{suffix}-{sequence:02d}.{tld}")
    return values


def main() -> int:
    if os.environ.get("PULPO_NAMECOM_FIRE", "0") != "0":
        raise DiscoveryViolation("fire_must_remain_disabled")

    username = _require_secret("NAMECOM_SANDBOX_USERNAME")
    executor_token = _require_secret("NAMECOM_SANDBOX_EXECUTOR_TOKEN")
    observer_token = _require_secret("NAMECOM_SANDBOX_OBSERVER_TOKEN")
    if not username.endswith("-test"):
        raise DiscoveryViolation("sandbox_username_must_end_test")
    if executor_token == observer_token:
        raise DiscoveryViolation("sandbox_executor_observer_tokens_not_distinct")

    # Authenticate both credential surfaces without printing their values.
    executor_hello = _request_json(
        "GET", "/core/v1/hello", username=username, token=executor_token
    )
    observer_hello = _request_json(
        "GET", "/core/v1/hello", username=username, token=observer_token
    )
    if executor_hello.get("username") != username:
        raise DiscoveryViolation("executor_identity_mismatch")
    if observer_hello.get("username") != username:
        raise DiscoveryViolation("observer_identity_mismatch")

    head = os.environ.get("GITHUB_SHA", "")
    candidates = _candidates(head)
    discovery = _request_json(
        "POST",
        "/core/v1/domains:checkAvailability",
        username=username,
        token=observer_token,
        payload={"domainNames": candidates, "purchaseType": "registration"},
    )
    results = discovery.get("results")
    if not isinstance(results, list):
        raise DiscoveryViolation("availability_results_invalid")

    acceptable: list[dict[str, Any]] = []
    candidate_set = set(candidates)
    for item in results:
        if not isinstance(item, dict):
            continue
        domain = item.get("domainName")
        if domain not in candidate_set:
            continue
        if item.get("purchasable") is not True:
            continue
        if item.get("purchaseType") != "registration":
            continue
        if item.get("premium") is not False:
            continue
        try:
            purchase_cents = _usd_to_cents(item.get("purchasePrice"))
            renewal_cents = _usd_to_cents(item.get("renewalPrice"))
        except DiscoveryViolation:
            continue
        if purchase_cents > PURCHASE_CEILING_CENTS:
            continue
        acceptable.append(
            {
                "domain": domain,
                "purchase_price_cents": purchase_cents,
                "renewal_price_cents": renewal_cents,
                "purchase_type": "registration",
                "premium": False,
            }
        )

    if not acceptable:
        raise DiscoveryViolation("no_disposable_domain_under_ceiling")
    acceptable.sort(key=lambda item: (item["purchase_price_cents"], item["domain"]))
    selected = acceptable[0]

    evidence = {
        "schema": "pulpo.namecom-sandbox-discovery.v0",
        "provider": "name.com",
        "environment": "sandbox",
        "origin": BASE_URL,
        "source_head": head,
        "purchase_ceiling_cents": PURCHASE_CEILING_CENTS,
        "credentials": {
            "executor_authenticated": True,
            "observer_authenticated": True,
            "executor_observer_distinct": True,
            "secret_material_recorded": False,
        },
        "selected": selected,
        "candidate_count": len(candidates),
        "acceptable_count": len(acceptable),
        "fire_authorized": False,
        "provider_write_attempted": False,
        "authority_effect": "none",
        "provider_effect": "read_only_discovery",
    }
    evidence_hash = sha256(_canonical(evidence)).hexdigest()
    evidence["evidence_hash"] = evidence_hash

    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    print("namecom_sandbox_credentials=AUTHENTICATED_DISTINCT")
    print(f"selected_domain={selected['domain']}")
    print(f"purchase_price_cents={selected['purchase_price_cents']}")
    print(f"renewal_price_cents={selected['renewal_price_cents']}")
    print(f"evidence_hash={evidence_hash}")
    print("provider_write_attempted=NO")
    print("fire_authorized=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiscoveryViolation as exc:
        # Failure messages contain only fixed reason codes, never secrets.
        print(f"namecom_sandbox_discovery=BLOCKED:{exc}")
        raise SystemExit(2)
