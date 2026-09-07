"""Test-only isolated effect-surface harness for PULPO-RWE-001.

This module is deliberately outside unittest discovery. A dedicated GitHub
Actions workflow runs it across isolated Docker networks.

It reuses the canonical GovernanceKernel for the authority decision. The
network/service harness is proof infrastructure only; it is not a second
canonical router, executor, custody service, or provider adapter.

Claim boundary:
- a hostile worker can reach the governed gateway but cannot reach the effect
  service by service name or raw effect-network IP in the tested topology;
- 100 production-scoped requests receive no authority and cause no durable
  production effect;
- one exactly allowed development request crosses the governed path and creates
  one durable effect;
- a separate observer process reads durable state after the effect service has
  stopped;
- this does NOT establish production deployment equivalence, external-provider
  containment, host-compromise resistance, or an independent trust domain.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy


NOW = 33_000_000


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _read_json(request: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(request.headers.get("Content-Length", "0"))
    raw = request.rfile.read(length)
    value = json.loads(raw.decode())
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _send_json(request: BaseHTTPRequestHandler, status: int, value: Any) -> None:
    body = _json_bytes(value)
    request.send_response(status)
    request.send_header("Content-Type", "application/json")
    request.send_header("Content-Length", str(len(body)))
    request.end_headers()
    request.wfile.write(body)


def _effect_handler(state_path: Path):
    class EffectHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/health":
                _send_json(self, 200, {"status": "ok", "authority_effect": "none"})
                return
            _send_json(self, 404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/write":
                _send_json(self, 404, {"error": "not_found"})
                return
            try:
                record = _read_json(self)
            except (ValueError, json.JSONDecodeError):
                _send_json(self, 400, {"error": "invalid_json"})
                return

            # The effect surface intentionally does not enforce Pulpo resource
            # scope. If reached directly, it will persist the requested record.
            # The proof therefore depends on capability custody + governance,
            # not a provider-side dev/prod safety rule.
            state_path.parent.mkdir(parents=True, exist_ok=True)
            with state_path.open("a", encoding="utf-8") as handle:
                handle.write(_json_bytes(record).decode() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            _send_json(self, 201, {"stored": True})

    return EffectHandler


def run_effect_service(state_path: Path, port: int) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), _effect_handler(state_path))
    server.serve_forever()


def _kernel() -> GovernanceKernel:
    grant = AgentGrant(
        "agent:builder",
        frozenset({"write"}),
        ("dev:",),
        0,
    )
    return GovernanceKernel(
        Policy(
            frozenset({"write"}),
            0,
            agent_grants=(grant,),
        ),
        secret=b"pulpo-rwe-001-isolated-effect-v0",
        clock=lambda: NOW,
    )


def _gateway_handler(kernel: GovernanceKernel, effect_url: str):
    class GatewayHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/health":
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "authority_effect": "none",
                        "provider_effect": "none",
                    },
                )
                return
            _send_json(self, 404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/intent":
                _send_json(self, 404, {"error": "not_found"})
                return
            try:
                payload = _read_json(self)
                intent = Intent(
                    str(payload["principal"]),
                    str(payload["action"]),
                    str(payload["resource"]),
                    int(payload["cost_cents"]),
                    str(payload["session_id"]),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                _send_json(self, 400, {"error": "invalid_intent"})
                return

            decision = kernel.evaluate(intent)
            if decision.permit is None:
                _send_json(
                    self,
                    200,
                    {
                        "outcome": decision.outcome,
                        "reason": decision.reason,
                        "authority_effect": "none",
                        "effect_dispatched": False,
                    },
                )
                return

            if not kernel.consume(decision.permit, intent):
                _send_json(
                    self,
                    409,
                    {
                        "outcome": "deny",
                        "reason": "permit_not_consumable",
                        "authority_effect": "none",
                        "effect_dispatched": False,
                    },
                )
                return

            record = {
                "principal": intent.principal,
                "action": intent.action,
                "resource": intent.resource,
                "session_id": intent.session_id,
                "intent_hash": kernel.intent_hash(intent),
            }
            upstream = Request(
                effect_url,
                data=_json_bytes(record),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urlopen(upstream, timeout=3) as response:
                    if response.status != 201:
                        raise RuntimeError("effect surface rejected governed write")
            except (HTTPError, URLError, TimeoutError) as exc:
                # The permit is already spent. This harness intentionally does
                # not claim full consequence reconciliation; external ambiguity
                # remains a later proof tier.
                _send_json(
                    self,
                    502,
                    {
                        "outcome": "unresolved",
                        "reason": "effect_surface_unavailable_after_permit_consumption",
                        "authority_effect": "none",
                        "effect_dispatched": False,
                    },
                )
                print(f"effect dispatch failed: {exc}", file=sys.stderr)
                return

            _send_json(
                self,
                200,
                {
                    "outcome": "allow",
                    "reason": decision.reason,
                    "authority_effect": "none",
                    "effect_dispatched": True,
                },
            )

    return GatewayHandler


def run_gateway(effect_url: str, port: int) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), _gateway_handler(_kernel(), effect_url))
    server.serve_forever()


def _post_json(url: str, value: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=_json_bytes(value),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=3) as response:
        body = json.loads(response.read().decode())
    if not isinstance(body, dict):
        raise AssertionError("gateway response must be an object")
    return body


def run_worker(gateway_url: str, effect_host: str, effect_ip: str, effect_port: int) -> None:
    # Negative route control 1: Docker service identity is absent from the
    # worker-only network.
    try:
        socket.gethostbyname(effect_host)
    except socket.gaierror:
        print("worker_effect_dns_route=BLOCKED")
    else:
        raise AssertionError("worker unexpectedly resolved isolated effect service")

    # Negative route control 2: a discovered raw address from the separate
    # effect network still must not be reachable from the worker network.
    try:
        connection = socket.create_connection((effect_ip, effect_port), timeout=1)
    except OSError:
        print("worker_effect_raw_ip_route=BLOCKED")
    else:
        connection.close()
        raise AssertionError("worker unexpectedly reached isolated effect service by raw IP")

    for attempt in range(100):
        response = _post_json(
            gateway_url,
            {
                "principal": "agent:builder",
                "action": "write",
                "resource": "prod:database:customers",
                "cost_cents": 0,
                "session_id": f"rwe-isolated-prod-{attempt}",
            },
        )
        assert response["outcome"] == "deny", response
        assert response["reason"] == "agent_resource_not_allowed", response
        assert response["authority_effect"] == "none", response
        assert response["effect_dispatched"] is False, response
        assert "permit" not in response, response

    allowed = _post_json(
        gateway_url,
        {
            "principal": "agent:builder",
            "action": "write",
            "resource": "dev:database:customers",
            "cost_cents": 0,
            "session_id": "rwe-isolated-dev-positive",
        },
    )
    assert allowed["outcome"] == "allow", allowed
    assert allowed["effect_dispatched"] is True, allowed
    assert "permit" not in allowed, allowed

    print("production_requests_denied=100")
    print("governed_dev_dispatch=1")


def run_observer(state_path: Path) -> None:
    if not state_path.exists():
        raise AssertionError("durable effect state missing")
    records = [
        json.loads(line)
        for line in state_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 1, records
    record = records[0]
    assert record["principal"] == "agent:builder", record
    assert record["action"] == "write", record
    assert record["resource"] == "dev:database:customers", record
    assert record["session_id"] == "rwe-isolated-dev-positive", record
    assert isinstance(record["intent_hash"], str) and len(record["intent_hash"]) == 64, record
    assert not any(str(item.get("resource", "")).startswith("prod:") for item in records), records
    print("durable_effect_count=1")
    print("durable_production_effect_count=0")
    print("observer_readback=PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    effect = subparsers.add_parser("effect-service")
    effect.add_argument("--state", required=True)
    effect.add_argument("--port", type=int, default=8081)

    gateway = subparsers.add_parser("gateway")
    gateway.add_argument("--effect-url", required=True)
    gateway.add_argument("--port", type=int, default=8080)

    worker = subparsers.add_parser("worker")
    worker.add_argument("--gateway-url", required=True)
    worker.add_argument("--effect-host", required=True)
    worker.add_argument("--effect-ip", required=True)
    worker.add_argument("--effect-port", type=int, default=8081)

    observer = subparsers.add_parser("observer")
    observer.add_argument("--state", required=True)

    args = parser.parse_args()
    if args.mode == "effect-service":
        run_effect_service(Path(args.state), args.port)
    elif args.mode == "gateway":
        run_gateway(args.effect_url, args.port)
    elif args.mode == "worker":
        run_worker(args.gateway_url, args.effect_host, args.effect_ip, args.effect_port)
    elif args.mode == "observer":
        run_observer(Path(args.state))
    else:  # pragma: no cover
        raise AssertionError(args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
