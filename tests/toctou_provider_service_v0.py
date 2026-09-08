"""Proof-only mutable provider used by the TOCTOU conditional-mutation test.

This file is intentionally outside unittest discovery. It models one external
service whose conditional mutation checks the expected version under the same
lock that commits the write. It also exposes a deliberately unsafe
check-then-write endpoint used only as a positive vulnerability control.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit


class ProviderState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.objects: dict[str, dict[str, Any]] = {}

    def get(self, object_id: str) -> dict[str, Any]:
        with self.lock:
            current = self.objects.setdefault(
                object_id,
                {
                    "object_id": object_id,
                    "version": 1,
                    "value": "initial",
                    "governed_effects": 0,
                    "out_of_band_effects": 0,
                    "unsafe_effects": 0,
                    "conditional_waiting": False,
                    "unsafe_checked": False,
                },
            )
            return dict(current)


STATE = ProviderState()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "PulpoTOCTOUProofProvider/0"

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        value = json.loads(raw.decode() if raw else "{}")
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/capabilities":
            self._send(
                200,
                {
                    "provider": "pulpo-proof-provider-v0",
                    "atomic_conditional_mutation": True,
                    "condition": "exact_integer_version",
                    "authority_effect": "none",
                },
            )
            return
        if parsed.path in {"/state", "/status"}:
            object_id = query.get("object_id", [""])[0]
            if not object_id:
                self._send(400, {"error": "object_id_required"})
                return
            self._send(200, STATE.get(object_id))
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            payload = self._body()
            object_id = str(payload["object_id"])
            value = str(payload.get("value", ""))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._send(400, {"error": "invalid_request"})
            return
        if not object_id:
            self._send(400, {"error": "object_id_required"})
            return

        if self.path == "/out-of-band":
            with STATE.lock:
                current = STATE.objects.setdefault(object_id, STATE.get(object_id))
                current["version"] += 1
                current["value"] = value
                current["out_of_band_effects"] += 1
                result = dict(current)
            self._send(200, result)
            return

        if self.path == "/conditional":
            try:
                expected_version = int(payload["expected_version"])
                delay_ms = int(payload.get("delay_ms", 0))
            except (KeyError, TypeError, ValueError):
                self._send(400, {"error": "expected_version_required"})
                return
            if delay_ms < 0 or delay_ms > 2000:
                self._send(400, {"error": "invalid_delay"})
                return
            if delay_ms:
                with STATE.lock:
                    current = STATE.objects.setdefault(object_id, STATE.get(object_id))
                    current["conditional_waiting"] = True
                time.sleep(delay_ms / 1000)
            with STATE.lock:
                current = STATE.objects.setdefault(object_id, STATE.get(object_id))
                current["conditional_waiting"] = False
                if current["version"] != expected_version:
                    self._send(
                        412,
                        {
                            "error": "version_precondition_failed",
                            "expected_version": expected_version,
                            "current_version": current["version"],
                            "governed_effects": current["governed_effects"],
                        },
                    )
                    return
                previous_version = current["version"]
                current["version"] += 1
                current["value"] = value
                current["governed_effects"] += 1
                result = {
                    "ok": True,
                    "object_id": object_id,
                    "previous_version": previous_version,
                    "version": current["version"],
                    "value": current["value"],
                    "governed_effects": current["governed_effects"],
                }
            self._send(200, result)
            return

        if self.path == "/unsafe-check-then-write":
            try:
                expected_version = int(payload["expected_version"])
                delay_ms = int(payload.get("delay_ms", 0))
            except (KeyError, TypeError, ValueError):
                self._send(400, {"error": "expected_version_required"})
                return
            if delay_ms < 1 or delay_ms > 2000:
                self._send(400, {"error": "unsafe_delay_required"})
                return

            # Deliberately vulnerable proof control: check under the lock, then
            # release it before the later write and never re-check.
            with STATE.lock:
                current = STATE.objects.setdefault(object_id, STATE.get(object_id))
                if current["version"] != expected_version:
                    self._send(
                        412,
                        {
                            "error": "initial_version_check_failed",
                            "expected_version": expected_version,
                            "current_version": current["version"],
                        },
                    )
                    return
                current["unsafe_checked"] = True
            time.sleep(delay_ms / 1000)
            with STATE.lock:
                current = STATE.objects.setdefault(object_id, STATE.get(object_id))
                current["unsafe_checked"] = False
                previous_version = current["version"]
                current["version"] += 1
                current["value"] = value
                current["unsafe_effects"] += 1
                result = {
                    "ok": True,
                    "vulnerable": True,
                    "object_id": object_id,
                    "authorized_against_version": expected_version,
                    "actual_version_before_write": previous_version,
                    "version": current["version"],
                    "value": current["value"],
                    "unsafe_effects": current["unsafe_effects"],
                }
            self._send(200, result)
            return

        self._send(404, {"error": "not_found"})

    def log_message(self, *_args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
