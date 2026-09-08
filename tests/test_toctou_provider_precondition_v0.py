from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.state import SQLiteKernelState


class ProviderResult:
    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status = status
        self.payload = payload


class TOCTOUProviderPreconditionProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = cls._free_port()
        service = Path(__file__).with_name("toctou_provider_service_v0.py")
        cls.process = subprocess.Popen(
            [sys.executable, "-I", str(service), "--port", str(cls.port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.base = f"http://127.0.0.1:{cls.port}"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                stderr = cls.process.stderr.read() if cls.process.stderr else ""
                raise RuntimeError(f"proof provider exited early: {stderr}")
            try:
                result = cls._request_static(cls.base, "GET", "/capabilities")
            except OSError:
                time.sleep(0.05)
                continue
            if result.status == 200:
                return
        cls.process.terminate()
        raise RuntimeError("proof provider did not become ready")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.process.terminate()
        try:
            cls.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait(timeout=3)
        if cls.process.stderr:
            cls.process.stderr.close()

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _request_static(
        base: str,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> ProviderResult:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return ProviderResult(response.status, json.loads(response.read()))
        except urllib.error.HTTPError as exc:
            return ProviderResult(exc.code, json.loads(exc.read()))

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> ProviderResult:
        return self._request_static(self.base, method, path, payload)

    def state(self, object_id: str) -> dict[str, object]:
        result = self.request(
            "GET",
            "/state?" + urllib.parse.urlencode({"object_id": object_id}),
        )
        self.assertEqual(result.status, 200)
        return result.payload

    def wait_for_flag(self, object_id: str, field: str) -> None:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.state(object_id).get(field) is True:
                return
            time.sleep(0.01)
        self.fail(f"provider proof flag did not become true: {field}")

    @staticmethod
    def policy() -> Policy:
        return Policy(allowed_actions=frozenset({"write"}), max_cost=10)

    @staticmethod
    def intent(object_id: str, version: int, value: str, session_id: str) -> Intent:
        value_hash = sha256(value.encode()).hexdigest()
        return Intent(
            principal="proof:toctou-worker",
            action="write",
            resource=f"provider-proof:{object_id}@version:{version}:value:{value_hash}",
            cost=1,
            session_id=session_id,
        )

    @staticmethod
    def strict_atomicity_claim_eligible(capabilities: dict[str, object]) -> bool:
        return capabilities.get("atomic_conditional_mutation") is True

    @staticmethod
    def reconciliation_matches(
        provider_result: dict[str, object],
        observed: dict[str, object],
        *,
        object_id: str,
        value: str,
    ) -> bool:
        return (
            provider_result.get("ok") is True
            and provider_result.get("object_id") == object_id
            and provider_result.get("value") == value
            and observed.get("object_id") == object_id
            and observed.get("value") == value
            and provider_result.get("version") == observed.get("version")
        )

    def test_stale_version_rejects_restart_cannot_retry_and_fresh_version_succeeds_once(self) -> None:
        object_id = "t01-stale-then-fresh"
        initial = self.state(object_id)
        self.assertEqual(initial["version"], 1)

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "kernel.sqlite3")
            secret = b"T" * 32
            state = SQLiteKernelState(path)
            kernel = GovernanceKernel(self.policy(), secret=secret, state=state)

            stale_intent = self.intent(object_id, 1, "governed-v1-write", "t01")
            decision = kernel.evaluate(stale_intent)
            self.assertEqual(decision.outcome, "allow")
            self.assertIsNotNone(decision.permit)
            permit = str(decision.permit)

            external = self.request(
                "POST",
                "/out-of-band",
                {"object_id": object_id, "value": "out-of-band-v2"},
            )
            self.assertEqual(external.status, 200)
            self.assertEqual(external.payload["version"], 2)

            self.assertTrue(kernel.consume(permit, stale_intent))
            stale_write = self.request(
                "POST",
                "/conditional",
                {
                    "object_id": object_id,
                    "expected_version": 1,
                    "value": "governed-v1-write",
                },
            )
            self.assertEqual(stale_write.status, 412)
            self.assertEqual(stale_write.payload["error"], "version_precondition_failed")
            after_stale = self.state(object_id)
            self.assertEqual(after_stale["version"], 2)
            self.assertEqual(after_stale["value"], "out-of-band-v2")
            self.assertEqual(after_stale["governed_effects"], 0)

            state.close()
            restarted_state = SQLiteKernelState(path)
            restarted = GovernanceKernel(self.policy(), secret=secret, state=restarted_state)
            self.assertFalse(restarted.consume(permit, stale_intent))

            current = self.state(object_id)
            current_version = int(current["version"])
            fresh_value = "fresh-governed-write"
            fresh_intent = self.intent(object_id, current_version, fresh_value, "t03")
            fresh = restarted.evaluate(fresh_intent)
            self.assertEqual(fresh.outcome, "allow")
            self.assertIsNotNone(fresh.permit)
            fresh_permit = str(fresh.permit)
            self.assertTrue(restarted.consume(fresh_permit, fresh_intent))

            executed = self.request(
                "POST",
                "/conditional",
                {
                    "object_id": object_id,
                    "expected_version": current_version,
                    "value": fresh_value,
                },
            )
            self.assertEqual(executed.status, 200)
            observed = self.state(object_id)
            self.assertEqual(observed["version"], current_version + 1)
            self.assertEqual(observed["value"], fresh_value)
            self.assertEqual(observed["governed_effects"], 1)
            self.assertTrue(
                self.reconciliation_matches(
                    executed.payload,
                    observed,
                    object_id=object_id,
                    value=fresh_value,
                )
            )
            tampered_observation = dict(observed)
            tampered_observation["version"] = int(observed["version"]) + 1
            self.assertFalse(
                self.reconciliation_matches(
                    executed.payload,
                    tampered_observation,
                    object_id=object_id,
                    value=fresh_value,
                )
            )
            self.assertFalse(restarted.consume(fresh_permit, fresh_intent))
            restarted_state.close()

    def test_atomic_provider_precondition_rejects_race_immediately_before_commit(self) -> None:
        object_id = "t04-atomic-race"
        observed = self.state(object_id)
        self.assertEqual(observed["version"], 1)
        kernel = GovernanceKernel(self.policy())
        intent = self.intent(object_id, 1, "stale-governed-race", "t04")
        decision = kernel.evaluate(intent)
        self.assertIsNotNone(decision.permit)
        self.assertTrue(kernel.consume(str(decision.permit), intent))

        holder: dict[str, ProviderResult] = {}

        def conditional_request() -> None:
            holder["result"] = self.request(
                "POST",
                "/conditional",
                {
                    "object_id": object_id,
                    "expected_version": 1,
                    "value": "stale-governed-race",
                    "delay_ms": 400,
                },
            )

        thread = threading.Thread(target=conditional_request)
        thread.start()
        self.wait_for_flag(object_id, "conditional_waiting")
        changed = self.request(
            "POST",
            "/out-of-band",
            {"object_id": object_id, "value": "race-winner-v2"},
        )
        self.assertEqual(changed.status, 200)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        result = holder["result"]
        self.assertEqual(result.status, 412)
        final = self.state(object_id)
        self.assertEqual(final["version"], 2)
        self.assertEqual(final["value"], "race-winner-v2")
        self.assertEqual(final["governed_effects"], 0)

    def test_deliberately_unsafe_check_then_write_reproduces_toctou_vulnerability(self) -> None:
        object_id = "t05-unsafe-baseline"
        observed = self.state(object_id)
        self.assertEqual(observed["version"], 1)
        kernel = GovernanceKernel(self.policy())
        intent = self.intent(object_id, 1, "stale-write-wins", "t05")
        decision = kernel.evaluate(intent)
        self.assertIsNotNone(decision.permit)
        self.assertTrue(kernel.consume(str(decision.permit), intent))

        holder: dict[str, ProviderResult] = {}

        def unsafe_request() -> None:
            holder["result"] = self.request(
                "POST",
                "/unsafe-check-then-write",
                {
                    "object_id": object_id,
                    "expected_version": 1,
                    "value": "stale-write-wins",
                    "delay_ms": 400,
                },
            )

        thread = threading.Thread(target=unsafe_request)
        thread.start()
        self.wait_for_flag(object_id, "unsafe_checked")
        external = self.request(
            "POST",
            "/out-of-band",
            {"object_id": object_id, "value": "out-of-band-v2"},
        )
        self.assertEqual(external.status, 200)
        self.assertEqual(external.payload["version"], 2)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

        result = holder["result"]
        self.assertEqual(result.status, 200)
        self.assertIs(result.payload["vulnerable"], True)
        self.assertEqual(result.payload["authorized_against_version"], 1)
        self.assertEqual(result.payload["actual_version_before_write"], 2)
        final = self.state(object_id)
        self.assertEqual(final["version"], 3)
        self.assertEqual(final["value"], "stale-write-wins")
        self.assertEqual(final["unsafe_effects"], 1)

    def test_atomicity_claim_requires_provider_atomic_primitive(self) -> None:
        capabilities = self.request("GET", "/capabilities")
        self.assertEqual(capabilities.status, 200)
        self.assertTrue(self.strict_atomicity_claim_eligible(capabilities.payload))
        no_atomic_provider = {
            "provider": "simulated-non-atomic-provider",
            "atomic_conditional_mutation": False,
        }
        self.assertFalse(self.strict_atomicity_claim_eligible(no_atomic_provider))
        local_hash_only = {
            "provider": "simulated-local-precheck-only",
            "external_state_hash_checked": True,
        }
        self.assertFalse(self.strict_atomicity_claim_eligible(local_hash_only))


if __name__ == "__main__":
    unittest.main()
