"""Synthetic fixtures, no Ollama prerequisite, credentials, or provider effects."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import http.client
import json
from pathlib import Path
import random
import tempfile
import threading
import unittest
from unittest.mock import patch

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy, PulpoOrchestrator, SQLiteKernelState
from pulpo.mcp_boundary import freeze_mcp_snapshot
from pulpo.ollama_proposal import (
    LocalModel, LocalProposalError, MAX_RESPONSE_BYTES, _request,
    project_local_proposal, request_local_proposal,
)


MODEL = LocalModel("qwen2.5-coder:3b", "f" * 64)
GOOD = '{"action":"read","resource":"repo:synthetic","cost":0}'


def replies(content=GOOD):
    return [
        {"models": [{"name": MODEL.name, "digest": MODEL.digest}]},
        {"capabilities": ["completion"]},
        {"model": MODEL.name, "done": True, "done_reason": "stop",
         "message": {"role": "assistant", "content": content}},
    ]


class OllamaProposalTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(frozenset({"read"}), 0, agent_grants=(
            AgentGrant("agent:local", frozenset({"read"}), ("repo:",), 0),))
        self.kernel = GovernanceKernel(self.policy, secret=b"synthetic-local-model-proof",
                                       clock=lambda: 10_000_000)
        self.snapshot = freeze_mcp_snapshot(PulpoOrchestrator(self.kernel))

    def project(self, content=GOOD, **overrides):
        options = dict(principal="agent:local", session_id="synthetic-session", target_id="synthetic-target")
        options.update(overrides)
        return project_local_proposal(content, self.snapshot, **options)

    def test_valid_output_reuses_existing_nonmutating_projection(self):
        before = list(self.kernel.audit)
        result = self.project()
        self.assertEqual("pulpo.mcp-proposal.v2", result["schema"])
        self.assertEqual("agent:local", result["intent"]["principal"])
        self.assertEqual("synthetic-session", result["intent"]["session_id"])
        self.assertFalse(result["canonical_state_mutation"])
        self.assertNotIn("permit", result)
        self.assertEqual(before, self.kernel.audit)
        self.assertIsNone(self.kernel.get_locked_target("synthetic-target"))

    def test_forged_authority_identity_and_hash_fields_are_rejected(self):
        fields = ("permit", "authority", "approved", "principal", "session_id", "target_id",
                  "policy_hash", "intent_hash", "directive", "execute", "tools")
        for field in fields:
            with self.subTest(field=field), self.assertRaises(LocalProposalError):
                self.project(json.dumps(dict(json.loads(GOOD), **{field: "forged"})))
        self.assertEqual([], self.kernel.audit)

    def test_duplicate_keys_wrong_types_and_nonfinite_values_rejected(self):
        cases = ['{"action":"delete","action":"read","resource":"repo:x","cost":0}',
                 '[]', 'null', 'true', '{"action":"read","resource":"repo:x","cost":NaN}',
                 '{"action":"read","resource":"repo:x","cost":Infinity}',
                 '{"action":"read","resource":"repo:x","cost":true}',
                 '{"action":"read","resource":"repo:x","cost":0.0}',
                 '{"action":"read","resource":"repo:x","cost":-1}',
                 '{"action":"read","resource":"repo:x","cost":2147483648}',
                 '{"action":"read","resource":"repo:x"}',
                 '```json\n' + GOOD + '\n```', GOOD + GOOD]
        for content in cases:
            with self.subTest(content=content), self.assertRaises(LocalProposalError):
                self.project(content)

    def test_empty_oversized_control_and_unicode_invalid_output_rejected(self):
        cases = ["", "x" * 4097, "[" * 1200, '\ud800',
                 json.dumps(dict(action="read\n", resource="repo:x", cost=0)),
                 json.dumps(dict(action="read", resource="repo:\u0000", cost=0)),
                 json.dumps(dict(action="read", resource="repo:\ud800", cost=0)),
                 json.dumps(dict(action="read", resource="repo:" + "x" * 256, cost=0))]
        for content in cases:
            with self.subTest(length=len(content)), self.assertRaises(LocalProposalError):
                self.project(content)

    def test_hostile_action_is_only_a_proposal_and_canonical_kernel_denies(self):
        result = self.project(json.dumps(dict(action="delete", resource="repo:synthetic", cost=0)))
        self.assertEqual([], self.kernel.audit)
        decision = self.kernel.evaluate(Intent(**result["intent"]))
        self.assertEqual("deny", decision.outcome)
        self.assertIsNone(decision.permit)

    def test_positive_control_then_identity_resource_session_and_cost_substitution(self):
        original = Intent(**self.project()["intent"])
        decision = self.kernel.evaluate(original)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        for changed in (replace(original, principal="agent:admin"),
                        replace(original, resource="repo:other"),
                        replace(original, session_id="other-session"), replace(original, cost=1)):
            self.assertFalse(self.kernel.consume(decision.permit, changed))
        self.assertTrue(self.kernel.consume(decision.permit, original))
        self.assertFalse(self.kernel.consume(decision.permit, original))

    def test_durable_state_unchanged_by_projection_then_replay_denied_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.sqlite3"
            state = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(self.policy, state=state, secret=b"fixture", clock=lambda: 99)
                frozen = freeze_mcp_snapshot(PulpoOrchestrator(kernel))
                before = state._connection.iterdump()
                before = list(before)
                for _ in range(20):
                    result = project_local_proposal(GOOD, frozen, principal="agent:local",
                                                   session_id="fixture", target_id="fixture")
                self.assertEqual(before, list(state._connection.iterdump()))
                intent = Intent(**result["intent"])
                permit = kernel.evaluate(intent).permit
                self.assertTrue(kernel.consume(permit, intent))
            finally:
                state.close()
            restored = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(self.policy, state=restored, secret=b"fixture", clock=lambda: 100)
                self.assertFalse(kernel.consume(permit, intent))
                self.assertTrue(kernel.verify_audit())
            finally:
                restored.close()

    def test_frozen_policy_metadata_does_not_override_live_kernel(self):
        result = self.project()
        live = GovernanceKernel(Policy(frozenset({"plan"}), 0), secret=b"fixture")
        self.assertNotEqual(result["policy_hash"], live.policy_hash)
        self.assertEqual("deny", live.evaluate(Intent(**result["intent"])).outcome)

    def test_seeded_mixed_proposals_and_concurrent_projection_do_not_write_state(self):
        rng = random.Random(0x4F4C4C41)
        inputs = []
        for _ in range(128):
            fields = dict(action=rng.choice(["read", "delete", "deploy"]),
                          resource="repo:item-" + str(rng.randrange(100)), cost=rng.randrange(3))
            inputs.append(json.dumps(fields))
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(self.project, inputs))
        self.assertEqual(128, len(results))
        self.assertEqual([], self.kernel.audit)
        self.assertTrue(all("permit" not in result for result in results))

    def test_inference_requests_pinned_local_model_and_no_tools(self):
        with patch("pulpo.ollama_proposal._request", side_effect=replies()) as transport:
            self.assertEqual(GOOD, request_local_proposal("Propose reading repo:synthetic.", MODEL))
        self.assertEqual(3, transport.call_count)
        request = transport.call_args_list[-1].args[2]
        self.assertEqual(MODEL.name, request["model"])
        self.assertFalse(request["stream"])
        self.assertEqual(0, request["keep_alive"])
        self.assertNotIn("tools", request)
        self.assertFalse(request["format"]["additionalProperties"])

    def test_missing_or_substituted_model_denies_before_inference_without_pull(self):
        for models in ([], [{"name": MODEL.name, "digest": "0" * 64}],
                       [{"name": MODEL.name, "digest": MODEL.digest}] * 2, "not-list"):
            with self.subTest(models=models), patch("pulpo.ollama_proposal._request", return_value={"models": models}) as t:
                with self.assertRaises(LocalProposalError):
                    request_local_proposal("Synthetic input", MODEL)
                self.assertEqual(1, t.call_count)

    def test_remote_alias_metadata_denies_before_chat(self):
        for field in ("remote_model", "remote_host"):
            fixtures = replies()
            fixtures[1][field] = "remote-example"
            with self.subTest(field=field), patch("pulpo.ollama_proposal._request", side_effect=fixtures) as t:
                with self.assertRaisesRegex(LocalProposalError, "remote_model_rejected"):
                    request_local_proposal("Synthetic input", MODEL)
                self.assertEqual(2, t.call_count)

    def test_cloud_names_urls_and_bad_digest_rejected_before_connection(self):
        for name in ("gemma4:31b-cloud", "glm-5.3:cloud", "https://example.com/model:tag", "untagged", "x:tag?redirect"):
            with self.subTest(name=name), self.assertRaises(LocalProposalError):
                LocalModel(name, MODEL.digest)
        with self.assertRaises(LocalProposalError):
            LocalModel(MODEL.name, "F" * 64)
        with patch("pulpo.ollama_proposal._request") as t:
            for prompt in ("", "x" * 4097):
                with self.assertRaises(LocalProposalError):
                    request_local_proposal(prompt, MODEL)
            t.assert_not_called()

    def test_incomplete_substituted_tool_and_forged_outputs_rejected(self):
        alterations = [dict(done=False), dict(done_reason="length"), dict(model="other:tag"),
                       dict(message={"role": "tool", "content": GOOD}),
                       dict(message={"role": "assistant", "content": GOOD, "tool_calls": [{"name": "execute"}]}),
                       dict(message={"role": "assistant", "content": GOOD[:-1] + ',"permit":"forged"}'})]
        for alteration in alterations:
            fixtures = replies()
            fixtures[-1].update(alteration)
            with self.subTest(alteration=alteration), patch("pulpo.ollama_proposal._request", side_effect=fixtures):
                with self.assertRaises(LocalProposalError):
                    request_local_proposal("Synthetic input", MODEL)


class LocalHTTPTests(unittest.TestCase):
    def test_real_http_protocol_fixture_has_only_expected_requests_and_no_redirect_follow(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        observed = []
        fixture_replies = replies()
        redirect = [False]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                observed.append((self.command, self.path, body, dict(self.headers)))
                self.send_response(302 if redirect[0] else 200)
                encoded = json.dumps(fixture_replies[len(observed) - 1] if not redirect[0] else {}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                if redirect[0]:
                    self.send_header("Location", "https://example.invalid/should-not-be-contacted")
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = handle_request
            do_POST = handle_request

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original = http.client.HTTPConnection

        def connect(host, port, timeout):
            self.assertEqual(("127.0.0.1", 11434, 45), (host, port, timeout))
            return original("127.0.0.1", server.server_port, timeout=5)

        try:
            with patch("pulpo.ollama_proposal.http.client.HTTPConnection", side_effect=connect):
                self.assertEqual(GOOD, request_local_proposal("Synthetic protocol fixture", MODEL))
                self.assertEqual([("GET", "/api/tags"), ("POST", "/api/show"), ("POST", "/api/chat")],
                                 [(method, path) for method, path, _, _ in observed])
                self.assertTrue(all("Authorization" not in headers for _, _, _, headers in observed))
                request = json.loads(observed[-1][2])
                self.assertNotIn("tools", request)
                redirect[0] = True
                with self.assertRaisesRegex(LocalProposalError, "local_http_status"):
                    request_local_proposal("Synthetic redirect fixture", MODEL)
                self.assertEqual(4, len(observed))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def connect(self, body=b'{}', status=200, encoding="identity", error=None, length=None):
        from unittest.mock import MagicMock
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = status
        response.getheader.side_effect = lambda key, default=None: {
            "Content-Encoding": encoding, "Content-Length": length,
        }.get(key, default)
        response.read.return_value = body
        connection.request.side_effect = error
        return connection

    def test_valid_json_in_truncated_http_body_and_invalid_lengths_are_rejected(self):
        for length in ("10", "-1", "invalid", "999999999999999999999", str(MAX_RESPONSE_BYTES + 1)):
            connection = self.connect(length=length)
            with self.subTest(length=length), \
                 patch("pulpo.ollama_proposal.http.client.HTTPConnection", return_value=connection), \
                 self.assertRaises(LocalProposalError):
                _request("GET", "/api/tags")
            connection.close.assert_called_once()

    def test_fixed_loopback_ignores_host_proxy_and_credentials_environment(self):
        with patch.dict("os.environ", {"OLLAMA_HOST": "https://example.invalid", "HTTP_PROXY": "http://example.invalid",
                                       "OLLAMA_API_KEY": "synthetic-secret"}), \
             patch("pulpo.ollama_proposal.http.client.HTTPConnection", return_value=self.connect()) as ctor:
            self.assertEqual({}, _request("GET", "/api/tags"))
        ctor.assert_called_once_with("127.0.0.1", 11434, timeout=45)
        self.assertEqual({"Content-Type": "application/json"}, ctor.return_value.request.call_args.kwargs["headers"])
        ctor.return_value.close.assert_called_once()

    def test_management_and_alternate_routes_rejected_before_connection(self):
        with patch("pulpo.ollama_proposal.http.client.HTTPConnection") as ctor:
            for method, path in (("DELETE", "/api/delete"), ("POST", "/api/pull"), ("POST", "/api/push"),
                                 ("POST", "/api/create"), ("POST", "http://example.invalid/api/chat")):
                with self.subTest(path=path), self.assertRaises(LocalProposalError):
                    _request(method, path, {})
            ctor.assert_not_called()

    def test_redirect_http_error_oversize_compression_and_malformed_response_fail_closed(self):
        cases = [dict(status=302), dict(status=500), dict(body=b'x' * (MAX_RESPONSE_BYTES + 1)),
                 dict(encoding="gzip"), dict(body=b'[]'), dict(body=b'{"x":1,"x":2}'),
                 dict(body=b'\xff'), dict(body=b'{"x":NaN}')]
        for case in cases:
            connection = self.connect(**case)
            with self.subTest(case={k: len(v) if k == "body" else v for k, v in case.items()}), \
                 patch("pulpo.ollama_proposal.http.client.HTTPConnection", return_value=connection), \
                 self.assertRaises(LocalProposalError):
                _request("GET", "/api/tags")
            connection.close.assert_called_once()

    def test_timeout_and_incomplete_read_close_once_without_retry(self):
        for error in (TimeoutError("synthetic timeout"), http.client.IncompleteRead(b'{}', 9)):
            connection = self.connect(error=error)
            with self.subTest(error=type(error).__name__), \
                 patch("pulpo.ollama_proposal.http.client.HTTPConnection", return_value=connection) as ctor, \
                 self.assertRaisesRegex(LocalProposalError, "local_inference_unavailable"):
                _request("POST", "/api/chat", {})
            ctor.assert_called_once()
            connection.request.assert_called_once()
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
