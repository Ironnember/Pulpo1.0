from http.server import BaseHTTPRequestHandler
import json

from public_lab import PublicProofError, evaluate_scenario, list_scenarios, usage_event


class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"lab": "Pulpo Public Proof Lab V0", "scenarios": list_scenarios(), "execution": "disabled"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "invalid_content_length"})
        if length <= 0 or length > 2048:
            return self._send(400, {"error": "invalid_body_size"})
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send(400, {"error": "invalid_json"})
        if not isinstance(body, dict) or set(body) != {"scenario"} or not isinstance(body.get("scenario"), str):
            return self._send(400, {"error": "expected_exact_scenario_object"})
        try:
            result = evaluate_scenario(body["scenario"])
        except PublicProofError as exc:
            return self._send(404, {"error": str(exc)})
        print(json.dumps(usage_event(body["scenario"], result), sort_keys=True))
        self._send(200, result)
