import hmac
import os

from flask import Flask, jsonify, render_template_string, request

from pulpo.kernel import GovernanceKernel, Intent, Policy


def create_app(auth_token: str, principal: str = "agent:phone"):
    if not auth_token or not principal:
        raise ValueError("auth_token and principal are required")
    app = Flask(__name__)
    app.config["PULPO_DEMO_PRINCIPAL"] = principal

    policy = Policy(
        allowed_actions=frozenset({"deploy", "read", "write"}),
        max_cost=100,
    )
    kernel = GovernanceKernel(policy=policy)

    @app.get("/")
    def index():
        return render_template_string('''
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
          <title>Pulpo Mobile Demo</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              background: #0f172a;
              color: #e2e8f0;
              margin: 0;
              padding: 24px;
            }
            .card {
              max-width: 420px;
              margin: 0 auto;
              background: #111827;
              border-radius: 16px;
              padding: 20px;
              box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            }
            label {
              display: block;
              margin-top: 12px;
              font-size: 0.9rem;
            }
            input, select, button {
              width: 100%;
              margin-top: 6px;
              padding: 12px 14px;
              border-radius: 10px;
              border: 1px solid #334155;
              background: #0b1220;
              color: white;
              font-size: 1rem;
              box-sizing: border-box;
            }
            button {
              background: linear-gradient(135deg, #3b82f6, #8b5cf6);
              border: none;
              margin-top: 18px;
              cursor: pointer;
              font-weight: 600;
            }
            .result {
              margin-top: 18px;
              padding: 12px;
              border-radius: 10px;
              background: #1e293b;
              min-height: 60px;
              white-space: pre-wrap;
            }
          </style>
        </head>
        <body>
          <div class="card">
            <h2>Pulpo Mobile Demo</h2>
            <form id="decision-form">
              <label>Principal
                <input name="principal" value="{{ principal }}" />
              </label>
              <label>Action
                <select name="action">
                  <option value="deploy">deploy</option>
                  <option value="read">read</option>
                  <option value="write">write</option>
                  <option value="execute">execute</option>
                </select>
              </label>
              <label>Resource
                <input name="resource" value="service:api-server" />
              </label>
              <label>Cost
                <input name="cost" type="number" min="0" value="80" />
              </label>
              <label>Access token
                <input name="token" type="password" autocomplete="off" required />
              </label>
              <button type="submit">Check policy</button>
            </form>
            <div id="result" class="result">Waiting...</div>
          </div>
          <script>
            const form = document.getElementById('decision-form');
            const result = document.getElementById('result');
            form.addEventListener('submit', async (event) => {
              event.preventDefault();
              const payload = Object.fromEntries(new FormData(form).entries());
              payload.cost = Number(payload.cost);
              const token = payload.token;
              delete payload.token;
              const response = await fetch('/api/decision', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`},
                body: JSON.stringify(payload)
              });
              const data = await response.json();
              result.textContent = JSON.stringify(data, null, 2);
            });
          </script>
        </body>
        </html>
        ''', principal=principal)

    @app.post("/api/decision")
    def decision():
        authorization = request.headers.get("Authorization", "")
        expected = f"Bearer {auth_token}"
        if not hmac.compare_digest(authorization, expected):
            return jsonify({"outcome": "deny", "reason": "authentication_required", "permit": None}), 401

        payload = request.get_json(force=True, silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"outcome": "deny", "reason": "invalid_request", "permit": None}), 400

        principal = payload.get("principal")
        action = payload.get("action")
        resource = payload.get("resource")
        cost = payload.get("cost", 0)
        if any(not isinstance(value, str) for value in (principal, action, resource)):
            return jsonify({"outcome": "deny", "reason": "invalid_intent", "permit": None}), 400
        if principal != app.config["PULPO_DEMO_PRINCIPAL"]:
          return jsonify({"outcome": "deny", "reason": "principal_not_allowed", "permit": None}), 403
        if isinstance(cost, bool) or not isinstance(cost, int):
            return jsonify({"outcome": "deny", "reason": "invalid_cost", "permit": None}), 400

        decision = kernel.evaluate(
            Intent(
                principal=principal,
                action=action,
                resource=resource,
                cost=cost,
            )
        )

        outcome = decision.outcome
        permit = decision.permit
        reason = decision.reason or "denied"

        return jsonify({
            "outcome": outcome,
            "reason": reason,
            "permit": permit,
            "details": {
                "outcome": decision.outcome,
                "reason": decision.reason,
                "intent_hash": decision.intent_hash,
                "permit": decision.permit,
            },
        })

    return app


if __name__ == "__main__":
  token = os.environ.get("PULPO_DEMO_TOKEN")
  principal = os.environ.get("PULPO_DEMO_PRINCIPAL", "agent:phone")
  if not token:
    raise SystemExit("Set PULPO_DEMO_TOKEN before starting the mobile demo")
  create_app(token, principal).run(host="0.0.0.0", port=8000, debug=False)
