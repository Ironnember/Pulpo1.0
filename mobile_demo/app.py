"""Authenticated mobile/PWA projection over canonical Pulpo state.

This module is deliberately non-authoritative. It requires an existing
``PulpoMCPProjection`` bound to the canonical ``PulpoOrchestrator`` and exposes
only proposal and evidence views. It cannot evaluate policy, approve work, mint
or consume permits, or invoke an executor.
"""

from __future__ import annotations

import hmac
from typing import Any

from pulpo.mcp_boundary import MCPBoundaryError, PulpoMCPProjection


_ALLOWED_PROPOSAL_FIELDS = {
    "target_id",
    "action",
    "resource",
    "cost",
    "session_id",
    "version",
}


def create_app(
    projection: PulpoMCPProjection,
    *,
    auth_token: str,
    principal: str,
):
    """Create a mobile projection bound to one existing canonical orchestrator.

    ``projection`` is required rather than constructed here so this UI cannot
    create a second kernel, policy, state store, trusted clock, or authority
    path. The configured principal is server-side state and cannot be replaced
    by a client payload.
    """

    if not isinstance(projection, PulpoMCPProjection):
        raise TypeError("canonical PulpoMCPProjection required")
    if not isinstance(auth_token, str) or not auth_token:
        raise ValueError("auth_token is required")
    if not isinstance(principal, str) or not principal or principal != principal.strip():
        raise ValueError("principal is required")

    try:
        from flask import Flask, jsonify, render_template_string, request
    except ImportError as exc:  # pragma: no cover - environment-specific path
        raise RuntimeError("Pulpo mobile projection requires the 'web' optional dependency") from exc

    app = Flask(__name__, static_folder="static")
    app.config["PULPO_MOBILE_PRINCIPAL"] = principal

    def authenticated() -> bool:
        authorization = request.headers.get("Authorization", "")
        return hmac.compare_digest(authorization, f"Bearer {auth_token}")

    @app.get("/")
    def index():
        return render_template_string(
            """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#0f172a" />
  <link rel="manifest" href="/manifest.webmanifest" />
  <link rel="apple-touch-icon" href="/static/icon.svg" />
  <title>Pulpo Mobile Projection</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }
    .card { max-width:460px; margin:0 auto; background:#111827; border-radius:16px; padding:20px; }
    label { display:block; margin-top:12px; font-size:.9rem; }
    input, select, button { width:100%; margin-top:6px; padding:12px 14px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:white; box-sizing:border-box; }
    button { background:#2563eb; border:none; margin-top:18px; font-weight:600; }
    .result { margin-top:18px; padding:12px; border-radius:10px; background:#1e293b; min-height:60px; white-space:pre-wrap; }
    .boundary { font-size:.85rem; color:#94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Pulpo Mobile Projection</h2>
    <p class="boundary">Proposal + evidence only. This surface cannot approve, execute, or issue permits.</p>
    <p>Principal: <strong>{{ principal }}</strong></p>
    <form id="proposal-form">
      <label>Target ID<input name="target_id" value="mobile-demo" required /></label>
      <label>Action<input name="action" value="read" required /></label>
      <label>Resource<input name="resource" value="repo:docs" required /></label>
      <label>Cost<input name="cost" type="number" min="0" value="0" required /></label>
      <label>Session ID<input name="session_id" value="mobile" required /></label>
      <label>Version<input name="version" type="number" min="1" value="1" required /></label>
      <label>Access token<input name="token" type="password" autocomplete="off" required /></label>
      <button type="submit">Lock proposal</button>
    </form>
    <button id="evidence" type="button">Read evidence</button>
    <div id="result" class="result">Waiting...</div>
  </div>
  <script>
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
    const form = document.getElementById('proposal-form');
    const result = document.getElementById('result');
    const tokenValue = () => form.elements.token.value;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const payload = Object.fromEntries(new FormData(form).entries());
      const token = payload.token;
      delete payload.token;
      payload.cost = Number(payload.cost);
      payload.version = Number(payload.version);
      const response = await fetch('/api/propose', {
        method:'POST',
        headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`},
        body:JSON.stringify(payload)
      });
      result.textContent = JSON.stringify(await response.json(), null, 2);
    });
    document.getElementById('evidence').addEventListener('click', async () => {
      const response = await fetch('/api/evidence', {headers:{'Authorization':`Bearer ${tokenValue()}`}});
      result.textContent = JSON.stringify(await response.json(), null, 2);
    });
  </script>
</body>
</html>
            """,
            principal=principal,
        )

    @app.get("/manifest.webmanifest")
    def manifest():
        return app.send_static_file("manifest.webmanifest")

    @app.get("/sw.js")
    def service_worker():
        response = app.send_static_file("sw.js")
        response.headers["Service-Worker-Allowed"] = "/"
        return response

    @app.post("/api/propose")
    def propose():
        if not authenticated():
            return jsonify({"outcome": "deny", "reason": "authentication_required", "authority_effect": "none"}), 401
        payload: Any = request.get_json(force=True, silent=True)
        if not isinstance(payload, dict) or set(payload) - _ALLOWED_PROPOSAL_FIELDS:
            return jsonify({"outcome": "deny", "reason": "mobile_payload_invalid", "authority_effect": "none"}), 400
        try:
            result = projection.propose_intent(
                target_id=payload.get("target_id"),
                principal=app.config["PULPO_MOBILE_PRINCIPAL"],
                action=payload.get("action"),
                resource=payload.get("resource"),
                cost=payload.get("cost", 0),
                session_id=payload.get("session_id", "mobile"),
                version=payload.get("version", 1),
            )
        except MCPBoundaryError as exc:
            return jsonify({"outcome": "deny", "reason": str(exc), "authority_effect": "none"}), 400
        except ValueError:
            # Canonical target versions are immutable. Do not turn a conflicting
            # mobile proposal into a new target, overwrite, or authority path.
            return jsonify({"outcome": "deny", "reason": "proposal_conflict", "authority_effect": "none"}), 409
        if "permit" in result:
            raise RuntimeError("mobile projection cannot return a permit")
        return jsonify(result), 200

    @app.get("/api/evidence")
    def evidence():
        if not authenticated():
            return jsonify({"outcome": "deny", "reason": "authentication_required", "authority_effect": "none"}), 401
        result = projection.evidence_snapshot()
        if "permit" in result:
            raise RuntimeError("mobile projection cannot return a permit")
        return jsonify(result), 200

    return app
