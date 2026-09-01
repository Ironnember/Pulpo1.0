"""Authenticated read-only mobile/PWA projection over canonical Pulpo evidence.

This module is deliberately non-authoritative and non-mutating. It requires an
existing ``PulpoMCPProjection`` bound to the canonical ``PulpoOrchestrator`` and
exposes only the existing read-only evidence snapshot. It cannot propose or
lock targets, append canonical audit state, evaluate policy, approve work, mint
or consume permits, or invoke an executor.
"""

from __future__ import annotations

import hmac

from pulpo.mcp_boundary import PulpoMCPProjection


def create_app(
    projection: PulpoMCPProjection,
    *,
    auth_token: str,
):
    """Create an evidence-only mobile projection over existing canonical state.

    ``projection`` is required rather than constructed here so this UI cannot
    create a second kernel, policy, state store, trusted clock, authority path,
    or evidence ledger. The bearer token gates read access only; it is not an
    individual identity or an authority credential.
    """

    if not isinstance(projection, PulpoMCPProjection):
        raise TypeError("canonical PulpoMCPProjection required")
    if not isinstance(auth_token, str) or not auth_token:
        raise ValueError("auth_token is required")

    try:
        from flask import Flask, jsonify, render_template_string, request
    except ImportError as exc:  # pragma: no cover - environment-specific path
        raise RuntimeError("Pulpo mobile projection requires the 'web' optional dependency") from exc

    app = Flask(__name__, static_folder="static")

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
  <title>Pulpo Mobile Evidence</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }
    .card { max-width:460px; margin:0 auto; background:#111827; border-radius:16px; padding:20px; }
    label { display:block; margin-top:12px; font-size:.9rem; }
    input, button { width:100%; margin-top:6px; padding:12px 14px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:white; box-sizing:border-box; }
    button { background:#2563eb; border:none; margin-top:18px; font-weight:600; }
    .result { margin-top:18px; padding:12px; border-radius:10px; background:#1e293b; min-height:60px; white-space:pre-wrap; }
    .boundary { font-size:.85rem; color:#94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Pulpo Mobile Evidence</h2>
    <p class="boundary">Read-only evidence projection. This surface cannot propose, lock canonical state, approve, execute, or issue permits.</p>
    <label>Access token<input id="token" type="password" autocomplete="off" required /></label>
    <button id="evidence" type="button">Read evidence</button>
    <div id="result" class="result">Waiting...</div>
  </div>
  <script>
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
    const result = document.getElementById('result');
    document.getElementById('evidence').addEventListener('click', async () => {
      const token = document.getElementById('token').value;
      const response = await fetch('/api/evidence', {headers:{'Authorization':`Bearer ${token}`}});
      result.textContent = JSON.stringify(await response.json(), null, 2);
    });
  </script>
</body>
</html>
            """
        )

    @app.get("/manifest.webmanifest")
    def manifest():
        return app.send_static_file("manifest.webmanifest")

    @app.get("/sw.js")
    def service_worker():
        response = app.send_static_file("sw.js")
        response.headers["Service-Worker-Allowed"] = "/"
        return response

    @app.get("/api/evidence")
    def evidence():
        if not authenticated():
            return jsonify({"outcome": "deny", "reason": "authentication_required", "authority_effect": "none"}), 401
        result = projection.evidence_snapshot()
        if "permit" in result:
            raise RuntimeError("mobile projection cannot return a permit")
        return jsonify(result), 200

    return app
