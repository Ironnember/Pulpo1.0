"""Authenticated read-only mobile/PWA view over a frozen Pulpo evidence snapshot.

The distribution process deliberately receives no kernel, orchestrator, MCP
projection, authority client, state backend, or executor. V0 accepts only a
validated primitive evidence snapshot copied into a read-only source object.
The snapshot is explicitly represented as frozen; this surface does not claim
that it is a live view of canonical state.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


class FrozenEvidenceSource:
    """Validated immutable primitive evidence projection for distribution V0.

    The source copies only the narrow evidence fields used by the UI. It retains
    no reference to the originating Pulpo object, so the web application does
    not receive a canonical-state mutation capability through dependency
    injection.
    """

    __slots__ = ("__snapshot",)

    def __init__(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping):
            raise TypeError("evidence snapshot mapping required")

        schema = snapshot.get("schema")
        policy_hash = snapshot.get("policy_hash")
        audit_valid = snapshot.get("audit_valid")
        audit_records = snapshot.get("audit_records")
        audit_tip = snapshot.get("audit_tip")
        authority_effect = snapshot.get("authority_effect")

        if schema != "pulpo.mcp-evidence.v0":
            raise ValueError("evidence_schema_invalid")
        if not isinstance(policy_hash, str) or not policy_hash:
            raise ValueError("evidence_policy_hash_invalid")
        if not isinstance(audit_valid, bool):
            raise ValueError("evidence_audit_valid_invalid")
        if isinstance(audit_records, bool) or not isinstance(audit_records, int) or audit_records < 0:
            raise ValueError("evidence_audit_records_invalid")
        if audit_tip is not None and (not isinstance(audit_tip, str) or not audit_tip):
            raise ValueError("evidence_audit_tip_invalid")
        if authority_effect != "none" or "permit" in snapshot:
            raise ValueError("evidence_authority_boundary_invalid")

        self.__snapshot = MappingProxyType(
            {
                "schema": schema,
                "policy_hash": policy_hash,
                "audit_valid": audit_valid,
                "audit_records": audit_records,
                "audit_tip": audit_tip,
                "authority_effect": authority_effect,
            }
        )

    def read_evidence(self) -> dict[str, Any]:
        """Return a copy of the validated frozen evidence payload."""

        return dict(self.__snapshot)


def create_app(
    evidence_source: FrozenEvidenceSource,
    *,
    auth_token: str,
):
    """Create a mobile evidence view with no canonical write-capable dependency."""

    if not isinstance(evidence_source, FrozenEvidenceSource):
        raise TypeError("FrozenEvidenceSource required")
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

    def no_store(response):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Vary"] = "Authorization"
        return response

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
    <p class="boundary">Frozen read-only evidence snapshot. Freshness is not asserted. This surface has no canonical-state writer, approval, execution, or permit capability.</p>
    <label>Access token<input id="token" type="password" autocomplete="off" required /></label>
    <button id="evidence" type="button">Read evidence snapshot</button>
    <div id="result" class="result">Waiting...</div>
  </div>
  <script>
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
    const result = document.getElementById('result');
    document.getElementById('evidence').addEventListener('click', async () => {
      const token = document.getElementById('token').value;
      const response = await fetch('/api/evidence', {
        cache:'no-store',
        headers:{'Authorization':`Bearer ${token}`}
      });
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
            response = jsonify(
                {
                    "outcome": "deny",
                    "reason": "authentication_required",
                    "authority_effect": "none",
                }
            )
            response.status_code = 401
            return no_store(response)

        response = jsonify(
            {
                "schema": "pulpo.mobile-evidence-snapshot.v0",
                "freshness": "not_asserted",
                "source": evidence_source.read_evidence(),
                "authority_effect": "none",
            }
        )
        return no_store(response)

    return app
