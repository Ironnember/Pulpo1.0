"""Same-origin human UI for the existing WebAuthn approval ceremony."""

from __future__ import annotations

from html import escape


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "publickey-credentials-get=(self)",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


APPROVAL_JAVASCRIPT = r"""'use strict';

const button = document.querySelector('#pulpo-approve');
const status = document.querySelector('#pulpo-status');

function setStatus(message) {
  status.textContent = message;
}

function decodeBase64url(value) {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const encoded = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(encoded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function serializeAssertion(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: encodeBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    response: {
      clientDataJSON: encodeBase64url(response.clientDataJSON),
      authenticatorData: encodeBase64url(response.authenticatorData),
      signature: encodeBase64url(response.signature),
      userHandle: response.userHandle ? encodeBase64url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function jsonResponse(response, message) {
  if (!response.ok) {
    throw new Error(message);
  }
  return response.json();
}

async function approve() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    setStatus('This browser cannot perform the required WebAuthn verification.');
    return;
  }

  button.disabled = true;
  setStatus('Waiting for your approved Pulpo hardware authenticator...');
  try {
    const path = window.location.pathname;
    const challenge = await fetch(`${path}/challenge`, {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      headers: {'Accept': 'application/json'},
    }).then((response) => jsonResponse(response, 'Approval request is unavailable.'));

    if (challenge.user_verification !== 'required') {
      throw new Error('Authority did not require user verification.');
    }

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: decodeBase64url(challenge.challenge),
        rpId: challenge.rp_id,
        userVerification: 'required',
        hints: ['security-key'],
        timeout: 120000,
      },
    });
    if (!credential) {
      throw new Error('No verified credential was returned.');
    }

    const completed = await fetch(`${path}/assertion`, {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({
        credential_id: credential.id,
        assertion: JSON.stringify(serializeAssertion(credential)),
      }),
    }).then((response) => jsonResponse(response, 'Verification was rejected.'));

    if (completed.status !== 'approved') {
      throw new Error('Authority did not confirm approval.');
    }
    setStatus('Verified and approved for this exact request.');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Verification failed.';
    setStatus(message);
    button.disabled = false;
  }
}

if (button) {
  button.addEventListener('click', approve);
}
"""


def render_approval_page(display: dict[str, object]) -> str:
    """Render immutable request details without placing untrusted text in script."""

    labels = (
        ("Request ID", "request_id"),
        ("Principal", "principal"),
        ("Action", "action"),
        ("Resource", "resource"),
        ("Cost", "cost"),
        ("Session", "session_id"),
        ("Intent hash", "intent_hash"),
        ("Policy hash", "policy_hash"),
        ("Deployment", "deployment_id"),
        ("Expires at (ns)", "expires_at_ns"),
    )
    details = "".join(
        f"<div class=\"detail\"><dt>{escape(label)}</dt><dd>{escape(str(display[key]))}</dd></div>"
        for label, key in labels
    )
    pending = display.get("status") == "pending"
    disabled = "" if pending else " disabled"
    status_value = escape(str(display.get("status", "unavailable")))
    status = (
        "Review every field, then use the separately approved Pulpo hardware "
        "authenticator. The browser prompt is guidance; the service enforces the credential."
        if pending
        else f"This request is {status_value}."
    )
    step_state = "active" if pending else "complete"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pulpo approval</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: #f7f7f2; color: #171712; }}
    main {{ width: min(760px, calc(100% - 32px)); margin: 48px auto; }}
    .brand {{ font-size: 13px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }}
    h1 {{ margin: 12px 0 8px; font-size: clamp(28px, 5vw, 44px); line-height: 1.05; letter-spacing: -.03em; }}
    .lede {{ margin: 0 0 28px; color: #5c5c52; line-height: 1.55; }}
    .steps {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin: 0 0 18px; }}
    .step {{ padding: 12px; border: 1px solid #d9d9cf; border-radius: 12px; background: #fff; font-size: 12px; font-weight: 700; }}
    .step strong {{ display: block; margin-bottom: 4px; font-size: 11px; color: #747468; }}
    .step.active, .step.complete {{ border-color: #171712; }}
    .card {{ background: #fff; border: 1px solid #deded5; border-radius: 20px; padding: clamp(20px, 4vw, 32px); box-shadow: 0 12px 40px rgba(20,20,12,.06); }}
    .eyebrow {{ margin: 0 0 6px; color: #747468; font-size: 12px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }}
    h2 {{ margin: 0 0 20px; font-size: 22px; }}
    dl {{ margin: 0; display: grid; gap: 1px; background: #ecece4; border: 1px solid #ecece4; border-radius: 12px; overflow: hidden; }}
    .detail {{ min-width: 0; display: grid; grid-template-columns: minmax(110px, .45fr) minmax(0, 1fr); gap: 16px; padding: 12px 14px; background: #fff; }}
    dt {{ color: #6b6b60; font-size: 12px; font-weight: 700; }}
    dd {{ margin: 0; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
    .boundary {{ margin: 20px 0; padding: 14px; border-radius: 12px; background: #f3f3ec; line-height: 1.5; font-size: 13px; }}
    button {{ width: 100%; min-height: 52px; border: 0; border-radius: 12px; background: #171712; color: #fff; font: inherit; font-weight: 800; cursor: pointer; }}
    button:disabled {{ cursor: not-allowed; opacity: .42; }}
    #pulpo-status {{ min-height: 24px; margin: 14px 0 0; color: #56564d; font-size: 13px; line-height: 1.5; }}
    .foot {{ margin: 18px 2px 0; color: #747468; font-size: 12px; line-height: 1.5; }}
    @media (max-width: 600px) {{
      main {{ margin: 24px auto; }}
      .steps {{ grid-template-columns: 1fr; }}
      .detail {{ grid-template-columns: 1fr; gap: 5px; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="brand">Pulpo Authority</div>
    <h1>Approve this exact Pulpo request</h1>
    <p class="lede">A click alone grants no authority. Review the consequence first; the server then requires a fresh WebAuthn assertion from an approved hardware authenticator.</p>
    <div class="steps" aria-label="Approval progress">
      <div class="step complete"><strong>01</strong>Request received</div>
      <div class="step complete"><strong>02</strong>Review consequence</div>
      <div class="step {step_state}"><strong>03</strong>Verify and approve</div>
    </div>
    <section class="card">
      <p class="eyebrow">Exact consequential object</p>
      <h2>Review every field</h2>
      <dl>{details}</dl>
      <p class="boundary">The interface cannot grant authority. Pulpo verifies the exact request, credential, challenge, user verification, policy binding, and approval envelope on the authority service.</p>
      <button id="pulpo-approve" type="button"{disabled}>Verify with approved authenticator</button>
      <p id="pulpo-status" role="status" aria-live="polite">{status}</p>
    </section>
    <p class="foot">Human-friendly presentation does not change the authority boundary. OTP, email verification, a button click, or browser-local identity claims cannot substitute for the required Pulpo ceremony.</p>
  </main>
  <script src="/human/approval.js" defer></script>
</body>
</html>"""
