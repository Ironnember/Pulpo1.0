"""Same-origin human UI for the existing WebAuthn approval ceremony."""

from __future__ import annotations

from html import escape


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; connect-src 'self'; "
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
        f"<dt>{escape(label)}</dt><dd>{escape(str(display[key]))}</dd>" for label, key in labels
    )
    pending = display.get("status") == "pending"
    disabled = "" if pending else " disabled"
    status = (
        "Review every field, then use the separately approved Pulpo hardware "
        "authenticator. The browser prompt is guidance; the service enforces the credential."
        if pending
        else f"This request is {escape(str(display.get('status', 'unavailable')))}."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pulpo approval</title>
</head>
<body>
  <main>
    <h1>Approve this exact Pulpo request</h1>
    <p>A click alone grants no authority. The server requires a fresh WebAuthn assertion.</p>
    <dl>{details}</dl>
    <button id="pulpo-approve" type="button"{disabled}>Verify with approved authenticator</button>
    <p id="pulpo-status" role="status" aria-live="polite">{status}</p>
  </main>
  <script src="/human/approval.js" defer></script>
</body>
</html>"""
