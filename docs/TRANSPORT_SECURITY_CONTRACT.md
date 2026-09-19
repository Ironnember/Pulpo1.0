# Pulpo outbound transport security contract

This is the canonical contract for existing provider transports. Pulpo remains
AI-governance-only: a transport may deliver an already governed consequence,
but it never approves intent, creates permits, stores credentials, or mutates
canonical governance state.

## Required behavior

- Only the adapter's pinned `https://` origin is accepted. Redirects,
  cross-origin responses, plaintext URLs, and insecure fallback are rejected.
  The deployment must terminate TLS with a managed certificate and verify both
  certificate chain and hostname; disabling either check is unsupported.
- Connect and read timeouts are bounded, responses have a byte limit, and
  timeout, oversize, flood, and provider-ambiguity outcomes are explicit.
  A possibly-delivered request is `UNKNOWN` and is never silently retried.
- Provider identity, destination, operation, idempotency/replay key, and exact
  message hash are checked before accepting a claim. Message substitution and
  replay fail closed.
- Credentials are opaque references or execution-side secrets only. Logs must
  redact tokens, authorization headers, credential references, request bodies,
  and assertion material. Rotation is a deployment concern; old credentials
  must not be retained in governed code.

The current Name.com adapter accepts only its two pinned HTTPS origins and the
Telegram adapter uses the pinned HTTPS Bot API origin, a five-second bound, and
a one-megabyte response limit. These checks are contracts around the existing
adapters, not a second router or transport implementation.

## Evidence limits

The tests prove deterministic rejection and bounded adapter behavior. They do
not prove a deployment's certificate store, proxy configuration, rate limits,
or provider availability. Those remain deployment evidence obligations.

Claims in this document are **Recorded** requirements; test assertions are
**Verified** only at the exact commit.
