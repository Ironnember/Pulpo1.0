"""Operator packaging for a single-action Pulpo deployment.

``pulpo-ops`` (also ``python -m pulpo.ops``) is the deployability surface for
one governed deployment directory. A deployment directory holds exactly these
operator artifacts plus the canonical kernel state:

- ``policy.json`` — the deployment configuration written by ``init``
  (schema ``pulpo.ops-policy.v1``): the single allowed/approval action, the
  cost ceiling, the default session/deployment ids, the pinned authority
  trust (when configured), and the public verifier configuration.
- ``kernel-secret`` — the deployment's kernel secret (the permit-token
  HMAC key), created by ``init`` as an owner-only (``0600``) file and
  loaded by every command that opens the kernel. Permit tokens are
  authenticated against this secret at consume time, so the secret is the
  deployment's writer-custody root: whoever holds it can mint tokens the
  kernel will honor, and it is protected exactly like the state it keys.
  A deployment directory written before this file existed gains one the
  first time a *mutating* command (``authorize`` / ``consume``) opens the
  kernel; permit tokens issued before that point were minted under
  ephemeral secrets and can no longer be consumed (fail closed, by
  design). The read-only projections (``verify`` / ``status``) never
  create or repair the file: they load it when present and otherwise
  open the kernel with an ephemeral secret, because nothing they report
  authenticates a token — a legacy deployment, or one on a read-only
  mount, can be verified and inspected before anything provisions its
  secret.
- ``audit-secret`` — the deployment's audit-record signing key (the
  HMAC key for audit-record signatures), created by ``init`` as an
  owner-only (``0600``) file and deliberately distinct from both
  ``kernel-secret`` and ``anchor-secret``: one key must not carry both
  permit authentication and history attestation, so a single theft
  cannot yield both minting and undetectable history forgery. Every
  record appended after signing is enabled carries an HMAC over its
  hash under this key; ``verify`` loads the key read-only — never
  creating or repairing it — to verify those signatures. Signing is
  enabled from ``init`` for new deployments; a deployment that predates
  it enables signing with the ``enable-audit-signing`` command, which
  records the enablement (and the length of the unsigned legacy prefix)
  in ``policy.json``, outside the state file. A record past the legacy
  prefix whose signature is missing or wrong fails ``verify`` closed.
- ``anchor-secret`` — the deployment's anchor witness key (the HMAC key
  for audit anchors), created by ``init`` as an owner-only (``0600``)
  file and deliberately distinct from ``kernel-secret``: the anchor
  layer's trust separation requires the witness key never be the
  kernel's permit secret, so the writer who can rewrite the state file
  does not thereby hold the key that ratifies the rewrite. The
  ``anchor`` command loads it (provisioning it first on a legacy
  deployment that predates it); ``verify`` loads it read-only — never
  creating or repairing it — to build the verifier its anchored check
  passes to ``verify_anchored_audit``. A deployment whose
  ``anchors.jsonl`` is present but unsigned, or signed under a key this
  deployment does not hold, fails ``verify`` closed with an
  anchor-specific reason (see Anchoring below).
- ``anchors.jsonl`` — the external anchor witness log, appended only by
  the ``anchor`` command; a witness log for the audit trail, not a
  second ledger. Absent until the first anchor is taken, and ``verify``
  treats its absence as "not checked", never as a failure.
- ``state.db`` — the canonical SQLite kernel state, owned by the kernel.
- ``permits/<intent_hash>--<approval_id>.permit`` — one file per
  kernel-issued permit, written by ``authorize``; the file content is the
  permit string exactly as the kernel issued it. Permit files are bearer
  artifacts, so the directory and each file are owner-only (``0700`` /
  ``0600``), each file is created atomically without overwriting, and the
  filename carries the approval id because distinct approvals for one
  intent share an intent hash but never an approval id.

Transport-surface invariant, addressed head-on: this CLI is an operator
transport, and every operation it declares IS a governed kernel transition
or a read-only projection of one. ``authorize`` delegates to
``GovernanceKernel.evaluate_with_approval`` and nothing else can issue a
permit; ``consume`` delegates to ``GovernanceKernel.consume``; ``verify``
and ``status`` only read ``kernel.audit`` / ``kernel.verify_audit()`` (plus
the optional external anchor witness described below); ``anchor``
delegates to ``pulpo.anchor.anchor_records`` over a read-only kernel
projection and writes only the witness file (plus, once, on a legacy
deployment, the rotation of an unsigned witness file and the first
provisioning of ``anchor-secret`` described below) — it appends nothing
to the audit chain. The CLI holds no
approval signing key; it holds the deployment's kernel secret (above),
never opens ``state.db`` except through
``SQLiteKernelState`` handed to a ``GovernanceKernel``, and never writes
canonical state directly — the only files it writes are its own
``policy.json``, ``kernel-secret``, ``audit-secret``, and
``anchor-secret`` at ``init`` time (plus a secret's first provisioning
by a mutating command on a legacy deployment, and the
``enable-audit-signing`` command's one-time ``policy.json`` update on a
legacy deployment), permit files at ``authorize`` time, and the anchor
witness at ``anchor`` time, all outside the audit chain.
``verify`` and ``status`` write nothing at all. It is not a second router, executor, ledger,
memory system, or authority plane: approval envelopes are produced by the
external authority, and this tool only presents them to the kernel.
``authorize`` preflights the permits directory (owner-only, provably
writable) before the kernel is opened, so a known-unusable destination
refuses before anything is issued; if the permit write still fails after
issuance, the command fails closed and its report carries the issued
permit string as the recoverable artifact, reconcilable against the audit
chain — the write probe used by the preflight is transient and removed
before issuance.

Audit signing: every record the state layer appends after signing is
enabled carries an HMAC over its own hash under the deployment's
``audit-secret`` (see above). The signature is a sibling of the record
hash, excluded from the hashed body, so the unkeyed chain math is
unchanged. ``verify`` verifies those signatures and reports the
coverage — how many records are signed, how many are the unsigned
legacy prefix — separately from the chain verdict; a record past the
legacy prefix whose signature is missing or wrong fails ``verify``
closed. Signing proves the deployment's state layer wrote the record;
it does not prove the kernel governed the write (any caller who can
make the state append gets a valid signature — Item 3's handles), and
it does not bind the chain's length, so tail truncation still needs
the anchor (§6). The legacy prefix is the records that predate
enablement: they verify by hash alone and are reported as unsigned,
with a count, and the operator is told to witness them with ``anchor``
at enablement time — the pair (signed records + signed anchors) is
the unit of coverage against a state-file writer. Enablement itself is
recorded in ``policy.json`` (outside the state file) so a writer who
strips signatures cannot re-label the whole chain as legacy: where
the config requires signing, an unsigned record fails. A writer who
can also rewrite ``policy.json`` and delete the audit secret is the
whole-directory writer this layer's scope already places out of scope,
exactly as for the anchor-secret gate.

Anchoring: when the sibling ``pulpo.anchor`` module is importable, the
``anchor`` command appends a signed witness of the current audit head to
``anchors.jsonl``, signed with ``HmacAnchorSigner`` under the
deployment's ``anchor-secret``; ``verify`` additionally checks that file
(when present) with ``verify_anchored_audit`` and a real verifier built
from the same secret, and ``status`` reports the last anchor, whether it
is signed, and a named warning when the witness cannot be verified. An
anchor file that is present but unsigned, signed under a key this
deployment does not hold, or unverifiable for want of the secret fails
``verify`` closed with an anchor-specific reason — it is never silently
accepted, and the anchored verdict is reported separately from the audit
chain verdict, never as one. A legacy unsigned ``anchors.jsonl`` is
rotated byte-for-byte to ``anchors.jsonl.legacy-unsigned`` by the first
``anchor`` run and the signed history starts at the current head; the
rotation is reported as a migration, because signatures attest from the
anchor that carries them forward, never retroactively. The rotation is
a migration *into* a signed deployment, so it is reachable only while
the deployment holds no ``anchor-secret``: once a witness key exists,
an all-unsigned anchor file fails the ``anchor`` command closed
(``anchor_unsigned``) instead of being rotated — inside a signed
deployment that file is a replaced witness, not a legacy artifact —
and a signed file whose key the deployment does not hold fails the
command closed as well (``anchor_verifier_unavailable``) rather than
being extended under a freshly provisioned key. The witness
scope is ``pulpo.anchor``'s own, unchanged: anchoring detects tampering
with the audit store relative to the anchor history the verifier holds;
it does not protect against a writer who can also rewrite the anchor
store and, for signed anchors, holds the anchor key; that writer is
outside this layer's scope, and the tail after the latest anchor is
witnessed only when the next anchor is taken. When ``pulpo.anchor`` is
not importable, those outputs state plainly that anchoring is not
available in this build. This module never copies or reimplements the
anchor code.

What this tool does not do: it does not sign approvals, hold approval
private keys, execute the permitted consequence, manage multi-action
policies, or provide production-grade key custody: the deployment secrets'
custody is the deployment directory's filesystem permissions, the same
custody the permit files and the state file already rely on. The ``hmac-test`` verifier kind is a
test-only development flow: its secret is read from the
``PULPO_OPS_TEST_AUTHORITY_SECRET`` environment variable at authorize time
and is never written to ``policy.json``.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Sequence

from .authority import (
    ApprovalEnvelope,
    AuthorityTrust,
    Ed25519ApprovalVerifier,
    P256ApprovalVerifier,
)
from .kernel import GovernanceKernel, Intent, Policy
from .state import AuditSigner, SQLiteKernelState


POLICY_SCHEMA = "pulpo.ops-policy.v1"
REPORT_SCHEMA = "pulpo.ops.v1"
STATE_FILENAME = "state.db"
POLICY_FILENAME = "policy.json"
KERNEL_SECRET_FILENAME = "kernel-secret"
KERNEL_SECRET_BYTES = 32
AUDIT_SECRET_FILENAME = "audit-secret"
AUDIT_SECRET_BYTES = 32
ANCHOR_SECRET_FILENAME = "anchor-secret"
ANCHOR_SECRET_BYTES = 32
PERMITS_DIRNAME = "permits"
# Permit files are bearer artifacts: whoever holds the file can consume the
# permit. They and their directory are therefore owner-only, created
# atomically, and never overwritten (see _write_permit_file).
PERMITS_DIR_MODE = 0o700
PERMIT_FILE_MODE = 0o600
_PROBE_PREFIX = ".write-probe-"
ANCHORS_FILENAME = "anchors.jsonl"
LEGACY_UNSIGNED_ANCHORS_FILENAME = ANCHORS_FILENAME + ".legacy-unsigned"
TEST_SECRET_ENV = "PULPO_OPS_TEST_AUTHORITY_SECRET"
ANCHOR_UNAVAILABLE_NOTE = "anchoring is not available in this build"
DEFAULT_DEPLOYMENT_ID = "deployment:ops"
DEFAULT_SESSION_ID = "default"
DEFAULT_MAX_APPROVAL_TTL_NS = 300_000_000_000

# The hmac-test verifier mirrors tests/authority_support.HmacTestVerifier so
# envelopes signed by that test double verify here. Its fingerprint is the
# fingerprint of the fixed test key label, not of the runtime secret, exactly
# as in the test double. Test-only: never evidence of independent authority.
_HMAC_TEST_ALGORITHM = "hmac-sha256-test-only"
_HMAC_TEST_KEY_FINGERPRINT = sha256(b"pulpo-test-verifier-key").hexdigest()
_HMAC_TEST_DEFAULTS = {
    "authority_id": "authority:test-owner",
    "verifier_id": "verifier:test-only",
    "key_id": "key:test-only:v1",
}

_ENVELOPE_FIELDS = {
    "approval_id",
    "authority_id",
    "verifier_id",
    "key_id",
    "deployment_id",
    "trust_hash",
    "session_id",
    "principal",
    "intent_hash",
    "policy_hash",
    "nonce",
    "issued_at_ns",
    "expires_at_ns",
    "signature",
    "schema",
}


class OpsError(RuntimeError):
    """Raised when an operator command cannot proceed without ambiguity."""


class _HmacTestVerifier:
    """Test-only HMAC approval verifier; the secret lives only in memory.

    The secret is supplied by the operator's environment at authorize time.
    This class exists so the documented development flow can run end to end
    without private authority material ever entering the deployment files.
    """

    algorithm = _HMAC_TEST_ALGORITHM
    key_fingerprint = _HMAC_TEST_KEY_FINGERPRINT

    def __init__(
        self,
        *,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        secret: bytes,
    ) -> None:
        self.authority_id = authority_id
        self.verifier_id = verifier_id
        self.key_id = key_id
        self._secret = secret

    def verify(self, payload: bytes, signature: str) -> bool:
        expected = hmac.new(self._secret, payload, sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _deployment_paths(directory: Path) -> tuple[Path, Path]:
    return directory / STATE_FILENAME, directory / POLICY_FILENAME


def _save_config(directory: Path, config: dict[str, Any]) -> Path:
    _, policy_path = _deployment_paths(directory)
    policy_path.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return policy_path


def _load_config(directory: Path) -> dict[str, Any]:
    _, policy_path = _deployment_paths(directory)
    if not policy_path.is_file():
        raise OpsError(f"deployment policy not found at {policy_path}; run init first")
    try:
        config = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OpsError(f"deployment policy at {policy_path} is unreadable") from error
    if not isinstance(config, dict) or config.get("schema") != POLICY_SCHEMA:
        raise OpsError(f"deployment policy at {policy_path} has an unsupported schema")
    return config


def _ensure_permits_dir(directory: Path) -> Path:
    """Create the permits directory owner-only and repair its permissions.

    ``mkdir``'s mode is ignored when the directory already exists (for
    example one created ``0755`` by an earlier ``init`` under a typical
    umask), so an existing directory is tightened explicitly: bearer
    permit files must never sit inside a world-traversable directory.
    """

    permits_dir = directory / PERMITS_DIRNAME
    try:
        permits_dir.mkdir(mode=PERMITS_DIR_MODE, exist_ok=True)
        if not permits_dir.is_dir():
            raise OpsError(f"permits path at {permits_dir} is not a directory")
        if stat.S_IMODE(permits_dir.stat().st_mode) != PERMITS_DIR_MODE:
            os.chmod(permits_dir, PERMITS_DIR_MODE)
    except OpsError:
        raise
    except OSError as error:
        raise OpsError(
            f"permits directory at {permits_dir} is unavailable: {error}"
        ) from error
    return permits_dir


def _preflight_permits_writable(permits_dir: Path) -> None:
    """Prove the permits directory accepts a new file, before issuance.

    ``authorize`` runs this before opening the kernel, so the filesystem
    failures that can be known in advance (permits path replaced by a
    file, directory unwritable) refuse the command before
    ``evaluate_with_approval`` commits anything — issuance and
    persistence must not diverge silently. The probe file is removed
    immediately; it is never a permit artifact.
    """

    probe_path = permits_dir / f"{_PROBE_PREFIX}{os.getpid()}"
    try:
        fd = os.open(probe_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PERMIT_FILE_MODE)
    except OSError as error:
        raise OpsError(
            f"permits directory at {permits_dir} is not writable: {error}"
        ) from error
    os.close(fd)
    try:
        probe_path.unlink()
    except OSError:
        pass  # A leftover empty probe file is inert; writability is proven.


def _permit_filename(intent_hash: str, approval_id: str) -> str:
    """One unique file per issued permit: intent hash + approval id.

    Two distinct approvals for the same intent share an intent hash but
    never an approval id, so the approval id disambiguates the artifact.
    An approval id carrying path-unsafe characters is replaced by its
    SHA-256 so an envelope can never influence the path shape.
    """

    safe = (
        bool(approval_id)
        and approval_id not in (".", "..")
        and all(char.isalnum() or char in "._-" for char in approval_id)
        and ".." not in approval_id
    )
    suffix = approval_id if safe else sha256(approval_id.encode("utf-8")).hexdigest()
    return f"{intent_hash}--{suffix}.permit"


def _write_permit_file(permit_path: Path, permit: str) -> None:
    """Write a bearer permit atomically, owner-only, never overwriting.

    ``O_EXCL`` makes a name collision fail loudly instead of silently
    replacing another issued permit's only artifact. The mode is pinned
    with ``fchmod`` so the file is owner-only regardless of the process
    umask. A failed write removes the partial file; the caller reports
    the issued permit string as the recoverable artifact.
    """

    fd = os.open(
        permit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PERMIT_FILE_MODE
    )
    try:
        os.fchmod(fd, PERMIT_FILE_MODE)
        view = memoryview((permit + "\n").encode("utf-8"))
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    except BaseException:
        try:
            permit_path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _trust_from_config(config: dict[str, Any]) -> AuthorityTrust | None:
    raw = config.get("authority_trust")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise OpsError("deployment authority_trust is malformed")
    try:
        return AuthorityTrust(**raw)
    except (TypeError, ValueError) as error:
        raise OpsError("deployment authority_trust is malformed") from error


def _effective_policy(config: dict[str, Any]) -> Policy:
    """Rebuild the kernel policy from the deployment configuration.

    ``policy.json`` always records the operator's approval action, but the
    kernel forbids approval actions without a pinned authority trust. A
    trustless deployment therefore boots with the approval action recorded
    but not kernel-enabled, and ``authorize`` refuses before any kernel
    call (see ``_cmd_authorize``), so no permit can be issued there.
    """

    trust = _trust_from_config(config)
    try:
        allowed = frozenset(str(item) for item in config["allowed_actions"])
        recorded_approval = frozenset(str(item) for item in config["approval_actions"])
        max_cost = int(config["max_cost"])
    except (KeyError, TypeError, ValueError) as error:
        raise OpsError("deployment policy fields are malformed") from error
    return Policy(
        allowed_actions=allowed,
        max_cost=max_cost,
        approval_actions=recorded_approval if trust is not None else frozenset(),
        authority_trust=trust,
    )


def _build_verifier(config: dict[str, Any]):
    """Build the public-key (or test-secret) verifier pinned by the config.

    Returns ``None`` when no authority trust is configured. Raises
    ``OpsError`` — failing closed before any state is opened — when the
    configuration is incomplete or a required runtime secret is absent.
    """

    trust = _trust_from_config(config)
    verifier_config = config.get("verifier")
    if trust is None or verifier_config is None:
        return None
    if not isinstance(verifier_config, dict):
        raise OpsError("deployment verifier configuration is malformed")
    kind = verifier_config.get("kind")
    if kind == "hmac-test":
        secret_env = str(verifier_config.get("secret_env") or TEST_SECRET_ENV)
        secret = os.environ.get(secret_env)
        if not secret:
            raise OpsError(
                f"authority trust is configured for hmac-test but {secret_env} "
                "is not set; failing closed"
            )
        return _HmacTestVerifier(
            authority_id=trust.authority_id,
            verifier_id=trust.verifier_id,
            key_id=trust.key_id,
            secret=secret.encode("utf-8"),
        )
    if kind in {"ed25519", "p256"}:
        public_key_hex = verifier_config.get("public_key_hex")
        if not isinstance(public_key_hex, str) or not public_key_hex:
            raise OpsError("deployment verifier public key is missing")
        try:
            public_key = bytes.fromhex(public_key_hex)
        except ValueError as error:
            raise OpsError("deployment verifier public key is malformed") from error
        verifier_type = Ed25519ApprovalVerifier if kind == "ed25519" else P256ApprovalVerifier
        try:
            return verifier_type(
                authority_id=trust.authority_id,
                verifier_id=trust.verifier_id,
                key_id=trust.key_id,
                public_key=public_key,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise OpsError(f"deployment verifier cannot be constructed: {error}") from error
    raise OpsError(f"unsupported verifier kind in deployment policy: {kind!r}")


def _verifier_attributes(verifier: Any) -> tuple[str, str, str, str, str]:
    return (
        verifier.authority_id,
        verifier.verifier_id,
        verifier.key_id,
        verifier.algorithm,
        verifier.key_fingerprint,
    )


def _read_secret_file(secret_path: Path, label: str, size: int) -> bytes | None:
    """Load a deployment secret file without provisioning anything.

    Returns ``None`` when the file does not exist yet. An existing file
    is read and validated exactly as on the provisioning path — a
    malformed or wrong-length secret fails closed — but this function
    never writes: no creation, and no permission repair. It is the only
    secret path the read-only projections (``verify`` / ``status``) may
    take, so those commands stay non-mutating on any deployment,
    including legacy ones and ones on read-only mounts.
    """

    if not secret_path.exists():
        return None
    try:
        encoded = secret_path.read_text(encoding="utf-8").strip()
        secret = bytes.fromhex(encoded)
    except (OSError, UnicodeError, ValueError) as error:
        raise OpsError(
            f"{label} at {secret_path} is unreadable or malformed"
        ) from error
    if len(secret) != size:
        raise OpsError(f"{label} at {secret_path} has an invalid length")
    return secret


def _load_kernel_secret(directory: Path) -> bytes | None:
    """Load the deployment's kernel secret without provisioning anything.

    Returns ``None`` when the deployment has no secret file yet; see
    :func:`_read_secret_file` for the load-only contract the read-only
    projections rely on.
    """

    return _read_secret_file(
        directory / KERNEL_SECRET_FILENAME, "kernel secret", KERNEL_SECRET_BYTES
    )


def _load_anchor_secret(directory: Path) -> bytes | None:
    """Load the deployment's anchor secret without provisioning anything.

    The load-only half of the anchor-secret custody split, mirroring
    :func:`_load_kernel_secret`: ``verify`` / ``status`` build their
    anchor verifier from this and never create or repair the file.
    Returns ``None`` when the deployment has no anchor secret yet.
    """

    return _read_secret_file(
        directory / ANCHOR_SECRET_FILENAME, "anchor secret", ANCHOR_SECRET_BYTES
    )


def _provision_secret_file(secret_path: Path, label: str, size: int) -> bytes:
    """Load a deployment secret file, creating it owner-only on first use.

    This is the provisioning path, taken only by commands that may
    mutate the deployment. The file is written atomically with
    ``O_EXCL`` and never overwritten: a collision means another process
    created it first, and the winner's secret is the one to load. An
    existing file's permissions are repaired to owner-only. A malformed
    or wrong-length secret fails closed.
    """

    if not secret_path.exists():
        encoded = secrets.token_bytes(size).hex()
        try:
            fd = os.open(
                secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PERMIT_FILE_MODE
            )
        except FileExistsError:
            pass  # Another process created it first; load the winner below.
        except OSError as error:
            raise OpsError(
                f"{label} at {secret_path} could not be created: {error}"
            ) from error
        else:
            try:
                os.fchmod(fd, PERMIT_FILE_MODE)
                view = memoryview((encoded + "\n").encode("utf-8"))
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            except BaseException:
                try:
                    secret_path.unlink()
                except OSError:
                    pass
                raise
            finally:
                os.close(fd)
    try:
        if stat.S_IMODE(secret_path.stat().st_mode) != PERMIT_FILE_MODE:
            os.chmod(secret_path, PERMIT_FILE_MODE)
    except OSError as error:
        raise OpsError(
            f"{label} at {secret_path} is unreadable or malformed"
        ) from error
    secret = _read_secret_file(secret_path, label, size)
    if secret is None:  # The file existed or was just created above.
        raise OpsError(f"{label} at {secret_path} is unreadable or malformed")
    return secret


def _deployment_kernel_secret(directory: Path) -> bytes:
    """Load the deployment's kernel secret, creating it on first use.

    This is the provisioning path, taken only by commands that may
    mutate the deployment (``init``, ``authorize``, ``consume``). The
    secret keys the permit tokens this deployment's kernel mints and
    authenticates, so every process that opens the kernel for the
    deployment must present the same one (authorize and consume are
    separate invocations). It lives in an owner-only file beside the
    state it keys. Deployments created before this file existed gain
    one here; tokens minted earlier were keyed by ephemeral secrets and
    can no longer be consumed.
    """

    return _provision_secret_file(
        directory / KERNEL_SECRET_FILENAME, "kernel secret", KERNEL_SECRET_BYTES
    )


def _deployment_anchor_secret(directory: Path) -> bytes:
    """Load the deployment's anchor secret, creating it on first use.

    The provisioning path for the witness key, taken by ``init`` and by
    the ``anchor`` command on a legacy deployment that predates the
    file. The key signs and verifies this deployment's audit anchors
    and is deliberately not the kernel secret: anchor.py's trust
    separation requires the witness key be held apart from the permit
    secret, so a writer holding the state file (or the kernel secret)
    cannot ratify a rewritten anchor history. It lives in an
    owner-only file beside the state it witnesses.
    """

    return _provision_secret_file(
        directory / ANCHOR_SECRET_FILENAME, "anchor secret", ANCHOR_SECRET_BYTES
    )


def _load_audit_secret(directory: Path) -> bytes | None:
    """Load the deployment's audit secret without provisioning anything.

    The load-only half of the audit-secret custody split, mirroring
    :func:`_load_kernel_secret`: ``verify`` / ``status`` / ``anchor``
    build their signature verifier from this and never create or
    repair the file. Returns ``None`` when the deployment has no audit
    secret yet.
    """

    return _read_secret_file(
        directory / AUDIT_SECRET_FILENAME, "audit secret", AUDIT_SECRET_BYTES
    )


def _deployment_audit_secret(directory: Path) -> bytes:
    """Load the deployment's audit secret, creating it on first use.

    The provisioning path for the record-signing key, taken by ``init``
    and by ``enable-audit-signing`` on a legacy deployment that
    predates the file. The key signs audit records at append and
    verifies them at boot/verify, and is deliberately not the kernel
    secret and not the anchor secret: one key must not carry both
    permit authentication and history attestation, and the witness key
    must stay apart from both. It lives in an owner-only file beside
    the state it attests.
    """

    return _provision_secret_file(
        directory / AUDIT_SECRET_FILENAME, "audit secret", AUDIT_SECRET_BYTES
    )


def _audit_signing_settings(config: dict[str, Any]) -> tuple[bool, int]:
    """Read the audit-signing enablement from deployment config.

    Returns ``(enabled, legacy_records)``. The enablement lives in
    ``policy.json`` — outside the state file — so a state-file writer
    who strips signatures cannot re-label the chain as legacy: where
    this config requires signing, an unsigned record past the legacy
    prefix fails verification. A malformed entry fails closed here,
    before any state is opened.
    """

    raw = config.get("audit_signing")
    if raw is None:
        return False, 0
    if not isinstance(raw, dict):
        raise OpsError("deployment audit_signing configuration is malformed")
    enabled = raw.get("enabled")
    legacy_records = raw.get("legacy_records")
    if (
        not isinstance(enabled, bool)
        or isinstance(legacy_records, bool)
        or not isinstance(legacy_records, int)
        or legacy_records < 0
    ):
        raise OpsError("deployment audit_signing configuration is malformed")
    return enabled, legacy_records


def _audit_signer_for(
    directory: Path, config: dict[str, Any], *, projection: bool
) -> tuple[AuditSigner | None, int]:
    """Resolve the audit signer for a kernel open, if signing is enabled.

    Projections take the load-only half: a configured signer whose key
    is unavailable fails closed (the signatures cannot be verified, so
    the chain cannot be trusted), rather than opening unsigned. Mutating
    commands take the provisioning half. Deployments that never enabled
    signing open unsigned, exactly as before.
    """

    enabled, legacy_records = _audit_signing_settings(config)
    if not enabled:
        return None, 0
    if projection:
        secret = _load_audit_secret(directory)
        if secret is None:
            raise OpsError(
                "audit signing is enabled but the audit secret is "
                "unavailable; failing closed"
            )
    else:
        secret = _deployment_audit_secret(directory)
    return AuditSigner(secret), legacy_records


def _open_kernel(
    directory: Path,
    config: dict[str, Any],
    *,
    verifier: Any = None,
    projection: bool = False,
) -> tuple[GovernanceKernel, SQLiteKernelState]:
    state_path, _ = _deployment_paths(directory)
    # The audit signer is resolved before the state is constructed: it
    # signs at append and verifies at boot, so the state must hold it
    # from its first open. A projection whose signing is enabled but
    # whose audit secret is unavailable fails closed here, before the
    # chain is read (see _audit_signer_for).
    audit_signer, legacy_audit_records = _audit_signer_for(
        directory, config, projection=projection
    )
    state = SQLiteKernelState(
        state_path,
        audit_signer=audit_signer,
        legacy_audit_records=legacy_audit_records,
    )
    try:
        if projection:
            # Read-only projection (verify / status): load the secret
            # when one exists, but never create or repair it. Nothing a
            # projection reports authenticates a token -- it reads the
            # audit trail, the (unkeyed) chain verification, and the
            # policy hash -- so a deployment without a secret file yet
            # is opened with an ephemeral one and left untouched.
            secret = _load_kernel_secret(directory)
            if secret is None:
                secret = secrets.token_bytes(KERNEL_SECRET_BYTES)
        else:
            secret = _deployment_kernel_secret(directory)
        kernel = GovernanceKernel(
            _effective_policy(config),
            secret=secret,
            approval_verifier=verifier,
            state=state,
        )
    except Exception:
        state.close()
        raise
    return kernel, state


def _resolve_session(config: dict[str, Any], requested: str | None) -> str:
    if requested:
        return requested
    stored = config.get("session_id")
    return stored if isinstance(stored, str) and stored else DEFAULT_SESSION_ID


def _anchor_module():
    try:
        import pulpo.anchor as anchor_module
    except ImportError:
        return None
    return anchor_module


def _anchored_check(directory: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    anchor_module = _anchor_module()
    if anchor_module is None:
        return {"available": False, "checked": False, "note": ANCHOR_UNAVAILABLE_NOTE}
    anchors_path = directory / ANCHORS_FILENAME
    if not anchors_path.is_file():
        return {
            "available": True,
            "checked": False,
            "present": False,
            "note": "no anchor file present in this deployment",
        }
    try:
        anchors = anchor_module.FileAnchorStore(anchors_path).anchors()
        # Load-only: this check runs inside the read-only projections,
        # so it never provisions. An anchor secret that cannot be read
        # fails the check closed, exactly like a damaged witness.
        anchor_secret = _load_anchor_secret(directory)
    except Exception as error:  # A damaged witness fails closed, never open.
        return {
            "available": True,
            "checked": True,
            "present": True,
            "ok": False,
            "reason": f"anchor_check_failed: {error}",
        }
    signed = any(anchor.signature for anchor in anchors)
    if anchors and not signed and anchor_secret is None:
        # No witness key is configured and nothing in the file is
        # signed: there is no provenance to check against, and an
        # unsigned witness is state, not provenance. Fail closed under
        # the named posture instead of letting the library call below
        # ratify the file (a ``None`` verifier accepts unsigned
        # anchors). When a secret IS configured, the same file fails
        # below as ``anchor_signature_missing``.
        return {
            "available": True,
            "checked": True,
            "present": True,
            "ok": False,
            "reason": "anchor_unsigned",
            "signed": False,
            "anchored_records": 0,
            "total_records": len(records),
            "anchors_checked": 0,
        }
    verifier = (
        anchor_module.HmacAnchorSigner(anchor_secret)
        if anchor_secret is not None
        else None
    )
    try:
        result = anchor_module.verify_anchored_audit(
            records, anchors, verifier=verifier
        )
    except Exception as error:  # A damaged witness fails closed, never open.
        return {
            "available": True,
            "checked": True,
            "present": True,
            "ok": False,
            "reason": f"anchor_check_failed: {error}",
        }
    return {
        "available": True,
        "checked": True,
        "present": True,
        "ok": bool(result.ok),
        "reason": result.reason,
        "signed": signed,
        "anchored_records": result.anchored_records,
        "total_records": result.total_records,
        "anchors_checked": result.anchors_checked,
    }


def _last_anchor_info(directory: Path) -> dict[str, Any]:
    anchor_module = _anchor_module()
    if anchor_module is None:
        return {"available": False, "note": ANCHOR_UNAVAILABLE_NOTE}
    anchors_path = directory / ANCHORS_FILENAME
    if not anchors_path.is_file():
        return {"available": True, "present": False, "last_anchor": None}
    try:
        anchors = anchor_module.FileAnchorStore(anchors_path).anchors()
    except Exception as error:
        return {"available": True, "present": True, "last_anchor": None, "error": str(error)}
    if not anchors:
        return {"available": True, "present": True, "last_anchor": None}
    last = anchors[-1]
    info: dict[str, Any] = {
        "available": True,
        "present": True,
        "last_anchor": {
            "sequence": last.sequence,
            "record_count": last.record_count,
            "head_hash": last.head_hash,
            "timestamp_ns": last.timestamp_ns,
            "anchor_hash": last.anchor_hash,
            "signed": bool(last.signature),
        },
    }
    # ``status`` reports; ``verify`` enforces. The two postures a reader
    # must not mistake for a verified witness get a named warning here:
    # the file is unsigned, or it is signed under a key this deployment
    # cannot load (absent or unreadable), so no verifier can be built.
    if not any(anchor.signature for anchor in anchors):
        info["warning"] = "anchor_unsigned"
    else:
        try:
            secret_available = _load_anchor_secret(directory) is not None
        except Exception:
            secret_available = False
        if not secret_available:
            info["warning"] = "anchor_verifier_unavailable"
    return info


def _cmd_init(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    state_path, policy_path = _deployment_paths(directory)
    if policy_path.exists() or state_path.exists():
        raise OpsError(f"deployment already initialized at {directory}; refusing to overwrite")
    if directory.exists() and any(directory.iterdir()):
        raise OpsError(f"deployment directory {directory} is not empty; refusing to initialize")

    deployment_id = args.deployment_id or DEFAULT_DEPLOYMENT_ID
    session_id = args.session_id or DEFAULT_SESSION_ID
    trust_requested = any(
        value is not None
        for value in (
            args.authority_id,
            args.verifier_id,
            args.key_id,
            args.algorithm,
            args.key_fingerprint,
            args.verifier_kind,
            args.public_key_hex,
        )
    )

    trust: AuthorityTrust | None = None
    verifier_config: dict[str, Any] | None = None
    if trust_requested:
        if args.verifier_kind is None:
            raise OpsError("--verifier-kind is required when authority trust flags are given")
        kind = args.verifier_kind
        if kind == "hmac-test":
            authority_id = args.authority_id or _HMAC_TEST_DEFAULTS["authority_id"]
            verifier_id = args.verifier_id or _HMAC_TEST_DEFAULTS["verifier_id"]
            key_id = args.key_id or _HMAC_TEST_DEFAULTS["key_id"]
            algorithm = args.algorithm or _HMAC_TEST_ALGORITHM
            fingerprint = args.key_fingerprint or _HMAC_TEST_KEY_FINGERPRINT
            verifier_config = {"kind": kind, "secret_env": TEST_SECRET_ENV}
            probe: Any = _HmacTestVerifier(
                authority_id=authority_id,
                verifier_id=verifier_id,
                key_id=key_id,
                secret=b"",
            )
        elif kind in {"ed25519", "p256"}:
            missing = [
                flag
                for flag, value in (
                    ("--authority-id", args.authority_id),
                    ("--verifier-id", args.verifier_id),
                    ("--key-id", args.key_id),
                    ("--public-key-hex", args.public_key_hex),
                )
                if value is None
            ]
            if missing:
                raise OpsError(
                    f"missing required authority trust flags: {', '.join(missing)}"
                )
            authority_id = str(args.authority_id)
            verifier_id = str(args.verifier_id)
            key_id = str(args.key_id)
            try:
                public_key = bytes.fromhex(str(args.public_key_hex))
            except ValueError as error:
                raise OpsError("--public-key-hex is not valid hex") from error
            verifier_type = Ed25519ApprovalVerifier if kind == "ed25519" else P256ApprovalVerifier
            algorithm = args.algorithm or verifier_type.algorithm
            fingerprint = args.key_fingerprint or sha256(public_key).hexdigest()
            verifier_config = {"kind": kind, "public_key_hex": str(args.public_key_hex).lower()}
            try:
                probe = verifier_type(
                    authority_id=authority_id,
                    verifier_id=verifier_id,
                    key_id=key_id,
                    public_key=public_key,
                )
            except (TypeError, ValueError, RuntimeError) as error:
                raise OpsError(f"verifier cannot be constructed: {error}") from error
        else:  # argparse choices make this unreachable; fail closed anyway.
            raise OpsError(f"unsupported verifier kind: {kind!r}")
        try:
            trust = AuthorityTrust(
                authority_id=authority_id,
                verifier_id=verifier_id,
                key_id=key_id,
                algorithm=algorithm,
                key_fingerprint=fingerprint,
                deployment_id=deployment_id,
                max_approval_ttl_ns=args.max_approval_ttl_ns,
            )
        except (TypeError, ValueError) as error:
            raise OpsError(f"authority trust is invalid: {error}") from error
        if _verifier_attributes(probe) != (
            trust.authority_id,
            trust.verifier_id,
            trust.key_id,
            trust.algorithm,
            trust.key_fingerprint,
        ):
            raise OpsError(
                "verifier does not match the pinned authority trust "
                "(authority/verifier/key ids, algorithm, or key fingerprint)"
            )

    config: dict[str, Any] = {
        "schema": POLICY_SCHEMA,
        "allowed_actions": [args.action],
        "approval_actions": [args.action],
        "max_cost": args.max_cost,
        "session_id": session_id,
        "deployment_id": deployment_id,
        "authority_trust": asdict(trust) if trust is not None else None,
        "verifier": verifier_config,
        # Audit signing is enabled from birth for a new deployment:
        # there is no legacy prefix, so every record the deployment
        # ever appends carries a signature under its audit secret.
        "audit_signing": {"enabled": True, "legacy_records": 0},
    }

    directory.mkdir(parents=True, exist_ok=True)
    _ensure_permits_dir(directory)
    # The audit secret is provisioned before the state is constructed,
    # so the deployment's first kernel boots over a signed state.
    audit_secret = _deployment_audit_secret(directory)
    state = SQLiteKernelState(
        state_path,
        audit_signer=AuditSigner(audit_secret),
        legacy_audit_records=0,
    )
    try:
        # Boot the kernel once so the deployment starts from a verified,
        # empty audit chain. The boot appends nothing; the kernel validates
        # the fresh state and, when a verifier is pinned, its trust match
        # is re-checked by the attribute comparison above and on every
        # later authorize call by the kernel itself.
        kernel = GovernanceKernel(
            _effective_policy(config),
            secret=_deployment_kernel_secret(directory),
            state=state,
        )
        # The anchor witness key is provisioned at init, beside — and
        # never interchangeable with — the kernel secret: the witness
        # must be holdable apart from the permit secret for the anchor
        # layer's trust separation to mean anything.
        _deployment_anchor_secret(directory)
        policy_hash = kernel.policy_hash
        record_count = len(kernel.audit)
    finally:
        state.close()
    _save_config(directory, config)

    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "init",
            "ok": True,
            "deployment": str(directory),
            "policy_path": str(policy_path),
            "state_path": str(state_path),
            "policy_hash": policy_hash,
            "audit_records": record_count,
            "authority_configured": trust is not None,
            "audit_signing": {"enabled": True, "legacy_records": 0},
        }
    )
    return 0


def _cmd_enable_audit_signing(args: argparse.Namespace) -> int:
    """Enable audit-record signing on a deployment that predates it.

    The enablement is recorded in ``policy.json`` — outside the state
    file — together with the length of the unsigned legacy prefix
    (every record present at enablement time). Records appended after
    this command are signed under the deployment's audit secret;
    records before it verify legacy-style and are reported as an
    unsigned prefix with a count. The command first opens the kernel
    in projection mode, which boots over the existing chain: a chain
    that already fails hash verification refuses enablement rather
    than being blessed as a legacy prefix. The operator is told to
    witness the prefix with ``anchor`` at enablement time — the pair
    (signed records + signed anchors) is the unit of coverage against
    a state-file writer. Re-running the command on an enabled
    deployment is a no-op that reports the current settings.
    """

    directory: Path = args.directory
    config = _load_config(directory)
    enabled, legacy_records = _audit_signing_settings(config)
    if enabled:
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "enable-audit-signing",
                "ok": True,
                "deployment": str(directory),
                "audit_signing": {"enabled": True, "legacy_records": legacy_records},
                "already_enabled": True,
            }
        )
        return 0
    # Boot over the existing chain in legacy mode first: enablement
    # must not bless a chain that already fails hash verification.
    kernel, state = _open_kernel(directory, config, projection=True)
    try:
        record_count = len(kernel.audit)
        if not kernel.verify_audit():
            raise OpsError(
                "audit chain is invalid; refusing to enable signing "
                "over a chain that does not verify"
            )
    finally:
        state.close()
    _deployment_audit_secret(directory)
    config["audit_signing"] = {"enabled": True, "legacy_records": record_count}
    _save_config(directory, config)
    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "enable-audit-signing",
            "ok": True,
            "deployment": str(directory),
            "audit_signing": {"enabled": True, "legacy_records": record_count},
            "audit_records": record_count,
            "note": (
                "signing is enabled from this record on; the "
                f"{record_count} pre-enablement records are the unsigned "
                "legacy prefix — run `anchor` now to witness them"
            ),
        }
    )
    return 0


def _load_envelope(path: Path) -> ApprovalEnvelope:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OpsError(f"approval envelope at {path} is unreadable") from error
    if not isinstance(raw, dict):
        raise OpsError(f"approval envelope at {path} is malformed")
    fields = {key: value for key, value in raw.items() if key in _ENVELOPE_FIELDS}
    try:
        return ApprovalEnvelope(**fields)
    except (TypeError, ValueError) as error:
        raise OpsError(f"approval envelope at {path} is malformed: {error}") from error


def _cmd_authorize(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    if config.get("authority_trust") is None or config.get("verifier") is None:
        # Fail closed before opening canonical state: a trustless
        # deployment can be inspected (status/verify) but can never mint
        # a permit through this surface, and this refusal records nothing.
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "authorize",
                "ok": False,
                "outcome": "deny",
                "reason": "authority_trust_not_configured",
                "error": (
                    "authority trust not configured for this deployment; "
                    "re-run init with the authority trust flags before authorizing"
                ),
            }
        )
        return 1
    verifier = _build_verifier(config)
    if verifier is None:  # Trust present but verifier missing: fail closed.
        raise OpsError("authority trust is configured but no verifier is available")
    envelope = _load_envelope(args.envelope)
    intent = Intent(
        principal=args.principal,
        action=args.action,
        resource=args.resource,
        cost=args.cost,
        session_id=_resolve_session(config, args.session_id),
    )
    # Preflight the permit destination before the kernel is opened, so a
    # destination that is already known to be unusable refuses the
    # command before evaluate_with_approval commits the approval and a
    # live permit (a retry would then be rejected as replayed with no
    # artifact to show for the issuance).
    permits_dir = _ensure_permits_dir(directory)
    _preflight_permits_writable(permits_dir)
    kernel, state = _open_kernel(directory, config, verifier=verifier)
    try:
        decision = kernel.evaluate_with_approval(intent, envelope)
        policy_hash = kernel.policy_hash
    finally:
        state.close()
    if decision.outcome != "allow" or decision.permit is None:
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "authorize",
                "ok": False,
                "outcome": decision.outcome,
                "reason": decision.reason,
                "intent_hash": decision.intent_hash,
                "policy_hash": policy_hash,
            }
        )
        return 1
    permit_path = permits_dir / _permit_filename(
        decision.intent_hash, envelope.approval_id
    )
    try:
        _write_permit_file(permit_path, decision.permit)
    except OSError as error:
        # The preflight passed but the write still failed (for example
        # the disk filled in between). The kernel has already consumed
        # the approval and issued a live permit: canonical state changed
        # and the same envelope cannot be retried. Fail closed, but do
        # not strand the permit — this report carries the exact permit
        # string as the recoverable artifact, and the issuance is
        # reconcilable against the audit chain via status/verify.
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "authorize",
                "ok": False,
                "outcome": decision.outcome,
                "reason": decision.reason,
                "intent_hash": decision.intent_hash,
                "policy_hash": policy_hash,
                "permit_persisted": False,
                "permit": decision.permit,
                "error": (
                    f"permit was issued but could not be persisted to "
                    f"{permit_path}: {error}; the permit string in this "
                    "report is the recoverable artifact — store it "
                    "owner-only and pass it to consume via --permit-file"
                ),
            }
        )
        return 1
    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "authorize",
            "ok": True,
            "outcome": decision.outcome,
            "reason": decision.reason,
            "intent_hash": decision.intent_hash,
            "policy_hash": policy_hash,
            "permit_path": str(permit_path),
        }
    )
    return 0


def _cmd_consume(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    try:
        permit = args.permit_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise OpsError(f"permit file at {args.permit_file} is unreadable") from error
    if not permit:
        raise OpsError(f"permit file at {args.permit_file} is empty")
    intent = Intent(
        principal=args.principal,
        action=args.action,
        resource=args.resource,
        cost=args.cost,
        session_id=_resolve_session(config, args.session_id),
    )
    # Consume authenticates the permit token against the deployment
    # kernel secret and then makes the state-level one-use check; it needs
    # no approval verifier, so the kernel is booted without one. The
    # permit itself was issued and stored by the kernel at authorize time.
    kernel, state = _open_kernel(directory, config)
    try:
        consumed = kernel.consume(permit, intent)
        intent_hash = kernel.intent_hash(intent)
    finally:
        state.close()
    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "consume",
            "ok": bool(consumed),
            "consumed": bool(consumed),
            "intent_hash": intent_hash,
        }
    )
    return 0 if consumed else 1


def _cmd_anchor(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    anchor_module = _anchor_module()
    if anchor_module is None:
        raise OpsError(ANCHOR_UNAVAILABLE_NOTE)
    anchors_path = directory / ANCHORS_FILENAME
    store = anchor_module.FileAnchorStore(anchors_path)
    try:
        existing = store.anchors()
    except Exception as error:  # A damaged witness fails closed, never open.
        raise OpsError(
            f"anchor store at {anchors_path} is unreadable: {error}"
        ) from error
    # Load-only: whether this deployment already holds a witness key
    # decides which of the branches below is even reachable, and the
    # decision itself must not create or repair the key file. A
    # malformed key fails closed here, like any damaged witness.
    anchor_secret_present = _load_anchor_secret(directory) is not None
    migration: dict[str, Any] | None = None
    if existing and not any(anchor.signature for anchor in existing):
        if anchor_secret_present:
            # Not a legacy file: a deployment holding a witness key has
            # a signed witness history by construction, so an
            # all-unsigned anchors file inside it is a replaced witness,
            # not a pre-wiring artifact. Rotating it would let this
            # command launder a fabricated file into a freshly signed
            # attestation of whatever trail currently sits in the state
            # store — the rewrite attack this wiring exists to refuse —
            # so fail closed and touch nothing. The migration below is
            # reserved for deployments that predate anchor provisioning,
            # where no key has ever existed.
            raise OpsError(
                f"anchor file at {anchors_path} is unsigned but this "
                "deployment already holds an anchor secret; refusing to "
                "rotate unsigned anchor history in a signed deployment "
                "(anchor_unsigned): restore the signed anchor file or "
                "investigate the replacement"
            )
        # Legacy unsigned witness history. Signatures cannot reach
        # backward, so the unsigned file is preserved byte-for-byte
        # under a new name and the signed history starts at the current
        # head: the operator running this command attests the rotation,
        # and the report names it a migration — never a verification of
        # the unsigned past. A second rotation refuses rather than
        # overwriting the preserved file.
        legacy_path = directory / LEGACY_UNSIGNED_ANCHORS_FILENAME
        if legacy_path.exists():
            raise OpsError(
                f"unsigned anchor history already preserved at {legacy_path}; "
                "refusing to rotate a second legacy file"
            )
        migration = {
            "kind": "legacy_unsigned_history_rotated",
            "legacy_path": str(legacy_path),
            "rotated_anchors": len(existing),
            "note": (
                "signatures attest from the new anchor forward, never "
                "retroactively; the preserved unsigned file is unverified state"
            ),
        }
    elif existing and not anchor_secret_present:
        # Signed witness history, but the deployment does not hold the
        # key that signed it: this command cannot verify the history it
        # would extend, and provisioning a fresh key here would
        # silently re-key the witness. Fail closed, exactly as verify
        # does in this shape (anchor_verifier_unavailable), and touch
        # nothing — the operator restores the anchor secret.
        raise OpsError(
            f"anchor file at {anchors_path} is signed but this "
            "deployment holds no anchor secret to verify it "
            "(anchor_verifier_unavailable); refusing to extend a "
            "witness history whose key is absent"
        )
    # Anchoring reads the audit trail through a read-only projection:
    # it needs no token authentication (it mints and consumes nothing)
    # and so must not provision the kernel secret on a legacy
    # deployment either. The anchor secret is the only provisioning
    # this command performs, and only on a deployment that predates it.
    kernel, state = _open_kernel(directory, config, projection=True)
    try:
        records = list(kernel.audit)
    finally:
        state.close()
    signer = anchor_module.HmacAnchorSigner(_deployment_anchor_secret(directory))
    if migration is not None:
        os.replace(anchors_path, legacy_path)
    anchor = anchor_module.anchor_records(records, store, signer=signer)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "command": "anchor",
        "ok": True,
        "deployment": str(directory),
        "anchors_path": str(anchors_path),
        "sequence": anchor.sequence,
        "record_count": anchor.record_count,
        "head_hash": anchor.head_hash,
        "anchor_hash": anchor.anchor_hash,
        "signed": True,
    }
    if migration is not None:
        report["migration"] = migration
    _emit(report)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    try:
        kernel, state = _open_kernel(directory, config, projection=True)
    except Exception as error:
        # An open failure is not a chain verdict: the chain was never
        # read, so its validity is unknown (null), and the error is
        # reported as what it is -- the deployment could not be opened.
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "verify",
                "ok": False,
                "chain_valid": None,
                "error": f"kernel state could not be opened: {error}",
                "anchored": _anchored_check(directory, []),
            }
        )
        return 1
    try:
        records = list(kernel.audit)
        # The report carries the signing verdict and its coverage in
        # one pass: chain_valid is the report's ok, and the counts say
        # how much of the chain is signed versus legacy-unsigned. A
        # record past the legacy prefix whose signature is missing or
        # wrong makes chain_valid False with the named reason.
        audit_report = kernel.verify_audit_report()
        chain_valid = bool(audit_report["ok"])
        policy_hash = kernel.policy_hash
    finally:
        state.close()
    anchored = _anchored_check(directory, records)
    anchored_ok = (not anchored.get("checked")) or bool(anchored.get("ok"))
    ok = chain_valid and anchored_ok
    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "verify",
            "ok": ok,
            "chain_valid": chain_valid,
            "audit_records": len(records),
            "policy_hash": policy_hash,
            "audit_signing": {
                "enabled": audit_report["signing_enabled"],
                "signed_records": audit_report["signed_records"],
                "unsigned_records": audit_report["unsigned_records"],
                "legacy_records": audit_report["legacy_records"],
                "reason": audit_report["reason"],
            },
            "anchored": anchored,
        }
    )
    return 0 if ok else 1


def _cmd_status(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    try:
        kernel, state = _open_kernel(directory, config, projection=True)
    except Exception as error:
        # As in verify: an open failure is reported as an open failure,
        # with chain validity unknown (null) -- never as a chain verdict.
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "status",
                "ok": False,
                "chain_valid": None,
                "error": f"kernel state could not be opened: {error}",
            }
        )
        return 1
    try:
        records = list(kernel.audit)
        audit_report = kernel.verify_audit_report()
        chain_valid = bool(audit_report["ok"])
        policy_hash = kernel.policy_hash
    finally:
        state.close()
    counts = Counter(
        str(record.get("event")) for record in records if isinstance(record, dict)
    )
    event_counts = dict(sorted(counts.items()))
    for required in ("permit_consumed", "permit_rejected", "approval_verified"):
        event_counts.setdefault(required, 0)
    # ``status`` reports; ``verify`` enforces. A deployment that never
    # enabled signing carries a named warning here, exactly as the
    # unsigned-anchor posture does for the witness — the chain verifies
    # by hash alone and every record is unprovenanced.
    audit_signing: dict[str, Any] = {
        "enabled": audit_report["signing_enabled"],
        "signed_records": audit_report["signed_records"],
        "unsigned_records": audit_report["unsigned_records"],
        "legacy_records": audit_report["legacy_records"],
        "reason": audit_report["reason"],
    }
    if not audit_report["signing_enabled"]:
        audit_signing["warning"] = "audit_signing_not_enabled"
    _emit(
        {
            "schema": REPORT_SCHEMA,
            "command": "status",
            "ok": True,
            "deployment": str(directory),
            "audit_records": len(records),
            "chain_valid": chain_valid,
            "policy_hash": policy_hash,
            "event_counts": event_counts,
            "authority_configured": config.get("authority_trust") is not None,
            "audit_signing": audit_signing,
            "anchor": _last_anchor_info(directory),
        }
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="initialize a deployment directory")
    init_parser.add_argument("directory", type=Path)
    init_parser.add_argument("--action", required=True)
    init_parser.add_argument("--max-cost", type=int, default=0)
    init_parser.add_argument("--session-id")
    init_parser.add_argument("--deployment-id")
    init_parser.add_argument("--authority-id")
    init_parser.add_argument("--verifier-id")
    init_parser.add_argument("--key-id")
    init_parser.add_argument("--algorithm")
    init_parser.add_argument("--key-fingerprint")
    init_parser.add_argument(
        "--verifier-kind", choices=("ed25519", "p256", "hmac-test")
    )
    init_parser.add_argument("--public-key-hex")
    init_parser.add_argument(
        "--max-approval-ttl-ns", type=int, default=DEFAULT_MAX_APPROVAL_TTL_NS
    )

    authorize_parser = subparsers.add_parser(
        "authorize", help="evaluate an approval envelope and store the permit"
    )
    authorize_parser.add_argument("directory", type=Path)
    authorize_parser.add_argument("--envelope", type=Path, required=True)
    authorize_parser.add_argument("--principal", required=True)
    authorize_parser.add_argument("--action", required=True)
    authorize_parser.add_argument("--resource", required=True)
    authorize_parser.add_argument("--cost", type=int, default=0)
    authorize_parser.add_argument("--session-id")

    consume_parser = subparsers.add_parser(
        "consume", help="consume a one-use permit for an exact intent"
    )
    consume_parser.add_argument("directory", type=Path)
    consume_parser.add_argument("--permit-file", type=Path, required=True)
    consume_parser.add_argument("--principal", required=True)
    consume_parser.add_argument("--action", required=True)
    consume_parser.add_argument("--resource", required=True)
    consume_parser.add_argument("--cost", type=int, default=0)
    consume_parser.add_argument("--session-id")

    verify_parser = subparsers.add_parser(
        "verify", help="verify the audit chain (and anchors when available)"
    )
    verify_parser.add_argument("directory", type=Path)

    status_parser = subparsers.add_parser(
        "status", help="summarize deployment audit state"
    )
    status_parser.add_argument("directory", type=Path)

    anchor_parser = subparsers.add_parser(
        "anchor", help="append a signed anchor witnessing the current audit head"
    )
    anchor_parser.add_argument("directory", type=Path)

    enable_signing_parser = subparsers.add_parser(
        "enable-audit-signing",
        help="enable audit-record signing on a deployment that predates it",
    )
    enable_signing_parser.add_argument("directory", type=Path)

    args = parser.parse_args(argv)
    handlers = {
        "init": _cmd_init,
        "authorize": _cmd_authorize,
        "consume": _cmd_consume,
        "verify": _cmd_verify,
        "status": _cmd_status,
        "anchor": _cmd_anchor,
        "enable-audit-signing": _cmd_enable_audit_signing,
    }
    try:
        return handlers[args.command](args)
    except OpsError as error:
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": args.command,
                "ok": False,
                "overall": "fail",
                "error": str(error),
            }
        )
        return 1
    except Exception as error:  # Kernel integrity/trust failures fail closed.
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": args.command,
                "ok": False,
                "overall": "fail",
                "error": f"{type(error).__name__}: {error}",
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
