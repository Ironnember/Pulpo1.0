"""Operator packaging for a single-action Pulpo deployment.

``pulpo-ops`` (also ``python -m pulpo.ops``) is the deployability surface for
one governed deployment directory. A deployment directory holds exactly two
operator artifacts plus the canonical kernel state:

- ``policy.json`` — the deployment configuration written by ``init``
  (schema ``pulpo.ops-policy.v1``): the single allowed/approval action, the
  cost ceiling, the default session/deployment ids, the pinned authority
  trust (when configured), and the public verifier configuration.
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
the optional external anchor witness described below). The CLI holds no
signing key and no permit secret, never opens ``state.db`` except through
``SQLiteKernelState`` handed to a ``GovernanceKernel``, and never writes
canonical state directly — the only files it writes are its own
``policy.json`` at ``init`` time and permit files at ``authorize`` time,
both outside the audit chain. It is not a second router, executor, ledger,
memory system, or authority plane: approval envelopes are produced by the
external authority, and this tool only presents them to the kernel.
``authorize`` preflights the permits directory (owner-only, provably
writable) before the kernel is opened, so a known-unusable destination
refuses before anything is issued; if the permit write still fails after
issuance, the command fails closed and its report carries the issued
permit string as the recoverable artifact, reconcilable against the audit
chain — the write probe used by the preflight is transient and removed
before issuance.

Anchoring seam: when the sibling ``pulpo.anchor`` module is importable,
``verify`` additionally checks ``anchors.jsonl`` in the deployment
directory (when present) with ``verify_anchored_audit`` and ``status``
reports the last anchor. When it is not importable, those outputs state
plainly that anchoring is not available in this build. This module never
copies or reimplements the anchor code.

What this tool does not do: it does not sign approvals, hold private keys,
execute the permitted consequence, manage multi-action policies, or
provide production key custody. The ``hmac-test`` verifier kind is a
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
import stat
from typing import Any, Sequence

from .authority import (
    ApprovalEnvelope,
    AuthorityTrust,
    Ed25519ApprovalVerifier,
    P256ApprovalVerifier,
)
from .kernel import GovernanceKernel, Intent, Policy
from .state import SQLiteKernelState


POLICY_SCHEMA = "pulpo.ops-policy.v1"
REPORT_SCHEMA = "pulpo.ops.v1"
STATE_FILENAME = "state.db"
POLICY_FILENAME = "policy.json"
PERMITS_DIRNAME = "permits"
# Permit files are bearer artifacts: whoever holds the file can consume the
# permit. They and their directory are therefore owner-only, created
# atomically, and never overwritten (see _write_permit_file).
PERMITS_DIR_MODE = 0o700
PERMIT_FILE_MODE = 0o600
_PROBE_PREFIX = ".write-probe-"
ANCHORS_FILENAME = "anchors.jsonl"
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


def _open_kernel(directory: Path, config: dict[str, Any], *, verifier: Any = None) -> tuple[GovernanceKernel, SQLiteKernelState]:
    state_path, _ = _deployment_paths(directory)
    state = SQLiteKernelState(state_path)
    try:
        kernel = GovernanceKernel(
            _effective_policy(config),
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
        result = anchor_module.verify_anchored_audit(records, anchors, verifier=None)
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
    return {
        "available": True,
        "present": True,
        "last_anchor": {
            "sequence": last.sequence,
            "record_count": last.record_count,
            "head_hash": last.head_hash,
            "timestamp_ns": last.timestamp_ns,
            "anchor_hash": last.anchor_hash,
        },
    }


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
    }

    directory.mkdir(parents=True, exist_ok=True)
    _ensure_permits_dir(directory)
    state = SQLiteKernelState(state_path)
    try:
        # Boot the kernel once so the deployment starts from a verified,
        # empty audit chain. The boot appends nothing; the kernel validates
        # the fresh state and, when a verifier is pinned, its trust match
        # is re-checked by the attribute comparison above and on every
        # later authorize call by the kernel itself.
        kernel = GovernanceKernel(_effective_policy(config), state=state)
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
    # Consume is a state-level one-use check by the kernel; it needs no
    # approval verifier, so the kernel is booted without one. The permit
    # itself was issued and stored by the kernel at authorize time.
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


def _cmd_verify(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    try:
        kernel, state = _open_kernel(directory, config)
    except Exception as error:
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "verify",
                "ok": False,
                "chain_valid": False,
                "error": f"kernel state audit chain is invalid: {error}",
                "anchored": _anchored_check(directory, []),
            }
        )
        return 1
    try:
        records = list(kernel.audit)
        chain_valid = bool(kernel.verify_audit())
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
            "anchored": anchored,
        }
    )
    return 0 if ok else 1


def _cmd_status(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    config = _load_config(directory)
    try:
        kernel, state = _open_kernel(directory, config)
    except Exception as error:
        _emit(
            {
                "schema": REPORT_SCHEMA,
                "command": "status",
                "ok": False,
                "chain_valid": False,
                "error": f"kernel state audit chain is invalid: {error}",
            }
        )
        return 1
    try:
        records = list(kernel.audit)
        chain_valid = bool(kernel.verify_audit())
        policy_hash = kernel.policy_hash
    finally:
        state.close()
    counts = Counter(
        str(record.get("event")) for record in records if isinstance(record, dict)
    )
    event_counts = dict(sorted(counts.items()))
    for required in ("permit_consumed", "permit_rejected", "approval_verified"):
        event_counts.setdefault(required, 0)
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

    args = parser.parse_args(argv)
    handlers = {
        "init": _cmd_init,
        "authorize": _cmd_authorize,
        "consume": _cmd_consume,
        "verify": _cmd_verify,
        "status": _cmd_status,
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
