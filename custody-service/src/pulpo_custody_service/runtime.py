"""Deployment construction for the Hostile Worker V0 custody service.

This runtime is intentionally name.com SANDBOX ONLY. There is no environment
switch that can select the production registrar endpoint. Production execution
requires a later separately authorized code/config transition after the frozen
sandbox and containment proofs pass.

Secrets are read only inside the custody process. The worker receives only the
HTTP API exposed by :mod:`pulpo_custody_service.api`.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import time

from pulpo.authority import AuthorityTrust, Ed25519ApprovalVerifier
from pulpo.commerce import SQLiteBudgetAccount
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.namecom_core import NameComCoreClient, NameComCoreConfig, NameComCoreRegistrarAdapter
from pulpo.namecom_observer import NameComCoreObserver
from pulpo.namecom_proposal import NameComSandboxProposalBuilder
from pulpo.state import SQLiteKernelState

from .api import create_app
from .core import DomainCustodyService


PILOT_MAX_CENTS = 3_000
SANDBOX_PRINCIPAL = "agent:hostile-worker-sandbox-v0"


class RuntimeConfigError(RuntimeError):
    """Trusted runtime configuration is missing or violates the V0 boundary."""


def _required(name: str, environ: dict[str, str]) -> str:
    value = environ.get(name, "")
    if not value:
        raise RuntimeConfigError(f"missing required environment variable: {name}")
    return value


def _hex_secret(name: str, environ: dict[str, str], *, exact_bytes: int | None = None) -> bytes:
    value = _required(name, environ)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeConfigError(f"{name} must be lowercase/uppercase hex") from exc
    if exact_bytes is not None:
        if len(raw) != exact_bytes:
            raise RuntimeConfigError(f"{name} must encode exactly {exact_bytes} bytes")
    elif len(raw) < 32:
        raise RuntimeConfigError(f"{name} must encode at least 32 bytes")
    return raw


def _positive_int(name: str, environ: dict[str, str]) -> int:
    raw = _required(name, environ)
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeConfigError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeConfigError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class RuntimeConfig:
    state_path: Path
    kernel_secret: bytes
    custody_secret: bytes
    authority_public_key: bytes
    authority_id: str
    verifier_id: str
    key_id: str
    deployment_id: str
    max_approval_ttl_ns: int
    budget_cents: int
    owner_ref: str
    namecom_username: str
    namecom_executor_token: str
    namecom_observer_token: str

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "RuntimeConfig":
        env = dict(os.environ if environ is None else environ)
        state_path = Path(_required("PULPO_CUSTODY_STATE_PATH", env))
        if not state_path.is_absolute():
            raise RuntimeConfigError("PULPO_CUSTODY_STATE_PATH must be absolute")

        budget_cents = _positive_int("PULPO_PILOT_BUDGET_CENTS", env)
        if budget_cents > PILOT_MAX_CENTS:
            raise RuntimeConfigError("pilot budget exceeds frozen $30 ceiling")

        ttl_seconds = _positive_int("PULPO_AUTHORITY_MAX_TTL_SECONDS", env)
        if ttl_seconds > 3_600:
            raise RuntimeConfigError("approval TTL exceeds one-hour V0 ceiling")

        owner_ref = _required("PULPO_OWNER_REF", env)
        if not owner_ref.startswith("owner://") or owner_ref == "owner://":
            raise RuntimeConfigError("PULPO_OWNER_REF must be an opaque owner:// reference")

        username = _required("NAMECOM_SANDBOX_USERNAME", env)
        if not username.endswith("-test"):
            raise RuntimeConfigError("NAMECOM_SANDBOX_USERNAME must end in -test")
        executor_token = _required("NAMECOM_SANDBOX_EXECUTOR_TOKEN", env)
        observer_token = _required("NAMECOM_SANDBOX_OBSERVER_TOKEN", env)
        if executor_token == observer_token:
            raise RuntimeConfigError("executor and observer Name.com tokens must be distinct")

        return cls(
            state_path=state_path,
            kernel_secret=_hex_secret("PULPO_KERNEL_SECRET_HEX", env),
            custody_secret=_hex_secret("PULPO_CUSTODY_SECRET_HEX", env),
            authority_public_key=_hex_secret(
                "PULPO_AUTHORITY_PUBLIC_KEY_HEX", env, exact_bytes=32
            ),
            authority_id=_required("PULPO_AUTHORITY_ID", env),
            verifier_id=_required("PULPO_AUTHORITY_VERIFIER_ID", env),
            key_id=_required("PULPO_AUTHORITY_KEY_ID", env),
            deployment_id=_required("PULPO_AUTHORITY_DEPLOYMENT_ID", env),
            max_approval_ttl_ns=ttl_seconds * 1_000_000_000,
            budget_cents=budget_cents,
            owner_ref=owner_ref,
            namecom_username=username,
            namecom_executor_token=executor_token,
            namecom_observer_token=observer_token,
        )


def build_service(config: RuntimeConfig) -> DomainCustodyService:
    """Build one sandbox-only trusted service from custody-side configuration."""

    config.state_path.parent.mkdir(parents=True, exist_ok=True)

    verifier = Ed25519ApprovalVerifier(
        authority_id=config.authority_id,
        verifier_id=config.verifier_id,
        key_id=config.key_id,
        public_key=config.authority_public_key,
    )
    trust = AuthorityTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        deployment_id=config.deployment_id,
        max_approval_ttl_ns=config.max_approval_ttl_ns,
    )
    policy = Policy(
        frozenset({"purchase_domain"}),
        config.budget_cents,
        frozenset({"purchase_domain"}),
        authority_trust=trust,
    )

    def kernel_factory() -> GovernanceKernel:
        state = SQLiteKernelState(config.state_path)
        try:
            return GovernanceKernel(
                policy,
                secret=config.kernel_secret,
                approval_verifier=verifier,
                clock=time.time_ns,
                state=state,
            )
        except Exception:
            state.close()
            raise

    custody = SQLiteGovernanceCustody(
        config.state_path,
        signing_secret=config.custody_secret,
        clock=time.time_ns,
    )
    budget = SQLiteBudgetAccount(
        config.state_path,
        ceiling_cents=config.budget_cents,
    )

    # Hard-coded sandbox construction: production cannot be selected here.
    executor_client = NameComCoreClient(
        NameComCoreConfig(
            config.namecom_username,
            config.namecom_executor_token,
            environment="sandbox",
        )
    )
    observer_client = NameComCoreClient(
        NameComCoreConfig(
            config.namecom_username,
            config.namecom_observer_token,
            environment="sandbox",
        )
    )

    return DomainCustodyService(
        kernel_factory=kernel_factory,
        custody=custody,
        budget=budget,
        registrar=NameComCoreRegistrarAdapter(executor_client),
        observer=NameComCoreObserver(
            custody,
            observer_client,
            owner_ref=config.owner_ref,
            observation_id_prefix="namecom-sandbox-custody",
        ),
        observer_id="observer:namecom-sandbox-custody",
        executor_id="executor:namecom-sandbox-custody",
        proposal_builder=NameComSandboxProposalBuilder(
            observer_client,
            principal=SANDBOX_PRINCIPAL,
            owner_ref=config.owner_ref,
            credential_ref="credential://name-com/sandbox-executor",
            clock=time.time_ns,
        ),
    )


def create_runtime_app(environ: dict[str, str] | None = None):
    return create_app(build_service(RuntimeConfig.from_environ(environ)))
