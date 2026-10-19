"""Minimal hostile-worker HTTP surface over the trusted custody service.

The worker may propose only a normalized domain, submit an opaque trusted
proposal commitment with an external approval, and carry an opaque attempt
handle. Full consequential orders are never accepted from the worker surface.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from pulpo.authority import ApprovalEnvelope

from .core import ApprovalChallenge, AttemptHandle, DomainCustodyService, ServiceRejected


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    approval_id: str = Field(min_length=1, max_length=4_096)
    authority_id: str = Field(min_length=1, max_length=4_096)
    verifier_id: str = Field(min_length=1, max_length=4_096)
    key_id: str = Field(min_length=1, max_length=4_096)
    deployment_id: str = Field(min_length=1, max_length=4_096)
    trust_hash: str = Field(min_length=64, max_length=64)
    session_id: str = Field(min_length=1, max_length=4_096)
    principal: str = Field(min_length=1, max_length=4_096)
    intent_hash: str = Field(min_length=64, max_length=64)
    policy_hash: str = Field(min_length=64, max_length=64)
    nonce: str = Field(min_length=1, max_length=4_096)
    issued_at_ns: StrictInt
    expires_at_ns: StrictInt
    signature: str = Field(min_length=1, max_length=8_192)
    approval_schema: str = Field(
        default="pulpo.approval.v2",
        alias="schema",
        serialization_alias="schema",
    )

    def to_envelope(self) -> ApprovalEnvelope:
        return ApprovalEnvelope(**self.model_dump(by_alias=True))


class DomainProposalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=3, max_length=253)


class AuthorizeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_commitment_id: str = Field(min_length=1, max_length=4_096)
    approval: ApprovalBody | None = None


class HandleBody(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    attempt_id: str = Field(min_length=1, max_length=4_096)
    order_hash: str = Field(min_length=64, max_length=64)
    target_hash: str = Field(min_length=64, max_length=64)
    reservation_id: str = Field(min_length=1, max_length=4_096)
    reserved_cents: StrictInt
    state: str = Field(min_length=1, max_length=128)
    handle_schema: str = Field(
        default="pulpo.custody-attempt-handle.v0",
        alias="schema",
        serialization_alias="schema",
    )

    def to_handle(self) -> AttemptHandle:
        return AttemptHandle(**self.model_dump(by_alias=True))


class AttemptOperationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    handle: HandleBody


def _handle_payload(handle: AttemptHandle) -> dict[str, object]:
    return {
        "attempt_id": handle.attempt_id,
        "order_hash": handle.order_hash,
        "target_hash": handle.target_hash,
        "reservation_id": handle.reservation_id,
        "reserved_cents": handle.reserved_cents,
        "state": handle.state,
        "schema": handle.schema,
    }


def _challenge_payload(challenge: ApprovalChallenge) -> dict[str, object]:
    return {
        "schema": challenge.schema,
        "target_id": challenge.target_id,
        "target_hash": challenge.target_hash,
        "principal": challenge.principal,
        "action": challenge.action,
        "resource": challenge.resource,
        "cost": challenge.cost,
        "session_id": challenge.session_id,
        "intent_hash": challenge.intent_hash,
        "policy_hash": challenge.policy_hash,
        "deployment_id": challenge.deployment_id,
        "requested_ttl_ns": challenge.requested_ttl_ns,
        "approval_required": challenge.approval_required,
        "authority_request": challenge.authority_request(),
        "authority_effect": "none",
    }


def create_app(service: DomainCustodyService) -> FastAPI:
    app = FastAPI(
        title="Pulpo Hostile Worker Custody V0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "authority_effect": "none"}

    @app.post("/v1/domain-proposals")
    def prepare_domain_proposal(body: DomainProposalBody) -> dict[str, object]:
        try:
            proposal, commitment, challenge = service.prepare_proposal(body.domain)
        except (ValueError, ServiceRejected) as exc:
            raise HTTPException(status_code=403, detail="domain proposal rejected") from exc
        return {
            "schema": proposal.schema,
            "proposal_commitment": asdict(commitment),
            "availability_hash": proposal.availability_hash,
            "observed_at_ns": proposal.observed_at_ns,
            "expires_at_ns": proposal.expires_at_ns,
            # Read-only display material. The worker cannot submit these bytes
            # back as authority; authorization accepts only the commitment ref.
            "request": asdict(proposal.request),
            "quote": asdict(proposal.quote),
            "order": asdict(proposal.order),
            "approval_challenge": _challenge_payload(challenge),
            "authority_effect": "none",
        }

    @app.post("/v1/domain-attempts")
    def authorize(body: AuthorizeBody) -> dict[str, object]:
        try:
            handle = service.authorize_commitment(
                body.proposal_commitment_id,
                approval=body.approval.to_envelope() if body.approval else None,
            )
        except (ValueError, ServiceRejected) as exc:
            raise HTTPException(status_code=403, detail="custody authorization rejected") from exc
        return _handle_payload(handle)

    @app.post("/v1/domain-attempts/{attempt_id}/execute")
    def execute(attempt_id: str, body: AttemptOperationBody) -> dict[str, object]:
        handle = body.handle.to_handle()
        if attempt_id != handle.attempt_id:
            raise HTTPException(status_code=400, detail="attempt reference mismatch")
        try:
            claim = service.execute(handle)
            status = service.status(attempt_id)
        except (ValueError, ServiceRejected) as exc:
            raise HTTPException(status_code=409, detail="execution rejected") from exc
        if claim is None:
            return {
                "status": "reconciliation_required",
                "attempt_state": status["state"],
            }
        return {
            "status": "provider_claim_recorded",
            "claim_hash": claim.claim_hash,
            "preflight_hash": claim.preflight_hash,
            "attempt_state": status["state"],
        }

    @app.post("/v1/domain-attempts/{attempt_id}/reconcile")
    def reconcile(attempt_id: str, body: AttemptOperationBody) -> dict[str, object]:
        handle = body.handle.to_handle()
        if attempt_id != handle.attempt_id:
            raise HTTPException(status_code=400, detail="attempt reference mismatch")
        try:
            result = service.reconcile(handle)
            status = service.status(attempt_id)
        except (ValueError, ServiceRejected) as exc:
            raise HTTPException(status_code=409, detail="reconciliation rejected") from exc
        return {
            "outcome": result.outcome,
            "reason": result.reason,
            "observation_hash": result.observation_hash,
            "attempt_state": status["state"],
            "governance_epoch": status["governance_epoch"],
            "governance_state_root": status["governance_state_root"],
            "pending_evidence_obligations": status["pending_evidence_obligations"],
        }

    @app.get("/v1/domain-attempts/{attempt_id}")
    def status(attempt_id: str) -> dict[str, object]:
        try:
            return service.status(attempt_id)
        except ServiceRejected as exc:
            raise HTTPException(status_code=404, detail="unknown attempt") from exc

    return app
