"""Minimal hostile-worker HTTP surface over the trusted custody service."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from pulpo.authority import ApprovalEnvelope
from pulpo.commerce import DomainPurchaseOrder

from .core import AttemptHandle, DomainCustodyService, ServiceRejected


class OrderBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=4_096)
    request_hash: str = Field(min_length=64, max_length=64)
    quote_id: str = Field(min_length=1, max_length=4_096)
    quote_hash: str = Field(min_length=64, max_length=64)
    principal: str = Field(min_length=1, max_length=4_096)
    domain: str = Field(min_length=1, max_length=253)
    registrar: str = Field(min_length=1, max_length=255)
    purchase_price_cents: StrictInt
    renewal_price_cents: StrictInt
    owner_ref: str = Field(min_length=1, max_length=4_096)
    privacy_required: StrictBool
    prohibited_upsells: list[str] = Field(max_length=64)
    credential_ref: str = Field(min_length=1, max_length=4_096)
    expires_at_ns: StrictInt

    def to_order(self) -> DomainPurchaseOrder:
        values = self.model_dump()
        values["prohibited_upsells"] = tuple(values["prohibited_upsells"])
        return DomainPurchaseOrder(**values)


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    schema: str = "pulpo.approval.v2"

    def to_envelope(self) -> ApprovalEnvelope:
        return ApprovalEnvelope(**self.model_dump())


class AuthorizeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order: OrderBody
    approval: ApprovalBody | None = None


class HandleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=1, max_length=4_096)
    order_hash: str = Field(min_length=64, max_length=64)
    target_hash: str = Field(min_length=64, max_length=64)
    reservation_id: str = Field(min_length=1, max_length=4_096)
    reserved_cents: StrictInt
    state: str = Field(min_length=1, max_length=128)
    schema: str = "pulpo.custody-attempt-handle.v0"

    def to_handle(self) -> AttemptHandle:
        return AttemptHandle(**self.model_dump())


class AttemptOperationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    handle: HandleBody
    order: OrderBody


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

    @app.post("/v1/domain-attempts")
    def authorize(body: AuthorizeBody) -> dict[str, object]:
        try:
            handle = service.authorize(
                body.order.to_order(),
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
            claim = service.execute(handle, body.order.to_order())
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
            result = service.reconcile(handle, body.order.to_order())
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
        }

    @app.get("/v1/domain-attempts/{attempt_id}")
    def status(attempt_id: str) -> dict[str, object]:
        try:
            return service.status(attempt_id)
        except ServiceRejected as exc:
            raise HTTPException(status_code=404, detail="unknown attempt") from exc

    return app
