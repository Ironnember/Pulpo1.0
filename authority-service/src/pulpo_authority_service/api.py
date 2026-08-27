"""Minimal HTTP surface: worker request/poll plus human assertion ceremony."""

from __future__ import annotations

from base64 import urlsafe_b64encode

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .core import ApprovalRequest, AuthorityService
from .human_ui import APPROVAL_JAVASCRIPT, SECURITY_HEADERS, render_approval_page


class RequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    principal: str = Field(min_length=1, max_length=4_096)
    action: str = Field(min_length=1, max_length=4_096)
    resource: str = Field(min_length=1, max_length=4_096)
    cost: StrictInt
    session_id: str = Field(min_length=1, max_length=4_096)
    intent_hash: str = Field(min_length=64, max_length=64)
    policy_hash: str = Field(min_length=64, max_length=64)
    deployment_id: str = Field(min_length=1, max_length=4_096)
    requested_ttl_ns: StrictInt
    request_schema: str = Field(
        default="pulpo.authority-request.v1",
        alias="schema",
        serialization_alias="schema",
    )


class AssertionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(min_length=1, max_length=4_096)
    assertion: str = Field(min_length=1, max_length=131_072)


def create_app(service: AuthorityService) -> FastAPI:
    app = FastAPI(
        title="Pulpo Independent Authority",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.post("/v1/approval-requests")
    def request_approval(body: RequestBody) -> dict[str, str]:
        try:
            request_id, approval_url = service.request_approval(
                ApprovalRequest(**body.model_dump(by_alias=True))
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail="approval request rejected") from exc
        return {"request_id": request_id, "approval_url": approval_url}

    @app.get("/v1/approval-requests/{request_id}")
    def poll_approval(request_id: str) -> dict[str, object]:
        try:
            return service.poll(request_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="authority unavailable") from exc

    @app.get("/human/approval.js", response_class=Response)
    def approval_javascript() -> Response:
        return Response(
            APPROVAL_JAVASCRIPT,
            media_type="application/javascript",
            headers=SECURITY_HEADERS,
        )

    @app.get("/human/approval/{request_id}", response_class=HTMLResponse)
    def display_approval(request_id: str) -> HTMLResponse:
        try:
            display = service.display(request_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="authority unavailable") from exc
        return HTMLResponse(render_approval_page(display), headers=SECURITY_HEADERS)

    @app.post("/human/approval/{request_id}/challenge")
    def begin_approval(request_id: str) -> dict[str, object]:
        try:
            challenge = service.challenge(request_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="approval request unavailable") from exc
        encoded = urlsafe_b64encode(challenge).rstrip(b"=").decode()
        return {
            "challenge": encoded,
            "rp_id": service.config.rp_id,
            "credential_selection": "discoverable",
            "user_verification": "required",
            "hints": ["security-key"],
        }

    @app.post("/human/approval/{request_id}/assertion")
    def complete_approval(request_id: str, body: AssertionBody) -> dict[str, str]:
        try:
            envelope = service.approve(request_id, body.credential_id, body.assertion)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=403, detail="human verification rejected") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="approval failed closed") from exc
        return {"status": "approved", "envelope_hash": envelope.envelope_hash}

    return app
