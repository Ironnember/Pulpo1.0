"""Worker-side request/poll client for an independent authority service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Callable
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .authority import ApprovalEnvelope, _require_sha256, _require_text


MAX_AUTHORITY_RESPONSE_BYTES = 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class AuthorityApprovalRequest:
    """Exact intent context submitted by a worker; it carries no authority."""

    principal: str
    action: str
    resource: str
    cost: int
    session_id: str
    intent_hash: str
    policy_hash: str
    deployment_id: str
    requested_ttl_ns: int
    schema: str = "pulpo.authority-request.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.principal, "principal"),
            (self.action, "action"),
            (self.resource, "resource"),
            (self.session_id, "session_id"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
            if len(value) > 4_096:
                raise ValueError(f"{field} exceeds the authority request limit")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.policy_hash, "policy_hash")
        if isinstance(self.cost, bool) or not isinstance(self.cost, int) or self.cost < 0:
            raise ValueError("cost must be a non-negative integer")
        if (
            isinstance(self.requested_ttl_ns, bool)
            or not isinstance(self.requested_ttl_ns, int)
            or self.requested_ttl_ns <= 0
        ):
            raise ValueError("requested_ttl_ns must be positive")
        if self.schema != "pulpo.authority-request.v1":
            raise ValueError("unsupported authority request schema")


@dataclass(frozen=True)
class AuthorityPoll:
    status: str
    envelope: ApprovalEnvelope | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"pending", "approved", "denied", "expired"}:
            raise ValueError("unsupported authority poll status")
        if (self.status == "approved") != (self.envelope is not None):
            raise ValueError("only approved polls contain an envelope")


Transport = Callable[[str, str, dict[str, object] | None], dict[str, Any]]


class AuthorityClient:
    """The complete worker-visible authority interface: request and poll."""

    def __init__(self, base_url: str, *, transport: Transport | None = None) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("authority base_url must be an HTTPS origin")
        self._base_url = base_url.rstrip("/")
        self._transport = transport or self._https_transport
        self._opener = build_opener(_NoRedirect())

    def request_approval(self, approval: AuthorityApprovalRequest) -> tuple[str, str]:
        result = self._transport("POST", "/v1/approval-requests", asdict(approval))
        request_id = result.get("request_id")
        approval_url = result.get("approval_url")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("authority returned an invalid request_id")
        if not isinstance(approval_url, str):
            raise ValueError("authority returned an invalid approval_url")
        parsed = urlparse(approval_url)
        if f"{parsed.scheme}://{parsed.netloc}" != self._base_url:
            raise ValueError("authority returned a cross-origin approval_url")
        return request_id, approval_url

    def poll_approval(self, request_id: str) -> AuthorityPoll:
        _require_text(request_id, "request_id")
        result = self._transport("GET", f"/v1/approval-requests/{quote(request_id, safe='')}", None)
        status = result.get("status")
        if not isinstance(status, str):
            raise ValueError("authority returned an invalid status")
        envelope_value = result.get("envelope")
        envelope = ApprovalEnvelope(**envelope_value) if isinstance(envelope_value, dict) else None
        reason = result.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("authority returned an invalid reason")
        return AuthorityPoll(status, envelope, reason)

    def _https_transport(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = Request(
            f"{self._base_url}{path}",
            data=data,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        with self._opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError("authority request failed closed")
            final = urlparse(response.geturl())
            if f"{final.scheme}://{final.netloc}" != self._base_url:
                raise RuntimeError("authority response crossed the pinned origin")
            encoded = response.read(MAX_AUTHORITY_RESPONSE_BYTES + 1)
            if len(encoded) > MAX_AUTHORITY_RESPONSE_BYTES:
                raise RuntimeError("authority response exceeded the size limit")
            value = json.loads(encoded)
        if not isinstance(value, dict):
            raise ValueError("authority returned a non-object response")
        return value
