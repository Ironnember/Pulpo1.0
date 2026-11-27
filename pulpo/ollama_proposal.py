"""Local inference and untrusted proposal parsing; no authority or execution.

Uses only Ollama's existing HTTP inference API. No SDK fork, model management,
environment-selected host, proxy, credentials, retries, tools or state writer.
The local daemon is trusted here: loopback and metadata are not egress custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import re

from .mcp_boundary import MCPReadSnapshot, PulpoMCPProjection


class LocalProposalError(ValueError):
    """A local inference or untrusted proposal did not meet the input contract."""


MAX_RESPONSE_BYTES = 65_536
MAX_PROPOSAL_BYTES = 4_096
PROPOSAL_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string"},
        "resource": {"type": "string"},
        "cost": {"type": "integer", "minimum": 0},
    },
    "required": ["action", "resource", "cost"],
    "additionalProperties": False,
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LocalProposalError("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise LocalProposalError("nonfinite_json")


def _decode(encoded: bytes, limit: int):
    if type(encoded) is not bytes or not encoded or len(encoded) > limit:
        raise LocalProposalError("response_size_invalid")
    try:
        return json.loads(encoded.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise LocalProposalError("json_invalid") from exc


def _text(value, maximum=256):
    if (type(value) is not str or not value or value != value.strip()
            or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise LocalProposalError("text_invalid")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise LocalProposalError("text_invalid") from exc
    return value


@dataclass(frozen=True, slots=True)
class LocalModel:
    """Operator-selected model identity, not a grant or a signed attestation."""

    name: str
    digest: str

    def __post_init__(self):
        _text(self.name)
        if (not re.fullmatch(r"[A-Za-z0-9_.:/-]+", self.name)
                or "cloud" in self.name.lower() or ":" not in self.name
                or "://" in self.name):
            raise LocalProposalError("local_model_name_invalid")
        if type(self.digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise LocalProposalError("local_model_digest_invalid")


def _request(method: str, path: str, payload=None):
    # HTTPConnection does not consult proxy/auth environment variables and
    # does not follow redirects. Never substitute a URL supplied by the model.
    if (method, path) not in {("GET", "/api/tags"), ("POST", "/api/show"), ("POST", "/api/chat")}:
        raise LocalProposalError("local_endpoint_rejected")
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=45)
    try:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        connection.request(method, path, body=body,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise LocalProposalError("local_http_status")
        if response.getheader("Content-Encoding", "identity") != "identity":
            raise LocalProposalError("response_encoding_invalid")
        declared = response.getheader("Content-Length")
        if declared is not None:
            if not re.fullmatch(r"[0-9]{1,10}", declared) or not 0 < int(declared) <= MAX_RESPONSE_BYTES:
                raise LocalProposalError("response_size_invalid")
        encoded = response.read(MAX_RESPONSE_BYTES + 1)
        if declared is not None and len(encoded) != int(declared):
            raise LocalProposalError("response_incomplete")
        value = _decode(encoded, MAX_RESPONSE_BYTES)
        if type(value) is not dict:
            raise LocalProposalError("response_object_required")
        return value
    except (OSError, http.client.HTTPException) as exc:
        # An inference timeout is not retried and creates no execution right.
        raise LocalProposalError("local_inference_unavailable") from exc
    finally:
        connection.close()


def request_local_proposal(prompt: str, model: LocalModel) -> str:
    """Generate one bounded proposal string using an already installed model.

    This function sends the caller-supplied prompt to the existing daemon.
    Supply only data already permitted for model context. No files are read.
    A compromised daemon, changed model after preflight, daemon egress, process
    isolation, and direct API bypass remain outside this software contract.
    """
    if type(model) is not LocalModel:
        raise LocalProposalError("local_model_required")
    _text(prompt, 4_096)
    tags = _request("GET", "/api/tags")
    models = tags.get("models")
    if type(models) is not list:
        raise LocalProposalError("local_model_unavailable")
    matches = [item for item in models if type(item) is dict and item.get("name") == model.name]
    if len(matches) != 1 or matches[0].get("digest") != model.digest:
        raise LocalProposalError("local_model_identity_mismatch")
    details = _request("POST", "/api/show", {"model": model.name})
    if details.get("remote_model") or details.get("remote_host"):
        raise LocalProposalError("remote_model_rejected")
    response = _request("POST", "/api/chat", {
        "model": model.name,
        "messages": [
            {"role": "system", "content": "Return only a JSON action proposal with action, resource, cost. "
             "You cannot authorize or execute anything. Identity and session are supplied separately."},
            {"role": "user", "content": prompt},
        ],
        "format": PROPOSAL_SCHEMA,
        "stream": False,
        "keep_alive": 0,
        "options": {"temperature": 0, "seed": 0, "num_predict": 128, "num_ctx": 1024},
    })
    message = response.get("message")
    if (response.get("model") != model.name or response.get("done") is not True
            or response.get("done_reason") != "stop" or type(message) is not dict
            or message.get("role") != "assistant" or message.get("tool_calls")
            or type(message.get("content")) is not str):
        raise LocalProposalError("inference_response_incomplete_or_substituted")
    content = message["content"]
    # Validate before returning. JSON/schema output alone is not authority.
    _proposal_fields(content)
    return content


def _proposal_fields(content: str):
    if type(content) is not str:
        raise LocalProposalError("proposal_text_required")
    try:
        encoded = content.encode("utf-8")
    except UnicodeError as exc:
        raise LocalProposalError("json_invalid") from exc
    value = _decode(encoded, MAX_PROPOSAL_BYTES)
    if type(value) is not dict or set(value) != {"action", "resource", "cost"}:
        raise LocalProposalError("proposal_fields_invalid")
    _text(value["action"])
    _text(value["resource"])
    if type(value["cost"]) is not int or not 0 <= value["cost"] <= 2**31 - 1:
        raise LocalProposalError("proposal_cost_invalid")
    return value


def project_local_proposal(content: str, snapshot: MCPReadSnapshot, *,
                           principal: str, session_id: str, target_id: str):
    """Reuse the existing ephemeral projection. Identity comes from the caller.

    The caller must establish identity independently of model output. This
    function neither authenticates that caller nor evaluates policy. Nothing is
    locked, issued, reserved, consumed, reconciled or executed here.
    """
    value = _proposal_fields(content)
    return PulpoMCPProjection(snapshot).propose_intent(
        target_id, principal, value["action"], value["resource"], value["cost"], session_id,
    )
