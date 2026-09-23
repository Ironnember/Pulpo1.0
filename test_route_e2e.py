import json
from datetime import datetime, timedelta, timezone
from pulpo_governance.models.permit import Permit
from pulpo_governance.router import route_gpu_task

# registry pointing to the mock worker
registry = {
    "workers": [
        {
            "id": "mock-worker-1",
            "endpoint": "http://127.0.0.1:9001/execute",
            "capabilities": ["gpu_llm_inference"],
            "tags": ["gpu"],
        }
    ]
}

# create a timezone-aware expires_at timestamp (UTC)
expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

permit = Permit(
    id="test-permit-1",
    subject="tester",
    capability="gpu_llm_inference",
    model_id="mock-model",
    max_tokens=100,
    max_calls=1,
    remaining_calls=1,
    max_cost=None,
    expires_at=expires_at,
    allowed_tags=["gpu"],
    used=False,
)

payload = {"prompt": "test from pulpo", "model_id": "mock-model", "max_tokens": 50}

resp = route_gpu_task("gpu_llm_inference", payload, permit, registry)
print(json.dumps(resp, indent=2, default=str))

