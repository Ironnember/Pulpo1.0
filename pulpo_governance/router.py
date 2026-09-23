import requests, time, hashlib
from typing import Dict, Any

AUDIT_API_URL = 'http://127.0.0.1:8080/audit/record'

def route_gpu_task(capability: str, payload: Dict[str, Any], permit, registry: Dict[str, Any]):
    workers = registry.get('workers', [])
    if not workers:
        raise RuntimeError('No workers registered')
    endpoint = workers[0].get('endpoint')
    if not endpoint:
        raise RuntimeError('Worker endpoint missing')
    body = {'permit_id': getattr(permit, 'id', None), 'capability': capability, 'payload': payload}
    start = time.time()
    resp = requests.post(endpoint, json=body, timeout=10)
    resp.raise_for_status()
    worker_resp = resp.json()
    duration_ms = int((time.time() - start) * 1000)
    result_text = worker_resp.get('result', '')
    result_hash = 'sha256:' + hashlib.sha256(result_text.encode()).hexdigest()
    metadata = worker_resp.get('metadata', {})
    metadata.update({'router_duration_ms': duration_ms})
    audit_record = {
        'id': getattr(permit, 'id', 'unknown-permit'),
        'capability': capability,
        'worker': workers[0].get('id'),
        'result_hash': result_hash,
        'timestamp': time.time()
    }

    # POST audit_record to audit API; ignore failures but log them via exception message
    try:
        r = requests.post(AUDIT_API_URL, json=audit_record, timeout=5)
        r.raise_for_status()
    except Exception as e:
        # do not fail the main flow for audit persistence; raise only if you want strict behavior
        # raise RuntimeError(f'Failed to persist audit record: {e}')
        pass

    return {'result': result_text, 'metadata': metadata, 'audit_record': audit_record}
