import json
from pathlib import Path
import importlib.util
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def write_ndjson(path, lines):
    with open(path, "w", encoding="utf8") as f:
        for line in lines:
            f.write(line + "\n")

def test_loader_skips_malformed_lines(tmp_path):
    valid = {"id": "ok-1", "capability": "test", "worker": "w1", "result_hash": "h", "timestamp": 1}
    lines = [
        json.dumps(valid),
        '{"id": "bad-1", "capability": "test", "worker": "w1", "result_hash": "h", "timestamp":',
        'not-a-json-line'
    ]

    ndfile = tmp_path / "audit_chain.ndjson"
    write_ndjson(ndfile, lines)

    spec = importlib.util.spec_from_file_location("audit_api_test_target", str(PROJECT_ROOT / "pulpo_governance" / "api" / "audit_api.py"))
    module = importlib.util.module_from_spec(spec)
    module.AUDIT_FILE = ndfile
    sys.modules["audit_api_test_target"] = module
    spec.loader.exec_module(module)

    chain = getattr(module, "AUDIT_CHAIN", None)
    assert chain is not None
    assert any(r.get("id") == "ok-1" for r in chain)
    assert not any(r.get("id") == "bad-1" for r in chain)
