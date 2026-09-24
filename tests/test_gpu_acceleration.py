import pytest

from pulpo.gpu_acceleration import (
    cpu_record_hashes,
    verify_audit_gpu,
)


def make_record(index: int, previous_hash: str) -> dict:
    body = {
        "event": "benchmark_seed",
        "payload": {"index": index, "authority_effect": "none"},
        "previous_hash": previous_hash,
        "timestamp_ns": 1_000_000_000 + index,
    }
    from hashlib import sha256
    import json

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "hash": sha256(canonical).hexdigest()}


def make_chain(count: int) -> list[dict]:
    records = []
    previous = "0" * 64
    for index in range(count):
        record = make_record(index, previous)
        records.append(record)
        previous = record["hash"]
    return records


def test_cpu_hash_reference_matches_stored_hashes():
    records = make_chain(32)
    assert cpu_record_hashes(records) == [record["hash"] for record in records]


def test_gpu_verifier_requires_cuda():
    import torch

    records = make_chain(2)
    if torch.cuda.is_available():
        assert verify_audit_gpu(records)
    else:
        with pytest.raises(RuntimeError, match="CUDA is not available"):
            verify_audit_gpu(records)


def test_gpu_verifier_rejects_cpu_corruption_without_authority_side_effects():
    import torch

    if not torch.cuda.is_available():
        pytest.skip("CUDA GPU required for GPU-path corruption test")

    records = make_chain(4)
    records[2]["payload"]["index"] = 999
    assert verify_audit_gpu(records) is False
