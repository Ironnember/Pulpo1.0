import pytest

from pulpo.gpu_acceleration import gpu_record_hashes
from pulpo.gpu_triton import triton_record_hashes

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


def test_gpu_verifier_requires_accelerator():
    import torch

    records = make_chain(2)
    if torch.cuda.is_available():
        assert verify_audit_gpu(records)
    else:
        with pytest.raises(RuntimeError, match="No PyTorch GPU runtime is available"):
            verify_audit_gpu(records)


def test_gpu_verifier_rejects_cpu_corruption_without_authority_side_effects():
    import torch

    if not torch.cuda.is_available():
        pytest.skip("CUDA GPU required for GPU-path corruption test")

    records = make_chain(4)
    records[2]["payload"]["index"] = 999
    assert verify_audit_gpu(records) is False

def test_triton_sha256_padding_boundaries():
    import torch
    from hashlib import sha256

    if not torch.cuda.is_available():
        pytest.skip("CUDA or ROCm GPU required for fused-kernel test")

    lengths = [0, 1, 55, 56, 63, 64, 119, 120, 127, 128, 255, 1024]
    messages = [bytes((index % 251 for index in range(length))) for length in lengths]
    assert triton_record_hashes(messages, torch) == [
        sha256(message).hexdigest() for message in messages
    ]


def test_fused_triton_matches_eager_torch_reference():
    import torch

    if not torch.cuda.is_available():
        pytest.skip("CUDA or ROCm GPU required for fused-kernel test")

    records = make_chain(32)
    assert gpu_record_hashes(records, implementation="triton") == gpu_record_hashes(
        records, implementation="torch"
    )


def test_triton_profiled_hashes_report_separate_stages():
    import torch
    from hashlib import sha256
    from pulpo.gpu_triton import triton_record_hashes_profiled

    if not torch.cuda.is_available():
        pytest.skip("CUDA or ROCm GPU required for fused-kernel profiling")

    messages = [b"profile-stage-check", b"a" * 120]
    hashes, timings = triton_record_hashes_profiled(messages, torch)
    assert hashes == [sha256(message).hexdigest() for message in messages]
    assert set(timings) == {
        "host_preparation_ms",
        "host_to_device_ms",
        "kernel_ms",
        "device_to_host_ms",
        "total_ms",
    }
    assert all(value >= 0 for value in timings.values())
