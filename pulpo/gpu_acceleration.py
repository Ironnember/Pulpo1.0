"""Optional PyTorch accelerator support for Pulpo audit integrity verification.

The GPU path accelerates only the embarrassingly-parallel SHA-256 recomputation
of canonical audit-record bodies. CPU-side chain linkage, delta-root linkage,
and the final governance decision remain authoritative.

This module intentionally has no hard dependency on PyTorch. Importing Pulpo
without the optional GPU extra continues to work normally.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Iterable, Sequence


ZERO_HASH = "0" * 64


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def canonical_audit_body(record: dict[str, Any]) -> bytes:
    body = {key: value for key, value in record.items() if key != "hash"}
    return canonical_bytes(body)


def cpu_record_hashes(records: Sequence[dict[str, Any]]) -> list[str]:
    """Reference implementation used for correctness checks and CPU timing."""
    return [sha256(canonical_audit_body(record)).hexdigest() for record in records]


def _sha256_batch_torch(messages: Sequence[bytes], torch: Any, device_name: str) -> list[str]:
    """Compute SHA-256 for many messages in parallel with Torch CUDA tensors.

    The implementation uses int64 lanes with an explicit 32-bit mask because
    Torch does not implement arithmetic for uint32 on all supported builds.
    All state transitions are masked back to the SHA-256 32-bit domain.
    """

    if not messages:
        return []

    device = torch.device(device_name)
    mask = 0xFFFFFFFF

    constants = (
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    )

    h = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    lengths = []
    padded = []
    for message in messages:
        bit_length = len(message) * 8
        pad_length = (55 - len(message)) % 64 + 1
        data = (
            message
            + b"\x80"
            + b"\x00" * (pad_length - 1)
            + bit_length.to_bytes(8, "big")
        )
        lengths.append(len(data))
        padded.append(data)

    max_length = max(lengths)
    host = torch.zeros(
        (len(messages), max_length),
        dtype=torch.uint8,
        pin_memory=True,
    )
    for index, data in enumerate(padded):
        host[index, : len(data)] = torch.tensor(list(data), dtype=torch.uint8)

    data = host.to(device, non_blocking=True)
    del host

    def rotr(value: Any, amount: int) -> Any:
        return ((value >> amount) | ((value << (32 - amount)) & mask)) & mask

    state = [torch.full((len(messages),), value, dtype=torch.int64, device=device) for value in h]
    k = torch.tensor(constants, dtype=torch.int64, device=device)

    for block_offset in range(0, max_length, 64):
        block = data[:, block_offset : block_offset + 64]
        w = [
            (
                (block[:, index].to(torch.int64) << 24)
                | (block[:, index + 1].to(torch.int64) << 16)
                | (block[:, index + 2].to(torch.int64) << 8)
                | block[:, index + 3].to(torch.int64)
            )
            for index in range(0, 64, 4)
        ]

        for index in range(16, 64):
            s0 = rotr(w[index - 15], 7) ^ rotr(w[index - 15], 18) ^ (w[index - 15] >> 3)
            s1 = rotr(w[index - 2], 17) ^ rotr(w[index - 2], 19) ^ (w[index - 2] >> 10)
            w.append((w[index - 16] + s0 + w[index - 7] + s1) & mask)

        a, b, c, d, e, f, g, hh = state

        for index in range(64):
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + s1 + ch + k[index] + w[index]) & mask
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & mask

            hh = g
            g = f
            f = e
            e = (d + temp1) & mask
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & mask

        state = [
            (state[0] + a) & mask,
            (state[1] + b) & mask,
            (state[2] + c) & mask,
            (state[3] + d) & mask,
            (state[4] + e) & mask,
            (state[5] + f) & mask,
            (state[6] + g) & mask,
            (state[7] + hh) & mask,
        ]

    words = torch.stack(state, dim=1).cpu().tolist()
    return ["".join(f"{value:08x}" for value in row) for row in words]


def gpu_record_hashes(
    records: Sequence[dict[str, Any]],
    *,
    device: str = "auto",
    implementation: str = "triton",
) -> list[str]:
    """Return SHA-256 hashes using fused Triton or eager PyTorch operations."""
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "GPU support requires the optional 'gpu' dependency (PyTorch)."
        ) from exc

    if device not in {"auto", "cuda", "rocm"}:
        raise ValueError("device must be auto, cuda, or rocm")
    if implementation not in {"triton", "torch"}:
        raise ValueError("implementation must be triton or torch")
    if not records:
        return []
    if not torch.cuda.is_available():
        raise RuntimeError("No PyTorch GPU runtime is available; install CUDA or ROCm PyTorch.")
    backend = "rocm" if getattr(torch.version, "hip", None) else "cuda"
    if device != "auto" and device != backend:
        raise RuntimeError(f"Requested {device}, but installed PyTorch backend is {backend}")
    messages = [canonical_audit_body(record) for record in records]
    if implementation == "torch":
        return _sha256_batch_torch(messages, torch, "cuda")
    from pulpo.gpu_triton import triton_record_hashes
    return triton_record_hashes(messages, torch)


def verify_audit_gpu(
    records: Iterable[dict[str, Any]],
    *,
    device: str = "auto",
    implementation: str = "triton",
) -> bool:
    """Verify an audit chain with GPU hash recomputation and CPU linkage checks.

    The GPU never decides whether an audit is authoritative. It recomputes the
    cryptographic record hashes; the CPU verifies previous-hash and delta-root
    linkage and compares every recomputed hash before returning success.
    """

    materialized = list(records)
    if not materialized:
        return True

    recomputed = gpu_record_hashes(materialized, device=device, implementation=implementation)
    previous = ZERO_HASH
    previous_delta_root = ZERO_HASH

    for record, actual_hash in zip(materialized, recomputed):
        if record.get("previous_hash") != previous:
            return False
        if record.get("hash") != actual_hash:
            return False

        body = {key: value for key, value in record.items() if key != "hash"}
        delta = body.get("delta")
        if delta is not None:
            if body.get("previous_delta_root") != previous_delta_root:
                return False
            expected_delta_root = sha256(
                canonical_bytes(
                    {
                        "previous_delta_root": previous_delta_root,
                        "delta": delta,
                    }
                )
            ).hexdigest()
            if body.get("delta_root") != expected_delta_root:
                return False
            previous_delta_root = expected_delta_root
        else:
            previous_delta_root = record["hash"]

        previous = actual_hash

    return True
