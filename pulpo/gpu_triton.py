"""Fused Triton SHA-256 kernel for independent audit-record hashing.

Each Triton lane hashes one record. The 64 compression rounds and all message
blocks execute inside one accelerator kernel instead of thousands of eager
PyTorch launches. ROCm PyTorch and CUDA PyTorch both use the cuda tensor API.
"""
from __future__ import annotations

import sys
from typing import Any, Sequence

_SHA256_K = (
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

try:
    import triton as _triton
    import triton.language as _tl
except ImportError:
    _triton = None
    _tl = None


if _triton is not None:
    @_triton.jit
    def _rotr32(x, shift):
        return (x >> shift) | (x << (32 - shift))

    @_triton.jit
    def _sha256_batch_kernel(
        data_ptr,
        message_offset_ptr,
        message_length_ptr,
        output_ptr,
        count,
        MAX_BLOCKS: _tl.constexpr,
        BLOCK: _tl.constexpr,
        SHA256_K: _tl.constexpr,
    ):
        rows = _tl.program_id(0) * BLOCK + _tl.arange(0, BLOCK)
        valid = rows < count
        message_length = _tl.load(message_length_ptr + rows, mask=valid, other=0)
        message_offset = _tl.load(message_offset_ptr + rows, mask=valid, other=0)
        row_blocks = (message_length + 9 + 63) // 64

        h0 = _tl.full((BLOCK,), 0x6A09E667, _tl.uint32)
        h1 = _tl.full((BLOCK,), 0xBB67AE85, _tl.uint32)
        h2 = _tl.full((BLOCK,), 0x3C6EF372, _tl.uint32)
        h3 = _tl.full((BLOCK,), 0xA54FF53A, _tl.uint32)
        h4 = _tl.full((BLOCK,), 0x510E527F, _tl.uint32)
        h5 = _tl.full((BLOCK,), 0x9B05688C, _tl.uint32)
        h6 = _tl.full((BLOCK,), 0x1F83D9AB, _tl.uint32)
        h7 = _tl.full((BLOCK,), 0x5BE0CD19, _tl.uint32)

        for block_index in range(MAX_BLOCKS):
            active = valid & (block_index < row_blocks)
            local_base = block_index * 64
            padded_length = row_blocks * 64
            w = ()
            for word_index in _tl.static_range(16):
                offset = word_index * 4
                p0 = local_base + offset
                p1 = p0 + 1
                p2 = p0 + 2
                p3 = p0 + 3
                b0 = _tl.load(data_ptr + message_offset + p0, mask=active & (p0 < message_length), other=0).to(_tl.uint32)
                b1 = _tl.load(data_ptr + message_offset + p1, mask=active & (p1 < message_length), other=0).to(_tl.uint32)
                b2 = _tl.load(data_ptr + message_offset + p2, mask=active & (p2 < message_length), other=0).to(_tl.uint32)
                b3 = _tl.load(data_ptr + message_offset + p3, mask=active & (p3 < message_length), other=0).to(_tl.uint32)
                t0 = _tl.minimum(_tl.maximum(p0 - (padded_length - 8), 0), 7)
                t1 = _tl.minimum(_tl.maximum(p1 - (padded_length - 8), 0), 7)
                t2 = _tl.minimum(_tl.maximum(p2 - (padded_length - 8), 0), 7)
                t3 = _tl.minimum(_tl.maximum(p3 - (padded_length - 8), 0), 7)
                bit_length = message_length * 8
                l0 = (bit_length >> ((7 - t0) * 8)) & 0xFF
                l1 = (bit_length >> ((7 - t1) * 8)) & 0xFF
                l2 = (bit_length >> ((7 - t2) * 8)) & 0xFF
                l3 = (bit_length >> ((7 - t3) * 8)) & 0xFF
                b0 = _tl.where(p0 == message_length, 0x80, b0)
                b1 = _tl.where(p1 == message_length, 0x80, b1)
                b2 = _tl.where(p2 == message_length, 0x80, b2)
                b3 = _tl.where(p3 == message_length, 0x80, b3)
                b0 = _tl.where(p0 >= padded_length - 8, l0, b0)
                b1 = _tl.where(p1 >= padded_length - 8, l1, b1)
                b2 = _tl.where(p2 >= padded_length - 8, l2, b2)
                b3 = _tl.where(p3 >= padded_length - 8, l3, b3)
                b0 = b0.to(_tl.uint32)
                b1 = b1.to(_tl.uint32)
                b2 = b2.to(_tl.uint32)
                b3 = b3.to(_tl.uint32)
                w += ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3,)

            for word_index in _tl.static_range(16, 64):
                x = w[word_index - 15]
                y = w[word_index - 2]
                s0 = _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)
                s1 = _rotr32(y, 17) ^ _rotr32(y, 19) ^ (y >> 10)
                w += (w[word_index - 16] + s0 + w[word_index - 7] + s1,)

            a, b, c, d = h0, h1, h2, h3
            e, f, g, hh = h4, h5, h6, h7

            for round_index in _tl.static_range(64):
                sum1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
                choose = (e & f) ^ ((~e) & g)
                round_constant = _tl.full((BLOCK,), SHA256_K[round_index], _tl.uint32)
                temp1 = hh + sum1 + choose + round_constant + w[round_index]
                sum0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
                majority = (a & b) ^ (a & c) ^ (b & c)
                temp2 = sum0 + majority

                hh, g, f, e = g, f, e, d + temp1
                d, c, b, a = c, b, a, temp1 + temp2

            h0 = _tl.where(active, h0 + a, h0)
            h1 = _tl.where(active, h1 + b, h1)
            h2 = _tl.where(active, h2 + c, h2)
            h3 = _tl.where(active, h3 + d, h3)
            h4 = _tl.where(active, h4 + e, h4)
            h5 = _tl.where(active, h5 + f, h5)
            h6 = _tl.where(active, h6 + g, h6)
            h7 = _tl.where(active, h7 + hh, h7)

        _tl.store(output_ptr + rows * 8 + 0, h0, mask=valid)
        _tl.store(output_ptr + rows * 8 + 1, h1, mask=valid)
        _tl.store(output_ptr + rows * 8 + 2, h2, mask=valid)
        _tl.store(output_ptr + rows * 8 + 3, h3, mask=valid)
        _tl.store(output_ptr + rows * 8 + 4, h4, mask=valid)
        _tl.store(output_ptr + rows * 8 + 5, h5, mask=valid)
        _tl.store(output_ptr + rows * 8 + 6, h6, mask=valid)
        _tl.store(output_ptr + rows * 8 + 7, h7, mask=valid)


def triton_record_hashes(messages: Sequence[bytes], torch: Any) -> list[str]:
    """Hash an input batch using one fused Triton kernel."""
    hashes, _ = triton_record_hashes_profiled(messages, torch)
    return hashes


def triton_record_digests(messages: Sequence[bytes], torch: Any) -> bytes:
    """Return concatenated raw 32-byte digests from the fused Triton kernel."""
    digests, _ = triton_record_digests_profiled(messages, torch)
    return digests


def triton_record_hashes_profiled(
    messages: Sequence[bytes], torch: Any
) -> tuple[list[str], dict[str, float]]:
    """Hash messages as hex strings and report all stages including formatting."""
    from time import perf_counter_ns

    raw, timings = triton_record_digests_profiled(messages, torch)
    format_start = perf_counter_ns()
    hashes = [raw[index:index + 32].hex() for index in range(0, len(raw), 32)]
    format_ms = (perf_counter_ns() - format_start) / 1_000_000
    timings["digest_format_ms"] = timings.pop("digest_copy_ms") + format_ms
    timings["total_ms"] += format_ms
    return hashes, timings


def triton_record_digests_profiled(
    messages: Sequence[bytes], torch: Any
) -> tuple[bytes, dict[str, float]]:
    """Hash messages to raw digests, reporting pack, transfer, kernel and copy time."""
    from time import perf_counter_ns

    if not messages:
        return b"", {
            "host_preparation_ms": 0.0,
            "host_to_device_ms": 0.0,
            "kernel_ms": 0.0,
            "device_to_host_ms": 0.0,
            "digest_copy_ms": 0.0,
            "total_ms": 0.0,
        }
    if _triton is None:
        raise RuntimeError(
            "The fused GPU path requires the Triton package supplied by the "
            "CUDA or ROCm PyTorch environment."
        )

    total_start = perf_counter_ns()
    host_start = perf_counter_ns()
    import numpy as np

    count = len(messages)
    message_lengths = np.fromiter(map(len, messages), dtype=np.int64, count=count)
    message_offsets = np.empty(count, dtype=np.int64)
    message_offsets[0] = 0
    if count > 1:
        np.cumsum(message_lengths[:-1], out=message_offsets[1:])
    total_message_bytes = int(message_lengths.sum())
    max_blocks = (int(message_lengths.max()) + 9 + 63) // 64

    # Serialize once into a contiguous pinned buffer. The kernel reads variable
    # length messages directly and synthesizes SHA-256 padding, avoiding a Python
    # loop that copied and padded every row on the host.
    host_data = torch.empty((total_message_bytes,), dtype=torch.uint8, pin_memory=True)
    host_offsets = torch.empty((count,), dtype=torch.int64, pin_memory=True)
    host_lengths = torch.empty((count,), dtype=torch.int64, pin_memory=True)
    memoryview(host_data.numpy()).cast("B")[:] = b"".join(messages)
    host_offsets.numpy()[:] = message_offsets
    host_lengths.numpy()[:] = message_lengths
    device = torch.device("cuda")
    block_size = 64
    output = torch.empty((count, 8), dtype=torch.uint32, device=device)
    host_preparation_ms = (perf_counter_ns() - host_start) / 1_000_000

    transfer_start = perf_counter_ns()
    data = host_data.to(device, non_blocking=True)
    offsets = host_offsets.to(device, non_blocking=True)
    lengths = host_lengths.to(device, non_blocking=True)
    torch.cuda.synchronize()
    host_to_device_ms = (perf_counter_ns() - transfer_start) / 1_000_000

    # Events begin only after host preparation and completed transfers, so this
    # interval measures queued kernel execution rather than host-side idle gaps.
    kernel_start = torch.cuda.Event(enable_timing=True)
    kernel_end = torch.cuda.Event(enable_timing=True)
    kernel_start.record()
    _sha256_batch_kernel[( _triton.cdiv(count, block_size), )](
        data,
        offsets,
        lengths,
        output,
        count,
        max_blocks,
        block_size,
        _SHA256_K,
        num_warps=1,
    )
    kernel_end.record()
    torch.cuda.synchronize()
    kernel_ms = kernel_start.elapsed_time(kernel_end)

    device_to_host_start = perf_counter_ns()
    host_output = output.cpu()
    torch.cuda.synchronize()
    device_to_host_ms = (perf_counter_ns() - device_to_host_start) / 1_000_000

    copy_start = perf_counter_ns()
    host_words = host_output.numpy()
    if sys.byteorder == "little":
        host_words = host_words.byteswap()
    digests = host_words.tobytes()
    digest_copy_ms = (perf_counter_ns() - copy_start) / 1_000_000
    total_ms = (perf_counter_ns() - total_start) / 1_000_000
    return digests, {
        "host_preparation_ms": host_preparation_ms,
        "host_to_device_ms": host_to_device_ms,
        "kernel_ms": kernel_ms,
        "device_to_host_ms": device_to_host_ms,
        "digest_copy_ms": digest_copy_ms,
        "total_ms": total_ms,
    }
