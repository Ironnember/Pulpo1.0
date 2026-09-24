"""Fused Triton SHA-256 kernel for independent audit-record hashing.

Each Triton lane hashes one record. The 64 compression rounds and all message
blocks execute inside one accelerator kernel instead of thousands of eager
PyTorch launches. ROCm PyTorch and CUDA PyTorch both use the cuda tensor API.
"""
from __future__ import annotations

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
        block_count_ptr,
        output_ptr,
        count,
        STRIDE: _tl.constexpr,
        MAX_BLOCKS: _tl.constexpr,
        BLOCK: _tl.constexpr,
    ):
        rows = _tl.program_id(0) * BLOCK + _tl.arange(0, BLOCK)
        valid = rows < count
        row_blocks = _tl.load(block_count_ptr + rows, mask=valid, other=0)

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
            base = rows * STRIDE + block_index * 64
            w = []
            for word_index in _tl.static_range(16):
                offset = word_index * 4
                b0 = _tl.load(data_ptr + base + offset, mask=active, other=0).to(_tl.uint32)
                b1 = _tl.load(data_ptr + base + offset + 1, mask=active, other=0).to(_tl.uint32)
                b2 = _tl.load(data_ptr + base + offset + 2, mask=active, other=0).to(_tl.uint32)
                b3 = _tl.load(data_ptr + base + offset + 3, mask=active, other=0).to(_tl.uint32)
                w.append((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

            for word_index in _tl.static_range(16, 64):
                x = w[word_index - 15]
                y = w[word_index - 2]
                s0 = _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)
                s1 = _rotr32(y, 17) ^ _rotr32(y, 19) ^ (y >> 10)
                w.append(w[word_index - 16] + s0 + w[word_index - 7] + s1)

            a, b, c, d = h0, h1, h2, h3
            e, f, g, hh = h4, h5, h6, h7

            for round_index in _tl.static_range(64):
                sum1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
                choose = (e & f) ^ ((~e) & g)
                round_constant = _tl.full((BLOCK,), _SHA256_K[round_index], _tl.uint32)
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
    if not messages:
        return []
    if _triton is None:
        raise RuntimeError(
            "The fused GPU path requires the Triton package supplied by the "
            "CUDA or ROCm PyTorch environment."
        )

    count = len(messages)
    blocks_per_row = [(len(message) + 9 + 63) // 64 for message in messages]
    max_blocks = max(blocks_per_row)
    stride = max_blocks * 64

    host_data = torch.zeros((count, stride), dtype=torch.uint8, pin_memory=True)
    host_blocks = torch.tensor(blocks_per_row, dtype=torch.int32, pin_memory=True)
    for row, message in enumerate(messages):
        row_blocks = blocks_per_row[row]
        padded_size = row_blocks * 64
        if message:
            host_data[row, :len(message)] = torch.tensor(list(message), dtype=torch.uint8)
        host_data[row, len(message)] = 0x80
        bit_length = len(message) * 8
        host_data[row, padded_size - 8:padded_size] = torch.tensor(
            list(bit_length.to_bytes(8, "big")), dtype=torch.uint8
        )

    device = torch.device("cuda")
    data = host_data.to(device, non_blocking=True)
    block_counts = host_blocks.to(device, non_blocking=True)
    output = torch.empty((count, 8), dtype=torch.uint32, device=device)

    block_size = 64
    _sha256_batch_kernel[( _triton.cdiv(count, block_size), )](
        data,
        block_counts,
        output,
        count,
        stride,
        max_blocks,
        block_size,
        num_warps=1,
    )

    words = output.cpu().tolist()
    return ["".join(f"{word:08x}" for word in row) for row in words]
