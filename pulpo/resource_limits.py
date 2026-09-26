"""Fail-closed structural limits for untrusted JSON inputs.

Byte caps must be enforced before calling this parser when data comes from a
stream. These checks bound parser structure after decoding so deeply nested or
high-cardinality JSON cannot become an unbounded memory/CPU surface.
"""

from __future__ import annotations

import json
from typing import Any


class ResourceLimitError(ValueError):
    """Untrusted input exceeded a frozen resource bound."""


def load_bounded_json(
    data: bytes | bytearray | str,
    *,
    max_bytes: int,
    max_depth: int = 24,
    max_items: int = 4_096,
    max_string_chars: int = 262_144,
) -> Any:
    if min(max_bytes, max_depth, max_items, max_string_chars) <= 0:
        raise ValueError("resource limits must be positive")
    if isinstance(data, str):
        byte_length = len(data.encode("utf-8"))
    elif isinstance(data, (bytes, bytearray)):
        byte_length = len(data)
    else:
        raise TypeError("JSON input must be bytes or text")
    if byte_length > max_bytes:
        raise ResourceLimitError("json_byte_limit_exceeded")

    value = json.loads(data)
    stack: list[tuple[object, int]] = [(value, 1)]
    item_count = 0
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ResourceLimitError("json_depth_limit_exceeded")
        if isinstance(current, dict):
            item_count += len(current)
            if item_count > max_items:
                raise ResourceLimitError("json_item_limit_exceeded")
            for key, child in current.items():
                if len(key) > max_string_chars:
                    raise ResourceLimitError("json_string_limit_exceeded")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            item_count += len(current)
            if item_count > max_items:
                raise ResourceLimitError("json_item_limit_exceeded")
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str) and len(current) > max_string_chars:
            raise ResourceLimitError("json_string_limit_exceeded")
    return value
