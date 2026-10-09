"""Pure audit calculation shared by the coordinator and isolated interpreters.

Keep this module standard-library-only; it must never import Pulpo writers.
"""
from hashlib import sha256
import json
import sys


def digest_body(key):
    event, payload_json, previous_hash, timestamp_ns = key
    body = {"event": event, "payload": json.loads(payload_json),
            "previous_hash": previous_hash, "timestamp_ns": timestamp_ns}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return sha256(canonical).hexdigest()


if __name__ == "__main__":
    for line in sys.stdin:
        print(json.dumps([digest_body(key) for key in json.loads(line)]), flush=True)
