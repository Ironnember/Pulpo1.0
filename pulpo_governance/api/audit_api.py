from fastapi import APIRouter, Body
from typing import Any, Dict, List
from pathlib import Path
import json
import logging
import threading

router = APIRouter(prefix="/audit")

# logging
log = logging.getLogger("pulpo.audit")
if not log.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)
log.setLevel(logging.INFO)

# in-memory audit chain and lock for thread-safety
AUDIT_CHAIN: List[Dict[str, Any]] = []
_CHAIN_LOCK = threading.Lock()

# file for durable append (ndjson)
AUDIT_FILE = Path("audit_chain.ndjson")

def _append_to_file(record: Dict[str, Any]) -> None:
    try:
        with AUDIT_FILE.open("a", encoding="utf8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception as e:
        log.exception("Failed to persist audit record to file: %s", e)

def _load_from_file() -> None:
    if not AUDIT_FILE.exists():
        return
    try:
        with AUDIT_FILE.open("r", encoding="utf8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    AUDIT_CHAIN.append(rec)
                except Exception:
                    log.exception("Skipping malformed audit line")
    except Exception:
        log.exception("Failed to load audit file on startup")

# load persisted records at import time (so chain survives restarts)
_load_from_file()

@router.get("/chain")
def get_chain():
    """Return the current in-memory audit chain."""
    with _CHAIN_LOCK:
        return {"chain": AUDIT_CHAIN}

@router.post("/record")
def post_record(record: Dict[str, Any] = Body(...)):
    """
    Validate and persist an audit record.
    - If a record with the same id exists, update it.
    - Otherwise append as new.
    - Persist each accepted record to audit_chain.ndjson.
    """
    required = ("id", "capability", "worker", "result_hash", "timestamp")
    if not all(k in record for k in required):
        log.warning("Rejected audit record missing required fields: %s", record)
        return {"ok": False, "reason": "missing_fields"}

    with _CHAIN_LOCK:
        # update existing record if id matches
        for i, r in enumerate(AUDIT_CHAIN):
            if r.get("id") == record.get("id"):
                AUDIT_CHAIN[i] = record
                log.info("Updated audit record id=%s", record.get("id"))
                _append_to_file(record)
                return {"ok": True, "record": record}

        # append new record
        AUDIT_CHAIN.append(record)
        log.info("Appended new audit record id=%s", record.get("id"))
        _append_to_file(record)
        return {"ok": True, "record": record}

@router.post("/clear")
def clear_chain():
    """Clear the in-memory chain. Does not delete the ndjson file."""
    with _CHAIN_LOCK:
        AUDIT_CHAIN.clear()
    log.info("Cleared in-memory audit chain")
    return {"ok": True}

@router.get("/health")
def health():
    """Simple health check for the audit API."""
    return {"ok": True, "chain_length": len(AUDIT_CHAIN)}
