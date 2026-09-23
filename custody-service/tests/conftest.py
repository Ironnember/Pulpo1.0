# custody-service/tests/authority_support.py
from dataclasses import dataclass
import hmac
import hashlib
import json
from typing import Dict, Any, Optional

import sqlite3
import time
import gc
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session


# helper to unlink with retries (Windows-friendly)
def _try_unlink(path: Path, attempts: int = 8, base_delay: float = 0.05) -> bool:
    """
    Try to unlink a file, retrying on PermissionError (Windows file-lock).
    Returns True if removed or not present, False if still locked after retries.
    """
    for attempt in range(attempts):
        try:
            if path.exists():
                path.unlink(missing_ok=True)
            return True
        except PermissionError:
            time.sleep(base_delay * (attempt + 1))
        except FileNotFoundError:
            return True
    return False


@pytest.fixture
def tmp_sqlite_db(tmp_path):
    """
    Provide a temporary SQLite database for tests and tear it down safely on Windows.

    Yields a dict with:
      - db_path: pathlib.Path to the sqlite file
      - db_url: SQLAlchemy URL string
      - engine: SQLAlchemy Engine
      - Session: scoped_session factory
      - raw_conn: optional sqlite3.Connection
    """
    db_path = tmp_path / "custody.sqlite3"
    db_url = f"sqlite:///{str(db_path)}"

    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )
    SessionFactory = sessionmaker(bind=engine)
    Session = scoped_session(SessionFactory)

    raw_conn = sqlite3.connect(str(db_path))

    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=DELETE"))
            conn.commit()
    except Exception:
        pass

    try:
        yield {
            "db_path": db_path,
            "db_url": db_url,
            "engine": engine,
            "Session": Session,
            "raw_conn": raw_conn,
        }
    finally:
        try:
            raw_conn.close()
        except Exception:
            pass

        try:
            Session.remove()
        except Exception:
            pass

        try:
            engine.dispose()
        except Exception:
            pass

        gc.collect()
        time.sleep(0.05)

        _try_unlink(Path(str(db_path)))
        _try_unlink(Path(str(db_path) + "-wal"))
        _try_unlink(Path(str(db_path) + "-shm"))


# Keep the stored key as a JSON-friendly string; encode when signing.
DEFAULT_TEST_KEY = "pulpo-test-key"
DEFAULT_ALGORITHM = "hmac-sha256"

@dataclass
class HmacTestVerifier:
    """
    Minimal dataclass test verifier so dataclasses.asdict() works in tests.
    Stores key as a string so JSON serialization succeeds and includes an
    algorithm field so the kernel's canonicalization matches expectations.
    """
    key: str = DEFAULT_TEST_KEY
    algorithm: str = DEFAULT_ALGORITHM

    def sign(self, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        # Use HMAC-SHA256 for signing (algorithm name kept in algorithm field).
        return hmac.new(self.key.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def signed_envelope(payload: Dict[str, Any], key: Optional[str] = None) -> Dict[str, Any]:
    verifier = HmacTestVerifier(key if key is not None else DEFAULT_TEST_KEY)
    sig = verifier.sign(payload)
    return {"payload": payload, "signature": sig}


def trust_for(verifier: HmacTestVerifier) -> HmacTestVerifier:
    """
    Return the verifier instance (keeps API shape used by tests).
    The important part is that the returned object is a dataclass instance
    with the same canonical fields the kernel expects (algorithm + key).
    """
    return verifier
