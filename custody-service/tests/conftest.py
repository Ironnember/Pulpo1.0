# custody-service/tests/conftest.py
import tempfile
from pathlib import Path
import sqlite3
import os
import pytest

# Try to import SQLAlchemy; if not present, the fixture falls back to sqlite3 connections.
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
except Exception:
    create_engine = None
    sessionmaker = None


def _try_unlink(path):
    """
    Remove a file or directory if it exists. Silently ignore missing paths.
    Works for files and directories.
    """
    p = Path(path)
    try:
        if p.is_dir():
            import shutil
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    except PermissionError:
        # On Windows, sometimes files are locked briefly; ignore here for tests.
        return


@pytest.fixture
def tmp_sqlite_db(tmp_path):
    """
    Provide a mapping expected by tests:
      {
        "db_url": "sqlite:///...path...",
        "db_path": "/abs/path/to/file.sqlite3",
        "engine": <sqlalchemy.Engine> or None,
        "Session": <sqlalchemy.orm.sessionmaker> or a simple callable,
        "raw_conn": a DB-API connection object
      }

    Creates a temporary sqlite file and yields the mapping. Cleans up files on teardown.
    """
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)

    # Ensure a clean file exists and enable WAL so tests that expect -wal/-shm behave similarly.
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.commit()
    finally:
        conn.close()

    db_url = f"sqlite:///{path}"

    engine = None
    Session = None
    raw_conn = None
    if create_engine is not None and sessionmaker is not None:
        # Create SQLAlchemy engine and sessionmaker
        engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Session = sessionmaker(bind=engine)
        # raw_conn as DB-API connection from engine
        try:
            raw_conn = engine.raw_connection()
        except Exception:
            raw_conn = None
    else:
        # Fallback: provide a simple callable that returns a sqlite3.Connection
        def _simple_session_factory():
            return sqlite3.connect(path)
        Session = _simple_session_factory
        raw_conn = sqlite3.connect(path)

    yield {"db_url": db_url, "db_path": path, "engine": engine, "Session": Session, "raw_conn": raw_conn}

    # Teardown: close raw_conn and remove files (ignore permission errors)
    try:
        if raw_conn is not None:
            try:
                raw_conn.close()
            except Exception:
                pass
        _try_unlink(path)
        _try_unlink(f"{path}-wal")
        _try_unlink(f"{path}-shm")
    except Exception:
        pass
