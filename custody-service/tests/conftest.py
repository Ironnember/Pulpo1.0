# custody-service/tests/conftest.py
import time
import gc
import sqlite3
from pathlib import Path
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session

def _try_unlink(path: Path, retries: int = 8, delay: float = 0.05):
    for _ in range(retries):
        try:
            if path.exists():
                path.unlink()
            return True
        except PermissionError:
            time.sleep(delay)
    return False

@pytest.fixture
def tmp_sqlite_db(tmp_path):
    db_path = tmp_path / "custody.sqlite3"
    db_url = f"sqlite:///{db_path}"

    # SQLAlchemy engine (allow cross-thread if tests spawn threads)
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionFactory = sessionmaker(bind=engine)
    Session = scoped_session(SessionFactory)

    # raw sqlite3 connection if tests need it
    raw_conn = sqlite3.connect(str(db_path))

    # Prefer DELETE journal mode to avoid WAL files on Windows
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=DELETE"))
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
        # close raw sqlite3 connection
        try:
            raw_conn.close()
        except Exception:
            pass

        # remove SQLAlchemy sessions and dispose engine
        try:
            Session.remove()
        except Exception:
            pass

        try:
            engine.dispose()
        except Exception:
            pass

        # force GC and short delay to let OS release handles
        gc.collect()
        time.sleep(0.05)

        # remove DB and journal files with retries
        _try_unlink(db_path)
        _try_unlink(db_path.with_name(db_path.name + "-wal"))
        _try_unlink(db_path.with_name(db_path.name + "-shm"))
