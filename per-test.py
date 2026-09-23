import time
import sqlite3
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

@pytest.fixture
def tmp_sqlite_db(tmp_path):
    db_path = tmp_path / "custody.sqlite3"
    db_url = f"sqlite:///{db_path}"

    # Example for SQLAlchemy
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine)

    # If you also use raw sqlite3 connections in tests, create one here
    raw_conn = sqlite3.connect(str(db_path))

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

        # dispose SQLAlchemy engine and close pooled connections
        try:
            engine.dispose()
        except Exception:
            pass

        # small delay to allow OS to release handles
        time.sleep(0.05)

        # robust remove with retries
        for _ in range(5):
            try:
                if db_path.exists():
                    db_path.unlink()
                break
            except PermissionError:
                time.sleep(0.05)
