# (paste the conftest.py content here)
# custody-service/tests/conftest.py
import tempfile
from pathlib import Path
import sqlite3
import pytest

# existing helpers (if any) should remain here

@pytest.fixture
def tmp_sqlite_db(tmp_path):
    """
    Create a temporary sqlite3 file and yield its path as a string.
    Ensures the file is closed and removed after the test.
    """
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    # close the low-level fd; tests will open via sqlite3 or other code
    try:
        Path(path).unlink(missing_ok=True)  # ensure clean start
    except Exception:
        pass
    # create an empty sqlite DB file so code that expects it exists will work
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL;")  # match tests that expect -wal/-shm files
    conn.commit()
    conn.close()

    yield path

    # teardown: ensure DB file and WAL/SHM are removed
    try:
        Path(path).unlink(missing_ok=True)
        Path(f"{path}-wal").unlink(missing_ok=True)
        Path(f"{path}-shm").unlink(missing_ok=True)
    except Exception:
        # ignore permission errors during cleanup on Windows
        pass
