*** Begin Patch
*** Add File: custody-service/tests/conftest.py
+import sqlite3
+import time
+import gc
+from pathlib import Path
+
+import pytest
+from sqlalchemy import create_engine, text
+from sqlalchemy.orm import sessionmaker, scoped_session
+
+
+# helper to unlink with retries (Windows-friendly)
+def _try_unlink(path: Path, attempts: int = 6, base_delay: float = 0.1):
+    for attempt in range(attempts):
+        try:
+            if path.exists():
+                path.unlink(missing_ok=True)
+            return
+        except PermissionError:
+            time.sleep(base_delay * (attempt + 1))
+        except FileNotFoundError:
+            return
+
+
+@pytest.fixture
+def tmp_sqlite_db(tmp_path):
+    """
+    Provide a temporary SQLite database for tests and tear it down safely on Windows.
+
+    Yields a dict with:
+      - db_path: pathlib.Path to the sqlite file
+      - db_url: SQLAlchemy URL string
+      - engine: SQLAlchemy Engine
+      - Session: scoped_session factory
+      - raw_conn: optional sqlite3.Connection (if tests need it)
+    """
+    db_path = tmp_path / "custody.sqlite3"
+    db_url = f"sqlite:///{str(db_path)}"
+
+    # create engine (allow cross-thread if tests spawn threads)
+    engine = create_engine(db_url, connect_args={"check_same_thread": False})
+    SessionFactory = sessionmaker(bind=engine)
+    Session = scoped_session(SessionFactory)
+
+    # optional: raw sqlite3 connection if tests need it
+    raw_conn = sqlite3.connect(str(db_path))
+
+    # Prefer DELETE journal mode to avoid WAL/SHM files on Windows (best-effort)
+    try:
+        with engine.connect() as conn:
+            conn.execute(text("PRAGMA journal_mode=DELETE"))
+            conn.commit()
+    except Exception:
+        # best-effort; continue even if PRAGMA fails
+        pass
+
+    try:
+        yield {
+            "db_path": db_path,
+            "db_url": db_url,
+            "engine": engine,
+            "Session": Session,
+            "raw_conn": raw_conn,
+        }
+    finally:
+        # 1) close raw sqlite3 connection first
+        try:
+            raw_conn.close()
+        except Exception:
+            pass
+
+        # 2) remove scoped sessions (clears thread-local sessions)
+        try:
+            Session.remove()
+        except Exception:
+            pass
+
+        # 3) dispose engine so SQLAlchemy closes pooled connections
+        try:
+            engine.dispose()
+        except Exception:
+            pass
+
+        # 4) force GC and short delay to let OS release handles
+        gc.collect()
+        time.sleep(0.05)
+
+        # 5) remove DB and journal files with retries
+        _try_unlink(Path(str(db_path)))
+        _try_unlink(Path(str(db_path) + "-wal"))
+        _try_unlink(Path(str(db_path) + "-shm"))
+
+        # tmp_path cleanup is handled by pytest automatically
+
*** End Patch


import sqlite3
import tempfile
import time
import gc
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session

# helper to unlink with retries
def _try_unlink(path: Path, attempts: int = 6, base_delay: float = 0.1):
    for attempt in range(attempts):
        try:
            if path.exists():
                path.unlink(missing_ok=True)
            return
        except PermissionError:
            time.sleep(base_delay * (attempt + 1))
        except FileNotFoundError:
            return

@pytest.fixture
def tmp_sqlite_db(tmp_path):
    # prepare paths and DB URL
    db_path = tmp_path / "custody.sqlite3"
    db_url = f"sqlite:///{str(db_path)}"

    # create engine (allow cross-thread if tests spawn threads)
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionFactory = sessionmaker(bind=engine)
    Session = scoped_session(SessionFactory)

    # optional: raw sqlite3 connection if tests need it
    raw_conn = sqlite3.connect(str(db_path))

    # Prefer DELETE journal mode to avoid WAL/SHM files on Windows
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=DELETE"))
            conn.commit()
    except Exception:
        # best-effort; continue even if PRAGMA fails
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
        # 1) close raw sqlite3 connection first
        try:
            raw_conn.close()
        except Exception:
            pass

        # 2) remove scoped sessions (clears thread-local sessions)
        try:
            Session.remove()
        except Exception:
            pass

        # 3) dispose engine so SQLAlchemy closes pooled connections
        try:
            engine.dispose()
        except Exception:
            pass

        # 4) force GC and short delay to let OS release handles
        gc.collect()
        time.sleep(0.05)

        # 5) remove DB and journal files with retries
        _try_unlink(Path(str(db_path)))
        _try_unlink(Path(str(db_path) + "-wal"))
        _try_unlink(Path(str(db_path) + "-shm"))

        # 6) cleanup tmp_path is handled by pytest tmp_path fixture automatically
