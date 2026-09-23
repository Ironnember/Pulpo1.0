# custody-service/tests/test_utils.py
import shutil
from pathlib import Path

def _try_unlink(path):
    """
    Remove a file or directory if it exists. Silently ignore missing paths.
    Works for files and directories.
    """
    p = Path(path)
    try:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    except PermissionError:
        # On Windows, sometimes files are locked briefly; ignore here for tests.
        return
