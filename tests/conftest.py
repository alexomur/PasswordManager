from __future__ import annotations
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pwman  # noqa


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "db.json"


@pytest.fixture
def store(tmp_db: Path):
    return pwman.PasswordStore(pwman.JsonStorage(tmp_db))


def run_cli(args: list[str], db: Path):
    import subprocess, sys as _sys
    cmd = [_sys.executable, str(PROJECT_ROOT / "pwman.py"), *args, "--db", str(db)]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))
