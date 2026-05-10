import os
import subprocess
import sys
from pathlib import Path


def test_alembic_upgrade_head_on_empty_sqlite(tmp_path: Path):
    db_path = tmp_path / "migration.sqlite3"
    env = {**os.environ, "AGENTOPS_DATABASE_URL": f"sqlite:///{db_path.as_posix()}"}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert db_path.exists()

