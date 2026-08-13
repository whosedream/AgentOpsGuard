import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


def _upgrade(db_path: Path, revision: str) -> None:
    env = {**os.environ, "AGENTOPS_DATABASE_URL": f"sqlite:///{db_path.as_posix()}"}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_alembic_upgrade_from_identity_schema_creates_bound_credentials(
    tmp_path: Path,
):
    db_path = tmp_path / "migration.sqlite3"
    _upgrade(db_path, "0004_identity_rbac")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    assert "service_credentials" not in inspect(engine).get_table_names()

    _upgrade(db_path, "head")
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("service_credentials")}
    assert columns == {
        "credential_ref",
        "project_id",
        "name",
        "encrypted_secret",
        "binding_ciphertext",
        "provider",
        "tool",
        "origin",
        "injection_field",
        "credential_scope",
        "allowed_actor_ids",
        "status",
        "version",
        "last_used_at",
        "revoked_at",
        "created_at",
        "updated_at",
    }
    assert inspector.get_pk_constraint("service_credentials")["constrained_columns"] == [
        "credential_ref"
    ]
    assert {
        (foreign_key["constrained_columns"][0], foreign_key["referred_table"])
        for foreign_key in inspector.get_foreign_keys("service_credentials")
    } == {("project_id", "projects")}
    assert {
        index["name"] for index in inspector.get_indexes("service_credentials")
    } == {
        "ix_service_credentials_project_id",
        "ix_service_credentials_status",
    }
    with engine.connect() as connection:
        version = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    assert version == "0005_service_credentials"
