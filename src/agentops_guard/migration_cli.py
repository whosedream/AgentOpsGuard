from __future__ import annotations

import argparse
from pathlib import Path

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig


DEFAULT_SCANNER_RULE_PACK = Path(
    "policies/scanner/agentdojo-important-instructions-v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner-rule-pack", type=Path, default=DEFAULT_SCANNER_RULE_PACK)
    parser.add_argument("--project-id", default="default")
    args = parser.parse_args()

    alembic_config = AlembicConfig("alembic.ini")
    alembic_command.upgrade(alembic_config, "head")

    from agentops_guard.backend.database import SessionLocal, ensure_schema
    from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack

    ensure_schema(force=True)
    db = SessionLocal()
    try:
        result = install_scanner_rule_pack(
            db,
            project_id=args.project_id,
            path=args.scanner_rule_pack,
        )
        db.commit()
    finally:
        db.close()
    print(
        {
            "status": "ok",
            "scanner_rule_pack": result["pack_id"],
            "revision": result["revision"],
            "pack_sha256": result["pack_sha256"],
            "installed": result["installed"],
            "unchanged": result["unchanged"],
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
