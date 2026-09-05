#!/usr/bin/env python3
"""Verify historical and current managed scanner rule-pack evidence."""

from __future__ import annotations

import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from evidence_lock_compatibility import assert_compatible_uv_lock


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_REPORT = (
    ROOT / "artifacts" / "benchmarks" / "scanner_rule_pack_regression_v1.json"
)
HISTORICAL_REPORT_SHA256 = (
    "a7734ca6e07481c179c1096377bcc4b65441c5de25b42140d3b6957bbc339fc8"
)
HISTORICAL_PACK_SHA256 = (
    "be792789f55860a9805ac3fb33256b2f7f518b01eeaba3c988ae12ba8f4c732b"
)
PREVIOUS_REPORT = ROOT / "artifacts" / "benchmarks" / "scanner_rule_pack_regression_v2.json"
PREVIOUS_REPORT_SHA256 = "9277686e7330ca44c6cc4134d803a05e5dcd4e005a4716022d89d89a8f158037"
CURRENT_REPORT = ROOT / "artifacts" / "benchmarks" / "scanner_rule_pack_regression_v3.json"
CURRENT_REPORT_SHA256 = "864bd378ca5590e7ef763996189e1bf9205ba0e2d5bcd2d95e01299628f22677"
PACK = ROOT / "policies" / "scanner" / "agentdojo-important-instructions-v1.json"
PACK_SHA256 = "1ebcdf235cf05a73b1c51177b44e3383a054fb42e8e7943886f0d785be48d770"
CORPUS_SHA256 = "9d24ad3ea687ca676def33727c56c8e8676c753ca9b41031a3b9bb6a3e448794"
BENCHMARK = ROOT / "scripts" / "benchmark_scanner_rule_pack.py"
RE2_VERSION = "1.1.20251105"


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _assert_results(report: dict, *, pack_sha256: str) -> None:
    if report.get("rule_pack") != {
        "installed_rules": 1,
        "pack_id": "agentdojo-important-instructions",
        "pack_sha256": pack_sha256,
        "revision": "1.0.0",
    }:
        raise RuntimeError("managed scanner rule-pack identity changed")
    if report.get("dataset") != {
        "selected_corpus_sha256": CORPUS_SHA256,
        "sources": {
            "agentdojo_dynamic_controls": 2,
            "agentdojo_dynamic_templates": 7,
            "agentdojo_legitimate_tasks": 97,
            "llmail_normal_emails": 203,
        },
    }:
        raise RuntimeError("managed scanner rule-pack corpus changed")
    if report.get("attack") != {
        "flagged": 7,
        "rate": 1.0,
        "rows": 7,
        "wilson_95": [0.64567, 1.0],
    }:
        raise RuntimeError("managed scanner rule-pack attack regression changed")
    if report.get("benign") != {
        "flagged": 0,
        "rate": 0.0,
        "rows": 302,
        "wilson_95": [-0.0, 0.01256],
    }:
        raise RuntimeError("managed scanner rule-pack benign regression changed")


def _implementation_paths() -> dict[str, Path]:
    services = ROOT / "src" / "agentops_guard" / "backend" / "services"
    return {
        "benchmark": BENCHMARK,
        "installer": services / "scanner_rule_packs.py",
        "scanner": services / "scanner.py",
        "safe_regex": services / "safe_regex.py",
        "pack": PACK,
        "dynamic_exporter": ROOT / "evals" / "inspect" / "export_agentdojo_dynamic_cases.py",
        "static_exporter": ROOT / "evals" / "inspect" / "export_agentdojo_static_cases.py",
        "inspect_lock": ROOT / "evals" / "inspect" / "uv.lock",
        "root_lock": ROOT / "uv.lock",
    }


def _verify_current_report(report: dict) -> None:
    _assert_results(report, pack_sha256=PACK_SHA256)
    expected_engine = {
        "package": "google-re2",
        "version": RE2_VERSION,
        "official_project": "https://github.com/google/re2",
        "package_index": "https://pypi.org/project/google-re2/",
        "configured_max_memory_bytes": 8 * 1024 * 1024,
    }
    if report.get("metadata", {}).get("regex_engine") != expected_engine:
        raise RuntimeError("managed scanner regex-engine evidence changed")
    if version("google-re2") != RE2_VERSION:
        raise RuntimeError("installed google-re2 version changed")
    lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    if (
        'name = "google-re2"' not in lock_text
        or f'version = "{RE2_VERSION}"' not in lock_text
        or "sha256:809c5fa5d08279413b29c2e2c5c528e85cd94a0e0fd897db595a0c09eeee2782"
        not in lock_text
    ):
        raise RuntimeError("google-re2 dependency is not pinned with a locked artifact hash")
    recorded_hashes = report.get("metadata", {}).get("implementation_sha256")
    paths = _implementation_paths()
    if not isinstance(recorded_hashes, dict) or set(recorded_hashes) != set(paths):
        raise RuntimeError("managed scanner implementation inventory changed")
    for name, path in paths.items():
        actual = _sha256(path)
        expected = recorded_hashes[name]
        if actual == expected:
            continue
        if name == "root_lock":
            assert_compatible_uv_lock(baseline=expected, current=actual)
            continue
        raise RuntimeError(f"managed scanner rule-pack implementation changed: {name}")


def main() -> int:
    if _sha256(HISTORICAL_REPORT) != HISTORICAL_REPORT_SHA256:
        raise RuntimeError("historical managed scanner report SHA-256 changed")
    historical = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
    _assert_results(historical, pack_sha256=HISTORICAL_PACK_SHA256)

    if _sha256(PREVIOUS_REPORT) != PREVIOUS_REPORT_SHA256:
        raise RuntimeError("previous managed scanner report SHA-256 changed")
    previous = json.loads(PREVIOUS_REPORT.read_text(encoding="utf-8"))
    _assert_results(previous, pack_sha256=PACK_SHA256)

    if _sha256(CURRENT_REPORT) != CURRENT_REPORT_SHA256:
        raise RuntimeError("current managed scanner report SHA-256 changed")
    if _sha256(PACK) != PACK_SHA256:
        raise RuntimeError("current managed scanner rule pack changed")
    current = json.loads(CURRENT_REPORT.read_text(encoding="utf-8"))
    _verify_current_report(current)

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    helm_job = (
        ROOT / "deploy" / "helm" / "agentops-guard" / "templates" / "job-migration.yaml"
    ).read_text(encoding="utf-8")
    if "agentops-guard-migrate" not in compose or 'command: ["agentops-guard-migrate"]' not in helm_job:
        raise RuntimeError("managed scanner rule pack is not installed by deployment migration")

    with tempfile.TemporaryDirectory(prefix="agentops-rule-pack-verify-") as temp_dir:
        temp = Path(temp_dir)
        reproduced_path = temp / "reproduced.json"
        completed = subprocess.run(
            [sys.executable, str(BENCHMARK), "--output", str(reproduced_path)],
            cwd=ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("managed scanner rule-pack reproduction failed")
        reproduced = json.loads(reproduced_path.read_text(encoding="utf-8"))
        _verify_current_report(reproduced)

        database_path = temp / "migration.sqlite3"
        migration_environment = {
            **_safe_environment(),
            "AGENTOPS_ENV": "prod",
            "AGENTOPS_COMPONENT": "migration",
            "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
            "AGENTOPS_DATABASE_URL": f"sqlite:///{database_path.as_posix()}",
        }
        migration_command = [
            sys.executable,
            "-m",
            "agentops_guard.migration_cli",
            "--scanner-rule-pack",
            str(PACK),
            "--project-id",
            "default",
        ]
        for _attempt in range(2):
            migrated = subprocess.run(
                migration_command,
                cwd=ROOT,
                env=migration_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
            if migrated.returncode != 0:
                raise RuntimeError("managed scanner rule-pack migration entrypoint failed")
        with sqlite3.connect(database_path) as database:
            rule_count = database.execute("select count(*) from scan_rules").fetchone()[0]
            audit_count = database.execute(
                "select count(*) from audit_logs where action = 'scanner_rule_pack.install'"
            ).fetchone()[0]
            migration_revision = database.execute("select version_num from alembic_version").fetchone()[
                0
            ]
        if rule_count != 1 or audit_count != 1 or migration_revision != "0016_execution_reconciliation":
            raise RuntimeError("managed scanner rule-pack migration evidence is inconsistent")
    print("scanner_rule_pack_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
