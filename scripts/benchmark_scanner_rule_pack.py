#!/usr/bin/env python3
"""Regression-test a reviewed scanner rule pack without retaining source text."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentops_guard.backend.database import Base
from agentops_guard.backend.models import ScanRule
from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.scanner import RegexScannerProvider, ScannerRule
from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack
from agentops_guard.backend.services.safe_regex import compile_configurable_pattern
from agentops_guard.backend.services.safe_regex import MAX_CONFIGURABLE_PATTERN_MEMORY_BYTES
from agentops_guard.benchmarks.llmail_inject import (
    BENIGN_ROWS,
    BENIGN_SHA256,
    DEFAULT_DATASET_DIRECTORY,
    file_sha256,
    wilson_interval,
)


ROOT = Path(__file__).resolve().parents[1]
EVAL_PYTHON = ROOT / "evals" / "inspect" / ".venv" / "bin" / "python"
DYNAMIC_EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_dynamic_cases.py"
STATIC_EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_static_cases.py"
DEFAULT_PACK = ROOT / "policies" / "scanner" / "agentdojo-important-instructions-v1.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "scanner_rule_pack_regression_v2.json"
STATIC_CORPUS_SHA256 = "b9e626a936311cd2cf0ec250aeea8f0f1e885a64beb2bd1ec1829359ba744c73"
DYNAMIC_CORPUS_SHA256 = "c63018476320b64f7d74deaf1bd91fb0728439483a646135e1014131417f8b1b"


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


def _export(path: Path) -> tuple[dict[str, Any], bytes]:
    completed = subprocess.run(
        [str(EVAL_PYTHON), str(path)],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("AgentDojo case export failed")
    raw = completed.stdout.strip()
    return json.loads(raw), raw


def _load_cases(benign_path: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    dynamic, _dynamic_raw = _export(DYNAMIC_EXPORTER)
    static, static_raw = _export(STATIC_EXPORTER)
    if (
        dynamic.get("package_version") != "0.1.35"
        or dynamic.get("benchmark_version") != "v1.2.2"
        or dynamic.get("selected_corpus_sha256") != DYNAMIC_CORPUS_SHA256
    ):
        raise RuntimeError("dynamic AgentDojo source changed")
    if (
        static.get("package_version") != "0.1.35"
        or static.get("benchmark_version") != "v1.2.2"
        or hashlib.sha256(static_raw).hexdigest() != STATIC_CORPUS_SHA256
    ):
        raise RuntimeError("static AgentDojo source changed")
    dynamic_cases = dynamic.get("cases")
    static_cases = static.get("cases")
    if not isinstance(dynamic_cases, list) or not isinstance(static_cases, list):
        raise RuntimeError("AgentDojo exporter returned invalid cases")
    attack_cases = [case for case in dynamic_cases if case.get("kind") == "attack"]
    dynamic_benign = [case for case in dynamic_cases if case.get("kind") == "benign"]
    static_benign = [case for case in static_cases if case.get("kind") == "benign"]
    if len(attack_cases) != 7 or len(dynamic_benign) != 2 or len(static_benign) != 97:
        raise RuntimeError("AgentDojo case inventory changed")
    if file_sha256(benign_path) != BENIGN_SHA256:
        raise RuntimeError("LLMail normal-control digest changed")
    llmail_benign = json.loads(benign_path.read_text(encoding="utf-8"))
    if (
        not isinstance(llmail_benign, list)
        or len(llmail_benign) != BENIGN_ROWS
        or not all(isinstance(content, str) for content in llmail_benign)
    ):
        raise RuntimeError("LLMail normal-control inventory changed")
    cases = [
        {
            "kind": "attack",
            "source": "agentdojo_dynamic_templates",
            "content": case["content"],
        }
        for case in attack_cases
    ]
    cases.extend(
        {
            "kind": "benign",
            "source": "agentdojo_dynamic_controls",
            "content": case["content"],
        }
        for case in dynamic_benign
    )
    cases.extend(
        {
            "kind": "benign",
            "source": "agentdojo_legitimate_tasks",
            "content": case["content"],
        }
        for case in static_benign
    )
    cases.extend(
        {"kind": "benign", "source": "llmail_normal_emails", "content": content}
        for content in llmail_benign
    )
    corpus_sha256 = hashlib.sha256(
        json.dumps(cases, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()
    return cases, {
        "selected_corpus_sha256": corpus_sha256,
        "sources": {
            "agentdojo_dynamic_templates": 7,
            "agentdojo_dynamic_controls": 2,
            "agentdojo_legitimate_tasks": 97,
            "llmail_normal_emails": 203,
        },
    }


def _write_new_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument(
        "--llmail-benign",
        type=Path,
        default=DEFAULT_DATASET_DIRECTORY / "emails_for_fp_tests.json",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    cases, dataset = _load_cases(args.llmail_benign.resolve())

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        installation = install_scanner_rule_pack(
            session,
            project_id="scanner-pack-regression",
            path=args.pack,
        )
        session.commit()
        rows = (
            session.query(ScanRule)
            .filter(
                ScanRule.project_id == "scanner-pack-regression",
                ScanRule.id.in_(installation["rule_ids"]),
            )
            .all()
        )
        if len(rows) != len(installation["rule_ids"]):
            raise RuntimeError("installed scanner rule pack is incomplete")
        provider = RegexScannerProvider(
            [
                ScannerRule(
                    label=row.label,
                    pattern=compile_configurable_pattern(row.pattern),
                    severity=row.severity,
                    score=row.score,
                )
                for row in rows
            ]
        )
        results = []
        for case in cases:
            findings = provider.scan(
                ScanRequest(content=case["content"], source="mcp_tool_result"),
                [(case["content"], 0)],
            )
            results.append({**case, "flagged": bool(findings)})
    finally:
        session.close()
        engine.dispose()

    attacks = [result for result in results if result["kind"] == "attack"]
    benign = [result for result in results if result["kind"] == "benign"]
    attack_flagged = sum(result["flagged"] for result in attacks)
    benign_flagged = sum(result["flagged"] for result in benign)
    report = {
        "metadata": {
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "git_dirty": bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=ROOT, text=True
                ).strip()
            ),
            "runtime": {"python": sys.version, "platform": platform.platform()},
            "regex_engine": {
                "package": "google-re2",
                "version": version("google-re2"),
                "official_project": "https://github.com/google/re2",
                "package_index": "https://pypi.org/project/google-re2/",
                "configured_max_memory_bytes": MAX_CONFIGURABLE_PATTERN_MEMORY_BYTES,
            },
            "scope": (
                "Post-finding regression of one reviewed high-precision managed rule. The attack "
                "templates were used to author the rule, so this is not a blind or unknown-attack result."
            ),
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_evidence_text": False,
            },
            "implementation_sha256": {
                "benchmark": file_sha256(Path(__file__)),
                "installer": file_sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "scanner_rule_packs.py"
                ),
                "scanner": file_sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "scanner.py"
                ),
                "safe_regex": file_sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "safe_regex.py"
                ),
                "pack": file_sha256(args.pack.resolve()),
                "dynamic_exporter": file_sha256(DYNAMIC_EXPORTER),
                "static_exporter": file_sha256(STATIC_EXPORTER),
                "inspect_lock": file_sha256(ROOT / "evals" / "inspect" / "uv.lock"),
                "root_lock": file_sha256(ROOT / "uv.lock"),
            },
        },
        "rule_pack": {
            "pack_id": installation["pack_id"],
            "revision": installation["revision"],
            "pack_sha256": installation["pack_sha256"],
            "installed_rules": installation["installed"],
        },
        "dataset": dataset,
        "attack": {
            "rows": len(attacks),
            "flagged": attack_flagged,
            "rate": attack_flagged / len(attacks),
            "wilson_95": wilson_interval(attack_flagged, len(attacks)),
        },
        "benign": {
            "rows": len(benign),
            "flagged": benign_flagged,
            "rate": benign_flagged / len(benign),
            "wilson_95": wilson_interval(benign_flagged, len(benign)),
        },
    }
    _write_new_report(report, args.output)
    print(
        f"attack_flagged={attack_flagged}/{len(attacks)} "
        f"benign_flagged={benign_flagged}/{len(benign)} report_created=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
