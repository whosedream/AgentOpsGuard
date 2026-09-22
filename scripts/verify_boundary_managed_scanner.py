#!/usr/bin/env python3
"""Recheck consumed boundary cases through the DB-backed scanner and installed rule pack."""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from benchmark_boundary_quality import CHINESE, LOCK, ROOT, load_rows, metrics
from agentops_guard.backend.database import Base
from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.scanner import scan_content
from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack
from agentops_guard.backend.services.semantic_scanner import SemanticScanner
from agentops_guard.benchmarks.llmail_inject import DEFAULT_MODEL_SHA256, IPI_RISK_LABELS, file_sha256
from agentops_guard.evals.holdouts import load_holdout_manifest


@dataclass
class Result:
    regex_flagged: bool
    model_flagged: bool


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--english-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refusing to overwrite a verification report")
    lock = json.loads(LOCK.read_text())
    registered = {row["id"]: row for row in load_holdout_manifest(ROOT / "evals/holdouts/manifest.json")["datasets"]}
    for source in lock["datasets"]:
        if registered[source["id"]]["state"] != "consumed":
            raise RuntimeError("this runner is only for consumed regression cases")
    semantic = SemanticScanner(ROOT / "models/semantic-guard", DEFAULT_MODEL_SHA256,
                               "shadow", lock["threshold"])
    semantic.warm()
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    pack = ROOT / "policies/scanner/agentdojo-important-instructions-v1.json"
    reports = {}
    with Session(engine) as db, patch("agentops_guard.backend.services.scanner.get_semantic_scanner", return_value=semantic):
        install_scanner_rule_pack(db, project_id="boundary_recheck", path=pack)
        db.commit()
        for source, path in zip(lock["datasets"], (args.english_path, CHINESE), strict=True):
            rows = load_rows(path, source)
            results = []
            for row in rows:
                scan = scan_content(ScanRequest(project_id="boundary_recheck", content=row["text"],
                                    source="mcp_tool_result", metadata={"trust": "untrusted"}), db)
                assessment = scan.semantic_assessment
                if assessment is None or assessment.status != "ok":
                    raise RuntimeError("model did not score a case successfully")
                results.append(Result(bool(set(scan.risk_labels) & IPI_RISK_LABELS),
                                      assessment.label == "prompt_injection"))
            reports[source["id"]] = metrics(rows, results)
            if source["language"] == "en":
                original = {row["id"]: row for row in
                            (json.loads(line) for line in path.read_text().splitlines())}
                pair_contexts = defaultdict(list)
                for row in rows:
                    pair_contexts[row["pair_id"]].append(original[row["id"]]["source_context"])
                eligible = {pair for pair, contexts in pair_contexts.items()
                            if all(context not in {"direct_user", "agent_tool_request"} for context in contexts)}
                selected = [(row, result) for row, result in zip(rows, results, strict=True)
                            if row["pair_id"] in eligible]
                reports["english_external_context_pairs_post_hoc"] = metrics(
                    [row for row, _ in selected], [result for _, result in selected])
    engine.dispose()
    report = {"scope": "post_first_run_db_backed_scanner_regression_not_agent_e2e",
              "real_model": True, "model_errors": 0, "threshold": lock["threshold"],
              "managed_rules_installed": True, "pack_sha256": file_sha256(pack),
              "stores_raw_text": False, "independent_blind_test": False, "summary": reports,
              "source_slice_note": "Post-hoc scope analysis excludes entire pairs containing direct_user or agent_tool_request. It is not a new blind test.",
              "implementation_sha256": {str(path.relative_to(ROOT)): file_sha256(path) for path in
                  [Path(__file__), ROOT / "src/agentops_guard/backend/services/scanner.py",
                   ROOT / "src/agentops_guard/backend/services/semantic_scanner.py", LOCK]}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"model_errors": 0, "summary": reports}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
