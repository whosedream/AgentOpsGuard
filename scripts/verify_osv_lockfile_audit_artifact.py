#!/usr/bin/env python3
"""Verify that OSV evidence is clean and still bound to the current lockfiles."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "security" / "osv-lockfile-audit.json"
EXPECTED_INPUTS = ("uv.lock", "dashboard/package-lock.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(report: dict[str, object]) -> None:
    if report.get("schema_version") != 1:
        raise ValueError("unexpected OSV evidence schema")
    if report.get("evidence_type") != "online_osv_lockfile_audit":
        raise ValueError("unexpected OSV evidence type")
    if report.get("result") != "passed":
        raise ValueError("OSV audit did not pass")

    scanner = report.get("scanner")
    if not isinstance(scanner, dict) or scanner.get("name") != "google/osv-scanner":
        raise ValueError("OSV scanner identity is missing")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(scanner.get("version", ""))):
        raise ValueError("OSV scanner version is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(scanner.get("binary_sha256", ""))):
        raise ValueError("OSV scanner digest is invalid")

    inputs = report.get("inputs")
    if not isinstance(inputs, list):
        raise ValueError("OSV evidence inputs are missing")
    actual = {
        item.get("path"): item.get("sha256")
        for item in inputs
        if isinstance(item, dict)
    }
    if set(actual) != set(EXPECTED_INPUTS):
        raise ValueError("OSV evidence does not cover the fixed lockfile set")
    for relative in EXPECTED_INPUTS:
        if actual[relative] != _sha256(ROOT / relative):
            raise ValueError(f"OSV evidence is stale for {relative}")

    findings = report.get("findings")
    expected_findings = {
        "affected_packages_total": 0,
        "production_affected_packages": 0,
        "development_only_affected_packages": 0,
        "unique_vulnerabilities": 0,
    }
    if findings != expected_findings:
        raise ValueError("OSV evidence contains vulnerability findings")
    if report.get("database") != {"name": "OSV.dev", "mode": "online"}:
        raise ValueError("OSV evidence was not produced by an online database lookup")
    if report.get("privacy") != {
        "captures_scanner_output": False,
        "captures_environment_values": False,
        "captures_dependency_paths_outside_repository": False,
    }:
        raise ValueError("OSV evidence privacy boundary is invalid")


def main() -> int:
    report = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    verify(report)
    print("osv_audit_evidence=valid affected_packages=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
