from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


audit = _load("run_osv_lockfile_audit")
verifier = _load("verify_osv_lockfile_audit_artifact")


def test_summary_separates_production_and_development_findings():
    scan = {
        "results": [
            {
                "packages": [
                    {
                        "dependency_groups": ["dev"],
                        "vulnerabilities": [{"id": "OSV-DEV"}],
                    },
                    {
                        "dependency_groups": ["default"],
                        "vulnerabilities": [{"id": "OSV-PROD"}, {"id": "OSV-PROD"}],
                    },
                ]
            }
        ]
    }

    assert audit._summarize(scan) == {
        "affected_packages_total": 2,
        "production_affected_packages": 1,
        "development_only_affected_packages": 1,
        "unique_vulnerabilities": 2,
    }


def test_safe_environment_does_not_forward_credentials_or_proxy_urls(monkeypatch):
    marker = "must-not-reach-scanner"
    monkeypatch.setenv("AGENTOPS_ADMIN_API_KEY", marker)
    monkeypatch.setenv("HTTPS_PROXY", f"https://user:{marker}@proxy.invalid")
    monkeypatch.setenv("PATH", "/usr/bin")

    environment = audit._safe_environment()

    assert environment["PATH"] == "/usr/bin"
    assert marker not in json.dumps(environment)
    assert "HTTPS_PROXY" not in environment
    assert "AGENTOPS_ADMIN_API_KEY" not in environment


def test_verifier_rejects_stale_lockfile_evidence(monkeypatch, tmp_path):
    uv_lock = tmp_path / "uv.lock"
    npm_lock = tmp_path / "dashboard" / "package-lock.json"
    npm_lock.parent.mkdir()
    uv_lock.write_text("uv", encoding="utf-8")
    npm_lock.write_text("npm", encoding="utf-8")
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
    report = {
        "schema_version": 1,
        "evidence_type": "online_osv_lockfile_audit",
        "result": "passed",
        "scanner": {"name": "google/osv-scanner", "version": "2.4.0", "binary_sha256": "a" * 64},
        "database": {"name": "OSV.dev", "mode": "online"},
        "inputs": [
            {"path": "uv.lock", "sha256": verifier._sha256(uv_lock)},
            {"path": "dashboard/package-lock.json", "sha256": "0" * 64},
        ],
        "findings": {
            "affected_packages_total": 0,
            "production_affected_packages": 0,
            "development_only_affected_packages": 0,
            "unique_vulnerabilities": 0,
        },
        "privacy": {
            "captures_scanner_output": False,
            "captures_environment_values": False,
            "captures_dependency_paths_outside_repository": False,
        },
    }

    try:
        verifier.verify(report)
    except ValueError as error:
        assert "stale" in str(error)
    else:
        raise AssertionError("stale OSV evidence was accepted")
