#!/usr/bin/env python3
"""Run an online OSV lockfile scan and emit a content-free evidence record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCKFILES = (ROOT / "uv.lock", ROOT / "dashboard" / "package-lock.json")
DEFAULT_OUTPUT = ROOT / "artifacts" / "security" / "osv-lockfile-audit.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_environment() -> dict[str, str]:
    """Keep process/runtime settings while withholding credentials and proxy URLs."""
    allowed = (
        "PATH",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "WSL_INTEROP",
        "WSL_DISTRO_NAME",
        "WSLENV",
    )
    environment = {name: os.environ[name] for name in allowed if os.environ.get(name)}
    environment.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    environment.setdefault("TMPDIR", "/tmp")
    return environment


def _scanner_version(scanner: Path, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        (str(scanner), "--version"),
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("OSV-Scanner version check failed")
    text = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    match = re.search(r"osv-scanner version:\s*([^\s]+)", text, flags=re.IGNORECASE)
    if match is None:
        raise RuntimeError("OSV-Scanner version output was not recognized")
    return match.group(1)


def _summarize(scan: dict[str, object]) -> dict[str, int]:
    packages: list[dict[str, object]] = []
    for result in scan.get("results", []):
        if isinstance(result, dict):
            result_packages = result.get("packages", [])
            if isinstance(result_packages, list):
                packages.extend(item for item in result_packages if isinstance(item, dict))

    production = 0
    development_only = 0
    vulnerability_ids: set[str] = set()
    for item in packages:
        groups = item.get("dependency_groups", [])
        if isinstance(groups, list) and groups and set(groups) <= {"dev"}:
            development_only += 1
        else:
            production += 1
        vulnerabilities = item.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            identifier = vulnerability.get("id")
            if isinstance(identifier, str) and identifier:
                vulnerability_ids.add(identifier)

    return {
        "affected_packages_total": len(packages),
        "production_affected_packages": production,
        "development_only_affected_packages": development_only,
        "unique_vulnerabilities": len(vulnerability_ids),
    }


def _run_scan(scanner: Path, lockfiles: tuple[Path, ...]) -> tuple[dict[str, object], int]:
    command = [str(scanner), "scan", "source"]
    for lockfile in lockfiles:
        command.extend(("--lockfile", str(lockfile)))
    command.extend(("--format", "json", "--verbosity", "error"))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    try:
        scan = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("OSV-Scanner did not return valid JSON") from error
    if not isinstance(scan, dict):
        raise RuntimeError("OSV-Scanner returned an unexpected JSON document")
    return scan, completed.returncode


def build_report(
    *,
    scanner: Path,
    scanner_version: str,
    lockfiles: tuple[Path, ...],
    scan: dict[str, object],
    exit_code: int,
) -> dict[str, object]:
    findings = _summarize(scan)
    passed = exit_code == 0 and findings["affected_packages_total"] == 0
    return {
        "schema_version": 1,
        "evidence_type": "online_osv_lockfile_audit",
        "generated_at": datetime.now(UTC).isoformat(),
        "result": "passed" if passed else "failed",
        "scanner": {
            "name": "google/osv-scanner",
            "version": scanner_version,
            "binary_sha256": _sha256(scanner),
        },
        "database": {"name": "OSV.dev", "mode": "online"},
        "inputs": [
            {
                "path": path.resolve().relative_to(ROOT).as_posix(),
                "sha256": _sha256(path),
            }
            for path in lockfiles
        ],
        "findings": findings,
        "privacy": {
            "captures_scanner_output": False,
            "captures_environment_values": False,
            "captures_dependency_paths_outside_repository": False,
        },
    }


def write_report(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scanner = args.scanner.resolve(strict=True)
    lockfiles = tuple(path.resolve(strict=True) for path in DEFAULT_LOCKFILES)
    environment = _safe_environment()
    version = _scanner_version(scanner, environment)
    scan, exit_code = _run_scan(scanner, lockfiles)
    report = build_report(
        scanner=scanner,
        scanner_version=version,
        lockfiles=lockfiles,
        scan=scan,
        exit_code=exit_code,
    )
    write_report(report, args.output.resolve())
    print(
        f"osv_audit={report['result']} "
        f"affected_packages={report['findings']['affected_packages_total']}"
    )
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
