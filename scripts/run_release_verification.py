#!/usr/bin/env python3
"""Run the fixed local release checks and write a content-free evidence record."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = ROOT / "artifacts" / "verification"
BENCHMARK_DIR = ROOT / "artifacts" / "benchmarks"
EVALUATION_DIR = ROOT / "artifacts" / "evals"
SBOM_PATHS = (
    ROOT / "artifacts" / "agentops-guard-python.cdx.json",
    ROOT / "artifacts" / "agentops-guard-dashboard.cdx.json",
    ROOT / "artifacts" / "security" / "osv-lockfile-audit.json",
)
BENCHMARK_ARTIFACTS = (
    "agentdojo_static_blind_v1.json",
    "agentdojo_static_regression_v2.json",
    "agentdojo_static_regression_v3.json",
    "bipia_protectai_candidate_regression_v1.json",
    "bipia_static_holdout_v1.json",
    "bipia_windowing_calibration_v1.json",
    "bipia_windowing_probe_v1.json",
    "gateway_comparison_contextforge_v1.json",
    "gateway_security_path_v1.json",
    "injecagent_static_holdout_v1.json",
    "llmail_inject_phase2_blind_v1.json",
    "llmail_inject_phase2_semantic_shadow_v1.json",
    "llmail_inject_phase2_v1.json",
    "nemotron_agentic_ipi_v1.json",
    "scanner_rule_pack_regression_v1.json",
    "scanner_rule_pack_regression_v2.json",
    "scanner_rule_pack_regression_v3.json",
    "semantic_guard_blind_v1.json",
)
EVALUATION_ARTIFACTS = (
    "agent_threat_bench_gateway_v1.json",
    "agent_threat_bench_gateway_v2.json",
    "agent_threat_bench_gateway_v3.json",
    "agent_threat_bench_gateway_v4.json",
    "agent_threat_bench_gateway_v5.json",
    "agent_threat_bench_gateway_v6.json",
    "agentdojo_template_dynamic_gateway_v1.json",
    "agentdojo_template_dynamic_gateway_v2.json",
    "agentdojo_template_dynamic_gateway_v3.json",
    "agentdojo_template_dynamic_gateway_v6.json",
    "agentdojo_template_dynamic_gateway_v7.json",
    "agentdojo_template_dynamic_gateway_v8.json",
    "agentdojo_template_dynamic_gateway_v9.json",
    "agentdojo_template_dynamic_gateway_v10.json",
    "qwen3_4b_q4_k_m_agent_smoke_v2.json",
)


@dataclass(frozen=True)
class Check:
    id: str
    command: tuple[str, ...]
    preserve_paths: tuple[str, ...] = ()


CHECKS = (
    Check("dependency_lock", ("uv", "lock", "--check")),
    Check("python_lint", ("uv", "run", "ruff", "check", ".")),
    Check(
        "python_tests",
        (
            "uv",
            "run",
            "pytest",
            "--cov=agentops_guard",
            "--cov-fail-under=80",
            "-q",
        ),
    ),
    Check(
        "inspect_eval_dependency_lock",
        ("uv", "lock", "--project", "evals/inspect", "--check"),
    ),
    Check(
        "inspect_eval_environment",
        ("uv", "sync", "--project", "evals/inspect", "--locked", "--no-dev"),
    ),
    Check(
        "inspect_agent_gateway_smoke",
        ("uv", "run", "--frozen", "--offline", "python", "scripts/verify_inspect_agent_eval.py"),
    ),
    Check(
        "local_model_runtime_dependency_lock",
        ("uv", "lock", "--project", "evals/local-model-runtime", "--check"),
    ),
    Check(
        "local_model_runtime_environment",
        (
            "uv",
            "sync",
            "--project",
            "evals/local-model-runtime",
            "--locked",
            "--no-dev",
            "--offline",
        ),
    ),
    Check(
        "real_local_model_agent_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_local_model_agent_artifact.py",
        ),
    ),
    Check(
        "agentdojo_static_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_agentdojo_static_artifact.py",
        ),
    ),
    Check(
        "bipia_static_holdout_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_bipia_static_artifact.py",
        ),
    ),
    Check(
        "injecagent_static_holdout_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_injecagent_static_artifact.py",
        ),
    ),
    Check(
        "holdout_manifest_contract",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/manage_holdout.py",
            "validate",
        ),
    ),
    Check(
        "agentdojo_dynamic_gateway_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_agentdojo_dynamic_artifact.py",
        ),
    ),
    Check(
        "agent_threat_bench_gateway_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_agent_threat_gateway_artifact.py",
        ),
    ),
    Check(
        "scanner_rule_pack_evidence",
        (
            "uv",
            "run",
            "--frozen",
            "--offline",
            "python",
            "scripts/verify_scanner_rule_pack_artifact.py",
        ),
    ),
    Check(
        "keycloak_oidc_release_provenance",
        (
            "uv",
            "run",
            "python",
            "scripts/verify_keycloak_oidc_release_signature.py",
        ),
    ),
    Check(
        "keycloak_oidc_runtime",
        ("uv", "run", "python", "scripts/verify_keycloak_oidc.py"),
    ),
    Check(
        "opa_policy_runtime",
        ("uv", "run", "python", "scripts/verify_opa_runtime.py"),
    ),
    Check(
        "opa_remote_bundle_runtime",
        ("uv", "run", "python", "scripts/verify_opa_remote_bundle.py"),
    ),
    Check(
        "openbao_release_provenance",
        ("uv", "run", "python", "scripts/verify_openbao_release_signature.py"),
    ),
    Check(
        "openbao_proxy_workload_auth",
        ("uv", "run", "python", "scripts/verify_openbao_proxy.py"),
    ),
    Check(
        "openbao_raft_ha_tls_and_restore",
        ("uv", "run", "python", "scripts/verify_openbao_raft_ha.py"),
    ),
    Check(
        "postgres_audit_append_only",
        ("uv", "run", "python", "scripts/verify_postgres_audit_append_only.py"),
    ),
    Check(
        "postgres_backup_restore",
        ("uv", "run", "python", "scripts/verify_postgres_backup_restore.py"),
    ),
    Check(
        "postgres_streaming_replication_failover",
        ("uv", "run", "python", "scripts/verify_postgres_streaming_failover.py"),
    ),
    Check(
        "patroni_kubernetes_failover_evidence",
        (
            "uv",
            "run",
            "python",
            "scripts/verify_patroni_kubernetes_failover_artifact.py",
        ),
    ),
    Check(
        "operational_resilience",
        ("uv", "run", "python", "scripts/verify_operational_resilience.py"),
    ),
    Check(
        "openbao_audit_checkpoint",
        ("uv", "run", "python", "scripts/verify_openbao_audit_checkpoint.py"),
    ),
    Check(
        "otelcol_resilient_host_runtime",
        ("uv", "run", "python", "scripts/verify_otelcol_resilient_host_runtime.py"),
    ),
    Check(
        "signed_runtime_release_provenance",
        ("uv", "run", "python", "scripts/verify_otelcol_release_signature.py"),
    ),
    Check(
        "minio_object_lock_runtime",
        ("uv", "run", "python", "scripts/verify_minio_object_lock.py"),
    ),
    Check(
        "python_dockerfile_static_check",
        ("docker", "build", "--check", "--network=none", "."),
    ),
    Check(
        "dashboard_dockerfile_static_check",
        ("docker", "build", "--check", "--network=none", "dashboard"),
    ),
    Check(
        "compose_render",
        ("docker", "compose", "--env-file", "/dev/null", "config", "--quiet"),
    ),
    Check(
        "helm_render_and_negative_gates",
        ("uv", "run", "python", "scripts/helm_template_check.py"),
    ),
    Check(
        "kubernetes_isolation_evidence",
        ("uv", "run", "python", "scripts/verify_kubernetes_isolation_artifact.py"),
    ),
    Check(
        "sigstore_admission_partial_evidence",
        ("uv", "run", "python", "scripts/verify_sigstore_admission_artifact.py"),
    ),
    Check("dashboard_tests", ("npm", "test", "--prefix", "dashboard")),
    Check(
        "dashboard_build",
        ("npm", "run", "build", "--prefix", "dashboard"),
        preserve_paths=("dashboard/next-env.d.ts",),
    ),
    Check(
        "python_sbom",
        (
            "uv",
            "run",
            "python",
            "scripts/generate_python_sbom.py",
            "--output",
            "artifacts/agentops-guard-python.cdx.json",
        ),
    ),
    Check(
        "dashboard_sbom",
        (
            "uv",
            "run",
            "python",
            "scripts/generate_dashboard_sbom.py",
            "--output",
            "artifacts/agentops-guard-dashboard.cdx.json",
        ),
    ),
    Check(
        "dependency_vulnerability_audit_evidence",
        ("uv", "run", "python", "scripts/verify_osv_lockfile_audit_artifact.py"),
    ),
    Check("git_patch_integrity", ("git", "diff", "--check")),
)

UNVERIFIED_GATES = (
    "live_enterprise_oidc",
    "live_sigstore_image_admission",
    "production_opa_remote_bundle_distribution_and_current_stable_runtime",
    "production_otel_collector_export_and_backend",
    "production_openbao_proxy_delivery_tls_and_high_availability",
    "signed_private_registry_images",
    "successful_supply_chain_workflow_and_online_audits",
    "external_append_only_audit_checkpoint_storage",
    "production_scale_load_and_failover",
    "unknown_attack_agent_end_to_end_evaluation",
)


def _safe_environment() -> dict[str, str]:
    """Give verification tools only process settings, never application credentials."""
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR", "NPM_CONFIG_CACHE"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _run(command: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _run_preserving_generated_files(check: Check) -> subprocess.CompletedProcess[bytes]:
    snapshots: dict[Path, bytes | None] = {}
    for relative_path in check.preserve_paths:
        path = ROOT / relative_path
        snapshots[path] = path.read_bytes() if path.exists() else None
    try:
        return _run(check.command)
    finally:
        for path, content in snapshots.items():
            if content is None:
                if path.exists():
                    path.unlink()
            elif not path.exists() or path.read_bytes() != content:
                path.write_bytes(content)


def run_checks() -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    failed = False
    for check in CHECKS:
        if failed:
            results.append(
                {
                    "id": check.id,
                    "command": list(check.command),
                    "status": "skipped_after_failure",
                    "duration_ms": 0,
                    "exit_code": None,
                }
            )
            continue

        started = time.perf_counter()
        try:
            completed = _run_preserving_generated_files(check)
            exit_code: int | None = completed.returncode
        except FileNotFoundError:
            exit_code = None
        duration_ms = round((time.perf_counter() - started) * 1000)
        status = "passed" if exit_code == 0 else "failed"
        results.append(
            {
                "id": check.id,
                "command": list(check.command),
                "status": status,
                "duration_ms": duration_ms,
                "exit_code": exit_code,
            }
        )
        failed = status == "failed"
    return results


def _git_output(*arguments: str) -> bytes:
    return subprocess.check_output(
        ("git", *arguments),
        cwd=ROOT,
        env=_safe_environment(),
        stderr=subprocess.DEVNULL,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_state() -> dict[str, object]:
    commit = _git_output("rev-parse", "HEAD").decode("ascii").strip()
    status = _git_output("status", "--porcelain=v1", "-z")
    paths = _git_output("ls-files", "-z", "--cached", "--others", "--exclude-standard")

    digest = hashlib.sha256()
    file_count = 0
    for raw_path in sorted(path for path in paths.split(b"\0") if path):
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        path = ROOT / os.fsdecode(raw_path)
        if path.is_file():
            file_digest = bytes.fromhex(_sha256_file(path))
            digest.update(file_digest)
            file_count += 1
        else:
            digest.update(b"missing")

    uv_lock = ROOT / "uv.lock"
    return {
        "git_commit": commit,
        "worktree_dirty": bool(status),
        "source_state_sha256": digest.hexdigest(),
        "source_file_count": file_count,
        "uv_lock_sha256": _sha256_file(uv_lock),
    }


def benchmark_evidence() -> list[dict[str, str]]:
    if not BENCHMARK_DIR.is_dir():
        return []
    return [
        {"artifact": path.name, "sha256": _sha256_file(path)}
        for name in BENCHMARK_ARTIFACTS
        if (path := BENCHMARK_DIR / name).is_file()
    ]


def evaluation_evidence() -> list[dict[str, str]]:
    if not EVALUATION_DIR.is_dir():
        return []
    return [
        {"artifact": path.name, "sha256": _sha256_file(path)}
        for name in EVALUATION_ARTIFACTS
        if (path := EVALUATION_DIR / name).is_file()
    ]


def supply_chain_evidence() -> list[dict[str, str]]:
    return [
        {"artifact": path.name, "sha256": _sha256_file(path)}
        for path in SBOM_PATHS
        if path.is_file()
    ]


def build_report(checks: list[dict[str, object]]) -> dict[str, object]:
    passed = all(check["status"] == "passed" for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "local_release_candidate_verification",
        "generated_at": datetime.now(UTC).isoformat(),
        "result": "passed" if passed else "failed",
        "source": source_state(),
        "runtime": {
            "python": platform.python_version(),
            "system": platform.system().lower(),
            "machine": platform.machine().lower(),
        },
        "checks": checks,
        "benchmark_artifacts": benchmark_evidence(),
        "evaluation_artifacts": evaluation_evidence(),
        "supply_chain_artifacts": supply_chain_evidence(),
        "unverified_gates": list(UNVERIFIED_GATES),
        "privacy": {
            "captures_command_output": False,
            "captures_environment_values": False,
            "captures_request_or_model_content": False,
        },
    }


def _default_output_path() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    commit = _git_output("rev-parse", "--short=12", "HEAD").decode("ascii").strip()
    return DEFAULT_REPORT_DIR / f"{timestamp}-{commit}.json"


def write_report(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    checks = run_checks()
    report = build_report(checks)
    output = _default_output_path()
    write_report(report, output)
    print(f"verification={report['result']} report_created=true")
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
