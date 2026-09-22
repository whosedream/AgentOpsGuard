from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_release_verification.py"
SPEC = importlib.util.spec_from_file_location("run_release_verification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verification
SPEC.loader.exec_module(verification)

LLAMA_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_llama_cpp_agent_eval.py"
LLAMA_SPEC = importlib.util.spec_from_file_location("run_llama_cpp_agent_eval", LLAMA_SCRIPT)
assert LLAMA_SPEC is not None and LLAMA_SPEC.loader is not None
llama_eval = importlib.util.module_from_spec(LLAMA_SPEC)
sys.modules[LLAMA_SPEC.name] = llama_eval
LLAMA_SPEC.loader.exec_module(llama_eval)


def test_release_checks_are_fixed_and_fail_fast(monkeypatch):
    invoked: list[tuple[str, ...]] = []

    def fake_run(command):
        invoked.append(command)
        return type("Completed", (), {"returncode": 1 if len(invoked) == 2 else 0})()

    monkeypatch.setattr(verification, "_run", fake_run)
    results = verification.run_checks()

    assert invoked == [
        verification.CHECKS[0].command,
        verification.CHECKS[1].command,
    ]
    assert results[0]["status"] == "passed"
    assert results[1]["status"] == "failed"
    assert all(result["status"] == "skipped_after_failure" for result in results[2:])
    assert all(isinstance(result["command"], list) for result in results)


def test_release_checks_include_real_openbao_proxy_verification():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["openbao_release_provenance"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_openbao_release_signature.py",
    )
    assert checks["openbao_proxy_workload_auth"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_openbao_proxy.py",
    )
    assert checks["openbao_audit_checkpoint"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_openbao_audit_checkpoint.py",
    )
    assert checks["openbao_raft_ha_tls_and_restore"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_openbao_raft_ha.py",
    )


def test_release_checks_include_real_opa_policy_runtime_verification():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["opa_policy_runtime"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_opa_runtime.py",
    )
    assert checks["opa_remote_bundle_runtime"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_opa_remote_bundle.py",
    )


def test_release_checks_include_real_keycloak_oidc_verification():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["keycloak_oidc_release_provenance"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_keycloak_oidc_release_signature.py",
    )
    assert checks["keycloak_oidc_runtime"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_keycloak_oidc.py",
    )


def test_release_checks_include_current_recovery_and_restore_verification():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["postgres_backup_restore"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_postgres_backup_restore.py",
    )
    assert checks["postgres_streaming_replication_failover"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_postgres_streaming_failover.py",
    )
    assert checks["patroni_kubernetes_failover_evidence"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_patroni_kubernetes_failover_artifact.py",
    )
    assert checks["operational_resilience"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_operational_resilience.py",
    )
    assert checks["otelcol_resilient_host_runtime"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_otelcol_resilient_host_runtime.py",
    )


def test_release_checks_enforce_python_coverage_threshold():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["python_tests"] == (
        "uv",
        "run",
        "pytest",
        "--cov=agentops_guard",
        "--cov-fail-under=80",
        "-q",
    )
    assert checks["inspect_eval_dependency_lock"] == (
        "uv",
        "lock",
        "--project",
        "evals/inspect",
        "--check",
    )
    assert checks["inspect_eval_environment"] == (
        "uv",
        "sync",
        "--project",
        "evals/inspect",
        "--locked",
        "--no-dev",
    )
    assert checks["inspect_agent_gateway_smoke"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_inspect_agent_eval.py",
    )
    assert checks["local_model_runtime_dependency_lock"] == (
        "uv",
        "lock",
        "--project",
        "evals/local-model-runtime",
        "--check",
    )
    assert checks["local_model_runtime_environment"] == (
        "uv",
        "sync",
        "--project",
        "evals/local-model-runtime",
        "--locked",
        "--no-dev",
        "--offline",
    )
    assert checks["real_local_model_agent_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_local_model_agent_artifact.py",
    )
    assert checks["agentdojo_static_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_agentdojo_static_artifact.py",
    )
    assert checks["bipia_static_holdout_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_bipia_static_artifact.py",
    )
    assert checks["injecagent_static_holdout_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_injecagent_static_artifact.py",
    )
    assert checks["holdout_manifest_contract"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/manage_holdout.py",
        "validate",
    )
    assert checks["agentdojo_dynamic_gateway_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_agentdojo_dynamic_artifact.py",
    )
    assert checks["agent_threat_bench_gateway_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_agent_threat_gateway_artifact.py",
    )
    assert checks["scanner_rule_pack_evidence"] == (
        "uv",
        "run",
        "--frozen",
        "--offline",
        "python",
        "scripts/verify_scanner_rule_pack_artifact.py",
    )
    assert "agentdojo_static_blind_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "agentdojo_static_regression_v2.json" in verification.BENCHMARK_ARTIFACTS
    assert "agentdojo_static_regression_v3.json" in verification.BENCHMARK_ARTIFACTS
    assert "agentdojo_static_regression_v4.json" in verification.BENCHMARK_ARTIFACTS
    assert "boundary-quality-v1/boundary_pairs_en_test_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "bipia_protectai_candidate_regression_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "bipia_static_holdout_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "bipia_windowing_calibration_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "bipia_windowing_probe_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "injecagent_static_holdout_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "scanner_rule_pack_regression_v1.json" in verification.BENCHMARK_ARTIFACTS
    assert "scanner_rule_pack_regression_v2.json" in verification.BENCHMARK_ARTIFACTS
    assert "scanner_rule_pack_regression_v3.json" in verification.BENCHMARK_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v1.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v2.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v3.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v6.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v7.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v8.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v9.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v10.json" in verification.EVALUATION_ARTIFACTS
    assert "agentdojo_template_dynamic_gateway_v11.json" in verification.EVALUATION_ARTIFACTS
    assert "agent_threat_bench_gateway_v1.json" in verification.EVALUATION_ARTIFACTS
    assert "agent_threat_bench_gateway_v6.json" in verification.EVALUATION_ARTIFACTS
    assert "agent_threat_bench_gateway_v7.json" in verification.EVALUATION_ARTIFACTS
    assert verification.FAILED_ACCEPTANCE_GATES == (
        "single_host_full_security_path_fault_soak",
        "bilingual_attack_and_hard_negative_detection_quality",
    )
    assert "qwen3_4b_q4_k_m_agent_smoke_v2.json" in verification.EVALUATION_ARTIFACTS
    assert len(verification.UNVERIFIED_GATES) == len(set(verification.UNVERIFIED_GATES)) == 10


def test_release_checks_validate_both_dockerfiles_without_network():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["python_dockerfile_static_check"] == (
        "docker",
        "build",
        "--check",
        "--network=none",
        ".",
    )
    assert checks["dashboard_dockerfile_static_check"] == (
        "docker",
        "build",
        "--check",
        "--network=none",
        "dashboard",
    )


def test_release_checks_bind_live_kubernetes_isolation_evidence():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["kubernetes_isolation_evidence"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_kubernetes_isolation_artifact.py",
    )
    assert checks["sigstore_admission_partial_evidence"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_sigstore_admission_artifact.py",
    )


def test_release_checks_bind_clean_online_dependency_evidence():
    checks = {check.id: check.command for check in verification.CHECKS}

    assert checks["dependency_vulnerability_audit_evidence"] == (
        "uv",
        "run",
        "python",
        "scripts/verify_osv_lockfile_audit_artifact.py",
    )
    assert verification.SBOM_PATHS[-1] == (
        verification.ROOT / "artifacts" / "security" / "osv-lockfile-audit.json"
    )


def test_release_check_restores_known_generated_file(monkeypatch, tmp_path):
    generated = tmp_path / "dashboard" / "next-env.d.ts"
    generated.parent.mkdir()
    generated.write_text("before\n", encoding="utf-8")
    check = verification.Check(
        "dashboard_build",
        ("npm", "run", "build"),
        preserve_paths=("dashboard/next-env.d.ts",),
    )

    def fake_run(_command):
        generated.write_text("generated by build\n", encoding="utf-8")
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr(verification, "ROOT", tmp_path)
    monkeypatch.setattr(verification, "_run", fake_run)

    result = verification._run_preserving_generated_files(check)

    assert result.returncode == 0
    assert generated.read_text(encoding="utf-8") == "before\n"


def test_safe_environment_does_not_forward_application_secrets(monkeypatch):
    marker = "must-not-enter-verification"
    monkeypatch.setenv("AGENTOPS_ADMIN_API_KEY", marker)
    monkeypatch.setenv("OPENBAO_TOKEN", marker)
    monkeypatch.setenv("PATH", "/usr/bin")

    environment = verification._safe_environment()

    assert environment["PATH"] == "/usr/bin"
    assert marker not in json.dumps(environment)
    assert "AGENTOPS_ADMIN_API_KEY" not in environment
    assert "OPENBAO_TOKEN" not in environment
    assert marker not in json.dumps(llama_eval._safe_environment())


def test_report_contains_provenance_limits_and_no_command_output(monkeypatch):
    monkeypatch.setattr(
        verification,
        "source_state",
        lambda: {
            "git_commit": "a" * 40,
            "worktree_dirty": False,
            "source_state_sha256": "b" * 64,
            "source_file_count": 10,
            "uv_lock_sha256": "c" * 64,
        },
    )
    monkeypatch.setattr(verification, "benchmark_evidence", lambda: [])
    monkeypatch.setattr(verification, "evaluation_evidence", lambda: [])
    monkeypatch.setattr(verification, "supply_chain_evidence", lambda: [])
    checks = [
        {
            "id": "python_tests",
            "command": ["uv", "run", "pytest", "-q"],
            "status": "passed",
            "duration_ms": 10,
            "exit_code": 0,
        }
    ]

    report = verification.build_report(checks)

    assert report["result"] == "passed"
    assert report["acceptance_result"] == "failed"
    assert report["failed_acceptance_gates"] == list(verification.FAILED_ACCEPTANCE_GATES)
    assert report["privacy"] == {
        "captures_command_output": False,
        "captures_environment_values": False,
        "captures_request_or_model_content": False,
    }
    assert "live_enterprise_oidc" in report["unverified_gates"]
    assert "live_sigstore_image_admission" in report["unverified_gates"]
    assert "live_kubernetes_admission_and_network_policy" not in report["unverified_gates"]
    assert (
        "production_opa_remote_bundle_distribution_and_current_stable_runtime"
        in report["unverified_gates"]
    )
    assert "production_otel_collector_export_and_backend" in report["unverified_gates"]
    assert (
        "production_openbao_proxy_delivery_tls_and_high_availability" in report["unverified_gates"]
    )
    assert report["supply_chain_artifacts"] == []
    assert report["evaluation_artifacts"] == []
    assert "stdout" not in json.dumps(report)
    assert "stderr" not in json.dumps(report)


def test_write_report_refuses_to_replace_existing_file(tmp_path):
    output = tmp_path / "evidence.json"
    verification.write_report({"result": "passed"}, output)

    try:
        verification.write_report({"result": "changed"}, output)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing verification evidence was overwritten")

    assert json.loads(output.read_text(encoding="utf-8")) == {"result": "passed"}

    model = tmp_path / "model.gguf"
    model.write_bytes(b"fixed model fixture")
    expected_sha256 = llama_eval._sha256(model)
    pinned, size = llama_eval._pinned_file(model, expected_sha256, "model")
    assert pinned == model.resolve()
    assert size == len(b"fixed model fixture")

    try:
        llama_eval._pinned_file(model, "0" * 64, "model")
    except ValueError as error:
        assert str(error) == "model SHA-256 does not match"
    else:
        raise AssertionError("mismatched model digest was accepted")
