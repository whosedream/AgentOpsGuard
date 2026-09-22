"""Routing and preflight checks never create a real cluster or alter the host."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_two_layer_cluster_verification as runner  # noqa: E402


def test_required_tools_are_checked_explicitly(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None if name == "helm" else "/bin/docker")
    with pytest.raises(RuntimeError, match="helm"):
        runner.check_runtime_tools()
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/reviewed/" + name)
    assert runner.check_runtime_tools() == {"helm": "/reviewed/helm", "docker": "/reviewed/docker"}


def test_missing_tool_stops_before_host_or_directory_mutation(monkeypatch, tmp_path):
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    monkeypatch.setattr(runner, "check_host_storage", lambda: {"checked": True})
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(runner, "set_listener_limit", lambda value: pytest.fail("Host was changed"))
    directory = tmp_path / "must-not-be-created"
    monkeypatch.setattr(sys, "argv", ["runner", "--directory", str(directory),
                                    "--allow-temporary-listener-increase"])
    with pytest.raises(RuntimeError, match="Required test tools"):
        runner.main()
    assert not directory.exists()


def test_sustained_load_requires_explicit_baseline_scope(monkeypatch, tmp_path):
    directory = tmp_path / "not-created"
    monkeypatch.setattr(sys, "argv", ["runner", "--directory", str(directory), "--soak-seconds", "1800"])
    with pytest.raises(ValueError, match="requires --baseline-only"):
        runner.main()
    assert not directory.exists()


@pytest.mark.parametrize("failing_phase", [None, "baseline_2", "sustained_5rps"])
def test_sustained_load_keeps_original_gates_and_cleanup(monkeypatch, tmp_path, failing_phase):
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    monkeypatch.setattr(runner, "check_host_storage", lambda: {"checked": True})
    monkeypatch.setattr(runner, "check_runtime_tools", lambda: {"checked": True})
    monkeypatch.setattr(runner.cluster, "frozen_inputs", lambda: {})
    directory = tmp_path / "run"
    monkeypatch.setattr(sys, "argv", ["runner", "--directory", str(directory),
        "--allow-temporary-listener-increase", "--baseline-only", "--soak-seconds", "1800"])
    limits, loads, cleaned = [], [], []
    monkeypatch.setattr(runner, "set_listener_limit", limits.append)

    def setup(deployment, **kwargs):
        deployment.mkdir()
        runner.cluster.save(deployment / "state.json", {})

    async def load(state, deployment, name, rps, seconds, fault):
        loads.append((name, rps, seconds, fault))
        runner.cluster.save(deployment / (name + ".json"),
                            {"passed": name != failing_phase, "failed": int(name == failing_phase)})

    monkeypatch.setattr(runner.cluster, "setup", setup)
    monkeypatch.setattr(runner.cluster, "load_phase", load)
    monkeypatch.setattr(runner.evidence, "collect_phase", lambda state, deployment, name, **kw:
                        {"name": name, "complete": True, "errors": []})
    monkeypatch.setattr(runner.admission, "phase", lambda *a, **k: pytest.fail("Unexpected admission fault"))
    monkeypatch.setattr(runner.receipts, "verify", lambda *a, **k: pytest.fail("Unexpected receipt test"))
    monkeypatch.setattr(runner, "_delete_cluster", lambda kind, name, environment: cleaned.append(name))
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: "")
    runner.main()
    summary = json.loads((directory / "summary.json").read_text())
    assert limits == [512, 128] and cleaned == [summary["cluster"]]
    assert summary["soak_seconds"] == 1800 and summary["production_sla_verified"] is False
    assert loads[:4] == [("warmup", 1, 30, "none")] + [(f"baseline_{i}", 5, 120, "none") for i in range(1, 4)]
    assert ("sustained_5rps", 5, 1800, "none") in loads
    assert summary["soak_role"] == "same_load_diagnostic_not_replacement"
    assert (("fixed_target_10rps", 10, 120, "none") in loads) is (failing_phase is None)


@pytest.mark.parametrize("recovery_only,baseline_only", [(False, False), (True, False), (False, True)])
@pytest.mark.parametrize("result_recovery", [False, True])
def test_supplemental_scope_does_not_replace_failed_baselines(
        monkeypatch, tmp_path, recovery_only, baseline_only, result_recovery):
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    monkeypatch.setattr(runner, "check_host_storage", lambda: {"checked": True})
    monkeypatch.setattr(runner, "check_runtime_tools", lambda: {"helm": "/reviewed/helm"})
    monkeypatch.setattr(runner.cluster, "frozen_inputs", lambda: {})
    directory = tmp_path / "run"
    args = ["runner", "--directory", str(directory), "--allow-temporary-listener-increase"]
    monkeypatch.setattr(sys, "argv", args + (["--recovery-only"] if recovery_only else [])
                        + (["--baseline-only"] if baseline_only else [])
                        + (["--result-recovery-admission"] if result_recovery else []))
    limits, loads, faults, receipts, cleaned = [], [], [], [], []
    monkeypatch.setattr(runner, "set_listener_limit", limits.append)

    def setup(deployment, **kwargs):
        deployment.mkdir()
        runner.cluster.save(deployment / "state.json", {})

    async def load(state, deployment, name, rps, seconds, fault):
        loads.append(name)
        runner.cluster.save(deployment / (name + ".json"),
                            {"passed": name != "baseline_1", "failed": int(name == "baseline_1")})

    async def phase(state, deployment, name, fault, **kwargs):
        faults.append(name)
        assert kwargs["result_recovery"] is result_recovery
        if name == "admission_result_recovery":
            assert fault == "none" and kwargs["seconds"] == kwargs["rps"] == 1
            assert kwargs["crash_after_commit_index"] == 0
        return {"passed": True, "accepted": 180, "admission_failed": 0, "accepted_not_completed": 0}

    def receipt(state, deployment, name, **kwargs):
        receipts.append(name)
        return {"passed": True}

    monkeypatch.setattr(runner.cluster, "setup", setup)
    monkeypatch.setattr(runner.cluster, "load_phase", load)
    monkeypatch.setattr(runner.admission, "phase", phase)
    monkeypatch.setattr(runner.receipts, "verify", receipt)
    collected = []

    def collect(state, deployment, name, expected_cluster):
        assert not cleaned, "Collection must finish before cleanup"
        collected.append(name)
        return {"name": name, "complete": name != "business_loss_3", "errors": []}

    monkeypatch.setattr(runner.evidence, "collect_phase", collect)
    monkeypatch.setattr(runner, "_delete_cluster", lambda kind, name, environment: cleaned.append(name))
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: "")
    if baseline_only and result_recovery:
        with pytest.raises(ValueError, match="Baseline-only"):
            runner.main()
        assert not limits and not cleaned and not directory.exists()
        return
    runner.main()
    result = json.loads((directory / "summary.json").read_text())
    assert limits == [512, 128] and cleaned == [result["cluster"]]
    assert result["production_sla_verified"] is False
    assert result["admission_result_recovery"] is result_recovery
    assert result["baseline_only"] is baseline_only
    assert collected == loads + receipts + faults
    assert result["evidence_complete"] is baseline_only
    assert "fixed_target_10rps" not in loads
    if recovery_only:
        assert loads == ["warmup"] and receipts == []
        assert faults == (["admission_result_recovery"] if result_recovery else []) + [
            "backlog", "admission_primary_loss", "business_loss_1", "business_loss_2", "business_loss_3"]
        assert result["peak_test"] == "not_in_recovery_scope"
        assert not any(row["name"].startswith("baseline_") for row in result["phases"])
    elif baseline_only:
        assert loads == ["warmup", "baseline_1", "baseline_2", "baseline_3"]
        assert receipts == faults == []
        assert result["peak_test"] == "skipped_baseline_failed"
    else:
        assert loads == ["warmup", "baseline_1", "baseline_2", "baseline_3"]
        assert len(receipts) == 3
        assert result["peak_test"] == "skipped_baseline_failed"
        assert result["phases"][1]["passed"] is False
