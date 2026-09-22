from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("multinode_eval", ROOT / "scripts/verify_multinode_capacity.py")
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


def test_service_replicas_require_distinct_worker_nodes():
    document = evaluation.deployment("test-upstream", "test:fixed", ["sleep", "10"], replicas=3)
    spec = document["spec"]["template"]["spec"]
    assert spec["nodeSelector"] == {"eval-role": "worker"}
    rule = spec["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
    assert rule["topologyKey"] == "kubernetes.io/hostname"
    assert rule["labelSelector"]["matchLabels"] == {"app": "test-upstream"}
    assert spec["automountServiceAccountToken"] is False


def test_controller_does_not_share_a_worker_failure_target():
    document = evaluation.deployment("test-driver", "test:fixed", ["sleep", "10"], control=True)
    spec = document["spec"]["template"]["spec"]
    assert spec["nodeSelector"] == {"eval-role": "control"}
    assert spec["tolerations"][0]["key"] == "node-role.kubernetes.io/control-plane"


def test_completed_multinode_report_is_immutable(tmp_path):
    path = tmp_path / "report.json"
    evaluation.save(path, {"passed": False})
    with pytest.raises(FileExistsError):
        evaluation.save(path, {"passed": True})
    assert 'false' in path.read_text()


def test_queue_change_and_probe_instrumentation_are_frozen():
    files = evaluation.frozen_inputs()
    assert "src/agentops_guard/backend/services/semantic_scanner.py" in files
    assert "evals/multinode-runtime/runtime.py" in files
    assert "scripts/verify_multinode_capacity.py" in files
    assert "scripts/verify_clock_consistency.py" in files
    assert "deploy/helm/agentops-guard/templates/deployment-opa.yaml" in files


def test_controller_passes_namespace_to_helm_before_applying_documents():
    source = (ROOT / "scripts/verify_multinode_capacity.py").read_text()
    helm_call = source[source.index('rendered = run(["helm"'):source.index("documents = []")]
    assert '"--namespace", state["namespace"]' in helm_call


@pytest.mark.parametrize("limit,allowed", [(128, False), (512, True), (1024, True)])
def test_four_node_preflight_rejects_insufficient_shared_inotify_limit(tmp_path, monkeypatch, limit, allowed):
    path = tmp_path / "max_user_instances"
    path.write_text(str(limit))
    monkeypatch.setattr(evaluation, "INOTIFY_INSTANCES_PATH", path)
    if allowed:
        evaluation.check_host_limits()
    else:
        with pytest.raises(RuntimeError, match=">= 512"):
            evaluation.setup(tmp_path / "not-created")
        assert not (tmp_path / "not-created").exists()
    assert path.read_text() == str(limit)  # Checking never mutates host configuration.


def test_capacity_requires_clock_validation_before_during_and_after_load():
    source = (ROOT / "scripts/verify_multinode_capacity.py").read_text()
    assert 'if not clock_before["passed"]:' in source
    assert 'passed = (clock_report["passed"] and' in source
    assert 'for key in ("before", "during", "after")' in source
    assert '"production_sla_verified": False' in source


@pytest.mark.parametrize("status,body,expected", [
    (503, {"detail": "Database temporarily unavailable"}, "database_unavailable"),
    (429, {"detail": "MCP server capacity exceeded"}, "capacity_exceeded"),
    (200, {"isError": True, "upstreamError": {"code": "timeout"}}, "upstream_timeout"),
    (200, {"isError": True, "upstreamError": {"code": "secret-value"}}, "upstream_error"),
    (200, {"isError": True, "upstreamError": {"code": ["secret-value"]}}, "upstream_error"),
    (503, {"detail": {"secret": "value"}}, "http_error"),
    (200, {"isError": True, "content": "secret-value"}, "tool_or_policy_error"),
    (200, {"isError": False}, None),
])
def test_diagnostic_categories_never_store_arbitrary_error_text(status, body, expected):
    assert evaluation.response_error(status, body) == expected


def test_proxy_transition_log_keeps_only_fixed_metadata(monkeypatch):
    monkeypatch.setattr(evaluation, "kubectl", lambda *args, **kwargs:
        "2026-09-06T01:02:03.000Z [WARNING] Server gateway/replica1 is DOWN, "
        "reason: private-response-text, check duration: 500ms.\n"
        "arbitrary private log text\n")
    assert evaluation.proxy_transitions({}) == [{"timestamp": "2026-09-06T01:02:03.000Z",
        "backend": "gateway", "replica": "replica1", "status": "DOWN", "check_ms": 500}]


def test_scoring_proxy_collection_excludes_arbitrary_fields_and_has_no_tail_cap(monkeypatch):
    calls = []

    def kubectl(state, *args):
        calls.append(args)
        if args[0] == "get":
            return json.dumps({"items": [{"metadata": {"name": "test-proxy"}}]})
        return ("2026-09-09T13:00:00.123Z SCORING_PROXY status=503 termination=sQ "
                "queue_ms=200 connect_ms=-1 response_ms=-1 total_ms=201\n"
                "arbitrary private log text\n"
                "2026-09-09T13:00:00.123Z SCORING_PROXY status=503 termination=sQ "
                "queue_ms=200 connect_ms=-1 response_ms=-1 total_ms=201 private-extra\n")

    monkeypatch.setattr(evaluation, "kubectl", kubectl)
    since = "2026-09-09T13:00:00Z"
    assert evaluation.scoring_proxy_events({}, since) == [{"timestamp": "2026-09-09T13:00:00.123Z",
        "status": 503, "termination": "sQ", "queue_ms": 200, "connect_ms": -1,
        "response_ms": -1, "total_ms": 201}]
    assert "--tail=-1" in calls[1] and "--since-time=" + since in calls[1]


def test_long_phase_runtime_logs_use_time_window_not_fixed_line_cap(monkeypatch):
    calls = []

    def kubectl(state, *args):
        calls.append(args)
        if args[0] == "get":
            return json.dumps({"items": [{"metadata": {"name": "test-pod"}}]})
        return 'EVAL_EVENT {"id":"mn_0123456789ab:1","stage":"gateway_ingress"}\n'

    monkeypatch.setattr(evaluation, "kubectl", kubectl)
    rows = evaluation.runtime_events({}, "mn_0123456789ab", since="2026-09-09T13:00:00Z")
    assert len(rows) == 3
    assert all("--tail=-1" in args and "--since-time=2026-09-09T13:00:00Z" in args
               for args in calls if args[0] == "logs")


@pytest.mark.parametrize("state,expected", [("response_received", "response_received"),
    ("outcome_unknown", "outcome_unknown"), ("private-value", None), (["private-value"], None)])
def test_post_tool_failure_confirmation_is_separate_from_business_success(state, expected):
    body = {"detail": {"code": "post_tool_database_unavailable", "tool_execution": {"state": state}}}
    assert evaluation.response_error(503, body) == "post_tool_database_unavailable"
    assert evaluation.tool_execution_outcome(body) == expected


@pytest.mark.parametrize('profile', ['conservative', 'responsive'])
def test_effective_patroni_config_is_checked_and_only_safe_fields_returned(monkeypatch, profile):
    config = {**evaluation.PATRONI_TIMING_PROFILES[profile], 'synchronous_mode': True,
        'synchronous_mode_strict': True, 'synchronous_node_count': 1, 'maximum_lag_on_failover': 0}
    document = {'metadata': {'annotations': {'config': json.dumps({**config, 'private': 'not-for-report'})}}}
    monkeypatch.setattr(evaluation, 'kubectl', lambda *args: json.dumps(document))
    assert evaluation.patroni_configuration({'patroni_timing_profile': profile}) == config
    document['metadata']['annotations']['config'] = json.dumps({**config, 'synchronous_mode_strict': False})
    with pytest.raises(RuntimeError, match='durability'):
        evaluation.patroni_configuration({'patroni_timing_profile': profile})


def test_setup_rejects_unknown_timing_before_creating_anything(tmp_path):
    target = tmp_path / 'not-created'
    with pytest.raises(ValueError, match='timing profile'):
        evaluation.setup(target, 'unknown')
    assert not target.exists()


def test_concurrency_ablation_is_bounded_and_does_not_change_defaults(tmp_path):
    with pytest.raises(ValueError, match="controlled concurrency"):
        evaluation.setup(tmp_path / "not-created", concurrency=100)
    assert not (tmp_path / "not-created").exists()
    import yaml
    values = yaml.safe_load((ROOT / "deploy/helm/agentops-guard/values.yaml").read_text())
    assert values["gatewayConcurrency"]["maxPerServer"] == 1
    assert values["gatewayConcurrency"]["waitSeconds"] == 1


def test_isolated_test_profile_separates_coordination_database_and_model_cpus():
    profiles = evaluation.node_profiles("isolated", list(range(12)))
    assert len(profiles) == 7
    groups = {role: set().union(*(set(p["cpuset"].split(",")) for p in profiles if p["role"] == role))
              for role in ("control", "database", "worker")}
    assert groups["control"].isdisjoint(groups["worker"] | groups["database"])
    assert groups["database"].isdisjoint(groups["worker"])
    assert len(evaluation.node_profiles("shared", list(range(12)))) == 4
    with pytest.raises(ValueError, match="12"):
        evaluation.node_profiles("isolated", list(range(8)))


def test_failsafe_is_opt_in_and_keeps_strict_sync_durability():
    from verify_patroni_kubernetes_failover import _patroni_config

    baseline = _patroni_config()["bootstrap"]["dcs"]
    candidate = _patroni_config(failsafe_mode=True)["bootstrap"]["dcs"]
    assert not baseline["failsafe_mode"] and candidate["failsafe_mode"]
    assert {**baseline, "failsafe_mode": True} == candidate
    assert candidate["synchronous_mode_strict"] and candidate["synchronous_node_count"] == 1


def test_receipt_confirmation_is_not_business_success_or_rescanned_output():
    from verify_multinode_receipts import accepted_confirmation

    final = {"state": "execution_confirmed", "attempts": 1, "clientMayReplay": False,
             "summary": {"resultScanned": False, "resultAvailable": False}}
    ledger = {"effects": 1, "receipts": 1}
    assert accepted_confirmation("outcome_unknown", final, ledger)
    assert not accepted_confirmation("outcome_unknown", {**final, "attempts": 2}, ledger)
    assert not accepted_confirmation("outcome_unknown", final, {"effects": 2, "receipts": 1})
    assert not accepted_confirmation("succeeded", final, ledger)


@pytest.mark.asyncio
async def test_database_probe_failures_are_preserved_and_monitor_stops(tmp_path, monkeypatch):
    import asyncio

    def unavailable(*args, **kwargs):
        raise RuntimeError("private connection details")
    monkeypatch.setattr(evaluation, "kubectl", unavailable)
    monkeypatch.setattr(evaluation, "etcd_disk_metrics", lambda _state: {"available": False})
    with pytest.raises(ValueError, match="load aborted"):
        async with evaluation.database_timeline({}, tmp_path, "probe"):
            await asyncio.sleep(.05)
            raise ValueError("load aborted")
    report = json.loads((tmp_path / "probe_database_timeline.json").read_text())
    assert report["observations"][0]["probe_unavailable"]
    assert not report["observations"][0]["commit_confirmed"]
    assert "private" not in json.dumps(report)
    assert report["observations"][0]["finished_at"] >= report["observations"][0]["at"]
    host = json.loads((tmp_path / "probe_host_timeline.json").read_text())
    assert host["observations"]
    assert "private" not in json.dumps(host)


@pytest.mark.asyncio
@pytest.mark.parametrize("database_target,role", [("business", "database_probe"), ("admission", "admission_database_probe")])
async def test_timeline_observes_the_explicit_database(tmp_path, monkeypatch, database_target, role):
    import asyncio
    calls = []

    def probe(state, *args, **kwargs):
        calls.append(args[-1])
        assert kwargs["input_text"] == "{}"
        return '{"role_writable": true, "commit_confirmed": true}'

    monkeypatch.setattr(evaluation, "kubectl", probe)
    monkeypatch.setattr(evaluation, "etcd_disk_metrics", lambda _state: {"available": False})
    async with evaluation.database_timeline({}, tmp_path, "target", database_target):
        await asyncio.sleep(.02)
    report = json.loads((tmp_path / "target_database_timeline.json").read_text())
    assert calls == [role] and report["database_target"] == database_target


def test_host_counters_are_fixed_aggregate_fields_only(tmp_path, monkeypatch):
    (tmp_path / "pressure").mkdir()
    for resource in ("cpu", "io", "memory"):
        (tmp_path / "pressure" / resource).write_text(
            "some avg10=1.25 avg60=2.50 avg300=3.75 total=123456\n"
            "full avg10=0.10 avg60=0.20 avg300=0.30 total=9876\n")
    (tmp_path / "vmstat").write_text(
        "pgmajfault 10\npswpin 20\npswpout 30\nnr_dirty 40\nnr_writeback 50\nprivate_field 99\n")
    monkeypatch.setattr(evaluation, "HOST_PROC", tmp_path)
    value = evaluation.host_resource_snapshot()
    assert value["available"]
    assert value["pressure"]["io"]["some"] == {"total_us": 123456, "avg10_percent": 1.25}
    assert value["vmstat"] == {"pgmajfault": 10, "pswpin": 20, "pswpout": 30, "nr_dirty": 40, "nr_writeback": 50}
    assert "private" not in json.dumps(value)


@pytest.mark.asyncio
async def test_host_probe_failure_stays_visible_without_private_text(tmp_path, monkeypatch):
    import asyncio

    def unavailable():
        raise OSError("private host metadata")

    monkeypatch.setattr(evaluation, "host_resource_snapshot", unavailable)
    monkeypatch.setattr(evaluation, "kubectl", lambda *a, **k: '{"commit_confirmed": true}')
    monkeypatch.setattr(evaluation, "etcd_disk_metrics", lambda _state: {"available": False})
    async with evaluation.database_timeline({}, tmp_path, "host-error"):
        await asyncio.sleep(.02)
    host = json.loads((tmp_path / "host-error_host_timeline.json").read_text())
    assert not host["observations"][0]["available"]
    assert host["observations"][0]["error_type"] == "OSError"
    assert "private" not in json.dumps(host)


def test_etcd_observation_keeps_only_disk_histograms_not_arbitrary_metric_labels():
    raw = ('etcd_disk_wal_fsync_duration_seconds_bucket{le="0.1"} 12\n'
           'etcd_disk_wal_fsync_duration_seconds_bucket{le="+Inf"} 13\n'
           'etcd_disk_wal_fsync_duration_seconds_sum 0.21\n'
           'etcd_disk_wal_fsync_duration_seconds_count 13\n'
           'etcd_disk_wal_fsync_duration_seconds_count{customer="private"} 99\n'
           'arbitrary_metric{token="private"} 42\n')
    rows = evaluation.parse_etcd_disk_metrics(raw)
    assert len(rows) == 4
    assert rows[1]["le"] == "+Inf" and rows[2]["value"] == .21
    assert "private" not in json.dumps(rows)
