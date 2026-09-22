import importlib.util
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("independent_cluster_eval", ROOT / "scripts/verify_multinode_admission.py")
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


def test_acceptance_is_not_business_completion():
    rows = [{"request_id": "one", "id": "read", "variant": "read", "accepted": True},
            {"request_id": "two", "id": "write", "variant": "write", "accepted": True},
            {"request_id": "three", "id": "failed", "variant": "read", "accepted": False}]
    statuses = [{"request_id": "one", "state": "accepted", "business_state": None},
                {"request_id": "two", "state": "imported", "business_state": "waiting_approval"}]
    counts = evaluation.counts(rows, statuses)
    assert counts["accepted"] == 2 and counts["admission_failed"] == 1
    assert counts["completed_as_expected"] == 1 and counts["accepted_not_completed"] == 1
    statuses[0]["business_state"] = "execution_confirmed"
    assert evaluation.counts(rows, statuses)["completed_as_expected"] == 1
    statuses[0]["business_state"] = "succeeded"
    assert evaluation.counts(rows, statuses)["completed_as_expected"] == 2


def test_untrusted_bodies_do_not_count_as_receipts():
    for body in (None, [], {}, {"accepted": True}, {"accepted": True, "requestId": "other"}):
        assert not evaluation.accepted(body, "expected")
    assert evaluation.accepted({"accepted": True, "requestId": "expected"}, "expected")


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout])
async def test_status_transport_errors_are_classified_without_private_text(error_type):
    def handler(request):
        raise error_type("private URL or header must not be saved", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await evaluation.query(client, {"admission_entrypoint": "http://controlled.invalid"},
                                        "controlled", [{"id": "one", "request_id": "one"}])
    assert result == [{"id": "one", "request_id": "one", "status": 0,
                       "transport_error": error_type.__name__}]


@pytest.mark.asyncio
async def test_status_invalid_json_is_not_a_transport_failure():
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"not json"))) as client:
        result = await evaluation.query(client, {"admission_entrypoint": "http://controlled.invalid"},
                                        "controlled", [{"id": "one", "request_id": "one"}])
    assert result == [{"id": "one", "request_id": "one", "status": 200,
                       "response_error": "invalid_json"}]


def test_cluster_setup_keeps_admission_api_without_business_credentials(monkeypatch, tmp_path):
    docs = []
    monkeypatch.setattr(evaluation.cluster, "apply", lambda state, values: docs.extend(values))
    monkeypatch.setattr(evaluation.cluster, "kubectl", lambda *args, **kwargs: "")
    monkeypatch.setattr(evaluation.cluster, "wait_deployment", lambda *args: None)
    monkeypatch.setattr(evaluation.cluster, "patroni_configuration", lambda *args: {"synchronous_mode_strict": True})
    state = {"namespace": "owned", "admission_namespace": "owned-admission", "patroni_timing_profile": "responsive",
             "patroni_failsafe": True}
    evaluation.setup_admission(state, tmp_path)
    api = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "independent-admission")
    rendered = json.dumps(api)
    assert "AGENTOPS_ADMISSION_DATABASE_URL" in rendered
    assert "AGENTOPS_DATABASE_URL" not in rendered and "agentops-guard-runtime" not in rendered
    container = api["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"]["path"] == "/recoveryz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    pg = next(d for d in docs if d["kind"] == "StatefulSet")
    assert pg["spec"]["template"]["spec"]["nodeSelector"] == {"eval-role": "admission-database"}
    assert pg["metadata"]["namespace"] == "owned-admission"


def test_host_limit_helper_rejects_unapproved_values():
    from run_two_layer_cluster_verification import set_listener_limit
    with pytest.raises(ValueError):
        set_listener_limit(1024)


@pytest.mark.parametrize("host_gib,system_gib", [(2, 20), (60, 2)])
def test_storage_preflight_checks_backing_and_system_volumes(monkeypatch, host_gib, system_gib):
    import run_two_layer_cluster_verification as runner
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: json.dumps({
        "host_free_bytes": host_gib * 1024**3, "system_free_bytes": system_gib * 1024**3}))
    with pytest.raises(RuntimeError, match="Windows disk headroom"):
        runner.check_host_storage()


def test_storage_preflight_requires_actual_measurements(monkeypatch):
    import run_two_layer_cluster_verification as runner
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: '{"host_free_bytes":null}')
    with pytest.raises(ValueError, match="valid free space"):
        runner.check_host_storage()
    storage = {"host_drive": "D", "host_free_bytes": 50 * 1024**3,
               "system_drive": "C", "system_free_bytes": 10 * 1024**3}
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: json.dumps(storage))
    assert runner.check_host_storage() == storage


def test_storage_failure_does_not_change_host_or_create_cluster(monkeypatch, tmp_path):
    import run_two_layer_cluster_verification as runner
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    directory = tmp_path / "must-not-exist"
    monkeypatch.setattr(sys, "argv", ["runner", "--directory", str(directory),
                                    "--allow-temporary-listener-increase"])
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: json.dumps({
        "host_free_bytes": 2 * 1024**3, "system_free_bytes": 2 * 1024**3}))
    def forbidden(*a, **k):
        pytest.fail("Storage failure must happen before host mutation or cluster creation")
    monkeypatch.setattr(runner, "set_listener_limit", forbidden)
    monkeypatch.setattr(runner.cluster, "setup", forbidden)
    with pytest.raises(RuntimeError, match="Windows disk headroom"):
        runner.main()
    assert not directory.exists()


def test_listener_helper_does_not_decode_windows_error_output(monkeypatch, tmp_path):
    import run_two_layer_cluster_verification as runner
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    calls = []
    def command(args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=1, stdout=b"\x95")
    monkeypatch.setattr(runner.subprocess, "run", command)
    with pytest.raises(RuntimeError, match="exit=1"):
        runner.set_listener_limit(128)
    assert calls[0]["stdout"] == runner.subprocess.DEVNULL
    assert not calls[0].get("text", False)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_setup_io_failure_keeps_owned_cleanup_and_restore_independent(monkeypatch, tmp_path, cleanup_fails):
    import run_two_layer_cluster_verification as runner
    listener = tmp_path / "listener"
    listener.write_text("128")
    monkeypatch.setattr(runner.cluster, "INOTIFY_INSTANCES_PATH", listener)
    monkeypatch.setattr(runner, "check_host_storage", lambda: {"checked": True})
    monkeypatch.setattr(runner, "check_runtime_tools", lambda: {
        "helm": "/controlled/helm", "docker": "/controlled/docker"})
    monkeypatch.setattr(runner, "uuid4", lambda: SimpleNamespace(hex="01234567"))
    monkeypatch.setattr(runner.cluster, "frozen_inputs", lambda: {})
    directory = tmp_path / "run"
    monkeypatch.setattr(sys, "argv", ["runner", "--directory", str(directory),
                                    "--allow-temporary-listener-increase"])
    limits, cleaned = [], []
    monkeypatch.setattr(runner, "set_listener_limit", limits.append)
    def broken_setup(*a, **kwargs):
        assert kwargs["cluster_name"] == "agentops-mn-01234567"
        raise OSError(5, "controlled filesystem I/O failure")
    monkeypatch.setattr(runner.cluster, "setup", broken_setup)
    def cleanup(kind, name, environment):
        cleaned.append(name)
        if cleanup_fails:
            raise RuntimeError("controlled cleanup failure")
    monkeypatch.setattr(runner, "_delete_cluster", cleanup)
    monkeypatch.setattr(runner.cluster, "run", lambda *a, **k: "")
    with pytest.raises(ExceptionGroup if cleanup_fails else OSError):
        runner.main()
    assert cleaned == ["agentops-mn-01234567"]
    assert limits == [512, 128]
    summary = json.loads((directory / "summary.json").read_text())
    assert summary["controller_error"] == "OSError"
    assert summary["listener_after"] == 128
    assert summary["phases"] == [] and summary["production_sla_verified"] is False
    if cleanup_fails:
        assert summary["cleanup_error"] == "RuntimeError"
    else:
        assert summary["test_containers_remaining"] == 0


def primary_observation(statuses=(503, 200, 503)):
    return {"collection_error_type": None, "probes": [
        {"pod": f"agentops-pg-{index}", "node": f"agentops-mn-test-worker{index + 4}",
         "role_label": "primary" if index == 0 else "replica", "status": status, "error_type": None}
        for index, status in enumerate(statuses)]}


@pytest.mark.parametrize("namespace", ["owned", "owned-admission"])
def test_primary_probe_uses_scoped_ips_not_stale_role_labels(monkeypatch, namespace):
    state = {"cluster": "agentops-mn-test", "namespace": "owned", "admission_namespace": "owned-admission"}
    target = {**state, "namespace": namespace}
    expected = primary_observation()
    pods = [{"metadata": {"name": row["pod"], "namespace": namespace,
                          "labels": {"role": row["role_label"]}},
             "spec": {"nodeName": row["node"]}, "status": {"podIP": f"10.244.{index + 4}.2"}}
            for index, row in enumerate(expected["probes"])]
    calls = []

    def kubectl(current, *args, **kwargs):
        calls.append((current["namespace"], args))
        if args[0] == "get":
            assert current == target
            assert args == ("get", "pods", "-l", "cluster-name=agentops-pg", "-o", "json")
            return json.dumps({"items": list(reversed(pods))})
        assert current == state  # Admission probes also run from the business driver.
        assert args[:6] == ("exec", "-i", "deployment/eval-driver", "--", "python", "-c")
        sent = json.loads(kwargs["input_text"])
        assert [row["ip"] for row in sent] == [f"10.244.{index + 4}.2" for index in range(3)]
        assert all(set(row) == {"pod", "node", "ip", "role_label"} for row in sent)
        return json.dumps([{**row, "ignored_body": "must not be saved"} for row in expected["probes"]])

    monkeypatch.setattr(evaluation.cluster, "kubectl", kubectl)
    observation = evaluation.primary_snapshot(state, target)
    assert observation == expected
    assert evaluation.confirmed_primary(observation)["pod"] == "agentops-pg-1"
    assert len(calls) == 2
    assert "client.head(" in evaluation.PRIMARY_PROBE_PROGRAM
    assert ":8008/primary" in evaluation.PRIMARY_PROBE_PROGRAM
    assert "follow_redirects=False" in evaluation.PRIMARY_PROBE_PROGRAM
    assert "client.get(" not in evaluation.PRIMARY_PROBE_PROGRAM


@pytest.mark.parametrize("statuses", [(200, 200, 503), (503, 503, 503), (200, None, 503), (200, 401, 503)])
def test_primary_selection_rejects_double_primary_or_uncertain_status(statuses):
    with pytest.raises(RuntimeError, match="fully observed unique"):
        evaluation.confirmed_primary(primary_observation(statuses))


def test_primary_collection_error_is_explicit_and_sanitized(monkeypatch):
    state = {"cluster": "agentops-mn-test", "namespace": "owned"}
    def fail(*args, **kwargs):
        raise RuntimeError("a private transport error or credential must not be persisted")
    monkeypatch.setattr(evaluation.cluster, "kubectl", fail)
    observation = evaluation.primary_snapshot(state, state)
    assert observation == {"probes": [], "collection_error_type": "RuntimeError"}
    with pytest.raises(RuntimeError):
        evaluation.confirmed_primary(observation)
    with pytest.raises(ValueError, match="outside"):
        evaluation.primary_snapshot(state, {**state, "namespace": "not-owned"})


@pytest.mark.parametrize("invalid", ["namespace", "node", "address", "duplicate_ip", "missing_pod"])
def test_primary_inventory_rejects_out_of_scope_targets_before_http(monkeypatch, invalid):
    state = {"cluster": "agentops-mn-test", "namespace": "owned"}
    pods = [{"metadata": {"name": f"agentops-pg-{index}", "namespace": "owned", "labels": {}},
             "spec": {"nodeName": f"agentops-mn-test-worker{index + 4}"},
             "status": {"podIP": f"10.244.{index + 4}.2"}} for index in range(3)]
    if invalid == "namespace":
        pods[0]["metadata"]["namespace"] = "other"
    elif invalid == "node":
        pods[0]["spec"]["nodeName"] = "other-cluster-worker4"
    elif invalid == "address":
        pods[0]["status"]["podIP"] = "127.0.0.1"
    elif invalid == "duplicate_ip":
        pods[0]["status"]["podIP"] = pods[1]["status"]["podIP"]
    else:
        pods.pop()
    def kubectl(current, *args, **kwargs):
        assert args[0] == "get", "Invalid inventory must not trigger HTTP probes"
        return json.dumps({"items": pods})
    monkeypatch.setattr(evaluation.cluster, "kubectl", kubectl)
    observation = evaluation.primary_snapshot(state, state)
    assert observation == {"probes": [], "collection_error_type": "ValueError"}


def fault_record(after=(503, 200, 503)):
    before = {**primary_observation((200, 503, 503)), "stage": "before"}
    during = {**primary_observation((None, 200, 503)), "stage": "isolated"}
    during["probes"][0]["error_type"] = "ConnectTimeout"
    current = {**primary_observation(after), "stage": "after"}
    return {"primary_snapshots": [before, during, current], "restored_at": 50,
            "node": before["probes"][0]["node"], "primary_before": "agentops-pg-0",
            "primary_after": "agentops-pg-1", "promotion_observed": True}


@pytest.mark.parametrize("fault", ["business_primary", "admission_primary"])
def test_actual_promotion_is_required_for_fault_pass(fault):
    assert evaluation.fault_verification_passed(fault, [fault_record()])
    # Even a stale/falsified promotion flag cannot turn an unchanged live primary into a pass.
    assert not evaluation.fault_verification_passed(fault, [fault_record((200, 503, 503))])
    assert not evaluation.fault_verification_passed(fault, [fault_record((503, 503, 503))])
    assert not evaluation.fault_verification_passed(fault, [])
    missing = fault_record()
    missing["primary_snapshots"].pop()
    assert not evaluation.fault_verification_passed(fault, [missing])


@pytest.mark.parametrize("failure", ["collector", "double_primary", "unrestored", "no_isolated", "after_timeout"])
def test_fault_gate_rejects_missing_or_conflicting_probe_evidence(failure):
    record = fault_record()
    if failure == "collector":
        record["primary_snapshots"][1]["collection_error_type"] = "TimeoutExpired"
    elif failure == "double_primary":
        record["primary_snapshots"][1] = {**primary_observation((200, 200, 503)), "stage": "isolated"}
    elif failure == "unrestored":
        record.pop("restored_at")
    elif failure == "no_isolated":
        record["primary_snapshots"].pop(1)
    else:
        record["primary_snapshots"][-1]["probes"][0].update(status=None, error_type="ConnectTimeout")
    assert not evaluation.fault_verification_passed("business_primary", [record])


async def test_selection_failure_keeps_already_sent_request_metadata(monkeypatch, tmp_path):
    state = {"independent_admission": True, "source": {}, "cluster": "agentops-mn-test",
             "namespace": "owned", "admission_entrypoint": "http://controlled.invalid"}
    monkeypatch.setattr(evaluation.cluster, "frozen_inputs", lambda: {})
    seed = {"server_id": "private-server-id", "admission_token": "private-admission-key"}
    monkeypatch.setattr(evaluation.cluster, "driver", lambda *args: seed)
    monkeypatch.setattr(evaluation, "primary_snapshot", lambda *args: primary_observation((503, 503, 503)))
    def forbidden(*args, **kwargs):
        pytest.fail("Uncertain primary must not trigger Docker operations")
    monkeypatch.setattr(evaluation.cluster, "run", forbidden)
    async def clock(*args):
        return {"passed": True}
    async def monitor_clock(stop):
        await stop.wait()
        return {"passed": True}
    @asynccontextmanager
    async def timeline(*args):
        yield
    class Client:
        def __init__(self, **kwargs):
            self.posts = 0
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def post(self, url, **kwargs):
            await asyncio.sleep(.03)
            self.posts += 1
            return evaluation.httpx.Response(202, json={
                "accepted": True, "durabilityConfirmed": True, "requestId": kwargs["json"]["requestId"]})
        async def get(self, url, **kwargs):
            return evaluation.httpx.Response(200, json={
                "accepted": True, "requestId": url.rsplit("/", 1)[-1], "state": "accepted"})
    monkeypatch.setattr(evaluation, "measure_clock", clock)
    monkeypatch.setattr(evaluation, "monitor_recovery_clock", monitor_clock)
    monkeypatch.setattr(evaluation.cluster, "database_timeline", timeline)
    monkeypatch.setattr(evaluation.httpx, "AsyncClient", Client)
    with pytest.raises(RuntimeError, match="fully observed unique"):
        await evaluation.phase(state, tmp_path, "controlled", seconds=.09, rps=100)
    interrupted = json.loads((tmp_path / "controlled_interrupted.json").read_text())
    assert interrupted["controller_error"] == "RuntimeError"
    assert interrupted["task_error_types"] == ["RuntimeError"]
    assert len(interrupted["requests"]) == 9
    assert all(row["accepted"] for row in interrupted["requests"])
    assert set(interrupted["requests"][0]) == {
        "id", "request_id", "variant", "status", "accepted", "at", "latency_ms", "schedule_delay_ms"}
    assert interrupted["faults"][0]["promotion_observed"] is False
    assert interrupted["production_sla_verified"] is False
    assert not (tmp_path / "controlled.json").exists()
    for report in tmp_path.glob("*.json"):
        text = report.read_text()
        assert "private-admission-key" not in text and "private-server-id" not in text
        assert "controlled probe" not in text and '"arguments"' not in text


def test_result_query_seed_routing_preserves_default_and_nine_write_positions():
    seed = {"server_id": "legacy", "read_server_id": "reviewed", "read_tool": "read_status_v2"}
    phase = "mn_0123456789ab"
    plain = evaluation.admission_payload(seed, phase, 0)
    assert plain["serverId"] == "legacy" and plain["name"] == "read_status"
    assert plain["arguments"] == {"request_id": phase + ":0", "variant": "short"}
    payloads = [evaluation.admission_payload(seed, phase, index, result_recovery=True,
                    crash_after_commit_index=0) for index in range(180)]
    writes = [payload for payload in payloads if payload["name"] == "write_file"]
    assert len(writes) == 9 and all(payload["serverId"] == "legacy" for payload in writes)
    assert all("crash_after_commit" not in payload["arguments"] for payload in payloads[1:])
    assert payloads[0]["arguments"]["crash_after_commit"] is True
    assert payloads[0]["serverId"] == "reviewed" and payloads[0]["name"] == "read_status_v2"
    assert all("operation_id" not in payload["arguments"] for payload in payloads)
    assert payloads[0]["requestId"] == plain["requestId"]


@pytest.mark.parametrize("count,enabled,index", [
    (180, False, 0), (180, True, -1), (180, True, 180), (180, True, 19),
    (180, True, 179), (180, True, True), (180, True, 1.0), (0, True, 0)])
def test_commit_loss_must_target_an_existing_reviewed_read(count, enabled, index):
    with pytest.raises(ValueError, match="in-range result-query read"):
        evaluation.validate_recovery_options(count, enabled, index)
    evaluation.validate_recovery_options(180, False, None)
    evaluation.validate_recovery_options(180, True, 0)


def ledger_evidence():
    phase = "mn_0123456789ab"
    rows = [{"id": phase + ":" + str(i), "request_id": "uuid" + str(i),
             "variant": "read", "accepted": True} for i in range(2)]
    ledger = {"phase": phase, "read_only": True, "rows": [
        {"request_id": row["id"], "operation_id": str(i) * 64, "kind": "read", "tool": "read_status_v2",
         "executions": 1, "result_sha256": "a" * 64, "effect_present": True, "result_integrity": True}
        for i, row in enumerate(rows)]}
    oracle = {"upstream_reads": 0, "duplicate_executions": 0, "unauthorized_writes": 0,
              "acknowledged_missing_receipts": 2}
    return phase, rows, ledger, oracle


def test_v2_counts_independent_effects_without_overwriting_business_evidence():
    phase, rows, ledger, oracle = ledger_evidence()
    combined = evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)
    assert oracle["acknowledged_missing_receipts"] == 2 and oracle["upstream_reads"] == 0
    assert combined["upstream_reads"] == 2 and combined["acknowledged_missing_receipts"] == 0
    assert combined["v2_ledger_valid"] and not combined["duplicate_executions"]
    ledger["rows"][0]["executions"] = 2
    assert evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)["duplicate_executions"] == 1
    ledger["rows"][1]["effect_present"] = False
    result = evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)
    assert result["upstream_reads"] == 1 and result["acknowledged_missing_receipts"] == 1
    assert not result["v2_ledger_valid"]
    oracle["unauthorized_writes"] = 1
    assert evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)["unauthorized_writes"] == 1


def test_v2_rejects_duplicate_ledger_identity_or_unconfirmed_acceptance():
    phase, rows, ledger, oracle = ledger_evidence()
    rows[0]["accepted"] = False
    result = evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)
    assert result["executed_without_acknowledgement"] == 1
    ledger["rows"][1]["operation_id"] = ledger["rows"][0]["operation_id"]
    result = evaluation.reconcile_v2_effects(phase, rows, oracle, ledger)
    assert not result["v2_ledger_valid"] and result["v2_duplicate_ledger_rows"] == 1


def test_scoring_reconciles_both_original_id_and_uuid_without_aggregate_shortcut():
    _phase, rows, _ledger, _oracle = ledger_evidence()
    actual = [row["id"] for row in rows]
    repeated_one = [{"request_id": rows[0]["id"], "status": "ok"},
                    {"request_id": rows[0]["request_id"], "status": "ok"}]
    check = evaluation.reconcile_scoring(rows, actual, repeated_one)
    assert not check["passed"] and check["missing_scoring_ids"] == [rows[1]["id"]]
    assert check["successfully_scored_read_count"] == 1  # Two successful rows do not mean two different reads.
    complete = [*repeated_one, {"request_id": rows[1]["request_id"], "status": "ok"}]
    assert evaluation.reconcile_scoring(rows, actual, complete)["passed"]
    for extra in ({"request_id": None, "status": "ok"}, {"request_id": rows[0]["id"], "status": "error"}):
        assert not evaluation.reconcile_scoring(rows, actual, [*complete, extra])["passed"]


def recovered_body(request_id):
    return {"content": [{"type": "text", "text": "Service status is healthy."}], "isError": False,
        "provenance": {"source": "mcp_tool_result", "trust": "untrusted", "transformations": ["scanned"]},
        "invocation": {"requestId": request_id, "state": "succeeded", "attempts": 1, "resultStored": True,
                       "clientMayReplay": False, "summary": {"resultScanned": True}}}


@pytest.mark.parametrize("mutation", ["text", "error", "provenance", "identity", "attempts", "stored", "scanned", "replay"])
def test_result_verification_requires_original_safe_output_and_bound_success(mutation):
    body = recovered_body("uuid")
    assert evaluation.recovered_result_checks(body, "uuid")["passed"]
    if mutation == "text":
        body["content"][0]["text"] = "private changed content must not be saved"
    elif mutation == "error":
        body["isError"] = True
    elif mutation == "provenance":
        body["provenance"]["transformations"] = None
    elif mutation == "identity":
        body["invocation"]["requestId"] = "other"
    elif mutation == "attempts":
        body["invocation"]["attempts"] = 2
    elif mutation == "stored":
        body["invocation"]["resultStored"] = False
    elif mutation == "scanned":
        body["invocation"]["summary"]["resultScanned"] = False
    else:
        body["invocation"]["clientMayReplay"] = True
    evidence = evaluation.recovered_result_checks(body, "uuid")
    assert not evidence["passed"] and all(type(value) is bool for value in evidence.values())
    assert "private changed content" not in json.dumps(evidence)


def test_each_final_recovered_result_needs_its_own_verified_get():
    invocations = [{"requestId": "one", "result_recovered": True}, {"requestId": "two", "result_recovered": True}]
    assert not evaluation.recovered_results_complete(invocations, [{"request_id": "one", "passed": True}])
    checks = [{"request_id": name, "passed": True} for name in ("one", "two")]
    assert evaluation.recovered_results_complete(invocations, checks)
    assert not evaluation.recovered_results_complete(invocations, checks + [checks[0]])


async def test_forced_admission_recovery_collects_original_result_then_fresh_scoring(monkeypatch, tmp_path):
    state = {"independent_admission": True, "receipts_enabled": True, "source": {},
        "admission_entrypoint": "http://admission.invalid", "entrypoint": "http://gateway.invalid"}
    phase = "mn_0123456789ab"
    seed = {"server_id": "legacy", "read_server_id": "reviewed", "read_tool": "read_status_v2",
            "token": "private-token", "admission_token": "private-admission"}
    payload = evaluation.admission_payload(seed, phase, 0, result_recovery=True, crash_after_commit_index=0)
    request_id = payload["requestId"]
    invocation = {"requestId": request_id, "state": "succeeded", "attempts": 1,
        "receipt_bound": True, "result_stored": True, "result_recovered": True, "result_scanned": True}
    ledger = {"phase": phase, "read_only": True, "rows": [{"request_id": phase + ":0",
        "operation_id": "a" * 64, "kind": "read", "tool": "read_status_v2", "executions": 1,
        "result_sha256": "b" * 64, "effect_present": True, "result_integrity": True}]}
    sequence, posts = [], []
    def driver(_state, role, data):
        if role == "seed_admission":
            assert data == {"phase": phase, "result_recovery": True}
            return seed
        assert role == "stats"
        sequence.append("stats")
        count = sequence.count("stats")
        return {"invocations": [invocation], "upstream_reads": 0, "duplicate_executions": 0,
            "unauthorized_writes": 0, "acknowledged_missing_receipts": 1,
            "completed_scans": count, "scan_attempts": count, "semantic_error_events": 0, "audit_valid": True,
            "scoring_requests": [{"request_id": request_id, "status": "ok"} for _ in range(count)]}
    class Client:
        def __init__(self, **kwargs):
            assert kwargs["timeout"] == 10
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def post(self, url, **kwargs):
            assert kwargs["json"] == payload
            posts.append(url)
            return evaluation.httpx.Response(202, json={"accepted": True, "requestId": request_id,
                "durabilityConfirmed": True})
        async def get(self, url, **kwargs):
            if url.endswith("/result"):
                sequence.append("result_get")
                assert kwargs["headers"]["X-Eval-Request"] == request_id
                assert kwargs["headers"]["Authorization"] == "Bearer private-token"
                return evaluation.httpx.Response(200, json=recovered_body(request_id))
            return evaluation.httpx.Response(200, json={"accepted": True, "durabilityConfirmed": False,
                "requestId": request_id, "state": "completed", "businessState": "succeeded"})
    async def clock(*args):
        return {"passed": True}
    async def monitor(stop):
        await stop.wait()
        return {"passed": True}
    @asynccontextmanager
    async def timeline(*args):
        yield
    monkeypatch.setattr(evaluation, "uuid4", lambda: SimpleNamespace(hex="0123456789ab"))
    monkeypatch.setattr(evaluation.cluster, "frozen_inputs", lambda: {})
    monkeypatch.setattr(evaluation.cluster, "driver", driver)
    monkeypatch.setattr(evaluation, "v2_ledger", lambda *args: ledger)
    monkeypatch.setattr(evaluation.httpx, "AsyncClient", Client)
    monkeypatch.setattr(evaluation, "measure_clock", clock)
    monkeypatch.setattr(evaluation, "monitor_recovery_clock", monitor)
    monkeypatch.setattr(evaluation.cluster, "database_timeline", timeline)
    result = await evaluation.phase(state, tmp_path, "admission_result_recovery", fault="none", seconds=.01,
        rps=100, result_recovery=True, crash_after_commit_index=0)
    assert result["passed"] and result["forced_result_recovery_passed"]
    assert result["recovered_results_verified"] and result["per_request_scoring"]["passed"]
    assert result["business_reconciliation"]["acknowledged_missing_receipts"] == 1
    assert result["reconciliation"]["acknowledged_missing_receipts"] == 0
    assert sequence == ["stats", "result_get", "stats"]
    assert len(posts) == 11 and all(url.endswith("/v1/admissions") for url in posts)
    marker = json.loads((tmp_path / "admission_result_recovery_started.json").read_text())
    assert marker["admission"] and marker["result_recovery"] and marker["crash_after_commit_index"] == 0
    assert (tmp_path / "admission_result_recovery_v2_ledger.json").exists()
    for path in tmp_path.glob("*.json"):
        report = path.read_text()
        assert "private-token" not in report and "private-admission" not in report
        assert "Service status is healthy" not in report and '"arguments"' not in report
    bad_invocation = {**invocation, "result_recovered": False}
    rows = [{"id": phase + ":0", "request_id": request_id, "variant": "read", "accepted": True}]
    assert not evaluation.forced_recovery_passed(0, rows, ledger, [bad_invocation], result["recovered_result_checks"])
