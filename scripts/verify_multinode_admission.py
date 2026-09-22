"""Live independent admission -> importer -> Outbox -> Redis -> worker evaluation.

Only disposable test identities. Never print tokens, DSNs, request/response bodies.
The admission DB and business DB use separate Patroni groups and kind nodes.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from ipaddress import ip_address
import json
import math
from pathlib import Path
import re
import secrets
import subprocess
import time
from uuid import NAMESPACE_URL, uuid4, uuid5

from cryptography.fernet import Fernet
import httpx

import verify_multinode_capacity as cluster
from collect_multinode_evidence import v2_ledger
from verify_multinode_invocations import monitor_recovery_clock, scale_workers
from verify_clock_consistency import measure_clock
from verify_patroni_kubernetes_failover import _cluster_documents, CLUSTER_NAME


PRIMARY_PROBE_PROGRAM = r'''
import json, sys
from concurrent.futures import ThreadPoolExecutor
import httpx

def probe(target):
    result = {key: target[key] for key in ("pod", "node", "role_label")}
    result.update(status=None, error_type=None)
    host = "[" + target["ip"] + "]" if ":" in target["ip"] else target["ip"]
    try:
        with httpx.Client(timeout=2, trust_env=False, follow_redirects=False) as client:
            result["status"] = client.head("http://" + host + ":8008/primary").status_code
    except httpx.HTTPError as error:
        result["error_type"] = type(error).__name__
    return result

with ThreadPoolExecutor(max_workers=3) as pool:
    result = list(pool.map(probe, json.load(sys.stdin)))
print(json.dumps(result))
'''


def primary_snapshot(state, target):
    """HEAD only, from the business driver, against the three scoped Pod IPs.

    /primary needs both a running primary and leader lock; role labels alone
    can lag a switchover. No response body, arbitrary address or secret is saved.
    https://patroni.readthedocs.io/en/latest/rest_api.html#health-check-endpoints
    """
    if target["namespace"] not in {state["namespace"], state.get("admission_namespace")}:
        raise ValueError("Primary probe namespace is outside the owned test")
    observation = {"probes": [], "collection_error_type": None}
    try:
        pods = json.loads(cluster.kubectl(target, "get", "pods", "-l",
            "cluster-name=" + CLUSTER_NAME, "-o", "json"))["items"]
        if (len(pods) != 3 or {pod["metadata"]["name"] for pod in pods}
                != {CLUSTER_NAME + "-" + str(i) for i in range(3)}):
            raise ValueError("Expected the three configured Patroni pods")
        targets = []
        for pod in sorted(pods, key=lambda row: row["metadata"]["name"]):
            node = pod["spec"]["nodeName"]
            address = ip_address(pod["status"]["podIP"])
            if (pod["metadata"]["namespace"] != target["namespace"]
                    or not re.fullmatch(re.escape(state["cluster"]) + r"-worker[2-9]?", node)
                    or address.is_loopback or address.is_unspecified or address.is_multicast):
                raise ValueError("Unexpected Patroni pod address or node")
            targets.append({"pod": pod["metadata"]["name"], "node": node, "ip": str(address),
                "role_label": pod["metadata"]["labels"].get("role")})
        if len({row["ip"] for row in targets}) != 3:
            raise ValueError("Patroni Pod IPs must be distinct")
        probes = json.loads(cluster.kubectl(state, "exec", "-i", "deployment/eval-driver", "--",
            "python", "-c", PRIMARY_PROBE_PROGRAM, input_text=json.dumps(targets), timeout=15))
        if len(probes) != 3 or any(
            {key: probe[key] for key in ("pod", "node", "role_label")}
            != {key: target[key] for key in ("pod", "node", "role_label")}
            for probe, target in zip(probes, targets, strict=True)
        ):
            raise ValueError("Primary response does not match the scoped Pod inventory")
        observation["probes"] = [
            {key: probe[key] for key in ("pod", "node", "role_label", "status", "error_type")}
            for probe in probes
        ]
    except (RuntimeError, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        observation["collection_error_type"] = type(error).__name__
    return observation


def confirmed_primary(observation):
    probes = observation["probes"]
    primaries = [row for row in probes if row.get("status") == 200]
    if (observation.get("collection_error_type") or len(probes) != 3
            or any(row.get("error_type") or row.get("status") not in {200, 503} for row in probes)
            or len(primaries) != 1):
        raise RuntimeError("No fully observed unique Patroni /primary=200")
    return primaries[0]


def fault_verification_passed(fault, records):
    if fault not in {"business_primary", "admission_primary"}:
        return True
    if len(records) != 1:
        return False
    record = records[0]
    snapshots = record.get("primary_snapshots", [])
    before = [row for row in snapshots if row["stage"] == "before"]
    during = [row for row in snapshots if row["stage"] == "isolated"]
    after = [row for row in snapshots if row["stage"] == "after"]
    if (len(before) != 1 or not during or not after or record.get("restored_at") is None
            or any(row.get("collection_error_type") for row in snapshots)
            or any(sum(probe.get("status") == 200 for probe in row["probes"]) > 1 for row in snapshots)):
        return False
    try:
        previous, current = confirmed_primary(before[0]), confirmed_primary(after[-1])
    except RuntimeError:
        return False
    return (previous["pod"] != current["pod"] and record.get("node") == previous["node"]
            and record.get("primary_before") == previous["pod"]
            and record.get("primary_after") == current["pod"]
            and record.get("promotion_observed") is True)


def admission_state(state):
    return {**state, "namespace": state["admission_namespace"]}


def setup_admission(state, directory):
    other = admission_state(state)
    cluster.apply(other, [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": other["namespace"]}}])
    password = secrets.token_urlsafe(40)
    docs = _cluster_documents(other["namespace"], password, secrets.token_urlsafe(40),
        timing_profile=state["patroni_timing_profile"], failsafe_mode=state["patroni_failsafe"])
    for doc in docs:
        if doc["kind"] == "StatefulSet":
            pod = doc["spec"]["template"]["spec"]
            pod["nodeSelector"] = {"eval-role": "admission-database"}
            pod["affinity"] = {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
                "topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {
                    "application": "patroni", "cluster-name": CLUSTER_NAME}}}]}}
    cluster.apply(other, [doc for doc in docs if doc["kind"] != "Pod"])
    cluster.kubectl(other, "rollout", "status", "statefulset/" + CLUSTER_NAME, "--timeout=240s", timeout=250)
    # The HTTP service is not given ANY business DB or business API credential.
    secret = {"AGENTOPS_ADMISSION_DATABASE_URL":
        f"postgresql+psycopg://postgres:{password}@{CLUSTER_NAME}.{other['namespace']}.svc.cluster.local:5432/postgres",
        "AGENTOPS_ADMISSION_ENCRYPTION_KEY": Fernet.generate_key().decode()}
    cluster.apply(state, [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "eval-admission-runtime"},
                           "stringData": secret}])
    env = [{"name": "AGENTOPS_ADMISSION_ENABLED", "value": "true"}]
    env += [{"name": key, "valueFrom": {"secretKeyRef": {"name": "eval-admission-runtime", "key": key}}}
            for key in secret]
    # Add the independent credential only to the trusted seed process. Its output
    # is consumed in-memory by this controller, not written into the report.
    driver_patch = {"spec": {"template": {"spec": {"containers": [{"name": "eval-driver", "env": env}]}}}}
    cluster.kubectl(state, "patch", "deployment/eval-driver", "--type=strategic", "--patch", json.dumps(driver_patch))
    cluster.wait_deployment(state, "eval-driver")
    cluster.kubectl(state, "exec", "deployment/eval-driver", "--", "python", "-m",
                    "agentops_guard.admission.cli", "migrate")
    api = cluster.deployment("independent-admission", cluster.IMAGE,
        ["python", "-m", "agentops_guard.admission.cli", "serve", "--host", "0.0.0.0", "--port", "8003"],
        replicas=2, env=env, port=8003)
    api["spec"]["template"]["spec"]["containers"][0]["readinessProbe"] = {
        "httpGet": {"path": "/recoveryz", "port": 8003}, "periodSeconds": 2, "timeoutSeconds": 2, "failureThreshold": 2}
    api["spec"]["template"]["spec"]["containers"][0]["livenessProbe"] = {
        "httpGet": {"path": "/healthz", "port": 8003}, "periodSeconds": 2, "timeoutSeconds": 2, "failureThreshold": 3}
    service = cluster.service("independent-admission", 8003)
    service["spec"].update(type="NodePort")
    service["spec"]["ports"][0]["nodePort"] = 30083
    importer = cluster.deployment("independent-importer", cluster.IMAGE,
        ["python", "-m", "agentops_guard.admission.cli", "import"], replicas=2,
        env=[*env, {"name": "AGENTOPS_COMPONENT", "value": "worker"},
            {"name": "AGENTOPS_DATABASE_URL", "valueFrom": {"secretKeyRef": {
                "name": "agentops-guard-runtime", "key": "AGENTOPS_DATABASE_URL"}}},
            {"name": "AGENTOPS_INVOCATION_ENCRYPTION_KEY", "valueFrom": {"secretKeyRef": {
                "name": "eval-invocation-key", "key": "AGENTOPS_INVOCATION_ENCRYPTION_KEY"}}}])
    importer["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [
        {"configMapRef": {"name": "agentops-guard-config"}}]
    cluster.apply(state, [api, service, importer])
    for name in ("independent-admission", "independent-importer"):
        cluster.wait_deployment(state, name)
    cluster.save(directory / "admission_setup.json", {
        "replicas": {"http": 2, "importer": 2, "postgresql": 3},
        "same_business_database": False, "separate_kind_database_nodes": True,
        "same_physical_host_disk_and_control_plane": True, "automatic_queue_path": True,
        "admission_durability": cluster.patroni_configuration(other),
        "business_durability": cluster.patroni_configuration(state),
        "routing_probe": "/recoveryz", "database_readiness_probe": "/readyz",
        "routing_does_not_confirm_acceptance": True,
        "admission_api_receives_business_credentials": False})


def accepted(body, request_id):
    return isinstance(body, dict) and body.get("accepted") is True and body.get("requestId") == request_id


def admission_payload(seed, phase_id, index, *, result_recovery=False, crash_after_commit_index=None):
    external_id = f"{phase_id}:{index}"
    is_write = index % 20 == 19
    arguments = {"request_id": external_id}
    arguments.update({"path": "/controlled/probe.txt", "content": "controlled probe"}
                     if is_write else {"variant": "short"})
    if index == crash_after_commit_index:
        if is_write or not result_recovery:
            raise ValueError("Controlled commit loss requires a result-query read")
        arguments["crash_after_commit"] = True
    return {"requestId": str(uuid5(NAMESPACE_URL, "agentops-independent:" + external_id)),
        "serverId": seed["read_server_id"] if result_recovery and not is_write else seed["server_id"],
        "name": seed["read_tool"] if result_recovery and not is_write else "write_file" if is_write else "read_status",
        "arguments": arguments}


def validate_recovery_options(count, result_recovery, crash_after_commit_index):
    if crash_after_commit_index is not None and (
        not result_recovery or type(crash_after_commit_index) is not int
        or not 0 <= crash_after_commit_index < count or crash_after_commit_index % 20 == 19
    ):
        raise ValueError("Commit-loss index must select an in-range result-query read")


def reconcile_v2_effects(phase_id, rows, oracle, ledger):
    """Do not substitute the business DB's empty read table for independent effects."""
    read_rows = {row["id"]: row for row in rows if row["variant"] == "read"}
    acknowledged = {key for key, row in read_rows.items() if row["accepted"]}
    entries = ledger["rows"]
    reads = {row["request_id"] for row in entries if row["effect_present"]}
    identifiers = [row["request_id"] for row in entries]
    operations = [row["operation_id"] for row in entries]
    invalid = sum(row["request_id"] not in read_rows or row["kind"] != "read"
        or row["tool"] != "read_status_v2" or type(row["executions"]) is not int or row["executions"] < 1
        or not row["effect_present"] or not row["result_integrity"] for row in entries)
    duplicate_rows = len(identifiers) - len(set(identifiers)) + len(operations) - len(set(operations))
    return {**oracle, "upstream_reads": len(reads),
        "duplicate_executions": oracle["duplicate_executions"] + sum(max(0, row["executions"] - 1) for row in entries),
        "acknowledged_missing_receipts": len(acknowledged - reads),
        "executed_without_acknowledgement": len(reads - acknowledged),
        "executed_without_any_confirmation": len(reads - acknowledged),
        "unacknowledged_read_ids": sorted(reads - acknowledged),
        "v2_ledger_valid": (ledger["phase"] == phase_id and ledger["read_only"] is True
            and not invalid and not duplicate_rows and oracle["upstream_reads"] == 0),
        "v2_invalid_ledger_entries": invalid, "v2_duplicate_ledger_rows": duplicate_rows,
        "v2_unexpected_business_reads": oracle["upstream_reads"], "actual_read_ids": sorted(reads)}


def reconcile_scoring(rows, actual_read_ids, scoring_requests):
    by_id = {key: row["id"] for row in rows for key in (row["id"], row["request_id"])}
    actual = set(actual_read_ids)
    scored = {by_id[row["request_id"]] for row in scoring_requests
              if row["status"] == "ok" and row["request_id"] in by_id}
    unmatched = sum(row["request_id"] not in by_id for row in scoring_requests)
    failed = sum(row["status"] != "ok" for row in scoring_requests)
    return {"actual_read_count": len(actual), "successfully_scored_read_count": len(actual & scored),
        "missing_scoring_ids": sorted(actual - scored), "unexpected_scoring_ids": sorted(scored - actual),
        "unmatched_scoring_records": unmatched, "failed_scoring_records": failed,
        "passed": not (actual - scored or scored - actual or unmatched or failed)}


def recovered_result_checks(body, request_id):
    if not isinstance(body, dict):
        body = {}
    invocation = body.get("invocation")
    invocation = invocation if isinstance(invocation, dict) else {}
    summary = invocation.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    provenance = body.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    transformations = provenance.get("transformations")
    checks = {
        "original_result_matches": body.get("content") == [{"type": "text", "text": "Service status is healthy."}],
        "structured_result_absent": body.get("structuredContent") is None,
        "tool_error_absent": body.get("isError") is False,
        "provenance_scanned": provenance.get("source") == "mcp_tool_result"
            and provenance.get("trust") == "untrusted" and isinstance(transformations, list) and "scanned" in transformations,
        "original_invocation_matches": invocation.get("requestId") == request_id,
        "succeeded": invocation.get("state") == "succeeded",
        "one_attempt": type(invocation.get("attempts")) is int and invocation["attempts"] == 1,
        "result_stored": invocation.get("resultStored") is True,
        "result_scanned": summary.get("resultScanned") is True,
        "replay_forbidden": invocation.get("clientMayReplay") is False,
    }
    return {**checks, "passed": all(checks.values())}


async def verify_recovered_results(state, token, rows, invocations):
    allowed = {row["request_id"] for row in rows if row["variant"] == "read"}
    evidence = []
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        for row in invocations:
            if row.get("result_recovered") is not True:
                continue
            request_id = row["requestId"]
            item = {"request_id": request_id, "status": 0, "scope_valid": request_id in allowed,
                    "checks": recovered_result_checks(None, request_id), "passed": False}
            if item["scope_valid"]:
                try:
                    response = await client.get(state["entrypoint"] + "/mcp/invocations/" + request_id + "/result",
                        headers={"Authorization": "Bearer " + token, "X-Eval-Request": request_id})
                    item["status"] = response.status_code
                    if response.status_code == 200:
                        item["checks"] = recovered_result_checks(response.json(), request_id)
                        item["passed"] = item["checks"]["passed"]
                except (httpx.HTTPError, ValueError) as error:
                    item["error_type"] = type(error).__name__
            evidence.append(item)
    return evidence


def recovered_results_complete(invocations, result_checks):
    recovered = {row["requestId"] for row in invocations if row.get("result_recovered") is True}
    checked = {row["request_id"] for row in result_checks if row["passed"] is True}
    return (recovered == checked and len(result_checks) == len(checked)
            and all(row["passed"] is True for row in result_checks))


def forced_recovery_passed(index, rows, ledger, invocations, result_checks):
    if index is None:
        return True
    selected = [row for row in rows if row["id"].endswith(":" + str(index))]
    if len(selected) != 1 or not selected[0]["accepted"]:
        return False
    original = selected[0]
    effects = [row for row in ledger["rows"] if row["request_id"] == original["id"]]
    invocation = [row for row in invocations if row["requestId"] == original["request_id"]]
    checks = [row for row in result_checks if row["request_id"] == original["request_id"]]
    return (len(effects) == len(invocation) == len(checks) == 1
        and effects[0]["effect_present"] is True and effects[0]["result_integrity"] is True
        and effects[0]["executions"] == invocation[0]["attempts"] == 1
        and invocation[0]["state"] == "succeeded"
        and all(invocation[0].get(field) is True for field in (
            "receipt_bound", "result_stored", "result_recovered", "result_scanned"))
        and checks[0]["passed"] is True)


def snapshot(body):
    return {"state": body.get("state"), "business_state": body.get("businessState"),
        "observed_at": body.get("businessObservedAt"), "snapshot": body.get("businessStatusIsSnapshot") is True}


def counts(rows, statuses):
    by_id = {row["request_id"]: row for row in statuses}
    acknowledged = [row for row in rows if row["accepted"]]
    expected = []
    for row in acknowledged:
        current = by_id.get(row["request_id"], {})
        if ((row["variant"] == "write" and current.get("business_state") == "waiting_approval")
                or (row["variant"] == "read" and current.get("business_state") == "succeeded")):
            expected.append(row["id"])
    return {"attempted": len(rows), "accepted": len(acknowledged),
        "admission_failed": len(rows) - len(acknowledged), "completed_as_expected": len(expected),
        "accepted_not_completed": len(acknowledged) - len(expected), "expected_ids": expected,
        "accepted_missing": sum(by_id.get(row["request_id"], {}).get("status") == 404 for row in acknowledged),
        "outcome_unknown": sum(row.get("business_state") == "outcome_unknown" for row in statuses)}


async def query(client, state, token, rows):
    limit = asyncio.Semaphore(4)

    async def one(row):
        async with limit:
            result = {"id": row["id"], "request_id": row["request_id"], "status": 0}
            try:
                response = await client.get(state["admission_entrypoint"] + "/v1/admissions/" + row["request_id"],
                                            headers={"X-AgentOps-Admission-Key": token})
                result["status"] = response.status_code
                if response.status_code == 200:
                    body = response.json()
                    if accepted(body, row["request_id"]):
                        result.update(snapshot(body))
            except httpx.TransportError as error:
                result["transport_error"] = type(error).__name__
            except ValueError:
                result["response_error"] = "invalid_json"
            return result

    return await asyncio.gather(*(one(row) for row in rows))


async def phase(state, directory, name, *, fault="business_primary", seconds=60, rps=3, drain_seconds=300,
                result_recovery=False, crash_after_commit_index=None):
    validate_recovery_options(int(rps * seconds), result_recovery, crash_after_commit_index)
    if not state.get("independent_admission") or state["source"] != cluster.frozen_inputs():
        raise ValueError("Requires a current frozen independent-admission cluster")
    if result_recovery and not state.get("receipts_enabled"):
        raise ValueError("Result recovery requires the independent receipt fixture")
    phase_id = "mn_" + uuid4().hex[:12]
    cluster.save(directory / (name + "_started.json"), {"phase": phase_id, "fault": fault, "rps": rps, "seconds": seconds,
        "admission": True, "result_recovery": result_recovery, "crash_after_commit_index": crash_after_commit_index})
    before = await measure_clock()
    cluster.save(directory / (name + "_clock_before.json"), before)
    if not before["passed"]:
        raise RuntimeError("Clock check failed before admission phase")
    seed = await asyncio.to_thread(cluster.driver, state, "seed_admission", {
        "phase": phase_id, "result_recovery": result_recovery})
    if fault == "backlog":
        await asyncio.to_thread(scale_workers, state, 0)
    rows, status_observations, faults, duplicates, duplicate_confirmations = [], [], [], [], []
    started = time.monotonic()
    stop_clock = asyncio.Event()
    clock_task = asyncio.create_task(monitor_recovery_clock(stop_clock))
    load_clock = asyncio.create_task(measure_clock(math.ceil((seconds + 10) / 10), 10))
    probe_target = "admission" if fault == "admission_primary" else "business"
    async with cluster.database_timeline(state, directory, name, probe_target), httpx.AsyncClient(timeout=10, trust_env=False) as client:
        async def submit(index, scheduled):
            external_id = f"{phase_id}:{index}"
            payload = admission_payload(seed, phase_id, index, result_recovery=result_recovery,
                                        crash_after_commit_index=crash_after_commit_index)
            request_id = payload["requestId"]
            variant = "write" if index % 20 == 19 else "read"
            sent = time.monotonic()
            row = {"id": external_id, "request_id": request_id, "variant": variant, "status": 0, "accepted": False}
            try:
                response = await client.post(state["admission_entrypoint"] + "/v1/admissions", json=payload,
                    headers={"X-AgentOps-Admission-Key": seed["admission_token"]})
                row["status"] = response.status_code
                body = response.json()
                row.update(accepted=response.status_code == 202
                    and accepted(body, request_id) and body.get("durabilityConfirmed") is True)
            except httpx.TransportError as error:
                row["transport_error"] = type(error).__name__
            except ValueError:
                row["response_error"] = "invalid_json"
            row.update(at=time.monotonic()-started, latency_ms=(time.monotonic()-sent)*1000,
                       schedule_delay_ms=(sent-scheduled)*1000)
            rows.append(row)
            # Ten concurrent re-deliveries of an already acknowledged request;
            # no changed input, no retry with a new identifier.
            if index == 0 and row["accepted"]:
                async def repeat():
                    try:
                        reply = await client.post(state["admission_entrypoint"] + "/v1/admissions", json=payload,
                            headers={"X-AgentOps-Admission-Key": seed["admission_token"]})
                        body = reply.json()
                        return reply.status_code, (reply.status_code == 202 and accepted(body, request_id)
                                                   and body.get("durabilityConfirmed") is True)
                    except (httpx.TransportError, ValueError):
                        return 0, False
                repeated = await asyncio.gather(*(repeat() for _ in range(10)))
                duplicates.extend(status for status, _ in repeated)
                duplicate_confirmations.extend(confirmed for _, confirmed in repeated)

        async def disrupt():
            if fault not in {"business_primary", "admission_primary"}:
                return
            await asyncio.sleep(seconds / 3)
            target = state if fault == "business_primary" else admission_state(state)
            record = {"kind": fault + "_node_network", "primary_snapshots": [],
                      "promotion_observed": False}
            faults.append(record)

            async def observe(stage):
                at = time.monotonic()-started
                value = await asyncio.to_thread(primary_snapshot, state, target)
                value.update(stage=stage, at=at, finished_at=time.monotonic()-started)
                record["primary_snapshots"].append(value)
                cluster.save(directory / f"{name}_primary_{len(record['primary_snapshots']):03d}.json", value)
                return value

            leader = confirmed_primary(await observe("before"))
            node = leader["node"]
            info = json.loads(await asyncio.to_thread(cluster.run, ["docker", "inspect", node]))[0]
            if info["Config"]["Labels"].get("io.x-k8s.kind.cluster") != state["cluster"]:
                raise RuntimeError("Fault target does not belong to this test cluster")
            address = info["NetworkSettings"]["Networks"]["kind"]["IPAddress"]
            record.update(node=node, at=time.monotonic()-started, primary_before=leader["pod"])
            cluster.save(directory / (name + "_fault.json"), {**record, "address": address, "network": "kind"})
            await asyncio.to_thread(cluster.run, ["docker", "network", "disconnect", "kind", node])
            stop_primary_probes = asyncio.Event()

            async def monitor_primary():
                while not stop_primary_probes.is_set():
                    await observe("isolated")
                    try:
                        await asyncio.wait_for(stop_primary_probes.wait(), timeout=5)
                    except TimeoutError:
                        continue

            primary_monitor = asyncio.create_task(monitor_primary())
            try:
                await asyncio.sleep(30)
            finally:
                stop_primary_probes.set()
                try:
                    await asyncio.to_thread(cluster.run, ["docker", "network", "connect", "--ip", address, "kind", node])
                    record["restored_at"] = time.monotonic()-started
                finally:
                    await primary_monitor
            for _ in range(15):
                current = await observe("after")
                try:
                    leader = confirmed_primary(current)
                except RuntimeError:
                    record["primary_after"] = None
                    record["promotion_observed"] = False
                else:
                    record["primary_after"] = leader["pod"]
                    record["promotion_observed"] = leader["pod"] != record["primary_before"]
                    if record["promotion_observed"]:
                        break
                await asyncio.sleep(2)

        disruption = asyncio.create_task(disrupt())
        stop_probes = asyncio.Event()

        async def monitor_queries():
            while not stop_probes.is_set():
                if rows:
                    checked = await query(client, state, seed["admission_token"], rows[-3:])
                    status_observations.append({"at": time.monotonic()-started, "results": checked})
                try:
                    await asyncio.wait_for(stop_probes.wait(), timeout=5)
                except TimeoutError:
                    continue

        probes = asyncio.create_task(monitor_queries())
        requests = []
        try:
            for index in range(int(rps*seconds)):
                scheduled = started + index/rps
                await asyncio.sleep(max(0, scheduled-time.monotonic()))
                requests.append(asyncio.create_task(submit(index, scheduled)))
            await asyncio.gather(*requests, disruption)
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            # Preserve already-issued requests, without retrying or discarding
            # effects when fault selection/control fails. Awaiting disruption
            # also keeps its network-restoration finally ahead of cleanup.
            finished = await asyncio.gather(*requests, disruption, return_exceptions=True)
            stop_probes.set()
            await probes
            cluster.save(directory / (name + "_interrupted.json"), {
                "name": name, "phase": phase_id, "controller_error": type(error).__name__,
                "task_error_types": [type(item).__name__ for item in finished
                                     if isinstance(item, BaseException)],
                "requests": rows, "status_probes": status_observations, "faults": faults,
                "production_sla_verified": False})
            stop_clock.set()
            await clock_task
            load_clock.cancel()
            try:
                await load_clock
            except asyncio.CancelledError:
                pass
            raise
        finally:
            stop_probes.set()
            await probes
            if fault == "backlog":
                cluster.save(directory / (name + "_backlog.json"), await asyncio.to_thread(cluster.driver, state, "stats", {
                    "phase": phase_id, "acknowledged_reads": [], "decision_ids": []}))
                await asyncio.to_thread(scale_workers, state, 3)
        admission_end = time.monotonic()
        terminal_at, samples = {}, []
        while True:
            statuses = await query(client, state, seed["admission_token"], rows)
            current = counts(rows, statuses)
            for row in statuses:
                if row.get("business_state") in {"succeeded", "waiting_approval"}:
                    terminal_at.setdefault(row["request_id"], time.monotonic()-started)
            samples.append({"at": time.monotonic()-started, **{k: v for k, v in current.items() if k != "expected_ids"}})
            print(json.dumps({"phase": name, **samples[-1]}), flush=True)
            if current["accepted_not_completed"] == 0 or time.monotonic()-admission_end >= drain_seconds:
                break
            await asyncio.sleep(5)
        stop_clock.set()
        recovery_clock = await clock_task
    clocks = {"before": before, "load": await load_clock, "recovery": recovery_clock, "after": await measure_clock()}
    expected = set(current.pop("expected_ids"))
    # A later diagnostic/ledger query can fail independently. Preserve issued
    # requests and observed statuses before additional evidence collection.
    cluster.save(directory / (name + "_requests.json"), rows)
    cluster.save(directory / (name + "_status_probes.json"), status_observations)
    cluster.save(directory / (name + "_recovery.json"), {"snapshots": samples, "final": statuses})
    oracle = await asyncio.to_thread(cluster.driver, state, "stats", {"phase": phase_id,
        "acknowledged_reads": [row["id"] for row in rows if row["variant"] == "read" and row["id"] in expected], "decision_ids": []})
    business_oracle = oracle
    independent_ledger, result_checks, per_request_scoring = None, [], None
    forced_recovery = crash_after_commit_index is None
    recovered_results_verified = True
    if result_recovery:
        independent_ledger = await asyncio.to_thread(v2_ledger, state, phase_id)
        cluster.save(directory / (name + "_v2_ledger.json"), independent_ledger)
        result_checks = await verify_recovered_results(state, seed["token"], rows, oracle["invocations"])
        cluster.save(directory / (name + "_result_checks.json"), result_checks)
        # GET /result performs another authorization check and real output scan.
        # Read the committed evidence afterwards, not the pre-GET aggregate.
        business_oracle = await asyncio.to_thread(cluster.driver, state, "stats", {"phase": phase_id,
            "acknowledged_reads": [row["id"] for row in rows if row["variant"] == "read" and row["id"] in expected], "decision_ids": []})
        oracle = reconcile_v2_effects(phase_id, rows, business_oracle, independent_ledger)
        per_request_scoring = reconcile_scoring(rows, oracle["actual_read_ids"], oracle["scoring_requests"])
        forced_recovery = forced_recovery_passed(crash_after_commit_index, rows, independent_ledger,
                                                oracle["invocations"], result_checks)
        recovered_results_verified = recovered_results_complete(oracle["invocations"], result_checks)
    integrity = not any(oracle[key] for key in ("duplicate_executions", "unauthorized_writes", "acknowledged_missing_receipts"))
    scan_complete = (oracle["completed_scans"] == oracle["scan_attempts"] >= oracle["upstream_reads"]
                     and not oracle["semantic_error_events"])
    if result_recovery:
        integrity = integrity and oracle["v2_ledger_valid"] and not oracle["executed_without_acknowledgement"]
        scan_complete = scan_complete and per_request_scoring["passed"]
    status_errors = sum(row["status"] != 200 for sample in status_observations for row in sample["results"])
    safety_passed = (current["accepted_not_completed"] == 0 and current["accepted_missing"] == 0
        and integrity and scan_complete and oracle["audit_valid"] and forced_recovery
        and recovered_results_verified)
    result = {"name": name, "fault": fault, **current, "status_counts": dict(Counter(row["status"] for row in rows)),
        "transport_error_counts": dict(Counter(row["transport_error"] for row in rows if "transport_error" in row)),
        "response_error_counts": dict(Counter(row["response_error"] for row in rows if "response_error" in row)),
        "during_fault_status_errors": status_errors, "duplicate_submission_statuses": duplicates,
        "duplicate_durability_confirmations": duplicate_confirmations,
        "live_outbox_redis_worker_path": True, "small_model_mode": "shadow", "reconciliation": oracle,
        "result_recovery_enabled": result_recovery, "business_reconciliation": business_oracle,
        "per_request_scoring": per_request_scoring, "recovered_result_checks": result_checks,
        "forced_result_recovery_requested": crash_after_commit_index is not None,
        "forced_result_recovery_passed": forced_recovery, "client_action_retries": 0,
        "recovered_results_verified": recovered_results_verified,
        "integrity_passed": safety_passed, "uninterrupted_admission_passed": current["admission_failed"] == 0,
        "clocks": clocks, "clocks_passed": all(item["passed"] for item in clocks.values()),
        "admission_p95_ms": cluster.percentile([row["latency_ms"] for row in rows], .95),
        "schedule_delay_p95_ms": cluster.percentile([row["schedule_delay_ms"] for row in rows], .95),
        "completion_observed_upper_bound_p95_seconds": cluster.percentile([
            terminal_at[row["request_id"]]-(row["at"]-row["latency_ms"]/1000)
            for row in rows if row["id"] in expected], .95) if expected else None,
        "faults": faults, "fault_verification_passed": fault_verification_passed(fault, faults),
        "source": state["source"], "production_sla_verified": False}
    result["passed"] = safety_passed and result["clocks_passed"] and (fault == "admission_primary" or (
        result["uninterrupted_admission_passed"] and status_errors == 0)) and duplicates == [202]*10 \
        and duplicate_confirmations == [True]*10 and result["fault_verification_passed"]
    cluster.save(directory / (name + ".json"), result)
    print(json.dumps({k: result[k] for k in ("name", "attempted", "accepted", "completed_as_expected", "passed")}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--fault", choices=("none", "backlog", "business_primary", "admission_primary"), default="business_primary")
    parser.add_argument("--result-recovery", action="store_true")
    parser.add_argument("--crash-after-commit-index", type=int)
    args = parser.parse_args()
    if not args.name.replace("_", "").isalnum():
        raise ValueError("invalid report name")
    state = json.loads((args.directory / "state.json").read_text())
    asyncio.run(phase(state, args.directory, args.name, fault=args.fault,
        result_recovery=args.result_recovery, crash_after_commit_index=args.crash_after_commit_index))


if __name__ == "__main__":
    main()
