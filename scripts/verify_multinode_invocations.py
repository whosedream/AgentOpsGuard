#!/usr/bin/env python3
"""Explicit queue/backlog evaluation on a frozen, disposable kind cluster.

No admission retries, no approval, no output capture. A 202 is not completion.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import UTC, datetime
import json
import math
from pathlib import Path
import re
import time
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx

import verify_multinode_capacity as cluster
from verify_clock_consistency import measure_clock

STATES = {"pending", "queued", "preparing", "recovering", "dispatched", "succeeded", "failed", "execution_confirmed",
          "waiting_approval", "outcome_unknown", "expired", "not_dispatched"}
TERMINAL = {"succeeded", "failed", "waiting_approval", "outcome_unknown", "expired", "not_dispatched", "execution_confirmed"}


def sanitized_status(body):
    state = body.get("state")
    attempts = body.get("attempts")
    if not isinstance(state, str) or state not in STATES:
        return {"state": "invalid_status", "attempts": None}
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        return {"state": "invalid_status", "attempts": None}
    return {"state": state, "attempts": attempts}


async def query_statuses(client, state, token, rows):
    limit = asyncio.Semaphore(4)

    async def query(row):
        async with limit:
            try:
                response = await client.get(state["entrypoint"] + "/mcp/invocations/" + row["invocation_id"],
                    headers={"Authorization": "Bearer " + token})
                if response.status_code == 404:
                    result = {"state": "not_found", "attempts": None}
                elif response.status_code == 200:
                    body = response.json()
                    result = sanitized_status(body) if isinstance(body, dict) else {"state": "invalid_status", "attempts": None}
                else:
                    result = {"state": "query_failed", "attempts": None}
            except (httpx.TransportError, ValueError):
                result = {"state": "query_failed", "attempts": None}
            return {"id": row["id"], "invocation_id": row["invocation_id"], **result}

    return await asyncio.gather(*(query(row) for row in rows))


async def monitor_recovery_clock(stop):
    windows = []
    while not stop.is_set():
        windows.append(await measure_clock(1, 10))
    return {"passed": bool(windows) and all(window["passed"] for window in windows), "windows": windows}


def queue_counts(rows, recovered):
    by_id = {row["invocation_id"]: row for row in recovered}
    accepted = [row for row in rows if row["accepted"]]
    completed = []
    for row in accepted:
        current = by_id.get(row["invocation_id"], {})
        ok = current.get("state") == "succeeded" if row["variant"] != "write" else (
            current.get("state") == "waiting_approval" and current.get("attempts") == 0)
        if ok:
            completed.append(row["id"])
    missing = sum(by_id.get(row["invocation_id"], {}).get("state") == "not_found" for row in accepted)
    pending = sum(by_id.get(row["invocation_id"], {}).get("state") not in TERMINAL for row in accepted)
    return {"attempted": len(rows), "accepted": len(accepted), "admission_failed": len(rows)-len(accepted),
        "completed_as_expected": len(completed), "accepted_not_completed_as_expected": len(accepted)-len(completed),
        "accepted_missing_receipts": missing, "accepted_pending_or_unqueryable": pending,
        "outcome_unknown": sum(row["state"] == "outcome_unknown" for row in recovered),
        "states": dict(Counter(row["state"] for row in recovered)), "expected_completed_ids": completed}


def recovery_finished(counts, jobs):
    return counts["accepted_pending_or_unqueryable"] == 0 and not any(
        jobs.get(state, 0) for state in ("pending", "running")
    )


def scale_workers(state, replicas):
    cluster.kubectl(state, "scale", "deployment/agentops-guard-worker", f"--replicas={replicas}")
    if replicas:
        cluster.wait_deployment(state, "agentops-guard-worker")
    else:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            pods = json.loads(cluster.kubectl(state, "get", "pods", "-l", "app=agentops-guard-worker", "-o", "json"))["items"]
            if not pods:
                return
            time.sleep(1)
        raise RuntimeError("Workers did not stop; do not call this a paused backlog")


async def queue_phase(state, directory, name, rps, seconds, fault, drain_seconds):
    if not state.get("durable_queue_enabled"):
        raise ValueError("Cluster has no explicitly enabled queue")
    phase = "mn_" + uuid4().hex[:12]
    cluster.save(directory / (name+"_started.json"), {"phase": phase, "rps": rps, "seconds": seconds,
        "fault": fault, "drain_seconds": drain_seconds, "created_at": datetime.now(UTC).isoformat()})
    configuration = await asyncio.to_thread(cluster.patroni_configuration, state)
    before = await measure_clock()
    cluster.save(directory / (name+"_clock_before.json"), before)
    if not before["passed"]:
        raise RuntimeError("Clock check failed before queue phase")
    seed = await asyncio.to_thread(cluster.driver, state, "seed", {"phase": phase, "queue_policy": True})
    rows, faults, snapshots = [], [], []
    if fault in {"backlog", "redis_loss"}:
        await asyncio.to_thread(scale_workers, state, 0)
    started = time.monotonic()
    cluster.save(directory / (name+"_load_clock_origin.json"), {"monotonic": started, "wall": time.time()})
    during = asyncio.create_task(measure_clock(math.ceil((seconds+10)/10), 10))
    # Cover worker startup and recovery too, not just the admission interval.
    stop_clock = asyncio.Event()
    drain_clock = asyncio.create_task(monitor_recovery_clock(stop_clock))

    async def disrupt():
        if fault != "primary_network":
            return
        await asyncio.sleep(seconds/3)
        pods = json.loads(await asyncio.to_thread(cluster.kubectl, state, "get", "pods", "-l", "cluster-name=agentops-pg", "-o", "json"))["items"]
        leaders = [pod for pod in pods if pod["metadata"]["labels"].get("role") == "primary"]
        if len(leaders) != 1:
            raise RuntimeError("Primary network fault has no unique target")
        node = leaders[0]["spec"]["nodeName"]
        info = json.loads(await asyncio.to_thread(cluster.run, ["docker", "inspect", node]))[0]
        if info["Config"]["Labels"].get("io.x-k8s.kind.cluster") != state["cluster"]:
            raise RuntimeError("Network fault target is outside this disposable cluster")
        address = info["NetworkSettings"]["Networks"]["kind"]["IPAddress"]
        record = {"kind": "primary_node_network_disconnect", "node": node, "at": time.monotonic()-started}
        faults.append(record)
        cluster.save(directory / (name+"_fault.json"), {**record, "network": "kind", "address": address})
        await asyncio.to_thread(cluster.run, ["docker", "network", "disconnect", "kind", node])
        try:
            await asyncio.sleep(30)
        finally:
            await asyncio.to_thread(cluster.run, ["docker", "network", "connect", "--ip", address, "kind", node])
            record["reconnected_at"] = time.monotonic()-started
        print("queue_fault=primary_network_restored", flush=True)

    async with cluster.database_timeline(state, directory, name), httpx.AsyncClient(timeout=10, trust_env=False, limits=httpx.Limits(max_connections=128)) as client:
        async def submit(index, scheduled):
            request_id = f"{phase}:{index}"
            invocation_id = str(uuid5(NAMESPACE_URL, "agentops-eval:" + request_id))
            variant = "write" if index % 20 == 19 else "short"
            arguments = {"request_id": request_id}
            arguments.update({"path": "/controlled/probe.txt", "content": "controlled probe"} if variant == "write" else {"variant": "short"})
            sent = time.monotonic()
            status, accepted = 0, False
            try:
                response = await client.post(state["entrypoint"]+"/mcp/invocations",
                    headers={"Authorization": "Bearer " + seed["token"], "X-Eval-Request": request_id},
                    json={"requestId": invocation_id, "serverId": seed["server_id"],
                          "name": "write_file" if variant == "write" else "read_status", "arguments": arguments})
                status = response.status_code
                body = response.json()
                accepted = status == 202 and isinstance(body, dict) and body.get("requestId") == invocation_id and sanitized_status(body)["state"] in STATES
            except (httpx.TransportError, ValueError):
                pass  # Record a failed admission; no resend and no body logging.
            finished = time.monotonic()
            rows.append({"id": request_id, "invocation_id": invocation_id, "variant": variant,
                         "status": status, "accepted": accepted, "at": finished-started,
                         "latency_ms": 1000*(finished-sent), "schedule_delay_ms": 1000*(sent-scheduled)})

        disruption = asyncio.create_task(disrupt())
        requests = []
        try:
            for index in range(int(rps*seconds)):
                scheduled = started+index/rps
                await asyncio.sleep(max(0, scheduled-time.monotonic()))
                requests.append(asyncio.create_task(submit(index, scheduled)))
            await asyncio.gather(*requests, disruption)
            cluster.save(directory/(name+"_requests.json"), rows)
            if fault in {"backlog", "redis_loss"}:
                snapshots.append({"at": time.monotonic()-started, "before_worker_resume": True,
                    **await asyncio.to_thread(cluster.driver, state, "stats", {"phase": phase, "acknowledged_reads": [], "decision_ids": []})})
                cluster.save(directory/(name+"_backlog_before_resume.json"), snapshots[-1])
            if fault == "redis_loss":
                # This disposable Redis explicitly has persistence disabled.
                # Workers are stopped, admission is over, and only the owned
                # test deployment is restarted to lose delivered notifications.
                record = {"kind": "redis_restart_without_persistence", "at": time.monotonic()-started}
                faults.append(record)
                await asyncio.to_thread(cluster.kubectl, state, "rollout", "restart", "deployment/redis")
                await asyncio.to_thread(cluster.wait_deployment, state, "redis")
                record["ready_at"] = time.monotonic()-started
        finally:
            if fault in {"backlog", "redis_loss"}:
                faults.append({"kind": "worker_resume_requested", "at": time.monotonic()-started})
                await asyncio.to_thread(scale_workers, state, 3)
                faults[-1]["ready_at"] = time.monotonic()-started
        admission_end = time.monotonic()
        terminal_seen = {}
        while True:
            recovered = await query_statuses(client, state, seed["token"], rows)
            progress_oracle = await asyncio.to_thread(cluster.driver, state, "stats", {
                "phase": phase, "acknowledged_reads": [], "decision_ids": [],
            })
            jobs = progress_oracle["job_status_counts"]
            now = time.monotonic()-started
            for item in recovered:
                if item["state"] in TERMINAL:
                    terminal_seen.setdefault(item["invocation_id"], now)
            counts = queue_counts(rows, recovered)
            snapshots.append({"at": now, "job_status_counts": jobs, **{key: value for key, value in counts.items() if key != "expected_completed_ids"}})
            print(json.dumps({"phase": name, "at": round(now, 1), "job_status_counts": jobs, **{key: counts[key] for key in ("accepted", "completed_as_expected", "accepted_pending_or_unqueryable", "outcome_unknown")}}), flush=True)
            if recovery_finished(counts, jobs) or time.monotonic()-admission_end >= drain_seconds:
                break
            await asyncio.sleep(15)
        drain_finished = time.monotonic()
        stop_clock.set()
        drain_clock_result = await drain_clock
    after = await measure_clock()
    clock = {"before": before, "admission": await during, "after": after, "recovery": drain_clock_result}
    clock["admission_passed"] = all(clock[key]["passed"] for key in ("before", "admission", "after"))
    clock["recovery_passed"] = clock["admission_passed"] and drain_clock_result["passed"] is True
    expected_ids = set(counts.pop("expected_completed_ids"))
    acknowledged = [row["id"] for row in rows if row["id"] in expected_ids and row["variant"] != "write"]
    oracle = await asyncio.to_thread(cluster.driver, state, "stats", {"phase": phase,
        "acknowledged_reads": acknowledged, "decision_ids": []})
    await asyncio.to_thread(cluster.wait_deployment, state, "agentops-guard-worker")
    config_after = await asyncio.to_thread(cluster.patroni_configuration, state)
    if config_after != configuration:
        raise RuntimeError("Durability settings changed during queue phase")
    completed_times = [terminal_seen[row["invocation_id"]] - (row["at"] - row["latency_ms"]/1000)
                       for row in rows if row["id"] in expected_ids]
    integrity = not any(oracle[key] for key in ("duplicate_executions", "unauthorized_writes", "acknowledged_missing_receipts"))
    scanning = oracle["scan_attempts"] >= oracle["upstream_reads"] and oracle["completed_scans"] == oracle["scan_attempts"] and not oracle["semantic_error_events"]
    passed = (counts["admission_failed"] == 0 and counts["accepted_not_completed_as_expected"] == 0
              and recovery_finished(counts, oracle["job_status_counts"])
              and integrity and scanning and oracle["audit_valid"] and clock["recovery_passed"])
    result = {"name": name, "phase": phase, "scope": "single_host_four_kind_nodes_explicit_queue",
        **counts, "passed": passed, "queue_integrity_verified": integrity, "scanning_complete": scanning,
        "faults": faults, "status_counts": dict(Counter(str(row["status"]) for row in rows)),
        "admission_latency_ms": {str(p): cluster.percentile([row["latency_ms"] for row in rows], p/100) for p in (50,95,99)},
        "schedule_delay_p95_ms": cluster.percentile([row["schedule_delay_ms"] for row in rows], .95),
        "completion_observed_upper_bound_seconds": {str(p): cluster.percentile(completed_times, p/100) for p in (50,95,99)} if completed_times else {},
        "status_poll_interval_seconds": 15, "drain_wait_seconds": round(drain_finished-admission_end, 3),
        "drain_limit_seconds": drain_seconds,
        "background_work_settled": recovery_finished(counts, oracle["job_status_counts"]),
        "recovery_clock_includes_worker_startup": True,
        "clock": clock, "reconciliation": oracle, "client_admission_retries": 0,
        "production_sla_verified": False, "original_synchronous_failure_metrics_replaced": False,
        "full_mcp_tasks_protocol": False, "stores_raw_text_or_credentials": False,
        "patroni_configuration": configuration, "implementation_sha256": state["source"]}
    cluster.save(directory/(name+"_status_snapshots.json"), snapshots)
    cluster.save(directory/(name+"_recovered_invocations.json"), recovered)
    cluster.save(directory/(name+"_runtime_events.json"), await asyncio.to_thread(cluster.runtime_events, state, phase))
    cluster.save(directory/(name+".json"), result)
    print(json.dumps({key: result[key] for key in ("name", "attempted", "accepted", "completed_as_expected", "outcome_unknown", "passed")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--rps", type=float, default=2)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--fault", choices=("none", "backlog", "redis_loss", "primary_network"), default="none")
    parser.add_argument("--drain-seconds", type=int, default=300)
    args = parser.parse_args()
    if not (0 < args.rps <= 20 and 12 <= args.seconds <= 300 and int(args.rps*args.seconds) >= 1 and 15 <= args.drain_seconds <= 900) or not re.fullmatch(r"[a-zA-Z0-9_]+", args.name):
        raise ValueError("Invalid bounded queue phase parameters")
    state = json.loads((args.directory/"state.json").read_text())
    if not state["cluster"].startswith(cluster.PREFIX) or state["source"] != cluster.frozen_inputs():
        raise RuntimeError("Not the current frozen disposable cluster")
    asyncio.run(queue_phase(state, args.directory, args.name, args.rps, args.seconds, args.fault, args.drain_seconds))


if __name__ == "__main__":
    main()
