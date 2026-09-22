"""Controlled cluster: downstream commit + process death + automatic receipt lookup.

V1 verifies execution confirmation; explicit V2 verifies recovered/scanned output.
No client replay, forced lease expiry, direct status edits, customer tools or data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from uuid import uuid4

import httpx

from verify_multinode_capacity import PREFIX, driver, frozen_inputs, kubectl, save


def accepted_confirmation(initial, final, ledger):
    return (initial == "outcome_unknown" and final.get("state") == "execution_confirmed"
        and final.get("attempts") == 1 and final.get("clientMayReplay") is False
        and final.get("summary", {}).get("resultScanned") is False
        and final.get("summary", {}).get("resultAvailable") is False
        and ledger == {"effects": 1, "receipts": 1})


def verify(state, directory, name, *, result_recovery=False):
    if not state["cluster"].startswith(PREFIX) or not state.get("receipts_enabled"):
        raise ValueError("requires the opt-in disposable receipt cluster")
    if frozen_inputs() != state["source"]:
        raise RuntimeError("source changed since deployment; preserve the earlier evidence")
    phase, request_id = "mn_" + uuid4().hex[:12], str(uuid4())
    save(directory / (name + "_started.json"), {"phase": phase, "request_id": request_id})
    seed = driver(state, "seed_receipts", {"phase": phase, "result_recovery": result_recovery})
    initial, final, observations, failures = None, {}, [], 0
    started = time.monotonic()
    with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
        headers = {"Authorization": "Bearer " + seed["token"]}
        try:
            response = client.post(state["entrypoint"] + "/mcp/tools/call", headers=headers,
                json={"requestId": request_id, "serverId": seed["server_id"], "name": "echo_v2" if result_recovery else "echo",
                      "arguments": {"text": "synthetic business effect", "crash_after_commit": True}})
            if response.status_code == 200:
                initial = response.json().get("invocation", {}).get("state")
            else:
                failures += 1
        except httpx.HTTPError:
            failures += 1  # Never issue the original tool request again.
        while time.monotonic() - started < 90:
            try:
                response = client.get(state["entrypoint"] + "/mcp/invocations/" + request_id, headers=headers)
                if response.status_code == 200:
                    final = response.json()
                    observations.append({"at": round(time.monotonic() - started, 3), "state": final["state"]})
                    if final["state"] == ("succeeded" if result_recovery else "execution_confirmed"):
                        break
                else:
                    failures += 1
            except httpx.HTTPError:
                failures += 1
            time.sleep(1)
        released = False
        if result_recovery and final.get("state") == "succeeded":
            reply = client.get(state["entrypoint"] + "/mcp/invocations/" + request_id + "/result", headers=headers)
            if reply.status_code == 200:
                body = reply.json()
                released = body.get("content") == [{"type": "text", "text": "synthetic business effect"}] and bool(body.get("provenance"))
    binding = driver(state, "receipt_binding", {"phase": phase, "request_id": request_id})
    # Aggregate evidence only; never read the stored effect/result text into a report.
    receipt_table = "results_v2" if result_recovery else "receipts"
    program = ("import json,sqlite3,sys; key=json.load(sys.stdin)['operation_id']; "
        "db=sqlite3.connect('/receipt-data/ledger.db'); print(json.dumps({"
        "'effects':db.execute('SELECT count(*) FROM effects WHERE operation_id=?',(key,)).fetchone()[0],"
        f"'receipts':db.execute('SELECT count(*) FROM {receipt_table} WHERE operation_id=?',(key,)).fetchone()[0]}}))")
    ledger = json.loads(kubectl(state, "exec", "-i", "deployment/receipt-upstream", "--",
        "python", "-c", program, input_text=json.dumps(binding)))
    oracle = driver(state, "stats", {"phase": phase, "acknowledged_reads": [], "decision_ids": []})
    full_success = (result_recovery and initial == "outcome_unknown" and final.get("state") == "succeeded"
        and final.get("attempts") == 1 and final.get("summary", {}).get("resultScanned") is True
        and final.get("resultStored") is True and released and ledger == {"effects": 1, "receipts": 1}
        and oracle["scan_attempts"] >= 2 and oracle["completed_scans"] == oracle["scan_attempts"]
        and not oracle["semantic_error_events"] and oracle["audit_valid"])
    result = {"initial_state": initial, "final_state": final.get("state"),
        "observations": observations, "transport_failures": failures,
        "ledger": ledger, "tool_attempts": final.get("attempts"), "client_action_retries": 0,
        "result_recovered_and_scanned": full_success, "business_success": full_success,
        "result_recovery_protocol": "v2" if result_recovery else "v1", "scan_and_audit_evidence": oracle,
        "receipt_confirmation_passed": accepted_confirmation(initial, final, ledger),
        "production_sla_verified": False, "implementation_sha256": state["source"],
        "limits": ["synthetic effect", "independent single-replica SQLite ledger in Pod emptyDir",
                   "only container/process restart covered; Pod or node storage loss not covered",
                   "physical multi-host availability not verified"]}
    result["passed"] = full_success if result_recovery else result["receipt_confirmation_passed"]
    save(directory / (name + ".json"), result)
    print(json.dumps({key: result[key] for key in ("initial_state", "final_state", "transport_failures",
        "ledger", "tool_attempts", "receipt_confirmation_passed", "business_success")}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--name", default="receipt_recovery")
    parser.add_argument("--result-recovery", action="store_true")
    args = parser.parse_args()
    if not args.name.replace("_", "").isalnum():
        raise ValueError("invalid phase name")
    directory = args.directory.resolve()
    state = json.loads((directory / "state.json").read_text())
    result = verify(state, directory, args.name, result_recovery=args.result_recovery)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
