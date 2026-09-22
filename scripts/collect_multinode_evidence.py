"""Read-only, sanitized evidence collected synchronously before cluster cleanup."""
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess

import verify_multinode_capacity as cluster


QUERY_PROGRAM = r'''
import json, os, re, sys
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool
from agentops_guard.backend.database import engine

phase = sys.argv[1]
if not re.fullmatch(r"mn_[0-9a-f]{12}", phase):
    raise ValueError("Invalid synthetic phase")

queries = {
    "tool_receipts": """SELECT request_id,kind,executions
        FROM eval_tool_receipts WHERE phase=:phase ORDER BY request_id""",
    "invocations": """SELECT id,request_id,status,attempts,
        summary->>'policyDecisionId' AS decision_id,
        summary->>'approvalRequestId' AS approval_id,
        summary->>'executionRequestId' AS execution_id
        FROM tool_invocations WHERE project_id=:phase ORDER BY request_id""",
    "scan_receipts": """SELECT request_id,content_ref,status,reason,attempts,
        jsonb_array_length(attempt_errors) AS attempt_error_count
        FROM eval_scan_receipts WHERE phase=:phase ORDER BY content_ref""",
    "decisions": """SELECT id,action,
        CASE WHEN context->'data'->>'content_source' IN
          ('mcp_tool_arguments','mcp_tool_result')
          THEN context->'data'->>'content_source' ELSE NULL END AS content_source,
        context->'tool'->'args'->>'sanitized_content_ref' AS argument_content_ref
        FROM policy_decisions WHERE project_id=:phase ORDER BY id""",
    "explicit_audit_links": """SELECT i.request_id,count(a.id) AS entry_count
        FROM tool_invocations i LEFT JOIN audit_logs a
          ON a.project_id=i.project_id AND (
            a.resource_id=i.id OR
            a.resource_id=i.summary->>'executionRequestId' OR
            a.resource_id=i.summary->>'approvalRequestId' OR
            a.resource_id=i.summary->>'policyDecisionId' OR
            a.metadata_json->>'policy_decision_id'=i.summary->>'policyDecisionId')
        WHERE i.project_id=:phase GROUP BY i.request_id ORDER BY i.request_id""",
    "audit_counts": """SELECT count(*) AS entries,
        count(entry_hash) AS hashed_entries FROM audit_logs WHERE project_id=:phase""",
    "trace_counts": """SELECT count(*) AS entries FROM trace_events WHERE project_id=:phase""",
    "risk_counts": """SELECT
        count(*) FILTER (WHERE risk_type='semantic_prompt_injection_shadow') AS shadow_findings,
        count(*) FILTER (WHERE risk_type='semantic_scanner_error') AS scanner_errors,
        count(*) AS all_findings FROM risk_events WHERE project_id=:phase""",
}
out = {"phase": phase, "business_query_completed": False,
       "admission_query_requested": sys.argv[2] == "admission"}
try:
    with engine.connect() as connection, connection.begin():
        connection.execute(text("SET TRANSACTION READ ONLY"))
        connection.execute(text("SET LOCAL statement_timeout = '3000ms'"))
        for name, query in queries.items():
            out[name] = [dict(row) for row in connection.execute(text(query), {"phase":phase}).mappings()]
    out["business_query_completed"] = True
except (SQLAlchemyError, OSError, ValueError) as error:
    # Explicitly incomplete evidence; never expose driver text or connection URLs.
    out["business_query_error_type"] = type(error).__name__

if out["admission_query_requested"]:
    out["admission_query_completed"] = False
    admission_engine = None
    try:
        admission_engine = create_engine(os.environ["AGENTOPS_ADMISSION_DATABASE_URL"],
            poolclass=NullPool, connect_args={"connect_timeout":3}, echo=False, hide_parameters=True)
        with admission_engine.connect() as connection, connection.begin():
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout = '3000ms'"))
            out["admissions"] = [dict(row) for row in connection.execute(text("""
                SELECT request_id,state,business_id,business_state,
                    business_observed_at IS NOT NULL AS business_observed
                FROM admission_entries_v1 WHERE project_id=:phase ORDER BY request_id
            """), {"phase":phase}).mappings()]
        out["admission_query_completed"] = True
    except (SQLAlchemyError, OSError, ValueError, KeyError) as error:
        out["admission_query_error_type"] = type(error).__name__
    finally:
        if admission_engine is not None:
            admission_engine.dispose()
print(json.dumps(out))
'''


V2_LEDGER_PROGRAM = r'''
import hashlib, json, re, sqlite3, sys
phase = sys.argv[1]
if not re.fullmatch(r"mn_[0-9a-f]{12}", phase):
    raise ValueError("Invalid controlled phase")
with sqlite3.connect("file:/receipt-data/ledger.db?mode=ro", uri=True, timeout=3) as db:
    db.execute("PRAGMA query_only=ON")
    rows = db.execute("""SELECT r.request_id,r.operation_id,r.kind,r.tool,r.executions,
        r.result_hash,e.value,v.result_hash,v.result
        FROM eval_tool_receipts r LEFT JOIN effects e USING(operation_id)
        LEFT JOIN results_v2 v USING(operation_id) WHERE r.phase=? ORDER BY r.request_id""", (phase,)).fetchall()
    result = []
    for request_id, operation_id, kind, tool, executions, expected, effect, stored_hash, raw in rows:
        output = json.loads(raw) if raw is not None else None
        expected_output = {"content": [{"type": "text", "text": effect}], "isError": False}
        valid = (raw is not None and effect is not None and output == expected_output
            and expected == stored_hash == hashlib.sha256(raw.encode()).hexdigest())
        result.append({"request_id":request_id,"operation_id":operation_id,"kind":kind,"tool":tool,
            "executions":executions,"result_sha256":expected,"effect_present":effect is not None,
            "result_integrity":valid})
print(json.dumps({"phase":phase,"read_only":True,"rows":result}))
'''


def v2_ledger(state, phase):
    if not state.get("receipts_enabled") or not re.fullmatch(r"mn_[0-9a-f]{12}", phase):
        raise ValueError("Requires the controlled result-query fixture")
    return json.loads(cluster.kubectl(state, "exec", "-i", "deployment/receipt-upstream", "--",
        "python", "-c", V2_LEDGER_PROGRAM, phase, timeout=15))


def collect_phase(state, directory, phase_name, *, expected_cluster):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", phase_name):
        raise ValueError("Phase is not part of this authorized run")
    directory = Path(directory).resolve()
    output = directory / (phase_name + "_supplemental.json")
    if output.exists():
        raise FileExistsError("Supplemental evidence already exists; preserve it")
    # A completion report, not a start marker, gates this extra query.
    json.loads((directory / (phase_name + ".json")).read_text())
    if (not re.fullmatch(r"agentops-mn-[0-9a-f]{8}", expected_cluster)
            or state["cluster"] != expected_cluster or state["namespace"] != expected_cluster
            or Path(state["kubeconfig"]).resolve() != directory / "kubeconfig"):
        raise ValueError("Cluster does not belong to this exact run")
    started = json.loads((directory / (phase_name + "_started.json")).read_text())
    phase = started["phase"]
    if not re.fullmatch(r"mn_[0-9a-f]{12}", phase):
        raise ValueError("Invalid synthetic phase identifier")
    is_admission = started.get("admission", False) or phase_name.startswith("business_loss_") or phase_name in {"backlog", "admission_primary_loss"}
    result = {"phase": phase, "name": phase_name,
        "captured_at": datetime.now(UTC).isoformat(), "read_only": True,
        "production_sla_verified": False, "evidence_collection_complete": False,
        "limits": [
            "Collection is after phase completion, not a continuous fault observer",
            "Scoring and effects require request-ID reconciliation, not aggregate counts alone",
            "Runtime logs may be lost on restart/rotation; legacy collectors additionally cap at 10000 lines per pod",
            "Explicit audit links measure known ID associations, not complete semantic audit coverage",
            "Shadow finding counts do not establish per-request detection accuracy or blocking",
            "No new passing verdict and no original report changes",
        ]}
    errors = []
    try:
        raw = cluster.kubectl(state, "exec", "-i", "deployment/eval-driver", "--", "python", "-",
            phase, "admission" if is_admission else "business", input_text=QUERY_PROGRAM, timeout=60)
        evidence = json.loads(raw)
        result["database"] = evidence
        if not evidence.get("business_query_completed"):
            errors.append({"component": "business_database", "error_type": evidence.get("business_query_error_type", "MissingCompletion")})
        if is_admission and not evidence.get("admission_query_completed"):
            errors.append({"component": "admission_database", "error_type": evidence.get("admission_query_error_type", "MissingCompletion")})
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        errors.append({"component": "database_collection", "error_type": type(error).__name__})
    if started.get("result_recovery"):
        try:
            result["downstream_v2_ledger"] = v2_ledger(state, phase)
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append({"component": "downstream_v2_ledger", "error_type": type(error).__name__})
    if is_admission:
        try:
            result["runtime_events"] = cluster.runtime_events(state, phase)
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append({"component": "runtime_events", "error_type": type(error).__name__})
    else:
        result["runtime_events_file"] = phase_name + "_runtime_events.json" if (directory / (phase_name + "_runtime_events.json")).is_file() else None
    result["collection_errors"] = errors
    result["evidence_collection_complete"] = not errors
    cluster.save(output, result)
    print(json.dumps({"name": phase_name, "evidence_collection_complete": not errors,
        "collection_errors": errors, "output": str(output)}))
    return {"name": phase_name, "complete": not errors, "errors": errors}
