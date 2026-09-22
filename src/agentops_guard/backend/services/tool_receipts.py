"""Opt-in, operator-reviewed downstream reconciliation. Never replays an action.

Receipt v1 returns only a bound outcome and a result digest, not tool output.
Execution confirmation is deliberately NOT gateway success or scanned output.
Opt-in v2 can query a bound result and pass it through the current output boundary.
"""
from __future__ import annotations

from datetime import timedelta
import json
from typing import Literal

from cryptography.fernet import InvalidToken
from fastapi import HTTPException
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import McpServer, McpTool, Run, ToolExecutionPolicy, ToolInvocation
from agentops_guard.backend.schemas import PolicyContext
from agentops_guard.backend.security.context import (
    clear_auth_context, current_auth_context, set_auth_context,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.gateway.concurrency import (
    GatewayCapacityExceeded, GatewayCapacityUnavailable, server_call_slot,
)


class ReceiptContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    protocol: Literal["agentops-receipt-v1", "agentops-receipt-v2"] = "agentops-receipt-v1"
    key_argument: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    lookup_tool_id: str = Field(min_length=1, max_length=384)
    lookup_revision_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    retention_seconds: int = Field(ge=3600, le=31_536_000)
    result_tool_id: str | None = Field(default=None, min_length=1, max_length=384)
    result_revision_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    max_result_bytes: int = Field(default=16_384, ge=1, le=65_536)

    @model_validator(mode="after")
    def result_contract(self):
        fields_present = self.result_tool_id is not None and self.result_revision_digest is not None
        if self.protocol == "agentops-receipt-v2" and not fields_present:
            raise ValueError("Receipt v2 requires a reviewed result tool and revision")
        if self.protocol == "agentops-receipt-v1" and (self.result_tool_id or self.result_revision_digest):
            raise ValueError("Receipt v1 does not return results")
        return self


class DownstreamReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool: str = Field(min_length=1, max_length=255)
    state: Literal["completed", "not_found", "pending"]
    result_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class DownstreamResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool: str = Field(min_length=1, max_length=255)
    result_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    result: dict


class RecoveredText(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    type: Literal["text"]
    text: str


class RecoveredToolOutput(BaseModel):
    """V2 pilot supports text/JSON only, not URLs to fetch or binary resources."""
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    content: list[RecoveredText] = Field(max_length=128)
    structuredContent: dict | None = None
    isError: bool = False


def validate_contract(db: Session, project: str, tool_id: str, contract: ReceiptContract):
    from agentops_guard.backend.services.tool_invocations import current_revision

    current_revision(db, project, tool_id)
    lookup_revision = current_revision(db, project, contract.lookup_tool_id)
    tool = db.get(McpTool, tool_id)
    lookup_tool = db.get(McpTool, contract.lookup_tool_id)
    if (lookup_tool.id == tool.id or lookup_tool.server_id != tool.server_id
            or lookup_revision.content_digest != contract.lookup_revision_digest):
        raise HTTPException(409, "Receipt lookup must match a reviewed tool on the same server")
    if (tool.input_schema or {}).get("properties", {}).get(contract.key_argument, {}).get("type") != "string":
        raise HTTPException(400, "Receipt key must be a declared string argument")
    lookup_schema = lookup_tool.input_schema or {}
    if (lookup_schema.get("properties", {}).get("operation_id", {}).get("type") != "string"
            or set(lookup_schema.get("required", [])) - {"operation_id"}):
        raise HTTPException(400, "Receipt lookup must accept only operation_id as required input")
    if contract.result_tool_id is not None:
        result_revision = current_revision(db, project, contract.result_tool_id)
        result_tool = db.get(McpTool, contract.result_tool_id)
        schema = result_tool.input_schema or {}
        if (result_tool.id == tool.id or result_tool.server_id != tool.server_id
                or result_revision.content_digest != contract.result_revision_digest
                or schema.get("properties", {}).get("operation_id", {}).get("type") != "string"
                or set(schema.get("required", [])) - {"operation_id"}):
            raise HTTPException(409, "Result lookup must match a reviewed tool on the same server")
    return tool, lookup_tool


def reviewed_binding(db: Session, row: ToolInvocation):
    from agentops_guard.backend.services import tool_invocations as inv

    policy = db.get(ToolExecutionPolicy, row.tool_id, populate_existing=True)
    revision = inv.current_revision(db, row.project_id, row.tool_id)
    binding = row.receipt_binding
    if (policy is None or policy.project_id != row.project_id
            or policy.receipt_contract is None or policy.retry_mode != "never"
            or revision.content_digest != policy.revision_digest
            or (binding is not None and (
                binding["revision"] != revision.content_digest
                or binding["policy"] != inv._digest(inv._policy_value(policy))))):
        raise HTTPException(409, "Downstream receipt review changed or is unavailable")
    contract = ReceiptContract.model_validate(policy.receipt_contract)
    tool, lookup_tool = validate_contract(db, row.project_id, row.tool_id, contract)
    return policy, contract, tool, lookup_tool


def prepare_payload(db: Session, row: ToolInvocation, payload: dict) -> dict:
    from agentops_guard.backend.services import tool_invocations as inv

    policy = db.get(ToolExecutionPolicy, row.tool_id, populate_existing=True)
    if policy is None or policy.receipt_contract is None:
        if row.receipt_binding is not None:
            raise HTTPException(409, "Downstream receipt review was removed")
        return payload
    policy, contract, _tool, _lookup = reviewed_binding(db, row)
    if contract.key_argument in payload.get("arguments", {}):
        raise HTTPException(400, "Receipt key is reserved for the trusted executor")
    # No caller key or upstream hint can grant replay or choose another operation.
    key = inv._digest({"project": row.project_id, "actor": row.actor_digest,
        "request": row.request_id, "tool": row.tool_id,
        "revision": policy.revision_digest, "payload": row.payload_digest})
    row.receipt_binding = {"operation_id": key, "revision": policy.revision_digest,
                           "policy": inv._digest(inv._policy_value(policy))}
    if contract.protocol == "agentops-receipt-v2":
        row.receipt_binding = {**row.receipt_binding, "run_id": payload.get("runId")}
    # Injection happens BEFORE argument scanning, intent checks and approval binding.
    return {**payload, "arguments": {**payload.get("arguments", {}), contract.key_argument: key}}


def reconcile_receipt(db: Session, row: ToolInvocation) -> dict:
    from agentops_guard.backend.services import tool_invocations as inv
    from agentops_guard.gateway.app import _call_upstream_tool

    if inv.public_status(row)["state"] == "execution_confirmed":
        if row.receipt_binding and reviewed_binding(db, row)[1].protocol == "agentops-receipt-v2":
            return recover_result(db, row)
        return inv.public_status(row)
    if inv.public_status(row)["state"] != "outcome_unknown":
        return inv.public_status(row)
    if row.receipt_binding is None or row.attempts != 1:
        raise HTTPException(409, "No single-dispatch reviewed receipt binding")
    old_auth = current_auth_context()
    try:
        identity = inv.queued_identity(db, row)  # Also revalidates revoked/expired keys.
        _policy, contract, tool, lookup_tool = reviewed_binding(db, row)
        server = db.get(McpServer, tool.server_id, populate_existing=True)
        if server.allowed_agents and identity.agent_id not in server.allowed_agents:
            raise HTTPException(403, "Receipt lookup authority is no longer valid")
        if inv._utc(row.created_at) + timedelta(seconds=contract.retention_seconds) <= inv._now():
            raise HTTPException(409, "Downstream receipt retention window elapsed")
        operation_id, tool_name = row.receipt_binding["operation_id"], tool.name
        binding = dict(row.receipt_binding)
        db.commit()  # No transaction/row lock is held across the network query.
        settings = get_settings()
        try:
            with server_call_slot(server.id, limit=settings.gateway_max_concurrency_per_server,
                    wait_seconds=settings.gateway_capacity_wait_seconds,
                    backend=settings.gateway_concurrency_backend, redis_url=settings.redis_url,
                    lease_seconds=max(settings.gateway_concurrency_lease_seconds,
                                      settings.gateway_call_timeout_seconds + 10)):
                result = _call_upstream_tool(server, lookup_tool.name, {"operation_id": operation_id})
        except GatewayCapacityExceeded:
            raise HTTPException(429, "MCP server capacity exceeded") from None
        except GatewayCapacityUnavailable:
            raise HTTPException(503, "Gateway capacity coordination unavailable") from None
        if not isinstance(result, dict) or result.get("isError") or result.get("upstreamError"):
            raise HTTPException(502, "Downstream receipt lookup unavailable")
        try:
            receipt = DownstreamReceipt.model_validate(result.get("structuredContent"))
        except ValidationError:
            raise HTTPException(502, "Invalid downstream receipt") from None
        if (receipt.operation_id != operation_id or receipt.tool != tool_name
                or (receipt.state == "completed" and receipt.result_sha256 is None)):
            raise HTTPException(502, "Downstream receipt does not match original dispatch")
        # Recheck authority, contract and state after external I/O. Querying cannot
        # overwrite a newer owner or turn a changed destination into trusted evidence.
        db.refresh(row)
        inv.queued_identity(db, row)
        reviewed_binding(db, row)
        server = db.get(McpServer, tool.server_id, populate_existing=True)
        if server.allowed_agents and identity.agent_id not in server.allowed_agents:
            raise HTTPException(403, "Receipt lookup authority is no longer valid")
        if receipt.state != "completed":
            return inv.public_status(row)  # Absence/pending NEVER permits replay.
        summary = {"code": "downstream_execution_confirmed", "businessExecutionConfirmed": True,
                   "resultAvailable": False, "resultScanned": False,
                   "resultSha256": receipt.result_sha256}
        now = inv._now()
        changed = db.query(ToolInvocation).filter(
            ToolInvocation.id == row.id, ToolInvocation.attempts == 1,
            (ToolInvocation.status == "outcome_unknown")
            | ((ToolInvocation.status == "dispatched") & (ToolInvocation.lease_expires_at < now)),
            ToolInvocation.updated_at == row.updated_at,
        ).update({"status": "execution_confirmed", "summary": summary,
                  "encrypted_payload": None, "lease_token": None, "lease_expires_at": None,
                  "updated_at": now}, synchronize_session=False)
        if changed:
            record_audit(db, project_id=row.project_id, action="tool_invocation.receipt_confirmed",
                resource_type="tool_invocation", resource_id=row.id,
                after=summary, metadata={"contract_digest": binding["policy"]})
        db.commit()
        db.refresh(row)
        if contract.protocol == "agentops-receipt-v2" and row.status == "execution_confirmed":
            return recover_result(db, row)
        return inv.public_status(row)
    finally:
        set_auth_context(old_auth) if old_auth is not None else clear_auth_context()


def _result_authority(db: Session, row: ToolInvocation):
    from agentops_guard.backend.services import tool_invocations as inv

    identity = inv.queued_identity(db, row)
    _policy, contract, tool, _lookup = reviewed_binding(db, row)
    if contract.protocol != "agentops-receipt-v2" or not row.receipt_binding:
        raise HTTPException(409, "No reviewed result recovery contract")
    if inv._utc(row.created_at) + timedelta(seconds=contract.retention_seconds) <= inv._now():
        raise HTTPException(410, "Recovered result retention expired")
    server = db.get(McpServer, tool.server_id, populate_existing=True)
    if server.allowed_agents and identity.agent_id not in server.allowed_agents:
        raise HTTPException(403, "Recovered result authority revoked")
    run_id = row.receipt_binding.get("run_id")
    if run_id is not None:
        run = db.get(Run, run_id, populate_existing=True)
        if run is None or run.project_id != row.project_id or (run.agent_id and run.agent_id != identity.agent_id):
            raise HTTPException(403, "Recovered result run is unavailable")
    return identity, contract, server, tool


def _scan_recovered(db: Session, row: ToolInvocation, result: dict, *, include_provenance=False) -> dict:
    from agentops_guard.backend.services import tool_invocations as inv
    from agentops_guard.backend.services.content import detect_secret_labels
    from agentops_guard.backend.services.content_provenance import strip_untrusted_agentops_metadata
    from agentops_guard.backend.services.policy import evaluate_policy, persist_policy_decision
    from agentops_guard.gateway.app import scan_tool_result

    identity, _contract, server, tool = _result_authority(db, row)
    run_id = row.receipt_binding.get("run_id")
    context = PolicyContext(project_id=row.project_id, run_id=run_id, actor=identity.policy_actor,
        tool={"name": tool.name, "server_id": server.id, "allowed_agents": server.allowed_agents or []},
        data={"content_source": "mcp_tool_result", "trust": "untrusted"},
        metadata={"content_source": "mcp_tool_result", "result_recovery": True})
    decision = persist_policy_decision(db, evaluate_policy(context, db), context)
    if decision.action != "allow":
        db.commit()
        raise HTTPException(403, "Current policy does not permit result release")
    revision = inv.current_revision(db, row.project_id, row.tool_id)
    output_schema = revision.descriptor.get("outputSchema")
    if isinstance(output_schema, dict):
        try:
            validator = validator_for(output_schema)
            validator.check_schema(output_schema)
            valid = validator(output_schema).is_valid(result.get("structuredContent"))
        except SchemaError:
            valid = False
        if not valid:
            raise HTTPException(409, "Recovered result violates the reviewed output schema")
    checked = scan_tool_result(db, identity, server, tool.name, run_id, revision,
        strip_untrusted_agentops_metadata(result), decision, require_complete_scan=True)
    _result_authority(db, row)  # Revocation/review changes during scanning still apply.
    if result.get("isError") or checked.get("isError"):
        raise HTTPException(409, "Recovered output was blocked or reports a tool failure")
    safe = {key: value for key, value in checked.items() if key in {"content", "structuredContent", "isError"}}
    if set(detect_secret_labels(inv._json(safe))) - {"email", "phone"}:
        raise HTTPException(409, "Recovered output contains prohibited credential data")
    if include_provenance:
        safe["provenance"] = checked["provenance"]
    return safe


def recover_result(db: Session, row: ToolInvocation) -> dict:
    """Fetch only the reviewed result query, then scan and fence its state update."""
    from agentops_guard.backend.services import tool_invocations as inv
    from agentops_guard.gateway.app import _call_upstream_tool

    old_auth = current_auth_context()
    try:
        _identity, contract, server, tool = _result_authority(db, row)
        if row.status != "execution_confirmed" or row.attempts != 1:
            return inv.public_status(row)
        key, expected = row.receipt_binding["operation_id"], row.summary["resultSha256"]
        version = row.updated_at
        result_tool = db.get(McpTool, contract.result_tool_id)
        db.commit()
        settings = get_settings()
        try:
            with server_call_slot(server.id, limit=settings.gateway_max_concurrency_per_server,
                    wait_seconds=settings.gateway_capacity_wait_seconds,
                    backend=settings.gateway_concurrency_backend, redis_url=settings.redis_url,
                    lease_seconds=max(settings.gateway_concurrency_lease_seconds, settings.gateway_call_timeout_seconds + 10)):
                response = _call_upstream_tool(server, result_tool.name, {"operation_id": key})
        except GatewayCapacityExceeded:
            raise HTTPException(429, "Result query capacity exceeded") from None
        except GatewayCapacityUnavailable:
            raise HTTPException(503, "Result query coordination unavailable") from None
        if not isinstance(response, dict) or response.get("isError") or response.get("upstreamError"):
            raise HTTPException(502, "Downstream result query unavailable")
        try:
            recovered = DownstreamResult.model_validate(response.get("structuredContent"))
            RecoveredToolOutput.model_validate(recovered.result)
            encoded = inv._json(recovered.result).encode()
        except (ValidationError, ValueError, TypeError):
            raise HTTPException(502, "Invalid downstream result") from None
        if (len(encoded) > contract.max_result_bytes or recovered.operation_id != key
                or recovered.tool != tool.name or recovered.result_sha256 != expected
                or inv._digest(recovered.result) != expected):
            raise HTTPException(502, "Downstream result size or binding mismatch")
        safe = _scan_recovered(db, row, recovered.result)
        envelope = {"id": row.id, "actor": row.actor_digest, "project": row.project_id,
                    "operation_id": key, "result_sha256": expected, "result": safe}
        encrypted = inv._cipher().encrypt(inv._json(envelope).encode()).decode()
        summary = {**row.summary, "code": "downstream_result_recovered", "resultAvailable": True,
                   "resultScanned": True, "isError": False}
        changed = db.query(ToolInvocation).filter(ToolInvocation.id == row.id,
            ToolInvocation.status == "execution_confirmed", ToolInvocation.attempts == 1,
            ToolInvocation.updated_at == version).update({"status": "succeeded", "summary": summary,
                "encrypted_result": encrypted,
                "result_expires_at": inv._utc(row.created_at) + timedelta(seconds=contract.retention_seconds),
                "updated_at": inv._now()}, synchronize_session=False)
        if changed:
            record_audit(db, project_id=row.project_id, action="tool_invocation.result_recovered",
                resource_type="tool_invocation", resource_id=row.id,
                after={"result_scanned": True, "result_sha256": expected})
        db.commit()
        db.refresh(row)
        return inv.public_status(row)
    finally:
        set_auth_context(old_auth) if old_auth is not None else clear_auth_context()


def get_recovered_result(db: Session, row: ToolInvocation) -> dict:
    from agentops_guard.backend.services import tool_invocations as inv

    old_auth = current_auth_context()
    try:
        _result_authority(db, row)
        if not row.encrypted_result or row.status != "succeeded":
            raise HTTPException(409, "No scanned result stored")
        if row.result_expires_at is None or inv._utc(row.result_expires_at) <= inv._now():
            raise HTTPException(410, "Recovered result expired")
        try:
            envelope = json.loads(inv._cipher().decrypt(row.encrypted_result.encode()))
        except (InvalidToken, ValueError):
            raise HTTPException(409, "Recovered result integrity check failed") from None
        binding = {"id": row.id, "actor": row.actor_digest, "project": row.project_id,
                   "operation_id": row.receipt_binding["operation_id"],
                   "result_sha256": row.summary["resultSha256"]}
        if not isinstance(envelope, dict) or any(envelope.get(k) != v for k, v in binding.items()):
            raise HTTPException(409, "Recovered result binding mismatch")
        safe = _scan_recovered(db, row, envelope["result"], include_provenance=True)
        db.commit()
        return {**safe, "invocation": inv.public_status(row)}
    finally:
        set_auth_context(old_auth) if old_auth is not None else clear_auth_context()


def reconcile_batch(db: Session, *, after_id: str | None = None, limit: int = 10):
    """Bounded cursor scan for a separate receipt worker, never the Outbox loop."""
    from agentops_guard.backend.services.tool_invocations import _now

    db.query(ToolInvocation).filter(ToolInvocation.encrypted_result.is_not(None),
        ToolInvocation.result_expires_at <= _now()).update({"encrypted_result": None}, synchronize_session=False)
    db.commit()

    query = db.query(ToolInvocation.id).filter(
        (ToolInvocation.status == "outcome_unknown")
        | (ToolInvocation.status == "execution_confirmed")
        | ((ToolInvocation.status == "dispatched") & (ToolInvocation.lease_expires_at < _now())),
        ToolInvocation.attempts == 1,
    )
    if after_id is not None:
        query = query.filter(ToolInvocation.id > after_id)
    ids = [item[0] for item in query.order_by(ToolInvocation.id).limit(limit)]
    counts = {"queried": 0, "confirmed": 0, "unresolved": 0}
    for row_id in ids:
        row = db.get(ToolInvocation, row_id, populate_existing=True)
        if row.receipt_binding is None:
            continue
        counts["queried"] += 1
        try:
            status = reconcile_receipt(db, row)
            counts["confirmed" if status["state"] in {"execution_confirmed", "succeeded"} else "unresolved"] += 1
        except HTTPException as error:
            db.rollback()
            if error.status_code not in {403, 404, 409, 410, 429, 502, 503}:
                raise
            counts["unresolved"] += 1  # No arbitrary upstream error in logs.
    return counts, ids[-1] if len(ids) == limit else None
