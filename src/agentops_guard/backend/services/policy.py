from typing import Any

import httpx
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import ApprovalRequest, PolicyDecision, PolicyPack, Run
from agentops_guard.backend.schemas import PolicyContext, PolicyDecisionOut
from agentops_guard.backend.services.content import new_id

HIGH_RISK_TOOLS = {
    "shell.execute",
    "terminal.run",
    "filesystem.write",
    "filesystem.delete",
    "database.write",
    "http.post",
    "slack.send",
    "feishu.send",
}

DANGEROUS_COMMAND_FRAGMENTS = (
    "rm -rf /",
    "del /s",
    "format ",
    "mkfs",
    ":(){ :|:& };:",
    "curl ",
    "wget ",
    "Invoke-WebRequest",
)

EXFILTRATION_LABELS = {
    "credential_exfiltration",
    "data_exfiltration",
    "sensitive_data_exfiltration",
    "openai_api_key",
    "anthropic_api_key",
    "aws_access_key",
    "jwt",
    "ssh_private_key",
    "db_url",
}


def _tool_name(context: PolicyContext) -> str:
    return str(context.tool.get("name") or context.tool.get("id") or "")


def evaluate_policy(context: PolicyContext, db: Session | None = None) -> PolicyDecisionOut:
    opa_decision = _evaluate_opa(context)
    if opa_decision is not None:
        return opa_decision
    pack_decision = _evaluate_policy_packs(context, db)
    if pack_decision is not None:
        return pack_decision
    return evaluate_builtin_policy(context)


def evaluate_builtin_policy(context: PolicyContext) -> PolicyDecisionOut:
    tool_name = _tool_name(context)
    command = str(context.tool.get("command") or context.tool.get("args", {}).get("command", ""))
    labels = set(context.risk_labels) | set(context.data.get("labels", []))
    actor = context.actor.get("agent_id") or context.actor.get("role")
    allowed_agents = context.tool.get("allowed_agents") or []

    if allowed_agents and actor and actor not in allowed_agents:
        return PolicyDecisionOut(
            action="deny",
            reason_code="tool_not_allowed_for_agent",
            severity="high",
            matched_policy="tool_access",
            remediation="Bind this tool to the agent explicitly or route through a lower-risk tool.",
            context=context.model_dump(),
        )

    if context.tool.get("status") == "quarantined":
        return PolicyDecisionOut(
            action="quarantine",
            reason_code="mcp_tool_quarantined",
            severity="critical",
            matched_policy="mcp_trust",
            remediation="Review the MCP tool metadata and remove malicious instructions before enabling it.",
            context=context.model_dump(),
        )

    if labels & EXFILTRATION_LABELS:
        return PolicyDecisionOut(
            action="deny",
            reason_code="data_exfiltration",
            severity="critical",
            matched_policy="data_boundary",
            remediation="Redact sensitive data and avoid sending it to external tools or URLs.",
            context=context.model_dump(),
        )

    if any(fragment.lower() in command.lower() for fragment in DANGEROUS_COMMAND_FRAGMENTS):
        return PolicyDecisionOut(
            action="deny",
            reason_code="dangerous_command",
            severity="critical",
            matched_policy="dangerous_command",
            remediation="Replace the command with a scoped, reversible operation.",
            context=context.model_dump(),
        )

    if tool_name in HIGH_RISK_TOOLS or context.risk_score >= 0.7:
        return PolicyDecisionOut(
            action="require_approval",
            reason_code="high_risk_tool_or_content",
            severity="high",
            matched_policy="approval",
            remediation="Require human approval before executing this high-risk action.",
            context=context.model_dump(),
        )

    if context.risk_score >= 0.4:
        return PolicyDecisionOut(
            action="redact",
            reason_code="medium_risk_content",
            severity="medium",
            matched_policy="data_boundary",
            remediation="Return sanitized content to the agent context.",
            context=context.model_dump(),
        )

    return PolicyDecisionOut(
        action="allow",
        reason_code="no_policy_violation",
        severity="low",
        matched_policy="default_allow",
        remediation=None,
        context=context.model_dump(),
    )


def persist_policy_decision(db: Session, decision: PolicyDecisionOut, context: PolicyContext) -> PolicyDecisionOut:
    record = PolicyDecision(
        id=new_id("policy"),
        project_id=context.project_id,
        run_id=context.run_id,
        event_id=context.event_id,
        action=decision.action,
        reason_code=decision.reason_code,
        severity=decision.severity,
        matched_policy=decision.matched_policy,
        remediation=decision.remediation,
        context=decision.context,
    )
    db.add(record)
    db.flush()
    persisted = decision.model_copy(update={"id": record.id})
    if persisted.action == "require_approval":
        existing = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.project_id == context.project_id,
                ApprovalRequest.run_id == context.run_id,
                ApprovalRequest.event_id == context.event_id,
                ApprovalRequest.decision_id == record.id,
            )
            .first()
        )
        if existing is None:
            approval = ApprovalRequest(
                id=new_id("approval"),
                project_id=context.project_id,
                run_id=context.run_id,
                event_id=context.event_id,
                decision_id=record.id,
                action=persisted.action,
                requester=context.actor or {},
                status="pending",
                reason_code=persisted.reason_code,
                severity=persisted.severity,
                risk_score=context.risk_score,
                risk_labels=context.risk_labels,
                context=context.model_dump(),
            )
            db.add(approval)
            if context.run_id:
                run = db.get(Run, context.run_id)
                if run and run.status == "running":
                    run.status = "awaiting_approval"
                    run.metadata_json = {**(run.metadata_json or {}), "approval_request_id": approval.id}
            db.flush()
    return persisted


def _evaluate_policy_packs(context: PolicyContext, db: Session | None) -> PolicyDecisionOut | None:
    if db is None:
        return None
    packs = (
        db.query(PolicyPack)
        .filter(PolicyPack.project_id == context.project_id, PolicyPack.status == "active")
        .order_by(PolicyPack.created_at.desc())
        .all()
    )
    for pack in packs:
        for rule in pack.rules or []:
            decision = _evaluate_pack_rule(context, pack, rule)
            if decision is not None:
                return decision
    return None


def _evaluate_pack_rule(context: PolicyContext, pack: PolicyPack, rule: dict[str, Any]) -> PolicyDecisionOut | None:
    conditions = rule.get("when") or rule.get("conditions") or {}
    if not _conditions_match(context, conditions):
        return None
    action = str(rule.get("action") or "deny")
    return PolicyDecisionOut(
        action=action,
        reason_code=str(rule.get("reason_code") or rule.get("id") or "policy_pack_match"),
        severity=str(rule.get("severity") or "high"),
        matched_policy=f"{pack.name}:{rule.get('id') or rule.get('name') or 'rule'}",
        remediation=rule.get("remediation"),
        context={**context.model_dump(), "policy_pack_id": pack.id, "policy_pack_version": pack.version},
    )


def _conditions_match(context: PolicyContext, conditions: dict[str, Any]) -> bool:
    if not conditions:
        return False
    tool_name = _tool_name(context)
    if "tool_name" in conditions and tool_name != conditions["tool_name"]:
        return False
    if "tool_name_in" in conditions and tool_name not in set(conditions["tool_name_in"] or []):
        return False
    min_risk = conditions.get("min_risk_score")
    if min_risk is not None and context.risk_score < float(min_risk):
        return False
    required_labels = set(conditions.get("risk_labels_any") or [])
    labels = set(context.risk_labels) | set(context.data.get("labels", []))
    if required_labels and not (required_labels & labels):
        return False
    command_contains = conditions.get("command_contains")
    if command_contains:
        command = str(context.tool.get("command") or context.tool.get("args", {}).get("command", ""))
        if str(command_contains).lower() not in command.lower():
            return False
    environment = conditions.get("environment")
    if environment and context.environment != environment:
        return False
    return True


def _evaluate_opa(context: PolicyContext) -> PolicyDecisionOut | None:
    settings = get_settings()
    if not settings.opa_url:
        return None
    try:
        response = httpx.post(
            f"{settings.opa_url.rstrip('/')}/v1/data/agentops/guard/decision",
            json={"input": context.model_dump()},
            timeout=2.0,
        )
        response.raise_for_status()
        result = response.json().get("result")
    except httpx.HTTPError:
        return None
    if not isinstance(result, dict):
        return None
    return _decision_from_opa_result(result, context)


def _decision_from_opa_result(result: dict[str, Any], context: PolicyContext) -> PolicyDecisionOut:
    action = str(result.get("action") or ("allow" if result.get("allow", True) else "deny"))
    return PolicyDecisionOut(
        action=action,
        reason_code=str(result.get("reason_code") or "opa_decision"),
        severity=str(result.get("severity") or "low"),
        matched_policy=str(result.get("matched_policy") or "opa"),
        remediation=result.get("remediation"),
        context=context.model_dump(),
    )
