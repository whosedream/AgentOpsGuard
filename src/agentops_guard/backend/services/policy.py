import hashlib
import re
import unicodedata
from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import ApprovalRequest, PolicyDecision, PolicyPack, Run
from agentops_guard.backend.schemas import PolicyContext, PolicyDecisionOut
from agentops_guard.backend.services.content import new_id, redact_value
from agentops_guard.backend.services.opa import OpaUnavailable, evaluate_opa

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

INTENT_MANIFEST_KEY = "_guard_user_intent_v1"

ACTION_PRIORITY = {
    "allow": 0,
    "rate_limit": 1,
    "redact": 2,
    "sandbox": 3,
    "require_approval": 4,
    "quarantine": 5,
    "deny": 6,
}
BUILTIN_POLICY_VERSION = "2026-09-05.1"

USER_ACTION_TERMS = {
    "write": (
        "write",
        "update",
        "create",
        "edit",
        "modify",
        "set",
        "add",
        "change",
        "categorize",
        "classify",
        "draft",
        "resolve",
        "close",
        "写入",
        "更新",
        "创建",
        "编辑",
        "修改",
        "设置",
        "新增",
        "更改",
        "分类",
        "归类",
        "起草",
        "解决",
        "关闭",
    ),
    "send": (
        "send",
        "upload",
        "publish",
        "notify",
        "发送",
        "发给",
        "上传",
        "发布",
        "通知",
    ),
    "delete": (
        "delete",
        "remove",
        "drop",
        "destroy",
        "purge",
        "clear",
        "cancel",
        "删除",
        "移除",
        "清空",
        "取消",
    ),
    "payment": (
        "pay",
        "purchase",
        "buy",
        "transfer",
        "charge",
        "refund",
        "付款",
        "支付",
        "购买",
        "转账",
        "扣款",
        "退款",
    ),
    "permission": (
        "grant",
        "revoke",
        "invite",
        "授权",
        "撤销",
        "邀请",
    ),
}

TOOL_ACTION_TERMS = {
    "permission": {"grant", "revoke", "invite", "permission", "permissions", "role", "roles"},
    "payment": {"pay", "payment", "purchase", "buy", "transfer", "charge", "refund"},
    "delete": {"delete", "remove", "drop", "destroy", "purge", "clear", "cancel"},
    "send": {"send", "email", "post", "upload", "publish", "message", "notify"},
    "write": {
        "write",
        "update",
        "create",
        "edit",
        "modify",
        "set",
        "add",
        "patch",
        "put",
        "rename",
        "move",
        "categorize",
        "classify",
        "draft",
        "resolve",
        "close",
        "分类",
        "归类",
        "起草",
        "解决",
        "关闭",
    },
}

TARGET_ARGUMENT_KEYS = {
    "account",
    "account_id",
    "channel",
    "channel_id",
    "destination",
    "email",
    "endpoint",
    "file",
    "file_path",
    "path",
    "recipient",
    "recipients",
    "role",
    "target",
    "to",
    "uri",
    "url",
    "user_id",
    "webhook",
}
TARGET_ARGUMENT_SCOPES = {
    "email_index": "email",
}

INTENT_TARGET_PATTERN = re.compile(
    r"https?://[^\s]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"(?:[A-Za-z]:\\|/)[^\s]+|[\w.-]{3,}",
    re.UNICODE,
)


def _normalize_intent_value(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold().strip()


def _intent_value_hash(value: str) -> str:
    return hashlib.sha256(_normalize_intent_value(value).encode("utf-8")).hexdigest()


def _contains_action_term(text: str, term: str) -> bool:
    if term.isascii():
        return re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text) is not None
    return term in text


def build_user_intent_manifest(text: str | None) -> dict[str, Any]:
    normalized = _normalize_intent_value(text or "")
    actions = sorted(
        action
        for action, terms in USER_ACTION_TERMS.items()
        if any(_contains_action_term(normalized, term) for term in terms)
    )
    target_hashes = sorted(
        {
            _intent_value_hash(match.group(0).rstrip(".,;:!?)]}"))
            for match in INTENT_TARGET_PATTERN.finditer(normalized)
        }
    )
    target_scopes: list[str] = []
    if (
        any(
            _contains_action_term(normalized, term)
            for term in ("categorize", "classify", "分类", "归类")
        )
        and any(
            _contains_action_term(normalized, term)
            for term in ("email", "emails", "message", "messages", "邮件")
        )
    ):
        target_scopes.append("email")
    return {
        "version": 1,
        "present": bool(normalized),
        "actions": actions,
        "target_hashes": target_hashes,
        "target_scopes": target_scopes,
    }


def _tool_actions(
    tool_name: str, annotations: dict[str, Any], server_trust_level: str
) -> list[str]:
    actions: set[str] = set()
    if annotations.get("destructiveHint") is True:
        actions.add("delete")
    tokens = set(re.split(r"[^a-z0-9]+", tool_name.casefold()))
    for action, terms in TOOL_ACTION_TERMS.items():
        if tokens & terms:
            actions.add(action)
    if not actions and server_trust_level == "external":
        actions.add("external_unknown")
    if len(actions) > 1:
        actions.discard("write")
    return sorted(actions)


def _target_argument_values(
    arguments: dict[str, Any],
) -> tuple[list[str], list[tuple[str, str | None]]]:
    fields: set[str] = set()
    values: list[tuple[str, str | None]] = []

    def visit(value: Any, key: str | None = None) -> None:
        normalized_key = re.sub(r"(?<!^)(?=[A-Z])", "_", key or "").replace("-", "_").casefold()
        is_target = (
            normalized_key in TARGET_ARGUMENT_KEYS
            or normalized_key in TARGET_ARGUMENT_SCOPES
            or normalized_key.endswith(
            (
                "_account",
                "_channel",
                "_destination",
                "_email",
                "_file",
                "_id",
                "_path",
                "_recipient",
                "_role",
                "_target",
                "_uri",
                "_url",
                "_webhook",
            )
        )
        )
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_value, str(child_key))
        elif isinstance(value, list):
            for item in value:
                visit(item, key)
        elif is_target and isinstance(value, str | int | float):
            fields.add(normalized_key)
            values.append((str(value), TARGET_ARGUMENT_SCOPES.get(normalized_key)))

    visit(arguments)
    return sorted(fields), values


def assess_tool_action_alignment(
    tool_name: str,
    arguments: dict[str, Any],
    annotations: dict[str, Any],
    intent_manifest: dict[str, Any] | None,
    server_trust_level: str = "internal",
) -> dict[str, Any]:
    actions = _tool_actions(tool_name, annotations, server_trust_level)
    target_fields, target_values = _target_argument_values(arguments)
    manifest = intent_manifest or {}
    known_target_hashes = set(manifest.get("target_hashes") or [])
    known_target_scopes = set(manifest.get("target_scopes") or [])
    action_aligned = not actions or set(actions).issubset(set(manifest.get("actions") or []))
    target_aligned = (not arguments and not target_values) or (
        bool(target_values)
        and all(
            _intent_value_hash(value) in known_target_hashes
            or (scope is not None and scope in known_target_scopes)
            for value, scope in target_values
        )
    )
    required = bool(actions)
    return {
        "required": required,
        "action": actions[0] if len(actions) == 1 else None,
        "actions": actions,
        "intent_present": bool(manifest.get("present")),
        "action_aligned": action_aligned,
        "target_aligned": target_aligned,
        "aligned": not required
        or (bool(manifest.get("present")) and action_aligned and target_aligned),
        "target_fields": target_fields,
        "target_scopes": sorted(
            {scope for _, scope in target_values if scope is not None}
        ),
    }


def _tool_name(context: PolicyContext) -> str:
    return str(context.tool.get("name") or context.tool.get("id") or "")


def _redacted_context(context: PolicyContext) -> dict[str, Any]:
    return redact_value(context.model_dump())


def evaluate_policy(context: PolicyContext, db: Session | None = None) -> PolicyDecisionOut:
    tracer = trace.get_tracer("agentops_guard.policy")
    with tracer.start_as_current_span("policy.evaluate") as span:
        hard_decision = _evaluate_hard_boundary(context)
        if hard_decision is not None:
            decision = hard_decision
        else:
            decisions: list[PolicyDecisionOut] = []
            opa_decision = _evaluate_opa(context)
            if opa_decision is not None:
                decisions.append(opa_decision)
            pack_decision = _evaluate_policy_packs(context, db)
            if pack_decision is not None:
                decisions.append(pack_decision)
            decisions.append(_evaluate_builtin_soft_policy(context))
            decision = max(
                decisions,
                key=lambda candidate: ACTION_PRIORITY[candidate.action],
            )
        span.set_attribute("agentops.policy.action", decision.action)
        span.set_attribute(
            "agentops.risk.level",
            "high"
            if context.risk_score >= 0.7
            else "medium"
            if context.risk_score >= 0.4
            else "low",
        )
        return decision


def evaluate_builtin_policy(context: PolicyContext) -> PolicyDecisionOut:
    hard_decision = _evaluate_hard_boundary(context)
    if hard_decision is not None:
        return hard_decision
    return _evaluate_builtin_soft_policy(context)


def _evaluate_hard_boundary(context: PolicyContext) -> PolicyDecisionOut | None:
    command = str(context.tool.get("command") or context.tool.get("args", {}).get("command", ""))
    labels = set(context.risk_labels) | set(context.data.get("labels", []))
    actor = context.actor.get("agent_id")
    allowed_agents = context.tool.get("allowed_agents") or []

    if allowed_agents and actor not in allowed_agents:
        return PolicyDecisionOut(
            action="deny",
            reason_code="tool_not_allowed_for_agent",
            severity="high",
            matched_policy="tool_access",
            remediation="Bind this tool to the agent explicitly or route through a lower-risk tool.",
            context=_redacted_context(context),
        )

    if context.tool.get("status") == "quarantined":
        return PolicyDecisionOut(
            action="quarantine",
            reason_code="mcp_tool_quarantined",
            severity="critical",
            matched_policy="mcp_trust",
            remediation="Review the MCP tool metadata and remove malicious instructions before enabling it.",
            context=_redacted_context(context),
        )

    if labels & EXFILTRATION_LABELS:
        return PolicyDecisionOut(
            action="deny",
            reason_code="data_exfiltration",
            severity="critical",
            matched_policy="data_boundary",
            remediation="Redact sensitive data and avoid sending it to external tools or URLs.",
            context=_redacted_context(context),
        )

    if any(fragment.lower() in command.lower() for fragment in DANGEROUS_COMMAND_FRAGMENTS):
        return PolicyDecisionOut(
            action="deny",
            reason_code="dangerous_command",
            severity="critical",
            matched_policy="dangerous_command",
            remediation="Replace the command with a scoped, reversible operation.",
            context=_redacted_context(context),
        )

    alignment = context.data.get("action_alignment") or {}
    if alignment.get("required") and context.data.get("untrusted_content_risk"):
        return PolicyDecisionOut(
            action="require_approval",
            reason_code="untrusted_content_influenced_mutation",
            severity="high",
            matched_policy="content_data_flow",
            remediation="Review the mutation because it follows risky external content.",
            context=_redacted_context(context),
        )
    if alignment.get("required") and not alignment.get("aligned"):
        if "external_unknown" in (alignment.get("actions") or []):
            reason_code = "unreviewed_external_tool"
            remediation = (
                "Review the external tool and mark its server internal before automatic execution."
            )
        elif not alignment.get("intent_present"):
            reason_code = "trusted_user_intent_required"
            remediation = "Bind the tool call to a run containing the original user request."
        elif not alignment.get("action_aligned"):
            reason_code = "tool_action_not_authorized"
            remediation = "Ask the user to authorize this action explicitly."
        else:
            reason_code = "tool_target_not_authorized"
            remediation = "Ask the user to authorize the exact tool target explicitly."
        return PolicyDecisionOut(
            action="require_approval",
            reason_code=reason_code,
            severity="high",
            matched_policy="tool_action_alignment",
            remediation=remediation,
            context=_redacted_context(context),
        )

    return None


def _evaluate_builtin_soft_policy(context: PolicyContext) -> PolicyDecisionOut:
    tool_name = _tool_name(context)

    if tool_name in HIGH_RISK_TOOLS or context.risk_score >= 0.7:
        return PolicyDecisionOut(
            action="require_approval",
            reason_code="high_risk_tool_or_content",
            severity="high",
            matched_policy="approval",
            remediation="Require human approval before executing this high-risk action.",
            context=_redacted_context(context),
        )

    if context.risk_score >= 0.4:
        return PolicyDecisionOut(
            action="redact",
            reason_code="medium_risk_content",
            severity="medium",
            matched_policy="data_boundary",
            remediation="Return sanitized content to the agent context.",
            context=_redacted_context(context),
        )

    return PolicyDecisionOut(
        action="allow",
        reason_code="no_policy_violation",
        severity="low",
        matched_policy="default_allow",
        remediation=None,
        context=_redacted_context(context),
    )


def persist_policy_decision(
    db: Session, decision: PolicyDecisionOut, context: PolicyContext
) -> PolicyDecisionOut:
    safe_decision = PolicyDecisionOut.model_validate(redact_value(decision.model_dump()))
    snapshot = build_policy_snapshot(db, safe_decision, context)
    policy_pack_revisions = snapshot["policy_pack_revisions"]
    opa_bundle_revision = snapshot["opa_bundle_revision"]
    record = PolicyDecision(
        id=new_id("policy"),
        project_id=context.project_id,
        run_id=context.run_id,
        event_id=context.event_id,
        action=safe_decision.action,
        reason_code=safe_decision.reason_code,
        severity=safe_decision.severity,
        matched_policy=safe_decision.matched_policy,
        remediation=safe_decision.remediation,
        context=safe_decision.context,
        builtin_policy_version=BUILTIN_POLICY_VERSION,
        policy_pack_revisions=policy_pack_revisions,
        opa_bundle_revision=opa_bundle_revision,
    )
    db.add(record)
    db.flush()
    persisted = safe_decision.model_copy(
        update={
            "id": record.id,
            "builtin_policy_version": BUILTIN_POLICY_VERSION,
            "policy_pack_revisions": policy_pack_revisions,
            "opa_bundle_revision": opa_bundle_revision,
        }
    )
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
                requester=redact_value(context.actor or {}),
                status="pending",
                reason_code=persisted.reason_code,
                severity=persisted.severity,
                risk_score=context.risk_score,
                risk_labels=redact_value(context.risk_labels),
                context=_redacted_context(context),
            )
            db.add(approval)
            if context.run_id:
                run = db.get(Run, context.run_id)
                if run and run.status == "running":
                    run.status = "awaiting_approval"
                    run.metadata_json = {
                        **(run.metadata_json or {}),
                        "approval_request_id": approval.id,
                    }
            db.flush()
    return persisted


def build_policy_snapshot(
    db: Session,
    decision: PolicyDecisionOut,
    context: PolicyContext,
) -> dict[str, Any]:
    return {
        "builtin_policy_version": BUILTIN_POLICY_VERSION,
        "policy_pack_revisions": [
            {"id": pack.id, "family_id": pack.family_id, "version": pack.version}
            for pack in (
                db.query(PolicyPack)
                .filter(
                    PolicyPack.project_id == context.project_id,
                    PolicyPack.status == "active",
                )
                .order_by(PolicyPack.created_at.asc(), PolicyPack.id.asc())
                .all()
            )
        ],
        "opa_bundle_revision": decision.context.get("opa_bundle_revision"),
    }


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


def _evaluate_pack_rule(
    context: PolicyContext, pack: PolicyPack, rule: dict[str, Any]
) -> PolicyDecisionOut | None:
    conditions = rule.get("when") or rule.get("conditions") or {}
    if not _conditions_match(context, conditions):
        return None
    action = str(rule.get("action") or "deny")
    if action not in ACTION_PRIORITY:
        raise ValueError(f"Unsupported policy action: {action}")
    return PolicyDecisionOut(
        action=action,
        reason_code=str(rule.get("reason_code") or rule.get("id") or "policy_pack_match"),
        severity=str(rule.get("severity") or "high"),
        matched_policy=f"{pack.name}:{rule.get('id') or rule.get('name') or 'rule'}",
        remediation=rule.get("remediation"),
        context={
            **_redacted_context(context),
            "policy_pack_id": pack.id,
            "policy_pack_version": pack.version,
        },
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
        command = str(
            context.tool.get("command") or context.tool.get("args", {}).get("command", "")
        )
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
        return _decision_from_opa_result(evaluate_opa(_redacted_context(context)), context)
    except OpaUnavailable:
        return _opa_failure_decision(context, settings.policy_fail_mode)


def _decision_from_opa_result(result: dict[str, Any], context: PolicyContext) -> PolicyDecisionOut:
    action = str(result.get("action") or ("allow" if result.get("allow", True) else "deny"))
    if action not in ACTION_PRIORITY:
        raise OpaUnavailable("OPA returned an unsupported action")
    return PolicyDecisionOut(
        action=action,
        reason_code=str(result.get("reason_code") or "opa_decision"),
        severity=str(result.get("severity") or "low"),
        matched_policy=str(result.get("matched_policy") or "opa"),
        remediation=result.get("remediation"),
        context={
            **_redacted_context(context),
            "policy_provider": "opa",
            "policy_revision": result.get("policy_revision"),
            "opa_bundle_revision": result.get("bundle_revision") or result.get("revision"),
        },
    )


def _opa_failure_decision(context: PolicyContext, fail_mode: str) -> PolicyDecisionOut | None:
    if fail_mode == "open":
        return None
    high_risk = (
        _tool_name(context) in HIGH_RISK_TOOLS
        or context.risk_score >= 0.4
        or bool((context.data.get("action_alignment") or {}).get("required"))
    )
    if fail_mode == "closed_for_high_risk" and not high_risk:
        return None
    action = "deny" if fail_mode == "closed" else "require_approval"
    return PolicyDecisionOut(
        action=action,
        reason_code="opa_unavailable",
        severity="high",
        matched_policy="opa_fail_mode",
        remediation="Restore the OPA policy service before retrying this action.",
        context={**_redacted_context(context), "policy_provider": "opa", "provider_status": "error"},
    )
