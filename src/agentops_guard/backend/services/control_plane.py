from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import (
    ApprovalRequest,
    ExecutionRequest,
    PolicyPack,
    Project,
    Run,
    RunSuppression,
    ScanRule,
)
from agentops_guard.backend.schemas import (
    ApprovalRequestCreate,
    ApprovalRequestOut,
    ApprovalReview,
    ControlPlaneStatusOut,
    PolicyPackCreate,
    PolicyPackOut,
    PolicyPackUpdate,
    PolicyPackVersionCreate,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    RunSuppressionCreate,
    RunSuppressionOut,
    RunSuppressionUpdate,
    ScanRuleCreate,
    ScanRuleOut,
    ScanRuleUpdate,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import new_id, redact_text, redact_value
from agentops_guard.backend.services.identity import ensure_bootstrap_organization
from agentops_guard.backend.services.projects import ensure_project


def project_out(row: Project) -> ProjectOut:
    return ProjectOut(
        id=row.id,
        organization_id=row.organization_id,
        name=row.name,
        store_raw_content=row.store_raw_content,
        retention_days=row.retention_days,
        policy_fail_mode=row.policy_fail_mode or get_settings().policy_fail_mode,
        status=row.status or "active",
        metadata=row.metadata_json or {},
        created_at=row.created_at,
    )


def approval_out(row: ApprovalRequest) -> ApprovalRequestOut:
    return ApprovalRequestOut(
        id=row.id,
        project_id=row.project_id,
        run_id=row.run_id,
        event_id=row.event_id,
        decision_id=row.decision_id,
        execution_request_id=row.execution_request_id,
        action=row.action,
        requester=row.requester or {},
        status=row.status,
        reason_code=row.reason_code,
        severity=row.severity,
        risk_score=row.risk_score,
        risk_labels=row.risk_labels or [],
        context=row.context or {},
        resolved_by=row.resolved_by,
        resolved_reason=row.resolved_reason,
        expires_at=row.expires_at,
        resolved_at=row.resolved_at,
        created_at=row.created_at,
    )


def policy_pack_out(row: PolicyPack) -> PolicyPackOut:
    return PolicyPackOut(
        id=row.id,
        family_id=row.family_id,
        project_id=row.project_id,
        name=row.name,
        version=row.version,
        status=row.status,
        description=row.description,
        rules=row.rules or [],
        created_at=row.created_at,
    )


def scan_rule_out(row: ScanRule) -> ScanRuleOut:
    return ScanRuleOut(
        id=row.id,
        project_id=row.project_id,
        label=row.label,
        pattern=row.pattern,
        severity=row.severity,
        score=row.score,
        status=row.status,
        description=row.description,
        created_at=row.created_at,
    )


def suppression_out(row: RunSuppression) -> RunSuppressionOut:
    return RunSuppressionOut(
        id=row.id,
        project_id=row.project_id,
        run_id=row.run_id,
        reason=row.reason,
        status=row.status,
        created_by=row.created_by,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )


def create_project_config(db: Session, payload: ProjectCreate) -> ProjectOut:
    if db.get(Project, payload.id):
        raise ValueError("Project already exists")
    organization_id = payload.organization_id or ensure_bootstrap_organization(db).id
    row = Project(
        id=payload.id,
        organization_id=organization_id,
        name=payload.name or payload.id,
        store_raw_content=payload.store_raw_content,
        retention_days=payload.retention_days,
        policy_fail_mode=payload.policy_fail_mode,
        status=payload.status,
        metadata_json=redact_value(payload.metadata),
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        project_id=payload.id,
        action="project.create",
        resource_type="project",
        resource_id=payload.id,
        after=project_out(row).model_dump(mode="json"),
    )
    return project_out(row)


def update_project_config(db: Session, project_id: str, payload: ProjectUpdate) -> ProjectOut:
    ensure_project(db, project_id)
    row = db.get(Project, project_id)
    if row is None:
        raise ValueError("Project not found")
    before = project_out(row).model_dump(mode="json")
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if key == "metadata":
            row.metadata_json = {
                **(row.metadata_json or {}),
                **redact_value(value or {}),
            }
        else:
            setattr(row, key, value)
    record_audit(
        db,
        project_id=project_id,
        action="project.update",
        resource_type="project",
        resource_id=project_id,
        before=before,
        after=updates,
    )
    db.flush()
    return project_out(row)


def create_approval_request(db: Session, payload: ApprovalRequestCreate) -> ApprovalRequestOut:
    ensure_project(db, payload.project_id)
    row = ApprovalRequest(
        id=new_id("approval"),
        project_id=payload.project_id,
        run_id=payload.run_id,
        event_id=payload.event_id,
        decision_id=payload.decision_id,
        action=payload.action,
        requester=redact_value(payload.requester),
        reason_code=payload.reason_code,
        severity=payload.severity,
        risk_score=payload.risk_score,
        risk_labels=redact_value(payload.risk_labels),
        context=redact_value(payload.context),
        expires_at=payload.expires_at,
    )
    db.add(row)
    db.flush()
    if row.run_id:
        run = db.get(Run, row.run_id)
        if run and run.status == "running":
            run.status = "awaiting_approval"
            run.metadata_json = {**(run.metadata_json or {}), "approval_request_id": row.id}
    record_audit(
        db,
        project_id=payload.project_id,
        action="approval.create",
        resource_type="approval_request",
        resource_id=row.id,
        after=approval_out(row).model_dump(mode="json"),
    )
    return approval_out(row)


class ApprovalConflict(ValueError):
    pass


def review_approval_request(
    db: Session,
    approval_id: str,
    payload: ApprovalReview,
    reviewer_id: str,
) -> ApprovalRequestOut:
    row = db.get(ApprovalRequest, approval_id)
    if row is None:
        raise ValueError("Approval request not found")
    before = approval_out(row).model_dump(mode="json")
    now = datetime.now(UTC)
    expires_at = row.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            raise ApprovalConflict("Approval request expired")
    execution = (
        db.get(ExecutionRequest, row.execution_request_id)
        if row.execution_request_id is not None
        else None
    )
    if execution is not None and execution.status != "waiting_approval":
        raise ApprovalConflict("Execution request is no longer waiting for approval")
    updated = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.id == approval_id, ApprovalRequest.status == "pending")
        .update(
            {
                ApprovalRequest.status: payload.status,
                ApprovalRequest.resolved_by: reviewer_id,
                ApprovalRequest.resolved_reason: (
                    redact_text(payload.resolved_reason)
                    if payload.resolved_reason is not None
                    else None
                ),
                ApprovalRequest.resolved_at: now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        raise ApprovalConflict("Approval request has already been resolved")
    db.flush()
    db.refresh(row)
    if execution is not None:
        execution.status = "approved" if payload.status == "approved" else "denied"
        execution.approved_at = now if payload.status == "approved" else None
    if row.run_id:
        run = db.get(Run, row.run_id)
        if run:
            if payload.status == "approved" and run.status == "awaiting_approval":
                run.status = "running"
            elif payload.status == "denied":
                run.status = "blocked"
                run.ended_at = now
            run.metadata_json = {
                **(run.metadata_json or {}),
                "approval_request_id": row.id,
                "approval_status": payload.status,
            }
    record_audit(
        db,
        project_id=row.project_id,
        action=f"approval.{payload.status}",
        resource_type="approval_request",
        resource_id=row.id,
        before=before,
        after=approval_out(row).model_dump(mode="json"),
    )
    db.flush()
    return approval_out(row)


def create_policy_pack(db: Session, payload: PolicyPackCreate) -> PolicyPackOut:
    ensure_project(db, payload.project_id)
    family_id = new_id("pack_family")
    row = PolicyPack(
        id=new_id("pack"),
        family_id=family_id,
        project_id=payload.project_id,
        name=payload.name,
        version=payload.version,
        status=payload.status,
        description=payload.description,
        rules=payload.rules,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        project_id=payload.project_id,
        action="policy_pack.create",
        resource_type="policy_pack",
        resource_id=row.id,
        after=policy_pack_out(row).model_dump(mode="json"),
    )
    return policy_pack_out(row)


def create_policy_pack_version(
    db: Session, pack_id: str, payload: PolicyPackVersionCreate
) -> PolicyPackOut:
    source = db.get(PolicyPack, pack_id)
    if source is None:
        raise ValueError("Policy pack not found")
    row = PolicyPack(
        id=new_id("pack"),
        family_id=source.family_id or source.id,
        project_id=source.project_id,
        name=source.name,
        version=payload.version,
        status=payload.status,
        description=payload.description,
        rules=payload.rules,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        project_id=source.project_id,
        action="policy_pack.version.create",
        resource_type="policy_pack",
        resource_id=row.id,
        after=policy_pack_out(row).model_dump(mode="json"),
    )
    return policy_pack_out(row)


def update_policy_pack(db: Session, pack_id: str, payload: PolicyPackUpdate) -> PolicyPackOut:
    row = db.get(PolicyPack, pack_id)
    if row is None:
        raise ValueError("Policy pack not found")
    before = policy_pack_out(row).model_dump(mode="json")
    updates = payload.model_dump(exclude_unset=True)
    if "rules" in updates:
        raise ValueError("Policy pack rules must be versioned through a new revision")
    for key, value in updates.items():
        setattr(row, key, value)
    record_audit(
        db,
        project_id=row.project_id,
        action="policy_pack.update",
        resource_type="policy_pack",
        resource_id=row.id,
        before=before,
        after=updates,
    )
    db.flush()
    return policy_pack_out(row)


def create_scan_rule(db: Session, payload: ScanRuleCreate) -> ScanRuleOut:
    from agentops_guard.backend.services.safe_regex import compile_configurable_pattern

    compile_configurable_pattern(payload.pattern)
    ensure_project(db, payload.project_id)
    row = ScanRule(
        id=new_id("scan_rule"),
        project_id=payload.project_id,
        label=payload.label,
        pattern=payload.pattern,
        severity=payload.severity,
        score=payload.score,
        status=payload.status,
        description=payload.description,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        project_id=payload.project_id,
        action="scan_rule.create",
        resource_type="scan_rule",
        resource_id=row.id,
        after=scan_rule_out(row).model_dump(mode="json"),
    )
    return scan_rule_out(row)


def update_scan_rule(db: Session, rule_id: str, payload: ScanRuleUpdate) -> ScanRuleOut:
    from agentops_guard.backend.services.scanner_rule_packs import (
        ManagedScannerRuleImmutable,
        is_managed_scan_rule_id,
    )

    row = db.get(ScanRule, rule_id)
    if row is None:
        raise ValueError("Scan rule not found")
    if is_managed_scan_rule_id(rule_id):
        raise ManagedScannerRuleImmutable(
            "Managed scanner rules are immutable; install a new reviewed pack revision"
        )
    updates = payload.model_dump(exclude_unset=True)
    if "pattern" in updates:
        from agentops_guard.backend.services.safe_regex import compile_configurable_pattern

        compile_configurable_pattern(updates["pattern"])
    before = scan_rule_out(row).model_dump(mode="json")
    for key, value in updates.items():
        setattr(row, key, value)
    record_audit(
        db,
        project_id=row.project_id,
        action="scan_rule.update",
        resource_type="scan_rule",
        resource_id=row.id,
        before=before,
        after=updates,
    )
    db.flush()
    return scan_rule_out(row)


def create_run_suppression(
    db: Session, run_id: str, payload: RunSuppressionCreate
) -> RunSuppressionOut:
    ensure_project(db, payload.project_id)
    run = db.get(Run, run_id)
    if run is None:
        raise ValueError("Run not found")
    row = RunSuppression(
        id=new_id("suppress"),
        project_id=payload.project_id,
        run_id=run_id,
        reason=redact_text(payload.reason),
        created_by=redact_text(payload.created_by),
        expires_at=payload.expires_at,
    )
    db.add(row)
    db.flush()
    run.status = "suppressed"
    run.metadata_json = {
        **(run.metadata_json or {}),
        "suppression_id": row.id,
        "suppression_reason": row.reason,
    }
    record_audit(
        db,
        project_id=payload.project_id,
        action="run.suppress",
        resource_type="run",
        resource_id=run_id,
        after=suppression_out(row).model_dump(mode="json"),
    )
    return suppression_out(row)


def update_run_suppression(
    db: Session, suppression_id: str, payload: RunSuppressionUpdate
) -> RunSuppressionOut:
    row = db.get(RunSuppression, suppression_id)
    if row is None:
        raise ValueError("Run suppression not found")
    before = suppression_out(row).model_dump(mode="json")
    row.status = payload.status
    if payload.reason is not None:
        row.reason = redact_text(payload.reason)
    if payload.status in {"resolved", "expired"}:
        run = db.get(Run, row.run_id)
        if run and run.status == "suppressed":
            run.status = "completed"
            run.metadata_json = {**(run.metadata_json or {}), "suppression_status": payload.status}
    record_audit(
        db,
        project_id=row.project_id,
        action=f"run.suppression.{payload.status}",
        resource_type="run_suppression",
        resource_id=row.id,
        before=before,
        after=suppression_out(row).model_dump(mode="json"),
    )
    db.flush()
    return suppression_out(row)


def control_plane_status(db: Session, project_id: str) -> ControlPlaneStatusOut:
    ensure_project(db, project_id)
    project = db.get(Project, project_id)
    if project is None:
        raise ValueError("Project not found")
    status_rows = (
        db.query(Run.status, func.count(Run.id))
        .filter(Run.project_id == project_id)
        .group_by(Run.status)
        .all()
    )
    return ControlPlaneStatusOut(
        project=project_out(project),
        pending_approvals=db.query(ApprovalRequest)
        .filter(ApprovalRequest.project_id == project_id, ApprovalRequest.status == "pending")
        .count(),
        active_policy_packs=db.query(PolicyPack)
        .filter(PolicyPack.project_id == project_id, PolicyPack.status == "active")
        .count(),
        enabled_scan_rules=db.query(ScanRule)
        .filter(ScanRule.project_id == project_id, ScanRule.status == "enabled")
        .count(),
        active_suppressions=db.query(RunSuppression)
        .filter(RunSuppression.project_id == project_id, RunSuppression.status == "active")
        .count(),
        run_statuses={status: count for status, count in status_rows},
    )
