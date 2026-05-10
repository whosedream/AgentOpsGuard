from sqlalchemy.orm import Session

from agentops_guard.backend.models import EvalRun, EvalSuite
from agentops_guard.backend.schemas import EvalRunCreate, EvalRunOut, EvalSuiteCreate, EvalSuiteOut
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.policy import evaluate_policy
from agentops_guard.backend.services.scanner import scan_content
from agentops_guard.backend.schemas import PolicyContext, ScanRequest


def create_eval_suite(db: Session, request: EvalSuiteCreate) -> EvalSuiteOut:
    suite = EvalSuite(
        id=new_id("suite"),
        project_id=request.project_id,
        name=request.name,
        description=request.description,
        cases=request.cases,
    )
    db.add(suite)
    db.flush()
    return EvalSuiteOut(
        id=suite.id,
        project_id=suite.project_id,
        name=suite.name,
        description=suite.description,
        cases=suite.cases,
        created_at=suite.created_at,
    )


def run_eval(db: Session, request: EvalRunCreate) -> EvalRunOut:
    cases = request.cases
    if cases is None and request.suite_id:
        suite = db.get(EvalSuite, request.suite_id)
        cases = suite.cases if suite else []
    cases = cases or []
    results = [_run_case(request.project_id, case) for case in cases]
    passed = all(result["passed"] for result in results)
    summary = {
        "case_count": len(results),
        "passed_count": sum(1 for result in results if result["passed"]),
        "failed_count": sum(1 for result in results if not result["passed"]),
    }
    eval_run = EvalRun(
        id=new_id("eval"),
        project_id=request.project_id,
        suite_id=request.suite_id,
        status="completed",
        passed=passed,
        summary=summary,
        results=results,
    )
    db.add(eval_run)
    db.flush()
    return EvalRunOut(
        id=eval_run.id,
        project_id=eval_run.project_id,
        suite_id=eval_run.suite_id,
        status=eval_run.status,
        passed=eval_run.passed,
        summary=eval_run.summary,
        results=eval_run.results,
        created_at=eval_run.created_at,
    )


def _run_case(project_id: str, case: dict) -> dict:
    content = case.get("input", "")
    scan = scan_content(ScanRequest(project_id=project_id, content=content, source="eval"))
    tool = case.get("tool") or {"name": case.get("tool_name", "")}
    decision = evaluate_policy(
        PolicyContext(
            project_id=project_id,
            actor={"agent_id": case.get("agent")},
            tool=tool,
            risk_score=scan.risk_score,
            risk_labels=scan.risk_labels,
            data={"labels": scan.risk_labels},
        )
    )
    expected = case.get("expected", {})
    failures = []
    for expected_label in expected.get("risk_labels", []):
        if expected_label not in scan.risk_labels:
            failures.append(f"missing risk label: {expected_label}")
    for expected_decision in expected.get("policy_decisions", []):
        if expected_decision.get("action") and expected_decision["action"] != decision.action:
            failures.append(f"expected action {expected_decision['action']} got {decision.action}")
        if expected_decision.get("reason_code") and expected_decision["reason_code"] != decision.reason_code:
            failures.append(f"expected reason {expected_decision['reason_code']} got {decision.reason_code}")
    for forbidden_tool in expected.get("forbidden_tools", []):
        if forbidden_tool == tool.get("name") and decision.action == "allow":
            failures.append(f"forbidden tool allowed: {forbidden_tool}")
    return {
        "name": case.get("name", "unnamed"),
        "passed": not failures,
        "failures": failures,
        "scanner": scan.model_dump(),
        "policy_decision": decision.model_dump(),
    }
