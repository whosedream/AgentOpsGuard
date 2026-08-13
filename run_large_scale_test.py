#!/usr/bin/env python3
"""大规模测试运行器：确定性变异用例 → Scanner+Policy → 汇总报告。

用法: python3 run_large_scale_test.py [--llm-count 0]
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

# 确保项目根在 path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

os.environ.setdefault("AGENTOPS_ENV", "dev")
os.environ.setdefault("AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", "true")

from agentops_guard.backend.schemas import PolicyContext, ScanRequest  # noqa: E402
from agentops_guard.backend.services.scanner import scan_content  # noqa: E402
from agentops_guard.backend.services.policy import evaluate_builtin_policy  # noqa: E402

# 导入变异用例生成器（在 tests/agent_test/ 下）
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "agent_test"))
from mutation_cases import gen_all_mutation_cases  # noqa: E402


@dataclass
class TestResult:
    case_id: str
    category: str
    is_attack: bool
    content_preview: str
    risk_score: float
    risk_labels: list[str]
    policy_action: str
    detected: bool
    hard_blocked: bool
    approval_gated: bool
    redacted: bool
    source: str = "mutation"
    scored: bool = True


def run_mutation_tests() -> list[TestResult]:
    """运行全部变异用例。"""
    cases = gen_all_mutation_cases()
    results: list[TestResult] = []
    for case in cases:
        scan = scan_content(ScanRequest(content=case.content, source=case.source))
        if case.tool_name:
            tool = {"name": case.tool_name}
            if case.command:
                tool["command"] = case.command
            context = PolicyContext(
                tool=tool,
                risk_score=scan.risk_score,
                risk_labels=scan.risk_labels,
            )
        else:
            context = PolicyContext(
                risk_score=scan.risk_score,
                risk_labels=scan.risk_labels,
                data={"labels": scan.risk_labels},
            )
        decision = evaluate_builtin_policy(context)
        detected = bool(scan.risk_labels)
        report_category = (
            f"{case.category}_tool_command" if case.command else case.category
        )
        results.append(
            TestResult(
                case_id=case.case_id,
                category=report_category,
                is_attack=case.is_attack,
                content_preview=(case.content or case.command)[:120],
                risk_score=scan.risk_score,
                risk_labels=scan.risk_labels,
                policy_action=decision.action,
                detected=detected,
                hard_blocked=decision.action in {"deny", "quarantine"},
                approval_gated=decision.action == "require_approval",
                redacted=decision.action == "redact",
                source="mutation",
            )
        )
    return results


def generate_report(results: list[TestResult]) -> str:
    """生成汇总报告。"""
    candidate_total = len(results)
    scored_results = [r for r in results if r.scored]
    total = len(scored_results)
    attack_results = [r for r in scored_results if r.is_attack]
    benign_results = [r for r in scored_results if not r.is_attack]
    detected_attacks = sum(r.detected for r in attack_results)
    hard_blocked_attacks = sum(r.hard_blocked for r in attack_results)
    approval_gated_attacks = sum(r.approval_gated for r in attack_results)
    redacted_attacks = sum(r.redacted for r in attack_results)
    non_allow_attacks = sum(r.policy_action != "allow" for r in attack_results)
    detected_benign = sum(r.detected for r in benign_results)
    hard_blocked_benign = sum(r.hard_blocked for r in benign_results)

    by_category: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "hard_blocked": 0, "approval": 0, "redacted": 0}
    )
    for r in scored_results:
        by_category[r.category]["total"] += 1
        by_category[r.category]["detected"] += int(r.detected)
        by_category[r.category]["hard_blocked"] += int(r.hard_blocked)
        by_category[r.category]["approval"] += int(r.approval_gated)
        by_category[r.category]["redacted"] += int(r.redacted)

    by_source: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "hard_blocked": 0, "approval": 0, "redacted": 0}
    )
    for r in scored_results:
        by_source[r.source]["total"] += 1
        by_source[r.source]["detected"] += int(r.detected)
        by_source[r.source]["hard_blocked"] += int(r.hard_blocked)
        by_source[r.source]["approval"] += int(r.approval_gated)
        by_source[r.source]["redacted"] += int(r.redacted)

    missed = [r for r in attack_results if not r.detected][:20]
    false_pos = [r for r in benign_results if r.detected][:20]

    lines = []
    lines.append("=" * 70)
    lines.append("  AGENTOPS GUARD - SYNTHETIC STRESS REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total candidates:     {candidate_total}")
    lines.append(f"  Scored attacks:     {len(attack_results)}")
    lines.append(f"  Scored benign:      {len(benign_results)}")
    lines.append(f"  Scored deterministic cases: {total}")
    lines.append(f"  LLM candidates (unreviewed): {sum(1 for r in results if r.source == 'llm')}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  CORE METRICS")
    lines.append("-" * 70)
    attack_count = len(attack_results)
    benign_count = len(benign_results)
    lines.append(
        f"Scanner attack detection:          {detected_attacks / attack_count * 100:.1f}%  "
        f"({detected_attacks}/{attack_count})"
    )
    lines.append(
        f"Policy hard block (deny/quarantine): {hard_blocked_attacks / attack_count * 100:.1f}%  "
        f"({hard_blocked_attacks}/{attack_count})"
    )
    lines.append(
        f"Approval gate:                    {approval_gated_attacks / attack_count * 100:.1f}%  "
        f"({approval_gated_attacks}/{attack_count})"
    )
    lines.append(
        f"Redaction action:                 {redacted_attacks / attack_count * 100:.1f}%  "
        f"({redacted_attacks}/{attack_count})"
    )
    lines.append(
        f"Any non-allow action:             {non_allow_attacks / attack_count * 100:.1f}%  "
        f"({non_allow_attacks}/{attack_count})"
    )
    lines.append(
        f"Scanner benign FPR:               {detected_benign / benign_count * 100:.1f}%  "
        f"({detected_benign}/{benign_count})"
    )
    lines.append(
        f"Policy hard-block benign rate:    {hard_blocked_benign / benign_count * 100:.1f}%  "
        f"({hard_blocked_benign}/{benign_count})"
    )
    lines.append("")
    lines.append("-" * 70)
    lines.append("  BY CATEGORY")
    lines.append("-" * 70)
    lines.append(
        f"{'Category':<26} {'Total':>6} {'Detected':>9} {'Hard':>6} {'Approval':>8} {'Redact':>6}"
    )
    for cat in sorted(by_category.keys()):
        d = by_category[cat]
        lines.append(
            f"{cat:<26} {d['total']:>6} {d['detected']:>9} {d['hard_blocked']:>6} "
            f"{d['approval']:>8} {d['redacted']:>6}"
        )
    lines.append("")
    lines.append("-" * 70)
    lines.append("  BY SOURCE")
    lines.append("-" * 70)
    lines.append(
        f"{'Source':<15} {'Total':>6} {'Detected':>9} {'Hard':>6} {'Approval':>8} {'Redact':>6}"
    )
    for src in sorted(by_source.keys()):
        d = by_source[src]
        lines.append(
            f"{src:<15} {d['total']:>6} {d['detected']:>9} {d['hard_blocked']:>6} "
            f"{d['approval']:>8} {d['redacted']:>6}"
        )
    lines.append("")

    if missed:
        lines.append("-" * 70)
        lines.append("  SAMPLE UNDETECTED ATTACK CANDIDATES (first 20)")
        lines.append("-" * 70)
        for r in missed:
            lines.append(
                f"  [{r.case_id}] {r.category} | score={r.risk_score:.2f} action={r.policy_action} labels={r.risk_labels}"
            )
            lines.append(f"    {r.content_preview}")
        lines.append("")

    if false_pos:
        lines.append("-" * 70)
        lines.append("  SAMPLE SCANNER FALSE POSITIVES (first 20)")
        lines.append("-" * 70)
        for r in false_pos:
            lines.append(
                f"  [{r.case_id}] {r.category} | score={r.risk_score:.2f} action={r.policy_action} labels={r.risk_labels}"
            )
            lines.append(f"    {r.content_preview}")
        lines.append("")

    # Policy action 分布
    action_dist = Counter(r.policy_action for r in scored_results)
    lines.append("-" * 70)
    lines.append("  POLICY ACTION DISTRIBUTION")
    lines.append("-" * 70)
    for action, cnt in action_dist.most_common():
        lines.append(f"  {action:<25} {cnt:>6} ({cnt / total * 100:.1f}%)")
    lines.append("")

    lines.append("=" * 70)
    report = "\n".join(lines)
    return report


def main():
    llm_count = 0
    if "--llm-count" in sys.argv:
        idx = sys.argv.index("--llm-count")
        if idx + 1 < len(sys.argv):
            llm_count = int(sys.argv[idx + 1])
    if llm_count != 0:
        raise SystemExit(
            "LLM-generated candidates are disabled; run the pinned public benchmark instead"
        )

    print("=" * 70)
    print("  AgentOps Guard - Large Scale Test Runner")
    print("=" * 70)
    print()

    # Step 1: 运行变异用例
    print("[1/2] Running mutation-based tests...")
    t0 = time.time()
    mutation_results = run_mutation_tests()
    t1 = time.time()
    print(f"  {len(mutation_results)} mutation cases completed in {t1 - t0:.1f}s")

    # 打印变异用例统计
    mut_summary = Counter(r.category for r in mutation_results)
    for cat, cnt in sorted(mut_summary.items()):
        print(f"    {cat}: {cnt}")

    # Step 2: 汇总报告
    print()
    print("[2/2] Generating report...")
    all_results = mutation_results
    report = generate_report(all_results)
    print()
    print(report)

    # 保存报告到文件
    report_path = os.path.join(os.path.dirname(__file__), "large_scale_test_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")

    # 保存详细结果 JSON
    json_path = os.path.join(os.path.dirname(__file__), "large_scale_test_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            [
                {
                    "case_id": r.case_id,
                    "category": r.category,
                    "is_attack": r.is_attack,
                    "content_preview": r.content_preview,
                    "risk_score": r.risk_score,
                    "risk_labels": r.risk_labels,
                    "policy_action": r.policy_action,
                    "detected": r.detected,
                    "hard_blocked": r.hard_blocked,
                    "approval_gated": r.approval_gated,
                    "redacted": r.redacted,
                    "source": r.source,
                    "scored": r.scored,
                }
                for r in all_results
            ],
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"Detailed results saved to: {json_path}")
    print("RESULT: metrics reported without an arbitrary pass threshold")


if __name__ == "__main__":
    main()
