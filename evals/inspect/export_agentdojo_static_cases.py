from __future__ import annotations

from importlib.metadata import version
import json

from agentdojo.attacks.baseline_attacks import (
    DirectAttack,
    IgnorePreviousAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)
from agentdojo.task_suite.load_suites import get_suites


BENCHMARK_VERSION = "v1.2.2"
ATTACK_TYPES = (
    DirectAttack,
    IgnorePreviousAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)


def main() -> int:
    cases: list[dict[str, str]] = []
    suites = get_suites(BENCHMARK_VERSION)
    suite_summary: dict[str, dict[str, int]] = {}
    for suite_name, suite in sorted(suites.items()):
        suite_summary[suite_name] = {
            "user_tasks": len(suite.user_tasks),
            "injection_tasks": len(suite.injection_tasks),
            "tools": len(suite.tools),
            "injection_vectors": len(suite.get_injection_vector_defaults()),
        }
        for task_id, task in sorted(suite.user_tasks.items()):
            cases.append(
                {
                    "case_id": f"benign:{suite_name}:{task_id}",
                    "kind": "benign",
                    "suite": suite_name,
                    "family": "legitimate_user_task",
                    "content": task.PROMPT,
                }
            )
        for attack_type in ATTACK_TYPES:
            attack = attack_type(suite, None)  # type: ignore[arg-type]
            for task_id, task in sorted(suite.injection_tasks.items()):
                cases.append(
                    {
                        "case_id": f"attack:{suite_name}:{attack.name}:{task_id}",
                        "kind": "attack",
                        "suite": suite_name,
                        "family": attack.name,
                        "content": attack.jailbreak.format(
                            goal=task.GOAL,
                            user=attack.user_name,
                            model=attack.model_name,
                            task="",
                        ),
                    }
                )
    print(
        json.dumps(
            {
                "package": "agentdojo",
                "package_version": version("agentdojo"),
                "benchmark_version": BENCHMARK_VERSION,
                "suite_summary": suite_summary,
                "cases": cases,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
