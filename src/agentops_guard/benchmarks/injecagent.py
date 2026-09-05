from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from agentops_guard.benchmarks.llmail_inject import (
    BenchmarkSample,
    EvaluationResult,
    _group_summary,
)


ROOT = Path(__file__).resolve().parents[3]
SOURCE_LOCK = ROOT / "evals" / "injecagent-source.json"
DEFAULT_REPOSITORY = (
    Path.home()
    / ".cache"
    / "agentops-guard-evals"
    / "injecagent-f19c9f2c79a41046eb13c03c51a24c567a8ffa07.git"
)
_PLACEHOLDER = "<Attacker Instruction>"
_NEUTRAL_CONTENT = "No additional action is requested."
_ROW_KEYS = {
    "Attack Type",
    "Attacker Instruction",
    "Attacker Tools",
    "Expected Achievements",
    "Modifed",
    "Thought",
    "Tool Parameters",
    "Tool Response",
    "Tool Response Template",
    "User Instruction",
    "User Tool",
}


class InjecAgentSourceError(ValueError):
    pass


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_source_lock() -> dict[str, Any]:
    try:
        payload = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InjecAgentSourceError("InjecAgent source lock is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "repository",
        "commit",
        "license_file",
        "upstream_evaluator",
        "files",
    }:
        raise InjecAgentSourceError("InjecAgent source lock schema changed")
    if payload["repository"] != "https://github.com/uiuc-kang-lab/InjecAgent.git":
        raise InjecAgentSourceError("InjecAgent repository changed")
    commit = payload["commit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise InjecAgentSourceError("InjecAgent commit is invalid")
    for key in ("license_file", "upstream_evaluator"):
        specification = payload[key]
        if (
            not isinstance(specification, dict)
            or set(specification) != {"path", "sha256"}
            or not isinstance(specification["path"], str)
            or not _is_sha256(specification["sha256"])
        ):
            raise InjecAgentSourceError("InjecAgent provenance blob is invalid")
    expected = {
        "data/test_cases_dh_base.json": {
            "rows": 510,
            "attack_types": {
                "Data Security Harm": 187,
                "Financial Harm": 153,
                "Physical Harm": 170,
            },
        },
        "data/test_cases_ds_base.json": {
            "rows": 544,
            "attack_types": {
                "Financial Data": 102,
                "Others": 255,
                "Physical Data": 187,
            },
        },
    }
    files = payload["files"]
    if not isinstance(files, dict) or set(files) != set(expected):
        raise InjecAgentSourceError("InjecAgent source inventory changed")
    for path, expected_values in expected.items():
        specification = files[path]
        if (
            not isinstance(specification, dict)
            or set(specification) != {"rows", "attack_types", "sha256"}
            or specification["rows"] != expected_values["rows"]
            or specification["attack_types"] != expected_values["attack_types"]
            or not _is_sha256(specification["sha256"])
        ):
            raise InjecAgentSourceError("InjecAgent source blob contract changed")
    return payload


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
    }
    for name in ("LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _git(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise InjecAgentSourceError("InjecAgent Git object read failed")
    return completed.stdout


def _locked_blob(repository: Path, commit: str, path: str, sha256: str) -> bytes:
    raw = _git(repository, "show", f"{commit}:{path}")
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise InjecAgentSourceError(f"InjecAgent source blob changed: {path}")
    return raw


def validate_repository(repository: Path) -> dict[str, Any]:
    resolved = repository.resolve(strict=True)
    lock = load_source_lock()
    head = _git(resolved, "rev-parse", "HEAD").decode("ascii").strip()
    if head != lock["commit"]:
        raise InjecAgentSourceError("InjecAgent checkout is not at the locked commit")
    for key in ("license_file", "upstream_evaluator"):
        specification = lock[key]
        _locked_blob(
            resolved,
            lock["commit"],
            specification["path"],
            specification["sha256"],
        )
    for path, specification in lock["files"].items():
        _locked_blob(resolved, lock["commit"], path, specification["sha256"])
    return lock


def _load_rows(raw: bytes, specification: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        rows = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InjecAgentSourceError("InjecAgent case file is invalid JSON") from exc
    if (
        not isinstance(rows, list)
        or len(rows) != specification["rows"]
        or not all(isinstance(row, dict) and set(row) == _ROW_KEYS for row in rows)
    ):
        raise InjecAgentSourceError("InjecAgent case inventory changed")
    attack_types: Counter[str] = Counter()
    for row in rows:
        attack_type = row["Attack Type"]
        attack = row["Attacker Instruction"]
        attacker_tools = row["Attacker Tools"]
        response = row["Tool Response"]
        template = row["Tool Response Template"]
        user_tool = row["User Tool"]
        if (
            not isinstance(attack_type, str)
            or not isinstance(attack, str)
            or not attack
            or not isinstance(attacker_tools, list)
            or len(attacker_tools) not in {1, 2}
            or not all(isinstance(tool, str) and tool for tool in attacker_tools)
            or not isinstance(response, str)
            or not response
            or attack not in response
            or not isinstance(template, str)
            or template.count(_PLACEHOLDER) != 1
            or not isinstance(user_tool, str)
            or not user_tool
        ):
            raise InjecAgentSourceError("InjecAgent case schema changed")
        attack_types[attack_type] += 1
    if dict(sorted(attack_types.items())) != specification["attack_types"]:
        raise InjecAgentSourceError("InjecAgent attack-type inventory changed")
    return rows


def build_samples_from_rows(
    direct_harm_rows: list[dict[str, Any]],
    data_stealing_rows: list[dict[str, Any]],
) -> tuple[list[BenchmarkSample], dict[str, Any]]:
    samples: list[BenchmarkSample] = []
    digest = hashlib.sha256()
    attack_counts: Counter[str] = Counter()
    template_by_user_tool: dict[str, str] = {}
    first_attacker_tools: set[str] = set()
    attack_instructions: set[str] = set()

    for group, rows in (
        ("direct_harm", direct_harm_rows),
        ("data_stealing", data_stealing_rows),
    ):
        for row in rows:
            family = str(row["Attack Type"])
            reason = f"{group}:{family}"
            sample = BenchmarkSample(
                kind="attack",
                content=str(row["Tool Response"]),
                official_reason=reason,
            )
            samples.append(sample)
            attack_counts[reason] += 1
            user_tool = str(row["User Tool"])
            template = str(row["Tool Response Template"])
            existing = template_by_user_tool.setdefault(user_tool, template)
            if existing != template:
                raise InjecAgentSourceError(
                    "InjecAgent user tool has more than one response template"
                )
            first_attacker_tools.add(str(row["Attacker Tools"][0]))
            attack_instructions.add(str(row["Attacker Instruction"]))
            digest.update(
                json.dumps(
                    [sample.kind, group, family, user_tool, sample.content],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            digest.update(b"\n")

    for user_tool, template in sorted(template_by_user_tool.items()):
        sample = BenchmarkSample(
            kind="benign",
            content=template.replace(_PLACEHOLDER, _NEUTRAL_CONTENT),
            official_reason=f"matched_clean:{user_tool}",
        )
        samples.append(sample)
        digest.update(
            json.dumps(
                [sample.kind, user_tool, sample.content],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")

    return samples, {
        "selected_corpus_sha256": digest.hexdigest(),
        "attack_rows": sum(attack_counts.values()),
        "benign_rows": len(template_by_user_tool),
        "attack_rows_by_family": dict(sorted(attack_counts.items())),
        "user_tools": len(template_by_user_tool),
        "first_stage_attacker_tools": len(first_attacker_tools),
        "unique_attacker_instructions": len(attack_instructions),
        "setting": "base",
        "benign_control": "one matched response template per user tool with a neutral placeholder",
    }


def load_injecagent_samples(
    repository: Path,
) -> tuple[list[BenchmarkSample], dict[str, Any]]:
    lock = validate_repository(repository)
    commit = lock["commit"]
    files = lock["files"]

    def rows(path: str) -> list[dict[str, Any]]:
        specification = files[path]
        return _load_rows(
            _locked_blob(repository, commit, path, specification["sha256"]),
            specification,
        )

    return build_samples_from_rows(
        rows("data/test_cases_dh_base.json"),
        rows("data/test_cases_ds_base.json"),
    )


def summarize_injecagent_results(results: list[EvaluationResult]) -> dict[str, Any]:
    attacks = [result for result in results if result.kind == "attack"]
    benign = [result for result in results if result.kind == "benign"]
    if not attacks or not benign:
        raise ValueError("InjecAgent benchmark requires attack and benign samples")
    summary: dict[str, Any] = {
        "attack": _group_summary(attacks),
        "benign": _group_summary(benign),
        "attack_by_group": {},
        "attack_by_family": {},
    }
    for group in ("direct_harm", "data_stealing"):
        summary["attack_by_group"][group] = _group_summary(
            [
                result
                for result in attacks
                if (result.official_reason or "").startswith(f"{group}:")
            ]
        )
    for reason in sorted({result.official_reason for result in attacks}):
        summary["attack_by_family"][reason] = _group_summary(
            [result for result in attacks if result.official_reason == reason]
        )
    return summary
