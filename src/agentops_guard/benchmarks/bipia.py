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
SOURCE_LOCK = ROOT / "evals" / "bipia-source.json"
DEFAULT_REPOSITORY = (
    Path.home()
    / ".cache"
    / "agentops-guard-evals"
    / "bipia-a004b69ec0dd446e0afd461d98cb5e96e120a5d0.git"
)


class BipiaSourceError(ValueError):
    pass


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_source_lock() -> dict[str, Any]:
    payload = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    expected = {
        "repository",
        "commit",
        "package_version",
        "license_file",
        "upstream_insert_implementation",
        "files",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise BipiaSourceError("BIPIA source lock schema changed")
    if payload["repository"] != "https://github.com/microsoft/BIPIA.git":
        raise BipiaSourceError("BIPIA source repository changed")
    if not isinstance(payload["commit"], str) or len(payload["commit"]) != 40:
        raise BipiaSourceError("BIPIA source commit is invalid")
    if not all(character in "0123456789abcdef" for character in payload["commit"]):
        raise BipiaSourceError("BIPIA source commit is invalid")
    if payload["package_version"] != "0.1.0":
        raise BipiaSourceError("BIPIA source package version changed")
    license_spec = payload["license_file"]
    insert_spec = payload["upstream_insert_implementation"]
    files = payload["files"]
    if (
        not isinstance(license_spec, dict)
        or set(license_spec) != {"path", "sha256"}
        or not isinstance(insert_spec, dict)
        or set(insert_spec) != {"path", "sha256", "function"}
        or insert_spec["function"] != "insert_end"
        or not isinstance(files, dict)
    ):
        raise BipiaSourceError("BIPIA source lock details changed")
    if (
        not isinstance(license_spec["path"], str)
        or not _is_sha256(license_spec["sha256"])
        or not isinstance(insert_spec["path"], str)
        or not _is_sha256(insert_spec["sha256"])
    ):
        raise BipiaSourceError("BIPIA source lock contains an invalid blob")
    expected_files = {
        "benchmark/email/test.jsonl": ("text_context", "rows", 50),
        "benchmark/table/test.jsonl": ("text_context", "rows", 100),
        "benchmark/code/test.jsonl": ("code_context", "rows", 50),
        "benchmark/text_attack_test.json": ("text_attacks", "families", 15),
        "benchmark/code_attack_test.json": ("code_attacks", "families", 10),
    }
    if set(files) != set(expected_files):
        raise BipiaSourceError("BIPIA source file inventory changed")
    for path, (kind, count_key, count) in expected_files.items():
        specification = files[path]
        if (
            not isinstance(specification, dict)
            or specification.get("kind") != kind
            or specification.get(count_key) != count
            or not _is_sha256(specification.get("sha256"))
        ):
            raise BipiaSourceError("BIPIA source lock contains an invalid blob")
    if files["benchmark/text_attack_test.json"].get("variants") != 75 or files[
        "benchmark/code_attack_test.json"
    ].get("variants") != 50:
        raise BipiaSourceError("BIPIA attack source inventory changed")
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
        raise BipiaSourceError("BIPIA Git object read failed")
    return completed.stdout


def _locked_blob(repository: Path, commit: str, path: str, sha256: str) -> bytes:
    raw = _git(repository, "show", f"{commit}:{path}")
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise BipiaSourceError(f"BIPIA source blob changed: {path}")
    return raw


def validate_repository(repository: Path) -> dict[str, Any]:
    resolved = repository.resolve(strict=True)
    lock = load_source_lock()
    head = _git(resolved, "rev-parse", "HEAD").decode("ascii").strip()
    if head != lock["commit"]:
        raise BipiaSourceError("BIPIA checkout is not at the locked commit")
    license_spec = lock["license_file"]
    _locked_blob(resolved, lock["commit"], license_spec["path"], license_spec["sha256"])
    insert_spec = lock["upstream_insert_implementation"]
    _locked_blob(resolved, lock["commit"], insert_spec["path"], insert_spec["sha256"])
    for path, spec in lock["files"].items():
        _locked_blob(resolved, lock["commit"], path, spec["sha256"])
    return lock


def _json_lines(raw: bytes, *, expected_rows: int) -> list[dict[str, Any]]:
    try:
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BipiaSourceError("BIPIA context JSONL is invalid") from exc
    if len(rows) != expected_rows or not all(isinstance(row, dict) for row in rows):
        raise BipiaSourceError("BIPIA context row inventory changed")
    return rows


def _attacks(raw: bytes, *, expected_families: int, expected_variants: int) -> dict[str, list[str]]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BipiaSourceError("BIPIA attack JSON is invalid") from exc
    if (
        not isinstance(payload, dict)
        or len(payload) != expected_families
        or sum(len(values) for values in payload.values() if isinstance(values, list))
        != expected_variants
        or not all(
            isinstance(name, str)
            and isinstance(values, list)
            and len(values) == 5
            and all(isinstance(value, str) and value for value in values)
            for name, values in payload.items()
        )
    ):
        raise BipiaSourceError("BIPIA attack inventory changed")
    return payload


def _context(task: str, row: dict[str, Any]) -> str:
    content = row.get("context")
    if task == "code":
        if not isinstance(content, list) or not all(isinstance(value, str) for value in content):
            raise BipiaSourceError("BIPIA code context schema changed")
        return "\n".join(content)
    if not isinstance(content, str):
        raise BipiaSourceError("BIPIA text context schema changed")
    return content


def build_samples_from_payloads(
    contexts: dict[str, list[dict[str, Any]]],
    text_attacks: dict[str, list[str]],
    code_attacks: dict[str, list[str]],
) -> tuple[list[BenchmarkSample], dict[str, Any]]:
    samples: list[BenchmarkSample] = []
    digest = hashlib.sha256()
    attack_counts: Counter[str] = Counter()
    benign_counts: Counter[str] = Counter()
    for task in ("email", "table", "code"):
        attacks = code_attacks if task == "code" else text_attacks
        for row in contexts[task]:
            content = _context(task, row)
            sample = BenchmarkSample(kind="benign", content=content, official_reason=f"{task}:benign")
            samples.append(sample)
            benign_counts[task] += 1
            digest.update(
                json.dumps(
                    [sample.kind, task, "benign", sample.content],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            digest.update(b"\n")
            for family in sorted(attacks):
                for variant, attack in enumerate(attacks[family]):
                    poisoned = "\n".join([content, attack])
                    reason = f"{task}:{family}"
                    sample = BenchmarkSample(kind="attack", content=poisoned, official_reason=reason)
                    samples.append(sample)
                    attack_counts[task] += 1
                    digest.update(
                        json.dumps(
                            [sample.kind, task, family, variant, sample.content],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
                    digest.update(b"\n")
    return samples, {
        "selected_corpus_sha256": digest.hexdigest(),
        "attack_rows": sum(attack_counts.values()),
        "benign_rows": sum(benign_counts.values()),
        "attack_rows_by_task": dict(sorted(attack_counts.items())),
        "benign_rows_by_task": dict(sorted(benign_counts.items())),
        "insertion_position": "end",
    }


def load_bipia_samples(repository: Path) -> tuple[list[BenchmarkSample], dict[str, Any]]:
    lock = validate_repository(repository)
    commit = lock["commit"]
    files = lock["files"]

    def blob(path: str) -> bytes:
        return _locked_blob(repository, commit, path, files[path]["sha256"])

    contexts = {
        "email": _json_lines(
            blob("benchmark/email/test.jsonl"),
            expected_rows=files["benchmark/email/test.jsonl"]["rows"],
        ),
        "table": _json_lines(
            blob("benchmark/table/test.jsonl"),
            expected_rows=files["benchmark/table/test.jsonl"]["rows"],
        ),
        "code": _json_lines(
            blob("benchmark/code/test.jsonl"),
            expected_rows=files["benchmark/code/test.jsonl"]["rows"],
        ),
    }
    text_spec = files["benchmark/text_attack_test.json"]
    text_attacks = _attacks(
        blob("benchmark/text_attack_test.json"),
        expected_families=text_spec["families"],
        expected_variants=text_spec["variants"],
    )
    code_spec = files["benchmark/code_attack_test.json"]
    code_attacks = _attacks(
        blob("benchmark/code_attack_test.json"),
        expected_families=code_spec["families"],
        expected_variants=code_spec["variants"],
    )
    samples, inventory = build_samples_from_payloads(contexts, text_attacks, code_attacks)
    inventory["text_attack_families"] = len(text_attacks)
    inventory["text_attack_variants"] = sum(map(len, text_attacks.values()))
    inventory["code_attack_families"] = len(code_attacks)
    inventory["code_attack_variants"] = sum(map(len, code_attacks.values()))
    return samples, inventory


def summarize_bipia_results(results: list[EvaluationResult]) -> dict[str, Any]:
    attacks = [result for result in results if result.kind == "attack"]
    benign = [result for result in results if result.kind == "benign"]
    summary: dict[str, Any] = {
        "attack": _group_summary(attacks),
        "benign": _group_summary(benign),
        "by_task": {},
        "attack_by_family": {},
    }
    for task in ("email", "table", "code"):
        summary["by_task"][task] = {
            "attack": _group_summary(
                [
                    result
                    for result in attacks
                    if (result.official_reason or "").startswith(f"{task}:")
                ]
            ),
            "benign": _group_summary(
                [result for result in benign if result.official_reason == f"{task}:benign"]
            ),
        }
    for reason in sorted({result.official_reason for result in attacks}):
        summary["attack_by_family"][reason] = _group_summary(
            [result for result in attacks if result.official_reason == reason]
        )
    return summary
