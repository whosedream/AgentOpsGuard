from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Literal


HoldoutOutcome = Literal["succeeded", "failed", "interrupted"]

_HASH = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,127}")
_REFERENCE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_ROLES = {"training", "tuning", "regression", "first_run_holdout"}
_STATES = {"available", "sealed", "first_run_in_progress", "consumed"}
_OUTCOMES = {"succeeded", "failed", "interrupted"}
_TOP_LEVEL_KEYS = {"schemaVersion", "manifestRevision", "datasets"}
_DATASET_KEYS = {
    "id",
    "role",
    "state",
    "corpusSha256",
    "counts",
    "source",
    "custodianRef",
    "frozenSystemSha256",
    "firstRun",
}
_SOURCE_KEYS = {"name", "revision", "license"}
_FIRST_RUN_KEYS = {
    "runRef",
    "startedAt",
    "frozenSystemSha256",
    "completedAt",
    "outcome",
    "reportSha256",
}


class HoldoutManifestError(ValueError):
    """Raised when the holdout registry would permit an ambiguous blind claim."""


@dataclass
class HoldoutRunTicket:
    manifest_path: Path
    dataset_id: str
    run_ref: str
    report_sha256: str | None = None

    def record_report(self, report_path: Path) -> str:
        if report_path.is_symlink() or not report_path.is_file():
            raise HoldoutManifestError("Holdout report must be a regular file")
        self.report_sha256 = file_sha256(report_path)
        return self.report_sha256


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def system_snapshot_sha256(files: Mapping[str, Path]) -> str:
    """Hash reviewed implementation inputs without returning their paths or contents."""

    if not files:
        raise HoldoutManifestError("At least one system input is required")
    digest = hashlib.sha256()
    for label, path in sorted(files.items()):
        _require_identifier(label, "system input label")
        if path.is_symlink() or not path.is_file():
            raise HoldoutManifestError("System input must be a regular file")
        encoded_label = label.encode("ascii")
        digest.update(len(encoded_label).to_bytes(4, "big"))
        digest.update(encoded_label)
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest()


def load_holdout_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HoldoutManifestError("Holdout manifest must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HoldoutManifestError("Holdout manifest is unreadable") from exc
    validate_holdout_manifest(payload)
    return payload


def validate_holdout_manifest(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_KEYS:
        raise HoldoutManifestError("Holdout manifest top-level contract changed")
    if payload["schemaVersion"] != 1:
        raise HoldoutManifestError("Unsupported holdout manifest schema")
    revision = payload["manifestRevision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise HoldoutManifestError("Holdout manifest revision must be positive")
    datasets = payload["datasets"]
    if not isinstance(datasets, list) or len(datasets) > 512:
        raise HoldoutManifestError("Holdout dataset inventory is invalid")

    ids: set[str] = set()
    corpus_hashes: set[str] = set()
    for dataset in datasets:
        _validate_dataset(dataset)
        dataset_id = dataset["id"]
        corpus_hash = dataset["corpusSha256"]
        if dataset_id in ids:
            raise HoldoutManifestError("Holdout dataset id is duplicated")
        if corpus_hash in corpus_hashes:
            raise HoldoutManifestError("A corpus cannot be reused under another evaluation role")
        ids.add(dataset_id)
        corpus_hashes.add(corpus_hash)


def register_holdout(
    path: Path,
    *,
    dataset_id: str,
    corpus_sha256: str,
    counts: Mapping[str, int],
    source: Mapping[str, str],
    custodian_ref: str,
    frozen_system_sha256: str,
) -> dict[str, Any]:
    """Register a sealed set using aggregate metadata supplied by its custodian."""

    dataset = {
        "id": dataset_id,
        "role": "first_run_holdout",
        "state": "sealed",
        "corpusSha256": corpus_sha256,
        "counts": dict(counts),
        "source": dict(source),
        "custodianRef": custodian_ref,
        "frozenSystemSha256": frozen_system_sha256,
    }
    _validate_dataset(dataset)

    def add(payload: dict[str, Any]) -> dict[str, Any]:
        payload["datasets"].append(dataset)
        return deepcopy(dataset)

    return _mutate_manifest(path, add)


def claim_holdout(
    path: Path,
    *,
    dataset_id: str,
    run_ref: str,
    frozen_system_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Consume the blind status before any evaluation content is made available."""

    _require_identifier(dataset_id, "dataset id")
    _require_reference(run_ref, "run reference")
    _require_hash(frozen_system_sha256, "frozen system digest")
    started_at = _timestamp(now)

    def claim(payload: dict[str, Any]) -> dict[str, Any]:
        dataset = _find_dataset(payload, dataset_id)
        if dataset["role"] != "first_run_holdout" or dataset["state"] != "sealed":
            raise HoldoutManifestError("Dataset is no longer an unseen holdout")
        if dataset["frozenSystemSha256"] != frozen_system_sha256:
            raise HoldoutManifestError("Current system does not match the frozen holdout baseline")
        dataset["role"] = "regression"
        dataset["state"] = "first_run_in_progress"
        dataset["firstRun"] = {
            "runRef": run_ref,
            "startedAt": started_at,
            "frozenSystemSha256": frozen_system_sha256,
        }
        return deepcopy(dataset)

    return _mutate_manifest(path, claim)


def complete_holdout(
    path: Path,
    *,
    dataset_id: str,
    run_ref: str,
    outcome: HoldoutOutcome,
    report_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    _require_identifier(dataset_id, "dataset id")
    _require_reference(run_ref, "run reference")
    if outcome not in _OUTCOMES:
        raise HoldoutManifestError("Holdout outcome is invalid")
    if outcome == "succeeded" and report_sha256 is None:
        raise HoldoutManifestError("A successful first run requires a report digest")
    if report_sha256 is not None:
        _require_hash(report_sha256, "report digest")
    completed_at = _timestamp(now)

    def complete(payload: dict[str, Any]) -> dict[str, Any]:
        dataset = _find_dataset(payload, dataset_id)
        first_run = dataset.get("firstRun")
        if (
            dataset["role"] != "regression"
            or dataset["state"] != "first_run_in_progress"
            or not isinstance(first_run, dict)
            or first_run.get("runRef") != run_ref
        ):
            raise HoldoutManifestError("Holdout run cannot be completed from its current state")
        first_run["completedAt"] = completed_at
        first_run["outcome"] = outcome
        if report_sha256 is not None:
            first_run["reportSha256"] = report_sha256
        dataset["state"] = "consumed"
        return deepcopy(dataset)

    return _mutate_manifest(path, complete)


@contextmanager
def first_run_holdout(
    path: Path,
    *,
    dataset_id: str,
    run_ref: str,
    frozen_system_sha256: str,
) -> Iterator[HoldoutRunTicket]:
    """Wrap a first evaluation so success, failure, or interruption consumes blind status."""

    claim_holdout(
        path,
        dataset_id=dataset_id,
        run_ref=run_ref,
        frozen_system_sha256=frozen_system_sha256,
    )
    ticket = HoldoutRunTicket(path, dataset_id, run_ref)
    try:
        yield ticket
    except KeyboardInterrupt:
        complete_holdout(
            path,
            dataset_id=dataset_id,
            run_ref=run_ref,
            outcome="interrupted",
        )
        raise
    except BaseException:
        complete_holdout(
            path,
            dataset_id=dataset_id,
            run_ref=run_ref,
            outcome="failed",
        )
        raise
    if ticket.report_sha256 is None:
        complete_holdout(
            path,
            dataset_id=dataset_id,
            run_ref=run_ref,
            outcome="failed",
        )
        raise HoldoutManifestError("First run completed without an aggregate report")
    complete_holdout(
        path,
        dataset_id=dataset_id,
        run_ref=run_ref,
        outcome="succeeded",
        report_sha256=ticket.report_sha256,
    )


def _validate_dataset(dataset: Any) -> None:
    if not isinstance(dataset, dict) or not set(dataset).issubset(_DATASET_KEYS):
        raise HoldoutManifestError("Holdout dataset contains unsupported fields")
    required = {"id", "role", "state", "corpusSha256", "counts", "source"}
    if not required.issubset(dataset):
        raise HoldoutManifestError("Holdout dataset is missing required fields")
    _require_identifier(dataset["id"], "dataset id")
    _require_hash(dataset["corpusSha256"], "corpus digest")
    role = dataset["role"]
    state = dataset["state"]
    if role not in _ROLES or state not in _STATES:
        raise HoldoutManifestError("Holdout dataset role or state is invalid")
    _validate_counts(dataset["counts"])
    _validate_source(dataset["source"])

    custodian_ref = dataset.get("custodianRef")
    frozen_system = dataset.get("frozenSystemSha256")
    first_run = dataset.get("firstRun")
    if custodian_ref is not None:
        _require_reference(custodian_ref, "custodian reference")
    if frozen_system is not None:
        _require_hash(frozen_system, "frozen system digest")

    if role == "first_run_holdout" and state == "sealed":
        if custodian_ref is None or frozen_system is None or first_run is not None:
            raise HoldoutManifestError("A sealed holdout requires a custodian and frozen system")
        if dataset["counts"].get("attack", 0) <= 0 or dataset["counts"].get("benign", 0) <= 0:
            raise HoldoutManifestError("A sealed holdout requires attack and benign controls")
        return
    if role in {"training", "tuning"} and state == "available":
        if custodian_ref is not None or frozen_system is not None or first_run is not None:
            raise HoldoutManifestError("Development datasets cannot carry blind-run metadata")
        return
    if role == "regression" and state == "available":
        if first_run is not None or frozen_system is not None or custodian_ref is not None:
            raise HoldoutManifestError("Ordinary regression data cannot claim a first blind run")
        return
    if role == "regression" and state in {"first_run_in_progress", "consumed"}:
        if custodian_ref is None or frozen_system is None:
            raise HoldoutManifestError("Consumed holdout metadata is incomplete")
        _validate_first_run(first_run, state, frozen_system)
        return
    raise HoldoutManifestError("Holdout role and lifecycle state are inconsistent")


def _validate_counts(counts: Any) -> None:
    if not isinstance(counts, dict) or not counts or len(counts) > 32:
        raise HoldoutManifestError("Holdout sample counts are invalid")
    for name, count in counts.items():
        _require_identifier(name, "sample-count label")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise HoldoutManifestError("Holdout sample count must be a non-negative integer")
    if sum(counts.values()) <= 0:
        raise HoldoutManifestError("Holdout dataset must contain samples")


def _validate_source(source: Any) -> None:
    if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
        raise HoldoutManifestError("Holdout source metadata contract changed")
    limits = {"name": 128, "revision": 128, "license": 64}
    for field, limit in limits.items():
        value = source[field]
        if (
            not isinstance(value, str)
            or not value
            or len(value) > limit
            or any(ord(character) < 32 for character in value)
            or "://" in value
        ):
            raise HoldoutManifestError("Holdout source metadata is invalid")


def _validate_first_run(first_run: Any, state: str, frozen_system: str) -> None:
    if not isinstance(first_run, dict) or not set(first_run).issubset(_FIRST_RUN_KEYS):
        raise HoldoutManifestError("First-run evidence contains unsupported fields")
    required = {"runRef", "startedAt", "frozenSystemSha256"}
    if not required.issubset(first_run):
        raise HoldoutManifestError("First-run evidence is incomplete")
    _require_reference(first_run["runRef"], "run reference")
    started_at = _require_timestamp(first_run["startedAt"], "first-run start")
    _require_hash(first_run["frozenSystemSha256"], "first-run system digest")
    if first_run["frozenSystemSha256"] != frozen_system:
        raise HoldoutManifestError("First-run system digest does not match the sealed baseline")
    completion_fields = {"completedAt", "outcome", "reportSha256"}
    if state == "first_run_in_progress":
        if set(first_run) & completion_fields:
            raise HoldoutManifestError("An in-progress first run cannot contain a result")
        return
    if not {"completedAt", "outcome"}.issubset(first_run):
        raise HoldoutManifestError("Consumed first-run evidence is incomplete")
    completed_at = _require_timestamp(first_run["completedAt"], "first-run completion")
    if completed_at < started_at:
        raise HoldoutManifestError("First-run completion cannot precede its start")
    outcome = first_run["outcome"]
    if outcome not in _OUTCOMES:
        raise HoldoutManifestError("First-run outcome is invalid")
    if outcome == "succeeded" and "reportSha256" not in first_run:
        raise HoldoutManifestError("Successful first-run evidence requires a report digest")
    if "reportSha256" in first_run:
        _require_hash(first_run["reportSha256"], "first-run report digest")


def _mutate_manifest(path: Path, mutation) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HoldoutManifestError("Holdout manifest must be a regular file")
    lock_path = path.with_name(f"{path.name}.lock")
    if lock_path.is_symlink():
        raise HoldoutManifestError("Holdout manifest lock cannot be a symlink")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        payload = load_holdout_manifest(path)
        result = mutation(payload)
        payload["manifestRevision"] += 1
        validate_holdout_manifest(payload)
        _atomic_write_json(path, payload)
        return result


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".holdout-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _find_dataset(payload: dict[str, Any], dataset_id: str) -> dict[str, Any]:
    for dataset in payload["datasets"]:
        if dataset["id"] == dataset_id:
            return dataset
    raise HoldoutManifestError("Holdout dataset is not registered")


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise HoldoutManifestError("Holdout timestamps must include a timezone")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise HoldoutManifestError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HoldoutManifestError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HoldoutManifestError(f"{label} must include a timezone")
    return parsed


def _require_hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise HoldoutManifestError(f"{label} must be a lowercase SHA-256")


def _require_identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise HoldoutManifestError(f"{label} is invalid")


def _require_reference(value: Any, label: str) -> None:
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        raise HoldoutManifestError(f"{label} is invalid")
