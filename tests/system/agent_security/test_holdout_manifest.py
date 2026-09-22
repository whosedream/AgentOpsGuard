from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
from pathlib import Path

import pytest

from agentops_guard.evals.holdouts import (
    HoldoutManifestError,
    claim_holdout,
    first_run_holdout,
    load_holdout_manifest,
    register_holdout,
    system_snapshot_sha256,
    validate_holdout_manifest,
)


SYSTEM_SHA256 = "a" * 64
CORPUS_SHA256 = "b" * 64
SOURCE = {"name": "public/example", "revision": "commit-1", "license": "MIT"}


def _empty_manifest(path: Path) -> None:
    path.write_text(
        json.dumps({"schemaVersion": 1, "manifestRevision": 1, "datasets": []}),
        encoding="utf-8",
    )


def _sealed_manifest(path: Path) -> None:
    _empty_manifest(path)
    register_holdout(
        path,
        dataset_id="unknown_attack_v1",
        corpus_sha256=CORPUS_SHA256,
        counts={"attack": 10, "benign": 10},
        source=SOURCE,
        custodian_ref="custodian_ref_01",
        frozen_system_sha256=SYSTEM_SHA256,
    )


def test_repository_manifest_is_aggregate_only_and_known_sets_are_not_blind():
    path = Path("evals/holdouts/manifest.json")

    manifest = load_holdout_manifest(path)

    assert {dataset["id"] for dataset in manifest["datasets"]} == {
        "agentdojo_static_v1",
        "agentdojo_dynamic_v1",
        "bipia_static_v1",
        "injecagent_static_v1",
        "nemotron_agentic_ipi_v1",
        "agent_threat_bench_dynamic_v1",
        "boundary_pairs_en_test_v1",
        "chinese_boundary_diagnostic_v1",
    }
    assert all(dataset["role"] == "regression" for dataset in manifest["datasets"])
    serialized = path.read_text(encoding="utf-8").lower()
    for forbidden in ('"content"', '"path"', '"url"', '"prompt"', '"credential"'):
        assert forbidden not in serialized


def test_registration_rejects_reusing_a_corpus_under_another_role(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    with pytest.raises(HoldoutManifestError, match="cannot be reused"):
        register_holdout(
            manifest_path,
            dataset_id="renamed_unknown_attack_v1",
            corpus_sha256=CORPUS_SHA256,
            counts={"attack": 10, "benign": 10},
            source=SOURCE,
            custodian_ref="custodian_ref_02",
            frozen_system_sha256=SYSTEM_SHA256,
        )

    manifest = load_holdout_manifest(manifest_path)
    assert len(manifest["datasets"]) == 1
    assert manifest["manifestRevision"] == 2


def test_claim_immediately_removes_blind_status_before_content_access(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    claimed = claim_holdout(
        manifest_path,
        dataset_id="unknown_attack_v1",
        run_ref="run_01",
        frozen_system_sha256=SYSTEM_SHA256,
        now=datetime(2026, 1, 2, tzinfo=UTC),
    )

    assert claimed["role"] == "regression"
    assert claimed["state"] == "first_run_in_progress"
    persisted = load_holdout_manifest(manifest_path)["datasets"][0]
    assert persisted == claimed
    with pytest.raises(HoldoutManifestError, match="no longer an unseen holdout"):
        claim_holdout(
            manifest_path,
            dataset_id="unknown_attack_v1",
            run_ref="run_02",
            frozen_system_sha256=SYSTEM_SHA256,
        )


def test_two_runners_cannot_claim_the_same_holdout(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    def attempt(run_ref: str) -> bool:
        try:
            claim_holdout(
                manifest_path,
                dataset_id="unknown_attack_v1",
                run_ref=run_ref,
                frozen_system_sha256=SYSTEM_SHA256,
            )
        except HoldoutManifestError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ("run_01", "run_02")))

    assert sum(results) == 1
    dataset = load_holdout_manifest(manifest_path)["datasets"][0]
    assert dataset["state"] == "first_run_in_progress"


def test_wrong_system_digest_does_not_consume_holdout(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    with pytest.raises(HoldoutManifestError, match="does not match"):
        claim_holdout(
            manifest_path,
            dataset_id="unknown_attack_v1",
            run_ref="run_01",
            frozen_system_sha256="c" * 64,
        )

    dataset = load_holdout_manifest(manifest_path)["datasets"][0]
    assert dataset["role"] == "first_run_holdout"
    assert dataset["state"] == "sealed"


def test_first_run_wrapper_records_only_report_digest_on_success(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "aggregate-report.json"
    _sealed_manifest(manifest_path)
    report_path.write_text('{"result":"passed"}\n', encoding="utf-8")

    with first_run_holdout(
        manifest_path,
        dataset_id="unknown_attack_v1",
        run_ref="run_01",
        frozen_system_sha256=SYSTEM_SHA256,
    ) as ticket:
        in_progress = load_holdout_manifest(manifest_path)["datasets"][0]
        assert in_progress["role"] == "regression"
        assert in_progress["state"] == "first_run_in_progress"
        expected_report_sha256 = ticket.record_report(report_path)

    dataset = load_holdout_manifest(manifest_path)["datasets"][0]
    assert dataset["state"] == "consumed"
    assert dataset["firstRun"]["outcome"] == "succeeded"
    assert dataset["firstRun"]["reportSha256"] == expected_report_sha256
    assert str(report_path) not in json.dumps(dataset)


def test_failed_first_run_stays_consumed_and_cannot_be_retried_as_blind(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    with pytest.raises(RuntimeError, match="runner failed"):
        with first_run_holdout(
            manifest_path,
            dataset_id="unknown_attack_v1",
            run_ref="run_01",
            frozen_system_sha256=SYSTEM_SHA256,
        ):
            raise RuntimeError("runner failed")

    dataset = load_holdout_manifest(manifest_path)["datasets"][0]
    assert dataset["role"] == "regression"
    assert dataset["state"] == "consumed"
    assert dataset["firstRun"]["outcome"] == "failed"


def test_success_without_aggregate_report_is_consumed_as_failed(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    _sealed_manifest(manifest_path)

    with pytest.raises(HoldoutManifestError, match="without an aggregate report"):
        with first_run_holdout(
            manifest_path,
            dataset_id="unknown_attack_v1",
            run_ref="run_01",
            frozen_system_sha256=SYSTEM_SHA256,
        ):
            pass

    dataset = load_holdout_manifest(manifest_path)["datasets"][0]
    assert dataset["state"] == "consumed"
    assert dataset["firstRun"]["outcome"] == "failed"


def test_manifest_rejects_raw_content_and_unapproved_fields():
    payload = {
        "schemaVersion": 1,
        "manifestRevision": 1,
        "datasets": [
            {
                "id": "unknown_attack_v1",
                "role": "first_run_holdout",
                "state": "sealed",
                "corpusSha256": CORPUS_SHA256,
                "counts": {"attack": 1, "benign": 1},
                "source": SOURCE,
                "custodianRef": "custodian_ref_01",
                "frozenSystemSha256": SYSTEM_SHA256,
                "rawPath": "/private/holdout.jsonl",
            }
        ],
    }

    with pytest.raises(HoldoutManifestError, match="unsupported fields"):
        validate_holdout_manifest(payload)


def test_manifest_rejects_source_urls_and_backdated_completion():
    payload = load_holdout_manifest(Path("evals/holdouts/manifest.json"))
    payload["datasets"][0]["source"]["name"] = "https://private.invalid/source"
    with pytest.raises(HoldoutManifestError, match="source metadata"):
        validate_holdout_manifest(payload)

    payload = load_holdout_manifest(Path("evals/holdouts/manifest.json"))
    payload["datasets"][0]["firstRun"]["completedAt"] = "2026-01-01T00:00:00Z"
    with pytest.raises(HoldoutManifestError, match="cannot precede"):
        validate_holdout_manifest(payload)


def test_system_snapshot_is_content_addressed_and_never_contains_paths(tmp_path):
    gateway = tmp_path / "gateway.py"
    policy = tmp_path / "policy.py"
    gateway.write_text("gateway-v1\n", encoding="utf-8")
    policy.write_text("policy-v1\n", encoding="utf-8")

    first = system_snapshot_sha256({"gateway": gateway, "policy": policy})
    second = system_snapshot_sha256({"policy": policy, "gateway": gateway})
    policy.write_text("policy-v2\n", encoding="utf-8")
    changed = system_snapshot_sha256({"gateway": gateway, "policy": policy})

    assert first == second
    assert changed != first
    assert str(tmp_path) not in first
