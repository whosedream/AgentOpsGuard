from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location("boundary_quality", Path("scripts/benchmark_boundary_quality.py"))
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


@dataclass
class Result:
    regex_flagged: bool
    model_flagged: bool


def test_metrics_count_false_positives_and_pairs_separately():
    rows = [{"label": 1, "pair_id": "a"}, {"label": 0, "pair_id": "a"},
            {"label": 1, "pair_id": "b"}, {"label": 0, "pair_id": "b"}]
    results = [Result(True, False), Result(False, True), Result(False, True), Result(False, False)]
    summary = benchmark.metrics(rows, results)
    assert summary["union"]["recall"] == 1
    assert summary["union"]["false_positive_rate"] == 0.5
    assert summary["union"]["pairs_both_correct"] == 1
    assert summary["union"]["meets_point_targets"] is False
    assert summary["rules"]["tp"] == 1
    assert summary["model"]["fn"] == 1


def test_zero_alerts_do_not_count_as_good_detection():
    rows = [{"label": 1, "pair_id": "a"}, {"label": 0, "pair_id": "a"}]
    summary = benchmark.metrics(rows, [Result(False, False), Result(False, False)])
    assert summary["union"]["precision"] is None
    assert summary["union"]["meets_point_targets"] is False


def test_chinese_diagnostic_is_explicitly_not_independent_public_data():
    sources = json.loads(benchmark.LOCK.read_text())["datasets"]
    assert sources[0]["independent_public_source"] is True
    assert sources[1]["independent_public_source"] is False
    rows = benchmark.load_rows(benchmark.CHINESE, sources[1])
    assert len(rows) == 80
    assert len({row["family"] for row in rows}) == 8


def test_changed_source_is_rejected_before_scoring(tmp_path):
    source = json.loads(benchmark.LOCK.read_text())["datasets"][1]
    changed = tmp_path / "changed.json"
    changed.write_text("{}")
    with pytest.raises(ValueError, match="digest changed"):
        benchmark.load_rows(changed, source)


def test_missing_classifier_result_cannot_silently_improve_metrics():
    rows = [{"label": 1, "pair_id": "a"}, {"label": 0, "pair_id": "a"}]
    with pytest.raises(ValueError):
        benchmark.metrics(rows, [Result(True, True)])
