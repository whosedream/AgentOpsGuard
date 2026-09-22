"""Sanitized collection is scoped, visible on failure, and never overwrites evidence."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_multinode_evidence as evidence  # noqa: E402


@pytest.fixture
def context(tmp_path):
    state = {"cluster": "agentops-mn-1234abcd", "namespace": "agentops-mn-1234abcd",
             "kubeconfig": str(tmp_path / "kubeconfig")}
    (tmp_path / "backlog.json").write_text(json.dumps({"passed": True}))
    (tmp_path / "backlog_started.json").write_text(json.dumps({"phase": "mn_123456abcdef", "admission": True}))
    return state, tmp_path


def test_wrong_cluster_never_queries(context, monkeypatch):
    state, directory = context
    monkeypatch.setattr(evidence.cluster, "kubectl", lambda *a, **k: pytest.fail("Foreign cluster queried"))
    with pytest.raises(ValueError, match="exact run"):
        evidence.collect_phase(state, directory, "backlog", expected_cluster="agentops-mn-ffffffff")


def test_missing_evidence_stays_failure_and_preserves_original(context, monkeypatch):
    state, directory = context

    def unavailable(*args, **kwargs):
        raise RuntimeError("Private connection details must not be exported")

    monkeypatch.setattr(evidence.cluster, "kubectl", unavailable)
    monkeypatch.setattr(evidence.cluster, "runtime_events", unavailable)
    result = evidence.collect_phase(state, directory, "backlog", expected_cluster=state["cluster"])
    assert result["complete"] is False
    saved = (directory / "backlog_supplemental.json").read_text()
    assert "Private connection" not in saved
    assert len(json.loads(saved)["collection_errors"]) == 2
    assert json.loads((directory / "backlog.json").read_text())["passed"] is True
    with pytest.raises(FileExistsError):
        evidence.collect_phase(state, directory, "backlog", expected_cluster=state["cluster"])


def test_completed_collection_is_explicit(context, monkeypatch):
    state, directory = context
    monkeypatch.setattr(evidence.cluster, "kubectl", lambda *a, **k: json.dumps({
        "business_query_completed": True, "admission_query_completed": True}))
    monkeypatch.setattr(evidence.cluster, "runtime_events", lambda *a, **k: [])
    result = evidence.collect_phase(state, directory, "backlog", expected_cluster=state["cluster"])
    assert result["complete"] is True and result["errors"] == []
