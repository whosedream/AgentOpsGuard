import importlib.util
from pathlib import Path
import sys

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("invocation_eval", ROOT / "scripts/verify_multinode_invocations.py")
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


def test_acceptance_does_not_become_completion_or_hide_failed_admission():
    rows = [{"id": str(i), "invocation_id": str(i), "variant": "short", "accepted": i != 3} for i in range(4)]
    recovered = [{"invocation_id": str(i), "state": state, "attempts": 1} for i, state in enumerate(["succeeded", "queued", "outcome_unknown", "succeeded"])]
    counts = evaluation.queue_counts(rows, recovered)
    assert counts["attempted"] == 4 and counts["accepted"] == 3
    assert counts["admission_failed"] == 1 and counts["completed_as_expected"] == 1
    assert counts["accepted_not_completed_as_expected"] == 2
    assert counts["accepted_pending_or_unqueryable"] == 1 and counts["outcome_unknown"] == 1


def test_waiting_approval_only_counts_as_safe_write_when_not_dispatched():
    rows = [{"id": "a", "invocation_id": "a", "variant": "write", "accepted": True}]
    for attempts in (0, 1):
        result = evaluation.queue_counts(rows, [{"invocation_id": "a", "state": "waiting_approval", "attempts": attempts}])
        assert result["completed_as_expected"] == (1 if attempts == 0 else 0)


@pytest.mark.parametrize("body", [{"state": "private", "attempts": 1}, {"state": ["secret"]}, {"state": "queued", "attempts": True}])
def test_status_decoder_rejects_arbitrary_data(body):
    assert evaluation.sanitized_status(body) == {"state": "invalid_status", "attempts": None}


@pytest.mark.asyncio
async def test_recovery_query_is_get_only_and_ignores_raw_outputs():
    methods = []
    def handle(request):
        methods.append(request.method)
        return httpx.Response(200, json={"state": "outcome_unknown", "attempts": 1, "summary": {"private": "do not save"}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await evaluation.query_statuses(client, {"entrypoint": "http://test"}, "test-only-token", [{"id": "a", "invocation_id": "b"}])
    assert methods == ["GET"]
    assert result == [{"id": "a", "invocation_id": "b", "state": "outcome_unknown", "attempts": 1}]


def test_freeze_includes_migrations_and_queue_controller():
    frozen = evaluation.cluster.frozen_inputs()
    assert "alembic/versions/0017_tool_invocations.py" in frozen
    assert "scripts/verify_multinode_invocations.py" in frozen


def test_recovery_does_not_stop_while_background_work_is_still_running():
    counts = {"accepted_pending_or_unqueryable": 0}
    assert not evaluation.recovery_finished(counts, {"running": 2, "completed": 134})
    assert not evaluation.recovery_finished(counts, {"pending": 1})
    assert evaluation.recovery_finished(counts, {"completed": 136})
    assert not evaluation.recovery_finished({"accepted_pending_or_unqueryable": 1}, {"completed": 136})


def test_recovering_is_not_a_terminal_state():
    assert "recovering" in evaluation.STATES
    assert "recovering" not in evaluation.TERMINAL
