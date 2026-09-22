import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('clock_check', Path(__file__).resolve().parents[1] / 'scripts/verify_clock_consistency.py')
clock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(clock)


@pytest.mark.parametrize('elapsed,reference,passed', [
    ((10, 10, 10), 10, True),
    ((10, 10, 10.91), 10.91, False),  # Previously observed WSL drift.
    ((10, 10, 10), 10.91, False),  # All Linux clocks agreeing is insufficient.
    ((9, 10, 10), 10, False),  # Wall clock step.
    ((10, 10, 10), 0, False),
    ((10, 10, float('nan')), 10, False),
])
def test_clock_gate_requires_every_clock_to_match_reference(elapsed, reference, passed):
    before = dict.fromkeys(('wall', 'monotonic', 'raw'), 100)
    after = dict(zip(before, (100 + value for value in elapsed)))
    assert clock.evaluate_window(before, after, reference)['passed'] is passed


@pytest.mark.asyncio
async def test_missing_reference_does_not_certify_capacity(tmp_path, monkeypatch):
    monkeypatch.setattr(clock, 'POWERSHELL', tmp_path / 'absent')
    report = await clock.measure_clock()
    assert report['passed'] is False
    assert report['error'] == 'independent_reference_unavailable'
