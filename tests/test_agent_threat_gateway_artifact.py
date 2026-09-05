from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_agent_threat_gateway_artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_agent_threat_gateway_artifact", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(verifier)


def _load(version: int) -> dict:
    return json.loads(verifier._report_path(version).read_text(encoding="utf-8"))


def test_historical_failures_remain_explicit_and_immutable():
    reports = {version: _load(version) for version in range(1, 6)}

    verifier._assert_historical_failures(reports)

    assert reports[1]["guarded"]["attack"]["gateway"]["tool_calls"] == 0
    assert reports[3]["guarded"]["benign"]["effect_utility_rate"] == 0.0
    assert reports[4]["guarded"]["attack"]["gateway"]["high_risk_action_attempts"] == 0


def test_current_report_has_no_raw_case_or_model_content():
    report = _load(6)

    verifier._assert_dataset(report)
    verifier._assert_privacy_boundaries(report)
    verifier._assert_current(report)

    keys: set[str] = set()

    def collect(value):
        if isinstance(value, dict):
            keys.update(str(key) for key in value)
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(report)
    assert {"prompt_text", "tool_arguments", "model_response", "raw_case"}.isdisjoint(keys)
