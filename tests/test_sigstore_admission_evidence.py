from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_sigstore_admission_artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_sigstore_admission_artifact", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verification
SPEC.loader.exec_module(verification)


def test_fixed_sigstore_evidence_is_bound_to_current_configuration():
    report = json.loads(verification.ARTIFACT.read_text(encoding="utf-8"))

    assert verification._sha256(verification.ARTIFACT) == verification.ARTIFACT_SHA256
    verification._verify_report(report)
    verification._verify_current_configuration()


def test_fixed_sigstore_evidence_preserves_unverified_positive_boundary():
    report = json.loads(verification.ARTIFACT.read_text(encoding="utf-8"))

    assert report["checks"]["matching_unsigned_image_rejected_as_no_signatures"] == {
        "passed": True,
        "controller_version": "0.13.1",
        "policy_source": "project_render",
    }
    assert report["checks"]["registry_timeout_request_rejected"] == {
        "passed": True,
        "controller_version": "0.15.1",
        "reason": "registry_unreachable",
    }
    assert all(result is False for result in report["limits"].values())
