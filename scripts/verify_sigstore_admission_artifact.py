#!/usr/bin/env python3
"""Bind fixed live Sigstore admission evidence to the current production configuration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "verification" / "sigstore-admission-partial-v1.json"
ARTIFACT_SHA256 = "9631ae56a5201c837e7a1e4993e928f21fae5253f1a2285a35f17857175899df"
CONTROLLER_VALUES = ROOT / "deploy" / "admission" / "policy-controller-values.prod.yaml"
POLICY_TEMPLATE = (
    ROOT / "deploy" / "helm" / "agentops-guard" / "templates" / "clusterimagepolicy.yaml"
)
APPLICATION_VALUES = ROOT / "deploy" / "helm" / "agentops-guard" / "values.yaml"
CONTROLLER_INDEX_DIGEST = "sha256:0492bb264fb1d9bdc8e3f343ef542cc85b7dd7c7fd8d9524b453c2bd31a1d128"
CONTROLLER_AMD64_DIGEST = "sha256:0a5806a61e0482e56153ae2ce6f6707846ffe0f9e3cd4be58655fbf88b874a3c"
CLEANUP_INDEX_DIGEST = "sha256:7200e12e0a13c12291314c31bbd0843baf07947e91091bce8755ee3f8374bea0"
CHART_SHA256 = "c5c7f0c421fdeb3944cdfd6706cb51d40e872b4a37fbecba03f8d35547c1e513"
TRUSTED_ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_report(report: dict[str, object]) -> None:
    expected_controller = {
        "official_chart_version": "0.10.7",
        "official_chart_sha256": CHART_SHA256,
        "version": "0.15.1",
        "image_index_digest": CONTROLLER_INDEX_DIGEST,
        "linux_amd64_manifest_digest": CONTROLLER_AMD64_DIGEST,
        "replicas_desired": 2,
        "replicas_ready_after_recovery": 2,
        "restart_count_after_recovery": 0,
        "trust_delivery": "managed_trust_root",
    }
    expected_checks = {
        "both_webhooks_failure_policy_fail": True,
        "no_match_policy_deny": True,
        "namespace_opt_in": True,
        "matching_unsigned_image_rejected_as_no_signatures": {
            "passed": True,
            "controller_version": "0.13.1",
            "policy_source": "project_render",
        },
        "all_replicas_stopped_request_rejected": {
            "passed": True,
            "controller_version": "0.15.1",
        },
        "all_replicas_recovered": {
            "passed": True,
            "controller_version": "0.15.1",
        },
        "recovery_milliseconds": 20442,
        "registry_timeout_request_rejected": {
            "passed": True,
            "controller_version": "0.15.1",
            "reason": "registry_unreachable",
        },
    }
    expected_limits = {
        "correctly_signed_private_image_admitted": False,
        "wrong_signer_rejected": False,
        "post_signature_mutation_rejected": False,
        "lookalike_repository_rejected": False,
        "production_registry_reachable": False,
        "production_cluster_tested": False,
    }
    if report.get("schema_version") != 1:
        raise ValueError("unexpected Sigstore evidence schema")
    if report.get("evidence_kind") != "live_sigstore_admission_partial":
        raise ValueError("unexpected Sigstore evidence kind")
    if report.get("cluster") != {"kubernetes_version": "v1.34.0"}:
        raise ValueError("Sigstore Kubernetes runtime evidence changed")
    if report.get("controller") != expected_controller:
        raise ValueError("Sigstore controller evidence changed")
    if report.get("trust_root") != {
        "name": "public-sigstore",
        "source_trusted_root_sha256": TRUSTED_ROOT_SHA256,
        "ready": True,
        "contains_private_key": False,
    }:
        raise ValueError("Sigstore TrustRoot evidence changed")
    if report.get("project_policy") != {
        "api_version": "policy.sigstore.dev/v1beta1",
        "mode": "enforce",
        "trust_root_ref": "public-sigstore",
        "ready": True,
    }:
        raise ValueError("Sigstore project policy evidence changed")
    if report.get("checks") != expected_checks:
        raise ValueError("Sigstore admission checks changed")
    if report.get("limits") != expected_limits:
        raise ValueError("Sigstore evidence limits changed")
    if report.get("contains_credentials_or_payloads") is not False:
        raise ValueError("Sigstore evidence privacy boundary changed")


def _verify_current_configuration() -> None:
    controller = yaml.safe_load(CONTROLLER_VALUES.read_text(encoding="utf-8"))
    webhook = controller["webhook"]
    if webhook["replicaCount"] != 2 or webhook["failurePolicy"] != "Fail":
        raise ValueError("policy-controller is no longer fail-closed with two replicas")
    if webhook["configData"] != {"no-match-policy": "deny"}:
        raise ValueError("policy-controller no-match behavior is no longer deny")
    if webhook["image"]["version"] != CONTROLLER_INDEX_DIGEST:
        raise ValueError("policy-controller image digest changed")
    if webhook["extraArgs"] != {"disable-tuf": True}:
        raise ValueError("policy-controller managed TrustRoot mode changed")
    if controller["leasescleanup"]["image"]["version"] != CLEANUP_INDEX_DIGEST:
        raise ValueError("policy-controller cleanup image digest changed")

    policy = POLICY_TEMPLATE.read_text(encoding="utf-8")
    values = yaml.safe_load(APPLICATION_VALUES.read_text(encoding="utf-8"))
    if values["imageVerification"]["trustRootRef"] != "":
        raise ValueError("default image verification TrustRoot must remain unset")
    required_fragments = (
        "imageVerification.trustRootRef is required",
        "imageVerification.trustRootRef must be a Kubernetes DNS-compatible TrustRoot name",
        "trustRootRef: {{ $trustRootRef | quote }}",
    )
    if any(fragment not in policy for fragment in required_fragments):
        raise ValueError("ClusterImagePolicy no longer requires a managed TrustRoot")


def main() -> int:
    if _sha256(ARTIFACT) != ARTIFACT_SHA256:
        raise ValueError("Sigstore admission evidence file digest changed")
    report = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    _verify_report(report)
    _verify_current_configuration()
    print(
        "sigstore_admission_evidence=valid scope=partial "
        "unsigned_rejection=true fail_closed=true positive_signature=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
