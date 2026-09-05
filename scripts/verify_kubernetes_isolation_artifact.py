#!/usr/bin/env python3
"""Verify the fixed live Kubernetes isolation evidence without replaying the cluster run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

from verify_kubernetes_isolation_runtime import _dump, _render_network_policies


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "verification" / "kubernetes-isolation-live-v1.json"
ARTIFACT_SHA256 = "066e7b25b38e7da370cd4a541f223c43169db5543dd6dbdca41aaa4187f79cd4"
IMAGE_SOURCE_DIGEST = "sha256:6a11fed904cf317684ebb75bfe987d4f777c605d6f4e98d1bf3066db6c58f0c1"
APPLICATION_NAMESPACE = "agentops-isolation-live"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(report: dict[str, object], policies: list[dict]) -> None:
    if report.get("schema_version") != 1:
        raise ValueError("unexpected Kubernetes isolation evidence schema")
    if report.get("evidence_kind") != "live_kubernetes_data_plane":
        raise ValueError("unexpected Kubernetes isolation evidence kind")
    kubernetes = report.get("kubernetes")
    if kubernetes != {
        "server_version": "v1.34.0",
        "cni": {
            "name": "kindnet",
            "image": "docker.io/kindest/kindnetd:v20250512-df8de77b",
            "ready": True,
        },
    }:
        raise ValueError("Kubernetes or CNI runtime evidence changed")
    if report.get("probe_image") != {
        "reference": "docker.io/library/redis:7.4.6",
        "source_manifest_digest": IMAGE_SOURCE_DIGEST,
    }:
        raise ValueError("Kubernetes probe image evidence changed")
    if report.get("pod_security") != {
        "profile": "restricted:v1.34",
        "privileged_pod_rejected": True,
    }:
        raise ValueError("restricted Pod Security rejection evidence changed")
    if report.get("contains_credentials_or_payloads") is not False:
        raise ValueError("Kubernetes evidence privacy boundary changed")

    baseline = report.get("baseline_probes")
    if (
        not isinstance(baseline, dict)
        or baseline.get("total") != 23
        or baseline.get("passed") != 23
    ):
        raise ValueError("Kubernetes baseline probe totals changed")
    baseline_results = baseline.get("results")
    if not isinstance(baseline_results, list) or len(baseline_results) != 23:
        raise ValueError("Kubernetes baseline probe detail changed")
    if any(
        set(result) != {"name", "expected_allowed", "passed"} or result.get("passed") is not True
        for result in baseline_results
        if isinstance(result, dict)
    ) or not all(isinstance(result, dict) for result in baseline_results):
        raise ValueError("Kubernetes baseline probe result changed")

    mutations = report.get("policy_removal_and_restoration")
    if (
        not isinstance(mutations, dict)
        or mutations.get("total") != 11
        or mutations.get("passed") != 11
    ):
        raise ValueError("Kubernetes policy mutation totals changed")
    mutation_results = mutations.get("results")
    if not isinstance(mutation_results, list) or len(mutation_results) != 11:
        raise ValueError("Kubernetes policy mutation detail changed")
    if any(
        set(result) != {"policy", "passed"} or result.get("passed") is not True
        for result in mutation_results
        if isinstance(result, dict)
    ) or not all(isinstance(result, dict) for result in mutation_results):
        raise ValueError("Kubernetes policy mutation result changed")

    rendered = _dump(policies).encode()
    rendered_digest = hashlib.sha256(rendered).hexdigest()
    policy_evidence = report.get("network_policies")
    if not isinstance(policy_evidence, dict):
        raise ValueError("Kubernetes NetworkPolicy evidence is missing")
    if (
        policy_evidence.get("count") != len(policies)
        or policy_evidence.get("rendered_sha256") != rendered_digest
    ):
        raise ValueError("Kubernetes NetworkPolicy render changed")
    expected_resources = [
        {
            "name": policy["metadata"]["name"],
            "sha256": hashlib.sha256(_dump([policy]).encode()).hexdigest(),
        }
        for policy in sorted(policies, key=lambda value: value["metadata"]["name"])
    ]
    if policy_evidence.get("resources") != expected_resources:
        raise ValueError("Kubernetes NetworkPolicy resource evidence changed")


def main() -> int:
    if _sha256(ARTIFACT) != ARTIFACT_SHA256:
        raise ValueError("Kubernetes isolation evidence file digest changed")
    helm = shutil.which("helm")
    if helm is None:
        raise RuntimeError("Helm is required to bind Kubernetes evidence to the current chart")
    report = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    policies = _render_network_policies(
        helm,
        application_namespace=APPLICATION_NAMESPACE,
        ingress_namespace=f"{APPLICATION_NAMESPACE}-ingress",
        external_namespace=f"{APPLICATION_NAMESPACE}-external",
    )
    verify(report, policies)
    print("kubernetes_isolation_evidence=valid baseline=23/23 mutations=11/11")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
