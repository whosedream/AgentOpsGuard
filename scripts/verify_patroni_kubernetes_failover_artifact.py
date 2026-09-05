#!/usr/bin/env python3
"""Bind fixed live Patroni failover evidence to the reviewed runtime definition."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "verification" / "patroni-kubernetes-failover-live-v1.json"
ARTIFACT_SHA256 = "73fb27ddf34ef4eeb49b6ec85836c098db30666aa46c764d62f8e7359cbf302d"
RUNTIME_SCRIPT = ROOT / "scripts" / "verify_patroni_kubernetes_failover.py"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_runtime() -> Any:
    spec = importlib.util.spec_from_file_location("patroni_failover_runtime", RUNTIME_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Patroni failover runtime verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _verify_runtime_definition(runtime: Any) -> None:
    configuration = runtime._patroni_config()
    dcs = configuration["bootstrap"]["dcs"]
    if "namespace" in configuration:
        raise ValueError("Patroni DCS must use the runtime Kubernetes namespace")
    if configuration["kubernetes"] != {
        "use_endpoints": True,
        "labels": {"application": "patroni", "cluster-name": "agentops-pg"},
    }:
        raise ValueError("Patroni Kubernetes DCS configuration changed")
    if {
        "ttl": dcs["ttl"],
        "loop_wait": dcs["loop_wait"],
        "retry_timeout": dcs["retry_timeout"],
        "maximum_lag_on_failover": dcs["maximum_lag_on_failover"],
        "synchronous_mode": dcs["synchronous_mode"],
        "synchronous_mode_strict": dcs["synchronous_mode_strict"],
        "synchronous_node_count": dcs["synchronous_node_count"],
    } != {
        "ttl": 20,
        "loop_wait": 5,
        "retry_timeout": 5,
        "maximum_lag_on_failover": 0,
        "synchronous_mode": True,
        "synchronous_mode_strict": True,
        "synchronous_node_count": 1,
    }:
        raise ValueError("Patroni failover policy changed")
    documents = runtime._cluster_documents("evidence-review", "runtime-only-a", "runtime-only-b")
    kinds = [document["kind"] for document in documents]
    if "ClusterRole" in kinds or "ClusterRoleBinding" in kinds:
        raise ValueError("Patroni verifier must not grant cluster-wide permissions")
    stateful_set = next(document for document in documents if document["kind"] == "StatefulSet")
    if stateful_set["spec"]["replicas"] != 3:
        raise ValueError("Patroni verifier no longer defines three members")
    pod_spec = stateful_set["spec"]["template"]["spec"]
    if pod_spec["automountServiceAccountToken"] is not False:
        raise ValueError("Patroni verifier restored implicit token mounting")
    containers = {container["name"]: container for container in pod_spec["containers"]}
    patroni_mounts = {mount["name"] for mount in containers["patroni"]["volumeMounts"]}
    proxy_mounts = {mount["name"] for mount in containers["dcs-proxy"].get("volumeMounts", [])}
    if "service-account" not in patroni_mounts or "service-account" in proxy_mounts:
        raise ValueError("Patroni service-account token boundary changed")
    if containers["dcs-proxy"]["command"] != [
        "toxiproxy-server",
        "-host",
        "127.0.0.1",
        "-port",
        "8474",
    ]:
        raise ValueError("Patroni DCS fault proxy boundary changed")
    role = next(document for document in documents if document["kind"] == "Role")
    if any("delete" in rule["verbs"] for rule in role["rules"]):
        raise ValueError("Patroni verifier RBAC gained delete permission")
    budget = next(document for document in documents if document["kind"] == "PodDisruptionBudget")
    if budget["spec"]["minAvailable"] != 2:
        raise ValueError("Patroni disruption budget changed")
    service = next(
        document
        for document in documents
        if document["kind"] == "Service" and document["metadata"]["name"] == "agentops-pg"
    )
    if service["spec"].get("selector") is not None or service["spec"]["ports"] != [
        {"port": 5432, "targetPort": 5432}
    ]:
        raise ValueError("Patroni leader Service contract changed")


def _verify_report(report: dict[str, Any], runtime: Any) -> None:
    if report["schema_version"] != 1:
        raise ValueError("Patroni failover evidence schema changed")
    if report["evidence_kind"] != "live_patroni_kubernetes_automatic_failover":
        raise ValueError("Patroni failover evidence kind changed")
    if report["upstream"] != {
        "project": "patroni/patroni",
        "version": runtime.PATRONI_VERSION,
        "reference_manifest": runtime.UPSTREAM_MANIFEST_URL,
        "reference_manifest_sha256": runtime.UPSTREAM_MANIFEST_SHA256,
        "fault_model_reference": "https://github.com/wb14123/jepsen-postgres-ha",
    }:
        raise ValueError("Patroni upstream provenance changed")
    expected_runtime = {
        "patroni_image": runtime.PATRONI_IMAGE,
        "patroni_image_id": runtime.PATRONI_IMAGE_ID,
        "postgresql_major": runtime.POSTGRESQL_MAJOR,
        "kind_version": "0.30.0",
        "kubectl_version": "v1.34.0",
        "kubernetes_server_version": "v1.34.0",
        "kind_node_image_id": runtime.KIND_NODE_IMAGE_ID,
    }
    if report["runtime"] != expected_runtime:
        raise ValueError("Patroni failover runtime evidence changed")
    required_checks = (
        "both_replicas_replayed_committed_state",
        "primary_failure_was_forced",
        "automatic_new_primary_elected",
        "old_primary_identity_terminated",
        "replaced_primary_rejoined_as_replica",
        "single_primary_after_recovery",
        "stable_service_address_unchanged",
        "stable_service_endpoint_changed",
        "stable_service_query_recovered",
        "committed_application_state_survived",
        "post_failover_application_write_succeeded",
        "audit_chain_valid_after_failover",
        "dcs_egress_partition_injected",
        "database_data_path_remained_reachable_at_partition_start",
        "isolated_primary_kubernetes_api_unreachable",
        "isolated_primary_stopped_writes",
        "partition_replacement_primary_elected",
        "partition_stable_service_address_unchanged",
        "partition_stable_service_endpoint_changed",
        "partition_service_query_recovered",
        "partition_committed_application_state_survived",
        "partition_post_failover_write_succeeded",
        "partition_audit_chain_valid",
        "partition_healed_to_one_primary_two_replicas",
    )
    if not all(report["checks"].get(name) is True for name in required_checks):
        raise ValueError("Patroni failover check did not pass")
    if report["checks"]["service_recovery_ms"] <= 0:
        raise ValueError("Patroni Service recovery measurement is invalid")
    if report["checks"]["automatic_failover_and_full_replica_recovery_ms"] <= 0:
        raise ValueError("Patroni topology recovery measurement is invalid")
    if report["checks"]["maximum_simultaneous_writable_primaries"] != 1:
        raise ValueError("Patroni DCS partition exposed an invalid writable-primary count")
    if report["checks"]["partition_service_recovery_ms"] <= 0:
        raise ValueError("Patroni DCS-partition Service recovery measurement is invalid")
    if report["checks"]["partition_full_topology_recovery_ms"] <= 0:
        raise ValueError("Patroni DCS-partition topology recovery measurement is invalid")
    if report["limits"] != {
        "single_machine_test_cluster": True,
        "durable_persistent_volumes_tested": False,
        "primary_to_dcs_egress_partition_self_demote_tested": True,
        "hardware_watchdog_or_node_fencing_tested": False,
        "arbitrary_host_or_zone_partition_tested": False,
        "cross_zone_failure_tested": False,
        "database_tls_tested": False,
        "production_image_signature_verified": False,
        "host_port_forward_is_stable_endpoint": False,
    }:
        raise ValueError("Patroni failover evidence limitations changed")
    if report["privacy"] != {
        "captures_database_credentials": False,
        "captures_database_urls": False,
        "captures_application_content": False,
    }:
        raise ValueError("Patroni failover evidence privacy boundary changed")


def main() -> int:
    if _sha256(ARTIFACT) != ARTIFACT_SHA256:
        raise ValueError("Patroni failover evidence digest changed")
    runtime = _load_runtime()
    _verify_runtime_definition(runtime)
    report = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    _verify_report(report, runtime)
    print(
        "patroni_kubernetes_failover_evidence=valid automatic_failover=true "
        "stable_service=true production_scope=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
