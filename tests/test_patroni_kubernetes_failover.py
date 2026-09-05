from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_patroni_kubernetes_failover.py"
SPEC = importlib.util.spec_from_file_location("verify_patroni_kubernetes_failover", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)
BUILD_SCRIPT = ROOT / "scripts" / "build_patroni_test_runtime.py"
BUILD_SPEC = importlib.util.spec_from_file_location("build_patroni_test_runtime", BUILD_SCRIPT)
assert BUILD_SPEC is not None and BUILD_SPEC.loader is not None
builder = importlib.util.module_from_spec(BUILD_SPEC)
sys.modules[BUILD_SPEC.name] = builder
BUILD_SPEC.loader.exec_module(builder)


def test_patroni_runtime_and_upstream_reference_are_pinned():
    assert verifier.PATRONI_IMAGE == "agentops-patroni-runtime:4.1.4"
    assert verifier.PATRONI_IMAGE_ID == (
        "sha256:f72e155837bf7061c5fd4efbb97891f8827bcb517b3e68fd833a4d43e95cd09b"
    )
    assert verifier.UPSTREAM_MANIFEST_SHA256 == (
        "17187a3f7e9acb8cdda6d970cca4787ea739acbe9b0d668fb087436a746e955c"
    )
    assert builder.TOXIPROXY_SHA256 == (
        "556d891134a3c582dc1e1a3f7335fd55142e5965769855a00b944e13e48302fc"
    )
    license_path = ROOT / "evals" / "patroni-runtime" / "PATRONI-LICENSE.txt"
    assert hashlib.sha256(license_path.read_bytes()).hexdigest() == (
        "65a74377ba31d499c61cd978e8e97e71486ba95e8a429e235d5be79474daf83a"
    )
    toxiproxy_license = ROOT / "evals" / "patroni-runtime" / "TOXIPROXY-LICENSE.txt"
    assert hashlib.sha256(toxiproxy_license.read_bytes()).hexdigest() == (
        "d270326aa9044adb5aa6f79cd56908ca5fbb37007ba6150fd8378be40f412646"
    )


def test_patroni_policy_requires_synchronous_three_member_failover():
    config = verifier._patroni_config()
    dcs = config["bootstrap"]["dcs"]

    assert "namespace" not in config
    assert config["kubernetes"]["use_endpoints"] is True
    assert dcs["maximum_lag_on_failover"] == 0
    assert dcs["synchronous_mode"] is True
    assert dcs["synchronous_mode_strict"] is True
    assert dcs["synchronous_node_count"] == 1


def test_patroni_manifest_keeps_secrets_and_permissions_narrow():
    documents = verifier._cluster_documents(
        "review-namespace", "generated-superuser", "generated-replication"
    )
    kinds = [document["kind"] for document in documents]
    secret = next(document for document in documents if document["kind"] == "Secret")
    role = next(document for document in documents if document["kind"] == "Role")
    stateful_set = next(document for document in documents if document["kind"] == "StatefulSet")
    budget = next(document for document in documents if document["kind"] == "PodDisruptionBudget")

    assert secret["stringData"] == {
        "superuser-password": "generated-superuser",
        "replication-password": "generated-replication",
    }
    assert "ClusterRole" not in kinds
    assert "ClusterRoleBinding" not in kinds
    assert all("delete" not in rule["verbs"] for rule in role["rules"])
    assert stateful_set["spec"]["replicas"] == 3
    assert budget["spec"]["minAvailable"] == 2
    pod_spec = stateful_set["spec"]["template"]["spec"]
    containers = {container["name"]: container for container in pod_spec["containers"]}
    assert pod_spec["automountServiceAccountToken"] is False
    assert containers["patroni"]["command"] == ["start-patroni"]
    assert containers["dcs-proxy"]["command"] == [
        "toxiproxy-server",
        "-host",
        "127.0.0.1",
        "-port",
        "8474",
    ]
    assert "service-account" in {
        mount["name"] for mount in containers["patroni"]["volumeMounts"]
    }
    assert "service-account" not in {
        mount["name"] for mount in containers["dcs-proxy"].get("volumeMounts", [])
    }


def test_dcs_partition_targets_only_the_selected_proxy():
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))

    original = verifier._run
    verifier._run = run
    try:
        verifier._set_dcs_proxy_enabled(["kubectl"], "test-space", "agentops-pg-1", enabled=False)
    finally:
        verifier._run = original

    command, options = calls[0]
    assert command[:6] == [
        "kubectl",
        "exec",
        "--namespace",
        "test-space",
        "agentops-pg-1",
        "--container",
    ]
    assert "'enabled':False" in command[-1]
    assert options["step"] == "Kubernetes API fault proxy state change"


def test_patroni_child_environment_does_not_inherit_ambient_secrets(monkeypatch):
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-be-inherited")

    environment = verifier._application_environment("postgresql://trusted-runtime-reference")

    assert "UNRELATED_SECRET" not in environment
    assert environment["AGENTOPS_DATABASE_URL"] == "postgresql://trusted-runtime-reference"
