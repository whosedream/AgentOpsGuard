from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_kubernetes_isolation_runtime.py"
SPEC = importlib.util.spec_from_file_location("verify_kubernetes_isolation_runtime", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


def test_probe_pod_satisfies_restricted_profile_without_cluster_credentials():
    pod = runtime._pod(
        "gateway",
        "agentops-guard-gateway",
        "docker.io/library/redis:7.4.6",
        port=8001,
    )

    spec = pod["spec"]
    security = spec["securityContext"]
    container = spec["containers"][0]
    assert spec["automountServiceAccountToken"] is False
    assert security["runAsNonRoot"] is True
    assert security["seccompProfile"] == {"type": "RuntimeDefault"}
    assert container["imagePullPolicy"] == "Never"
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert not any(key.startswith("env") for key in container)


def test_restricted_namespace_pins_the_cluster_minor():
    namespace = runtime._namespace("agentops-isolation-live", restricted=True)
    labels = namespace["metadata"]["labels"]

    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
    assert labels["pod-security.kubernetes.io/enforce-version"] == "v1.34"
    assert labels["pod-security.kubernetes.io/audit-version"] == "v1.34"
    assert labels["pod-security.kubernetes.io/warn-version"] == "v1.34"
