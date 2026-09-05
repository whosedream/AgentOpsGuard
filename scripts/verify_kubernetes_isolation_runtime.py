from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "agentops-guard"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        operation = " ".join(command[:3])
        raise RuntimeError(f"command failed ({result.returncode}): {operation}")
    return result


def _namespace(name: str, *, restricted: bool) -> dict[str, Any]:
    labels = {"kubernetes.io/metadata.name": name}
    if restricted:
        labels.update(
            {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "v1.34",
                "pod-security.kubernetes.io/audit": "restricted",
                "pod-security.kubernetes.io/audit-version": "v1.34",
                "pod-security.kubernetes.io/warn": "restricted",
                "pod-security.kubernetes.io/warn-version": "v1.34",
            }
        )
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name, "labels": labels},
    }


def _pod(
    name: str,
    app: str,
    image: str,
    *,
    port: int | None = None,
    extra_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    labels = {"app": app}
    labels.update(extra_labels or {})
    if port is None:
        command = ["sh", "-c", "sleep 3600"]
    else:
        command = [
            "redis-server",
            "--port",
            str(port),
            "--bind",
            "0.0.0.0",
            "--protected-mode",
            "no",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            "/data",
        ]
    container: dict[str, Any] = {
        "name": "probe",
        "image": image,
        "imagePullPolicy": "Never",
        "command": command,
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
    }
    if port is not None:
        container["ports"] = [{"name": "probe", "containerPort": port}]
        container["volumeMounts"] = [{"name": "data", "mountPath": "/data"}]
    spec: dict[str, Any] = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 999,
            "runAsGroup": 999,
            "fsGroup": 999,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [container],
    }
    if port is not None:
        spec["volumes"] = [{"name": "data", "emptyDir": {}}]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": labels},
        "spec": spec,
    }


def _render_network_policies(
    helm: str,
    *,
    application_namespace: str,
    ingress_namespace: str,
    external_namespace: str,
) -> list[dict[str, Any]]:
    external_rule = [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": external_namespace,
                        }
                    },
                    "podSelector": {"matchLabels": {"app": "external-target"}},
                }
            ],
            "ports": [{"protocol": "TCP", "port": 9000}],
        }
    ]
    result = _run(
        [
            helm,
            "template",
            "agentops-live",
            str(CHART),
            "--namespace",
            application_namespace,
            "--set",
            "networkPolicy.enabled=true",
            "--set-json",
            "networkPolicy.ingressController.namespaceSelector="
            + json.dumps(
                {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": ingress_namespace,
                    }
                },
                separators=(",", ":"),
            ),
            "--set-json",
            "networkPolicy.ingressController.podSelector="
            + json.dumps(
                {"matchLabels": {"access": "agentops"}},
                separators=(",", ":"),
            ),
            "--set-json",
            "networkPolicy.externalEgress.api=" + json.dumps(external_rule, separators=(",", ":")),
            "--set",
            "semanticScanner.mode=shadow",
            "--set-string",
            "semanticScanner.modelSha256=" + ("0" * 64),
            "--set-string",
            "semanticScanner.hostPath=/tmp",
            "--set",
            "opa.enabled=true",
        ]
    )
    policies = [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("kind") == "NetworkPolicy"
    ]
    if len(policies) != 11:
        raise RuntimeError(f"expected 11 rendered NetworkPolicies, found {len(policies)}")
    return policies


def _dump(documents: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(documents, sort_keys=True)


def _policy_by_suffix(policies: list[dict[str, Any]], suffix: str) -> dict[str, Any]:
    matches = [policy for policy in policies if str(policy["metadata"]["name"]).endswith(suffix)]
    if len(matches) != 1:
        raise RuntimeError(f"policy suffix did not resolve exactly once: {suffix}")
    return matches[0]


def _pod_ip(kubectl: list[str], namespace: str, pod: str) -> str:
    result = _run(
        [
            *kubectl,
            "get",
            "pod",
            pod,
            "--namespace",
            namespace,
            "--output",
            "jsonpath={.status.podIP}",
        ]
    )
    value = result.stdout.strip()
    if not value:
        raise RuntimeError(f"Pod has no IP: {pod}")
    return value


def _connection(
    kubectl: list[str],
    namespace: str,
    pod: str,
    destination_ip: str,
    port: int,
) -> bool:
    result = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            pod,
            "--",
            "timeout",
            "4",
            "redis-cli",
            "-h",
            destination_ip,
            "-p",
            str(port),
            "PING",
        ],
        timeout=12,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "PONG"


def _dns(kubectl: list[str], namespace: str, pod: str) -> bool:
    result = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            pod,
            "--",
            "timeout",
            "4",
            "getent",
            "hosts",
            "kubernetes.default.svc.cluster.local",
        ],
        timeout=12,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise the rendered AgentOps Guard policies on a real Kubernetes data path."
    )
    parser.add_argument("--kubectl", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--helm", default="helm")
    parser.add_argument("--image", default="docker.io/library/redis:7.4.6")
    parser.add_argument("--image-source-digest", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--namespace", default="agentops-isolation-live")
    parser.add_argument("--retain-resources", action="store_true")
    args = parser.parse_args()
    if not SHA256.fullmatch(args.image_source_digest):
        raise ValueError("image source digest must be sha256 followed by 64 lowercase hex digits")

    application_namespace = args.namespace
    ingress_namespace = f"{args.namespace}-ingress"
    rogue_namespace = f"{args.namespace}-rogue"
    external_namespace = f"{args.namespace}-external"
    kubectl = [args.kubectl, "--kubeconfig", args.kubeconfig]

    version = json.loads(_run([*kubectl, "version", "--output", "json"]).stdout)
    cni = json.loads(
        _run(
            [
                *kubectl,
                "get",
                "daemonset",
                "kindnet",
                "--namespace",
                "kube-system",
                "--output",
                "json",
            ]
        ).stdout
    )
    policies = _render_network_policies(
        args.helm,
        application_namespace=application_namespace,
        ingress_namespace=ingress_namespace,
        external_namespace=external_namespace,
    )
    namespaces = [
        _namespace(application_namespace, restricted=True),
        _namespace(ingress_namespace, restricted=True),
        _namespace(rogue_namespace, restricted=True),
        _namespace(external_namespace, restricted=True),
    ]
    _run([*kubectl, "apply", "--filename", "-"], input_text=_dump(namespaces))

    app_pods = [
        _pod("api", "agentops-guard-api", args.image, port=8000),
        _pod("gateway", "agentops-guard-gateway", args.image, port=8001),
        _pod("dashboard", "agentops-guard-dashboard", args.image, port=3000),
        _pod("scanner", "agentops-guard-semantic-scanner", args.image, port=8090),
        _pod("opa", "agentops-guard-opa", args.image, port=8181),
        _pod("worker", "agentops-guard-worker", args.image, port=6379),
    ]
    _run(
        [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
        input_text=_dump(app_pods),
    )
    _run(
        [*kubectl, "apply", "--namespace", ingress_namespace, "--filename", "-"],
        input_text=_dump(
            [_pod("ingress", "reviewed-ingress", args.image, extra_labels={"access": "agentops"})]
        ),
    )
    _run(
        [*kubectl, "apply", "--namespace", rogue_namespace, "--filename", "-"],
        input_text=_dump([_pod("rogue", "rogue-client", args.image)]),
    )
    _run(
        [*kubectl, "apply", "--namespace", external_namespace, "--filename", "-"],
        input_text=_dump([_pod("external", "external-target", args.image, port=9000)]),
    )
    for namespace, pod in [
        *((application_namespace, pod["metadata"]["name"]) for pod in app_pods),
        (ingress_namespace, "ingress"),
        (rogue_namespace, "rogue"),
        (external_namespace, "external"),
    ]:
        _run(
            [
                *kubectl,
                "wait",
                "--namespace",
                namespace,
                "--for=condition=Ready",
                f"pod/{pod}",
                "--timeout=90s",
            ],
            timeout=100,
        )

    preflight = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            ingress_namespace,
            "ingress",
            "--",
            "sh",
            "-c",
            "command -v timeout && command -v redis-cli && command -v getent",
        ]
    )
    if len(preflight.stdout.splitlines()) != 3:
        raise RuntimeError("probe image is missing a required executable")

    _run(
        [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
        input_text=_dump(policies),
    )
    time.sleep(2)

    pod_ips = {
        name: _pod_ip(kubectl, namespace, pod)
        for name, namespace, pod in [
            ("api", application_namespace, "api"),
            ("gateway", application_namespace, "gateway"),
            ("dashboard", application_namespace, "dashboard"),
            ("scanner", application_namespace, "scanner"),
            ("opa", application_namespace, "opa"),
            ("worker", application_namespace, "worker"),
            ("external", external_namespace, "external"),
        ]
    }

    probes: list[dict[str, Any]] = []

    def record(name: str, expected: bool, observed: bool) -> None:
        passed = observed is expected
        probes.append({"name": name, "expected_allowed": expected, "passed": passed})
        if not passed:
            raise RuntimeError(f"network probe failed: {name}")

    def connection_probe(
        name: str,
        expected: bool,
        source_namespace: str,
        source_pod: str,
        destination: str,
        port: int,
    ) -> None:
        record(
            name,
            expected,
            _connection(
                kubectl,
                source_namespace,
                source_pod,
                pod_ips[destination],
                port,
            ),
        )

    baseline_connections = [
        ("reviewed_ingress_to_gateway", True, ingress_namespace, "ingress", "gateway", 8001),
        ("reviewed_ingress_to_dashboard", True, ingress_namespace, "ingress", "dashboard", 3000),
        ("rogue_to_gateway", False, rogue_namespace, "rogue", "gateway", 8001),
        ("rogue_to_dashboard", False, rogue_namespace, "rogue", "dashboard", 3000),
        ("dashboard_to_api", True, application_namespace, "dashboard", "api", 8000),
        ("gateway_to_api", True, application_namespace, "gateway", "api", 8000),
        ("worker_to_api", False, application_namespace, "worker", "api", 8000),
        ("gateway_to_scanner", True, application_namespace, "gateway", "scanner", 8090),
        ("api_to_scanner", False, application_namespace, "api", "scanner", 8090),
        ("api_to_opa", True, application_namespace, "api", "opa", 8181),
        ("gateway_to_opa", True, application_namespace, "gateway", "opa", 8181),
        ("worker_to_opa", True, application_namespace, "worker", "opa", 8181),
        ("dashboard_to_opa", False, application_namespace, "dashboard", "opa", 8181),
        ("api_to_external", True, application_namespace, "api", "external", 9000),
        ("gateway_to_external", False, application_namespace, "gateway", "external", 9000),
        ("scanner_to_api", False, application_namespace, "scanner", "api", 8000),
        ("scanner_to_external", False, application_namespace, "scanner", "external", 9000),
        ("opa_to_api", False, application_namespace, "opa", "api", 8000),
        ("opa_to_external", False, application_namespace, "opa", "external", 9000),
    ]
    for probe in baseline_connections:
        connection_probe(*probe)
    for name, expected, pod in [
        ("api_dns", True, "api"),
        ("gateway_dns", True, "gateway"),
        ("scanner_dns", False, "scanner"),
        ("opa_dns", False, "opa"),
    ]:
        record(name, expected, _dns(kubectl, application_namespace, pod))

    invalid_pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "restricted-profile-negative"},
        "spec": {
            "containers": [
                {
                    "name": "invalid",
                    "image": args.image,
                    "imagePullPolicy": "Never",
                    "securityContext": {"privileged": True},
                }
            ]
        },
    }
    rejection = _run(
        [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
        input_text=_dump([invalid_pod]),
        check=False,
    )
    pod_security_rejected = (
        rejection.returncode != 0 and 'violates PodSecurity "restricted:v1.34"' in rejection.stderr
    )
    if not pod_security_rejected:
        raise RuntimeError("restricted Pod Security profile did not reject a privileged Pod")

    mutation_cases = [
        (
            "gateway-ingress",
            (ingress_namespace, "ingress", "gateway", 8001),
            (ingress_namespace, "ingress", "dashboard", 3000),
        ),
        (
            "dashboard-ingress",
            (ingress_namespace, "ingress", "dashboard", 3000),
            (ingress_namespace, "ingress", "gateway", 8001),
        ),
        (
            "api-ingress",
            (application_namespace, "dashboard", "api", 8000),
            (ingress_namespace, "ingress", "gateway", 8001),
        ),
        (
            "dashboard-egress",
            (application_namespace, "dashboard", "api", 8000),
            (application_namespace, "gateway", "api", 8000),
        ),
        (
            "gateway-internal-egress",
            (application_namespace, "gateway", "api", 8000),
            (application_namespace, "dashboard", "api", 8000),
        ),
        (
            "opa-client-egress",
            (application_namespace, "worker", "opa", 8181),
            (application_namespace, "gateway", "api", 8000),
        ),
        (
            "semantic-scanner",
            (application_namespace, "gateway", "scanner", 8090),
            (application_namespace, "gateway", "api", 8000),
        ),
        (
            "opa",
            (application_namespace, "api", "opa", 8181),
            (application_namespace, "gateway", "api", 8000),
        ),
        (
            "api-external-egress",
            (application_namespace, "api", "external", 9000),
            (application_namespace, "gateway", "api", 8000),
        ),
    ]
    mutations: list[dict[str, Any]] = []
    for suffix, intended, control in mutation_cases:
        policy = _policy_by_suffix(policies, suffix)
        policy_name = policy["metadata"]["name"]
        _run(
            [
                *kubectl,
                "delete",
                "networkpolicy",
                policy_name,
                "--namespace",
                application_namespace,
            ]
        )
        time.sleep(2)
        intended_blocked = not _connection(
            kubectl, intended[0], intended[1], pod_ips[intended[2]], intended[3]
        )
        control_allowed = _connection(
            kubectl, control[0], control[1], pod_ips[control[2]], control[3]
        )
        _run(
            [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
            input_text=_dump([policy]),
        )
        time.sleep(2)
        restored = _connection(kubectl, intended[0], intended[1], pod_ips[intended[2]], intended[3])
        passed = intended_blocked and control_allowed and restored
        mutations.append({"policy": policy_name, "passed": passed})
        if not passed:
            raise RuntimeError(f"policy removal/restoration probe failed: {policy_name}")

    dns_policy = _policy_by_suffix(policies, "dns-egress")
    dns_policy_name = dns_policy["metadata"]["name"]
    _run(
        [*kubectl, "delete", "networkpolicy", dns_policy_name, "--namespace", application_namespace]
    )
    time.sleep(2)
    dns_blocked = not _dns(kubectl, application_namespace, "api")
    ingress_control = _connection(kubectl, ingress_namespace, "ingress", pod_ips["gateway"], 8001)
    _run(
        [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
        input_text=_dump([dns_policy]),
    )
    time.sleep(2)
    dns_restored = _dns(kubectl, application_namespace, "api")
    dns_mutation_passed = dns_blocked and ingress_control and dns_restored
    mutations.append({"policy": dns_policy_name, "passed": dns_mutation_passed})
    if not dns_mutation_passed:
        raise RuntimeError(f"policy removal/restoration probe failed: {dns_policy_name}")

    default_deny = _policy_by_suffix(policies, "default-deny")
    default_deny_name = default_deny["metadata"]["name"]
    _run(
        [
            *kubectl,
            "delete",
            "networkpolicy",
            default_deny_name,
            "--namespace",
            application_namespace,
        ]
    )
    time.sleep(2)
    unselected_path_opened = _connection(kubectl, rogue_namespace, "rogue", pod_ips["worker"], 6379)
    reviewed_path_unchanged = _connection(
        kubectl, ingress_namespace, "ingress", pod_ips["gateway"], 8001
    )
    _run(
        [*kubectl, "apply", "--namespace", application_namespace, "--filename", "-"],
        input_text=_dump([default_deny]),
    )
    time.sleep(2)
    unselected_path_closed = not _connection(
        kubectl, rogue_namespace, "rogue", pod_ips["worker"], 6379
    )
    default_deny_mutation_passed = (
        unselected_path_opened and reviewed_path_unchanged and unselected_path_closed
    )
    mutations.append({"policy": default_deny_name, "passed": default_deny_mutation_passed})
    if not default_deny_mutation_passed:
        raise RuntimeError(f"default-deny removal/restoration probe failed: {default_deny_name}")

    policy_bytes = _dump(policies).encode()
    report = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "evidence_kind": "live_kubernetes_data_plane",
        "kubernetes": {
            "server_version": version["serverVersion"]["gitVersion"],
            "cni": {
                "name": "kindnet",
                "image": cni["spec"]["template"]["spec"]["containers"][0]["image"],
                "ready": cni["status"].get("numberReady")
                == cni["status"].get("desiredNumberScheduled"),
            },
        },
        "probe_image": {
            "reference": args.image,
            "source_manifest_digest": args.image_source_digest,
        },
        "network_policies": {
            "count": len(policies),
            "rendered_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "resources": [
                {
                    "name": policy["metadata"]["name"],
                    "sha256": hashlib.sha256(_dump([policy]).encode()).hexdigest(),
                }
                for policy in sorted(policies, key=lambda value: value["metadata"]["name"])
            ],
        },
        "pod_security": {
            "profile": "restricted:v1.34",
            "privileged_pod_rejected": pod_security_rejected,
        },
        "baseline_probes": {
            "total": len(probes),
            "passed": sum(probe["passed"] for probe in probes),
            "results": probes,
        },
        "policy_removal_and_restoration": {
            "total": len(mutations),
            "passed": sum(mutation["passed"] for mutation in mutations),
            "results": mutations,
        },
        "contains_credentials_or_payloads": False,
    }
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    args.artifact.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not args.retain_resources:
        for namespace in (
            application_namespace,
            ingress_namespace,
            rogue_namespace,
            external_namespace,
        ):
            _run([*kubectl, "delete", "namespace", namespace, "--wait=false"])
    print(json.dumps({"artifact": str(args.artifact), "passed": True}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
