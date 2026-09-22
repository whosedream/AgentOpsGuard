#!/usr/bin/env python3
"""Exercise Patroni automatic PostgreSQL failover on a disposable kind cluster."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from uuid import uuid4

import yaml


ROOT = Path(__file__).resolve().parents[1]
PATRONI_IMAGE = "agentops-patroni-runtime:4.1.4"
PATRONI_IMAGE_ID = "sha256:f72e155837bf7061c5fd4efbb97891f8827bcb517b3e68fd833a4d43e95cd09b"
PATRONI_VERSION = "4.1.4"
POSTGRESQL_MAJOR = 16
KIND_NODE_IMAGE = "kindest/node:v1.34.0"
KIND_NODE_IMAGE_ID = "sha256:7b4018623371c5a26df6cd146876385cae3fe8544c65168077d2dd218c3d8166"
UPSTREAM_MANIFEST_URL = (
    "https://github.com/patroni/patroni/blob/v4.1.4/kubernetes/patroni_k8s.yaml"
)
UPSTREAM_MANIFEST_SHA256 = "17187a3f7e9acb8cdda6d970cca4787ea739acbe9b0d668fb087436a746e955c"
CLUSTER_NAME = "agentops-pg"
SERVICE_NAME = CLUSTER_NAME


def _safe_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment.update(overrides)
    return environment


def _run(
    command: list[str],
    *,
    step: str,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
    timeout: float = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment or _safe_environment(),
        input=input_text,
        stdin=None if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"Patroni failover verification failed during {step}")
    return completed


def _dump(documents: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(documents, sort_keys=True)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Patroni failover verification could not open the local database tunnel")


def _start_port_forward(
    kubectl: list[str], namespace: str, pod: str, local_port: int
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            *kubectl,
            "port-forward",
            "--namespace",
            namespace,
            f"pod/{pod}",
            f"{local_port}:5432",
        ],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(local_port, process)
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        raise
    return process


def _stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


PATRONI_TIMING_PROFILES = {
    "conservative": {"ttl": 20, "loop_wait": 5, "retry_timeout": 5},
    "responsive": {"ttl": 20, "loop_wait": 2, "retry_timeout": 3},
}


def _patroni_config(*, timing_profile: str = "conservative", failsafe_mode: bool = False) -> dict[str, Any]:
    if timing_profile not in PATRONI_TIMING_PROFILES:
        raise ValueError("unknown Patroni timing profile")
    return {
        "scope": CLUSTER_NAME,
        "kubernetes": {
            "use_endpoints": True,
            "labels": {"application": "patroni", "cluster-name": CLUSTER_NAME},
        },
        "restapi": {"listen": "0.0.0.0:8008"},
        "postgresql": {
            "listen": "0.0.0.0:5432",
            "data_dir": "/var/lib/postgresql/data/pgroot",
            "bin_dir": "/usr/lib/postgresql/16/bin",
            "pgpass": "/tmp/pgpass",
            "parameters": {
                "password_encryption": "scram-sha-256",
                "ssl": "off",
            },
            "pg_hba": [
                "local all all trust",
                "host all all 0.0.0.0/0 scram-sha-256",
                "host replication standby 0.0.0.0/0 scram-sha-256",
            ],
        },
        "bootstrap": {
            "dcs": {
                **PATRONI_TIMING_PROFILES[timing_profile],
                "failsafe_mode": failsafe_mode,
                "maximum_lag_on_failover": 0,
                "synchronous_mode": True,
                "synchronous_mode_strict": True,
                "synchronous_node_count": 1,
                "postgresql": {
                    "use_pg_rewind": True,
                    "use_slots": True,
                    "parameters": {
                        "hot_standby": "on",
                        "max_connections": 100,
                        "max_replication_slots": 10,
                        "max_wal_senders": 10,
                        "wal_keep_size": "64MB",
                    },
                },
            },
            "initdb": [{"encoding": "UTF8"}, "data-checksums"],
        },
        "watchdog": {"mode": "off"},
        "tags": {"nofailover": False, "noloadbalance": False, "clonefrom": False},
    }


def _namespace(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace,
            "labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "v1.34",
            },
        },
    }


def _cluster_documents(
    namespace: str, superuser_password: str, replication_password: str,
    *, timing_profile: str = "conservative", failsafe_mode: bool = False,
) -> list[dict[str, Any]]:
    labels = {"application": "patroni", "cluster-name": CLUSTER_NAME}
    pod_security_context = {
        "runAsNonRoot": True,
        "runAsUser": 999,
        "runAsGroup": 999,
        "fsGroup": 999,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    container_security_context = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    return [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": f"{CLUSTER_NAME}-config", "namespace": namespace},
            "data": {"patroni.yml": yaml.safe_dump(_patroni_config(
                timing_profile=timing_profile, failsafe_mode=failsafe_mode), sort_keys=True)},
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace},
            "type": "Opaque",
            "stringData": {
                "superuser-password": superuser_password,
                "replication-password": replication_password,
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["create", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["endpoints"],
                    "verbs": ["create", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list", "patch", "update", "watch"],
                },
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": CLUSTER_NAME,
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": CLUSTER_NAME, "namespace": namespace}
            ],
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{CLUSTER_NAME}-config", "namespace": namespace},
            "spec": {"clusterIP": "None"},
        },
        {
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {"name": SERVICE_NAME, "namespace": namespace, "labels": labels},
            "subsets": [],
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": SERVICE_NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 5432, "targetPort": 5432}],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{SERVICE_NAME}-replicas", "namespace": namespace},
            "spec": {
                "selector": {**labels, "role": "replica"},
                "ports": [{"port": 5432, "targetPort": 5432}],
            },
        },
        {
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace},
            "spec": {"minAvailable": 2, "selector": {"matchLabels": labels}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": CLUSTER_NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 3,
                "serviceName": f"{CLUSTER_NAME}-config",
                "podManagementPolicy": "Parallel",
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "serviceAccountName": CLUSTER_NAME,
                        "automountServiceAccountToken": False,
                        "terminationGracePeriodSeconds": 10,
                        "securityContext": pod_security_context,
                        "containers": [
                            {
                                "name": "patroni",
                                "image": PATRONI_IMAGE,
                                "imagePullPolicy": "Never",
                                "command": ["start-patroni"],
                                "env": [
                                    {
                                        "name": "PATRONI_NAME",
                                        "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
                                    },
                                    {
                                        "name": "PATRONI_KUBERNETES_NAMESPACE",
                                        "valueFrom": {
                                            "fieldRef": {"fieldPath": "metadata.namespace"}
                                        },
                                    },
                                    {
                                        "name": "PATRONI_KUBERNETES_POD_IP",
                                        "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}},
                                    },
                                    {
                                        "name": "PATRONI_POSTGRESQL_CONNECT_ADDRESS",
                                        "value": "$(PATRONI_KUBERNETES_POD_IP):5432",
                                    },
                                    {
                                        "name": "PATRONI_RESTAPI_CONNECT_ADDRESS",
                                        "value": "$(PATRONI_KUBERNETES_POD_IP):8008",
                                    },
                                    {"name": "KUBERNETES_SERVICE_HOST", "value": "127.0.0.1"},
                                    {"name": "KUBERNETES_SERVICE_PORT", "value": "16443"},
                                    {"name": "PATRONI_SUPERUSER_USERNAME", "value": "postgres"},
                                    {
                                        "name": "PATRONI_SUPERUSER_PASSWORD",
                                        "valueFrom": {
                                            "secretKeyRef": {
                                                "name": CLUSTER_NAME,
                                                "key": "superuser-password",
                                            }
                                        },
                                    },
                                    {"name": "PATRONI_REPLICATION_USERNAME", "value": "standby"},
                                    {
                                        "name": "PATRONI_REPLICATION_PASSWORD",
                                        "valueFrom": {
                                            "secretKeyRef": {
                                                "name": CLUSTER_NAME,
                                                "key": "replication-password",
                                            }
                                        },
                                    },
                                ],
                                "ports": [
                                    {"name": "postgresql", "containerPort": 5432},
                                    {"name": "patroni", "containerPort": 8008},
                                ],
                                "startupProbe": {
                                    "httpGet": {"path": "/readiness", "port": "patroni"},
                                    "periodSeconds": 2,
                                    "failureThreshold": 45,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readiness", "port": "patroni"},
                                    "periodSeconds": 3,
                                    "timeoutSeconds": 2,
                                    "failureThreshold": 3,
                                },
                                "livenessProbe": {
                                    "httpGet": {"path": "/liveness", "port": "patroni"},
                                    "periodSeconds": 10,
                                    "timeoutSeconds": 3,
                                    "failureThreshold": 6,
                                },
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "128Mi"},
                                    "limits": {"cpu": "1", "memory": "768Mi"},
                                },
                                "securityContext": container_security_context,
                                "volumeMounts": [
                                    {"name": "data", "mountPath": "/var/lib/postgresql/data"},
                                    {"name": "runtime", "mountPath": "/var/run/postgresql"},
                                    {"name": "temporary", "mountPath": "/tmp"},
                                    {
                                        "name": "config",
                                        "mountPath": "/etc/patroni",
                                        "readOnly": True,
                                    },
                                    {
                                        "name": "service-account",
                                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                                        "readOnly": True,
                                    },
                                ],
                            },
                            {
                                "name": "dcs-proxy",
                                "image": PATRONI_IMAGE,
                                "imagePullPolicy": "Never",
                                "command": [
                                    "toxiproxy-server",
                                    "-host",
                                    "127.0.0.1",
                                    "-port",
                                    "8474",
                                ],
                                "env": [{"name": "LOG_LEVEL", "value": "error"}],
                                "resources": {
                                    "requests": {"cpu": "10m", "memory": "16Mi"},
                                    "limits": {"cpu": "100m", "memory": "64Mi"},
                                },
                                "securityContext": container_security_context,
                            },
                        ],
                        "volumes": [
                            {"name": "data", "emptyDir": {}},
                            {"name": "runtime", "emptyDir": {}},
                            {"name": "temporary", "emptyDir": {}},
                            {
                                "name": "config",
                                "configMap": {"name": f"{CLUSTER_NAME}-config"},
                            },
                            {
                                "name": "service-account",
                                "projected": {
                                    "defaultMode": 420,
                                    "sources": [
                                        {
                                            "serviceAccountToken": {
                                                "path": "token",
                                                "expirationSeconds": 3600,
                                            }
                                        },
                                        {
                                            "configMap": {
                                                "name": "kube-root-ca.crt",
                                                "items": [
                                                    {"key": "ca.crt", "path": "ca.crt"}
                                                ],
                                            }
                                        },
                                    ],
                                },
                            },
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "database-probe",
                "namespace": namespace,
                "labels": {"application": "database-probe"},
            },
            "spec": {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "securityContext": pod_security_context,
                "containers": [
                    {
                        "name": "probe",
                        "image": PATRONI_IMAGE,
                        "imagePullPolicy": "Never",
                        "command": ["sh", "-c", "sleep 3600"],
                        "env": [
                            {
                                "name": "PGPASSWORD",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": CLUSTER_NAME,
                                        "key": "superuser-password",
                                    }
                                },
                            },
                            {"name": "PGCONNECT_TIMEOUT", "value": "1"},
                        ],
                        "securityContext": container_security_context,
                        "volumeMounts": [{"name": "temporary", "mountPath": "/tmp"}],
                    }
                ],
                "volumes": [{"name": "temporary", "emptyDir": {}}],
            },
        },
    ]


def _pod_state(kubectl: list[str], namespace: str) -> dict[str, dict[str, str]]:
    result = _run(
        [
            *kubectl,
            "get",
            "pods",
            "--namespace",
            namespace,
            "--selector",
            "application=patroni",
            "--output",
            "json",
        ],
        step="Patroni Pod inspection",
    )
    payload = json.loads(result.stdout)
    return {
        item["metadata"]["name"]: {
            "uid": item["metadata"]["uid"],
            "ip": item.get("status", {}).get("podIP", ""),
            "role": item["metadata"].get("labels", {}).get("role", ""),
            "phase": item.get("status", {}).get("phase", ""),
            "ready": str(
                any(
                    condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in item.get("status", {}).get("conditions", [])
                )
            ).lower(),
        }
        for item in payload.get("items", [])
    }


def _wait_for_topology(
    kubectl: list[str],
    namespace: str,
    *,
    expected_primary: str | None = None,
    excluded_primary: str | None = None,
    ready_members: int = 3,
    timeout: float = 120,
) -> tuple[str, dict[str, dict[str, str]]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _pod_state(kubectl, namespace)
        primaries = [name for name, item in state.items() if item["role"] == "primary"]
        replicas = [name for name, item in state.items() if item["role"] == "replica"]
        ready = [name for name, item in state.items() if item["ready"] == "true"]
        if (
            len(primaries) == 1
            and len(replicas) == 2
            and len(ready) == ready_members
            and (expected_primary is None or primaries[0] == expected_primary)
            and (excluded_primary is None or primaries[0] != excluded_primary)
        ):
            return primaries[0], state
        time.sleep(1)
    raise RuntimeError("Patroni failover verification did not reach one-primary/two-replica state")


def _service_state(kubectl: list[str], namespace: str) -> tuple[str, tuple[str, ...]]:
    service = json.loads(
        _run(
            [
                *kubectl,
                "get",
                "service",
                SERVICE_NAME,
                "--namespace",
                namespace,
                "--output",
                "json",
            ],
            step="stable Service inspection",
        ).stdout
    )
    endpoints = json.loads(
        _run(
            [
                *kubectl,
                "get",
                "endpoints",
                SERVICE_NAME,
                "--namespace",
                namespace,
                "--output",
                "json",
            ],
            step="leader endpoint inspection",
        ).stdout
    )
    addresses = tuple(
        sorted(
            address["ip"]
            for subset in endpoints.get("subsets", [])
            for address in subset.get("addresses", [])
        )
    )
    return service["spec"]["clusterIP"], addresses


def _probe_sql(
    kubectl: list[str], namespace: str, database: str, statement: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            "database-probe",
            "--",
            "psql",
            "--host",
            SERVICE_NAME,
            "--username",
            "postgres",
            "--dbname",
            database,
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            statement,
        ],
        step="stable Service database probe",
        timeout=15,
        check=check,
    )


def _wait_for_stable_service(kubectl: list[str], namespace: str) -> int:
    started = time.monotonic()
    deadline = started + 90
    while time.monotonic() < deadline:
        result = _probe_sql(
            kubectl,
            namespace,
            "agentops",
            "SELECT 1",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == "1":
            return round((time.monotonic() - started) * 1000)
        time.sleep(0.5)
    raise RuntimeError("Patroni failover verification stable Service did not recover")


def _wait_for_replica_replay(
    kubectl: list[str], namespace: str, primary: str, state: dict[str, dict[str, str]]
) -> None:
    lsn = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            primary,
            "--",
            "psql",
            "--username",
            "postgres",
            "--dbname",
            "agentops",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            "SELECT pg_current_wal_flush_lsn()::text",
        ],
        step="primary WAL position inspection",
    ).stdout.strip()
    replicas = [name for name, item in state.items() if item["role"] == "replica"]
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        caught_up = 0
        for replica in replicas:
            result = _run(
                [
                    *kubectl,
                    "exec",
                    "--namespace",
                    namespace,
                    replica,
                    "--",
                    "psql",
                    "--username",
                    "postgres",
                    "--dbname",
                    "agentops",
                    "--no-psqlrc",
                    "--tuples-only",
                    "--no-align",
                    "--command",
                    f"SELECT pg_last_wal_replay_lsn() >= '{lsn}'::pg_lsn",
                ],
                step="replica WAL replay inspection",
                check=False,
            )
            caught_up += result.returncode == 0 and result.stdout.strip() == "t"
        if caught_up == 2:
            return
        time.sleep(0.5)
    raise RuntimeError("Patroni failover verification replicas did not replay committed state")


def _set_dcs_proxy_enabled(
    kubectl: list[str], namespace: str, pod: str, *, enabled: bool
) -> None:
    program = (
        "import json,urllib.request;"
        "body=json.dumps({'enabled':" + ("True" if enabled else "False") + "}).encode();"
        "request=urllib.request.Request("
        "'http://127.0.0.1:8474/proxies/kubernetes-api',"
        "data=body,headers={'Content-Type':'application/json'},method='POST');"
        "response=urllib.request.urlopen(request,timeout=5);"
        "assert response.status==200"
    )
    _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            pod,
            "--container",
            "patroni",
            "--",
            "python",
            "-c",
            program,
        ],
        step="Kubernetes API fault proxy state change",
        timeout=10,
    )


def _kubernetes_api_reachable(kubectl: list[str], namespace: str, pod: str) -> bool:
    program = (
        "import pathlib,sys,urllib3;"
        "root=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount');"
        "http=urllib3.PoolManager(cert_reqs='CERT_REQUIRED',ca_certs=str(root/'ca.crt'));"
        "response=http.request('GET','https://127.0.0.1:16443/version',"
        "headers={'Authorization':'Bearer '+(root/'token').read_text()},"
        "timeout=urllib3.Timeout(connect=1,read=1),retries=False);"
        "sys.exit(0 if response.status==200 else 1)"
    )
    result = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            pod,
            "--",
            "python",
            "-c",
            program,
        ],
        step="isolated primary Kubernetes API probe",
        timeout=6,
        check=False,
    )
    return result.returncode == 0


def _postgres_is_writable(kubectl: list[str], namespace: str, pod: str) -> bool:
    result = _run(
        [
            *kubectl,
            "exec",
            "--namespace",
            namespace,
            pod,
            "--",
            "psql",
            "--username",
            "postgres",
            "--dbname",
            "postgres",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            "SELECT NOT pg_is_in_recovery() "
            "AND current_setting('transaction_read_only') = 'off'",
        ],
        step="PostgreSQL writability probe",
        timeout=6,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "t"


def _wait_for_partition_failover(
    kubectl: list[str],
    namespace: str,
    *,
    isolated_primary: str,
    old_endpoint: tuple[str, ...],
) -> tuple[str, int, int, bool]:
    started = time.monotonic()
    maximum_writable_primaries = 0
    isolated_primary_stopped_writes = False
    deadline = started + 90
    while time.monotonic() < deadline:
        state = _pod_state(kubectl, namespace)
        writable = [
            pod
            for pod in sorted(state)
            if _postgres_is_writable(kubectl, namespace, pod)
        ]
        maximum_writable_primaries = max(maximum_writable_primaries, len(writable))
        if len(writable) > 1:
            raise RuntimeError("Patroni DCS partition exposed multiple writable primaries")
        isolated_primary_stopped_writes = (
            isolated_primary_stopped_writes or isolated_primary not in writable
        )
        _, endpoint = _service_state(kubectl, namespace)
        service_query = _probe_sql(
            kubectl,
            namespace,
            "agentops",
            "SELECT 1",
            check=False,
        )
        if (
            len(writable) == 1
            and writable[0] != isolated_primary
            and endpoint != old_endpoint
            and endpoint == (state[writable[0]]["ip"],)
            and service_query.returncode == 0
            and service_query.stdout.strip() == "1"
        ):
            recovery_ms = round((time.monotonic() - started) * 1000)
            new_primary = writable[0]
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("Patroni DCS partition did not elect a safe replacement primary")

    stable_until = time.monotonic() + 5
    while time.monotonic() < stable_until:
        state = _pod_state(kubectl, namespace)
        writable = [
            pod
            for pod in sorted(state)
            if _postgres_is_writable(kubectl, namespace, pod)
        ]
        maximum_writable_primaries = max(maximum_writable_primaries, len(writable))
        if writable != [new_primary]:
            raise RuntimeError("Patroni DCS partition did not retain exactly one writable primary")
        time.sleep(0.25)
    return (
        new_primary,
        recovery_ms,
        maximum_writable_primaries,
        isolated_primary_stopped_writes,
    )


def _application_environment(database_url: str) -> dict[str, str]:
    return _safe_environment(
        AGENTOPS_ENV="test",
        AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP="false",
        AGENTOPS_DATABASE_URL=database_url,
        AGENTOPS_SEMANTIC_SCANNER_MODE="disabled",
        AGENTOPS_OPA_URL="",
        AGENTOPS_OTEL_ENABLED="false",
    )


def _application_command(
    command: list[str], database_url: str, *, step: str
) -> dict[str, object] | None:
    result = _run(
        command,
        step=step,
        environment=_application_environment(database_url),
        timeout=90,
    )
    if not result.stdout.strip():
        return None
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("Patroni failover application verifier returned invalid output")
    return payload


def _verify_image(reference: str, expected_id: str, *, step: str) -> None:
    result = _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        step=step,
        timeout=20,
    )
    if result.stdout.strip() != expected_id:
        raise RuntimeError(f"Patroni failover verification found an unexpected {step}")


def _verify_tool_versions(kind: str, kubectl: str) -> tuple[str, str]:
    kind_version = _run([kind, "version"], step="kind version inspection").stdout.strip()
    if "0.30.0" not in kind_version:
        raise RuntimeError("Patroni failover verification requires kind 0.30.0")
    kubectl_version = json.loads(
        _run([kubectl, "version", "--client", "--output", "json"], step="kubectl version inspection").stdout
    )["clientVersion"]["gitVersion"]
    if kubectl_version != "v1.34.0":
        raise RuntimeError("Patroni failover verification requires kubectl v1.34.0")
    return "0.30.0", kubectl_version


def _delete_cluster(kind: str, cluster: str, environment: dict[str, str]) -> None:
    subprocess.run(
        [kind, "delete", "cluster", "--name", cluster],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=90,
        check=False,
    )
    remains = subprocess.run(
        ["docker", "ps", "--all", "--quiet", "--filter", f"label=io.x-k8s.kind.cluster={cluster}"],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=20,
        check=False,
    )
    if remains.stdout.strip():
        raise RuntimeError("Patroni failover verification cluster cleanup failed")


def _main_verification(arguments: argparse.Namespace) -> None:
    kind_version, kubectl_version = _verify_tool_versions(arguments.kind, arguments.kubectl)
    _run(["docker", "info"], step="Docker readiness", timeout=20)
    _verify_image(PATRONI_IMAGE, PATRONI_IMAGE_ID, step="Patroni image identifier")
    _verify_image(KIND_NODE_IMAGE, KIND_NODE_IMAGE_ID, step="kind node image identifier")

    suffix = uuid4().hex[:8]
    cluster = f"agentops-patroni-{suffix}"
    namespace = f"agentops-patroni-{suffix}"
    project_id = f"patroni_failover_{suffix}"
    partition_project_id = f"patroni_partition_{uuid4().hex[:8]}"
    superuser_password = secrets.token_urlsafe(48)
    replication_password = secrets.token_urlsafe(48)
    port_forward: subprocess.Popen[bytes] | None = None
    succeeded = False

    with tempfile.TemporaryDirectory(prefix="agentops-patroni-") as temporary_directory:
        temporary = Path(temporary_directory)
        kubeconfig = temporary / "kubeconfig"
        docker_config = temporary / "docker-config"
        docker_config.mkdir(mode=0o700)
        config = docker_config / "config.json"
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, b"{}\n")
        finally:
            os.close(descriptor)
        kind_environment = _safe_environment(DOCKER_CONFIG=str(docker_config))
        kubectl = [arguments.kubectl, "--kubeconfig", str(kubeconfig)]
        try:
            _run(
                [
                    arguments.kind,
                    "create",
                    "cluster",
                    "--name",
                    cluster,
                    "--image",
                    KIND_NODE_IMAGE,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--wait",
                    "120s",
                ],
                step="disposable Kubernetes cluster creation",
                environment=kind_environment,
                timeout=180,
            )
            _run(
                [arguments.kind, "load", "docker-image", "--name", cluster, PATRONI_IMAGE],
                step="reviewed Patroni image loading",
                environment=kind_environment,
                timeout=120,
            )
            server_version = json.loads(
                _run(
                    [*kubectl, "version", "--output", "json"],
                    step="Kubernetes server version inspection",
                ).stdout
            )["serverVersion"]["gitVersion"]
            if server_version != "v1.34.0":
                raise RuntimeError("Patroni failover verification Kubernetes version changed")

            _run(
                [*kubectl, "apply", "--filename", "-"],
                step="restricted namespace creation",
                input_text=_dump([_namespace(namespace)]),
            )
            documents = _cluster_documents(
                namespace,
                superuser_password=superuser_password,
                replication_password=replication_password,
            )
            _run(
                [*kubectl, "apply", "--filename", "-"],
                step="Patroni cluster creation",
                input_text=_dump(documents),
                timeout=60,
            )
            _run(
                [
                    *kubectl,
                    "wait",
                    "--namespace",
                    namespace,
                    "--for=condition=Ready",
                    "pod/database-probe",
                    "--timeout=90s",
                ],
                step="stable Service probe readiness",
                timeout=100,
            )
            initial_primary, initial_state = _wait_for_topology(kubectl, namespace, timeout=150)
            initial_uid = initial_state[initial_primary]["uid"]
            initial_primary_ip = initial_state[initial_primary]["ip"]
            cluster_ip_before, endpoints_before = _service_state(kubectl, namespace)
            if endpoints_before != (initial_primary_ip,):
                raise RuntimeError("Patroni leader endpoint did not match the elected primary")

            _run(
                [
                    *kubectl,
                    "exec",
                    "--namespace",
                    namespace,
                    initial_primary,
                    "--",
                    "createdb",
                    "--username",
                    "postgres",
                    "agentops",
                ],
                step="application database creation",
            )
            local_port = _free_port()
            port_forward = _start_port_forward(kubectl, namespace, initial_primary, local_port)
            database_url = (
                f"postgresql+psycopg://postgres:{superuser_password}"
                f"@127.0.0.1:{local_port}/agentops"
            )
            _application_command(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                database_url,
                step="application schema migration",
            )
            state_script = ROOT / "scripts" / "verify_postgres_backup_restore.py"
            seeded = _application_command(
                [sys.executable, str(state_script), "--seed", project_id],
                database_url,
                step="application state seed",
            )
            before = _application_command(
                [sys.executable, str(state_script), "--verify", project_id],
                database_url,
                step="application state verification before failover",
            )
            if seeded != {"seeded": True}:
                raise RuntimeError("Patroni failover application state seed failed")
            _stop_process(port_forward)
            port_forward = None
            _wait_for_replica_replay(kubectl, namespace, initial_primary, initial_state)
            probe_before = _probe_sql(
                kubectl,
                namespace,
                "agentops",
                "SELECT count(*) FROM audit_logs",
            )
            if probe_before.stdout.strip() != "2":
                raise RuntimeError("Patroni stable Service did not expose seeded application state")

            failover_started = time.monotonic()
            _run(
                [
                    *kubectl,
                    "delete",
                    "pod",
                    initial_primary,
                    "--namespace",
                    namespace,
                    "--grace-period=0",
                    "--force",
                    "--wait=false",
                ],
                step="primary Pod termination",
                timeout=30,
            )
            service_recovery_ms = _wait_for_stable_service(kubectl, namespace)
            new_primary, recovered_state = _wait_for_topology(
                kubectl,
                namespace,
                excluded_primary=initial_primary,
                timeout=150,
            )
            automatic_failover_ms = round((time.monotonic() - failover_started) * 1000)
            if recovered_state[initial_primary]["uid"] == initial_uid:
                raise RuntimeError("Patroni old primary Pod identity survived forced termination")
            if recovered_state[initial_primary]["role"] != "replica":
                raise RuntimeError("Patroni replaced primary did not rejoin as a replica")
            cluster_ip_after, endpoints_after = _service_state(kubectl, namespace)
            if cluster_ip_after != cluster_ip_before:
                raise RuntimeError("Patroni stable Service address changed during failover")
            if endpoints_after != (recovered_state[new_primary]["ip"],):
                raise RuntimeError("Patroni stable Service did not move to the new primary")
            if endpoints_after == endpoints_before:
                raise RuntimeError("Patroni leader endpoint did not change during failover")

            local_port = _free_port()
            port_forward = _start_port_forward(kubectl, namespace, new_primary, local_port)
            database_url = (
                f"postgresql+psycopg://postgres:{superuser_password}"
                f"@127.0.0.1:{local_port}/agentops"
            )
            after = _application_command(
                [sys.executable, str(state_script), "--verify", project_id],
                database_url,
                step="application state verification after failover",
            )
            appended = _application_command(
                [sys.executable, str(ROOT / "scripts" / "verify_postgres_streaming_failover.py"), "--append", project_id],
                database_url,
                step="application write after automatic failover",
            )
            final = _application_command(
                [sys.executable, str(ROOT / "scripts" / "verify_postgres_streaming_failover.py"), "--verify", project_id],
                database_url,
                step="application state verification after post-failover write",
            )
            if before != after or appended != {"post_failover_write": True}:
                raise RuntimeError("Patroni automatic failover changed committed application state")
            partition_seeded = _application_command(
                [sys.executable, str(state_script), "--seed", partition_project_id],
                database_url,
                step="DCS-partition application state seed",
            )
            partition_before = _application_command(
                [sys.executable, str(state_script), "--verify", partition_project_id],
                database_url,
                step="application state verification before DCS partition",
            )
            if partition_seeded != {"seeded": True}:
                raise RuntimeError("Patroni DCS-partition application state seed failed")
            _stop_process(port_forward)
            port_forward = None

            partition_primary, partition_state_before = _wait_for_topology(
                kubectl,
                namespace,
                expected_primary=new_primary,
            )
            partition_primary_uid = partition_state_before[partition_primary]["uid"]
            partition_cluster_ip_before, partition_endpoint_before = _service_state(
                kubectl, namespace
            )
            _wait_for_replica_replay(
                kubectl,
                namespace,
                partition_primary,
                partition_state_before,
            )
            partition_started = time.monotonic()
            _set_dcs_proxy_enabled(
                kubectl, namespace, partition_primary, enabled=False
            )
            initial_partition_query = _probe_sql(
                kubectl,
                namespace,
                "agentops",
                "SELECT 1",
                check=False,
            )
            if initial_partition_query.returncode != 0:
                raise RuntimeError("Patroni DCS partition also blocked the database data path")
            api_deadline = time.monotonic() + 15
            while _kubernetes_api_reachable(kubectl, namespace, partition_primary):
                if time.monotonic() >= api_deadline:
                    raise RuntimeError("Patroni DCS partition did not isolate the Kubernetes API")
                time.sleep(0.25)
            (
                partition_new_primary,
                _,
                maximum_writable_primaries,
                isolated_primary_stopped_writes,
            ) = _wait_for_partition_failover(
                kubectl,
                namespace,
                isolated_primary=partition_primary,
                old_endpoint=partition_endpoint_before,
            )
            partition_service_recovery_ms = round(
                (time.monotonic() - partition_started) * 1000
            )
            partition_cluster_ip_during, partition_endpoint_during = _service_state(
                kubectl, namespace
            )
            _set_dcs_proxy_enabled(
                kubectl, namespace, partition_primary, enabled=True
            )
            healed_primary, partition_state_after = _wait_for_topology(
                kubectl,
                namespace,
                expected_primary=partition_new_primary,
                timeout=150,
            )
            partition_full_recovery_ms = round(
                (time.monotonic() - partition_started) * 1000
            )
            if partition_state_after[partition_primary]["uid"] != partition_primary_uid:
                raise RuntimeError("Patroni DCS partition unexpectedly replaced the isolated Pod")
            if partition_state_after[partition_primary]["role"] != "replica":
                raise RuntimeError("Patroni isolated primary did not heal as a replica")
            partition_cluster_ip_after, partition_endpoint_after = _service_state(
                kubectl, namespace
            )
            if not (
                partition_cluster_ip_before
                == partition_cluster_ip_during
                == partition_cluster_ip_after
            ):
                raise RuntimeError("Patroni stable Service address changed during DCS partition")
            if partition_endpoint_during != (
                partition_state_after[partition_new_primary]["ip"],
            ) or partition_endpoint_after != partition_endpoint_during:
                raise RuntimeError("Patroni leader endpoint did not remain on the replacement primary")

            local_port = _free_port()
            port_forward = _start_port_forward(
                kubectl, namespace, partition_new_primary, local_port
            )
            database_url = (
                f"postgresql+psycopg://postgres:{superuser_password}"
                f"@127.0.0.1:{local_port}/agentops"
            )
            partition_after = _application_command(
                [sys.executable, str(state_script), "--verify", partition_project_id],
                database_url,
                step="application state verification after DCS partition",
            )
            partition_appended = _application_command(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "verify_postgres_streaming_failover.py"),
                    "--append",
                    partition_project_id,
                ],
                database_url,
                step="application write after DCS-partition failover",
            )
            partition_final = _application_command(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "verify_postgres_streaming_failover.py"),
                    "--verify",
                    partition_project_id,
                ],
                database_url,
                step="application state verification after DCS-partition write",
            )
            if (
                partition_before != partition_after
                or partition_appended != {"post_failover_write": True}
            ):
                raise RuntimeError("Patroni DCS partition changed committed application state")
            _stop_process(port_forward)
            port_forward = None

            report = {
                "schema_version": 1,
                "evidence_kind": "live_patroni_kubernetes_automatic_failover",
                "upstream": {
                    "project": "patroni/patroni",
                    "version": PATRONI_VERSION,
                    "reference_manifest": UPSTREAM_MANIFEST_URL,
                    "reference_manifest_sha256": UPSTREAM_MANIFEST_SHA256,
                    "fault_model_reference": "https://github.com/wb14123/jepsen-postgres-ha",
                },
                "runtime": {
                    "patroni_image": PATRONI_IMAGE,
                    "patroni_image_id": PATRONI_IMAGE_ID,
                    "postgresql_major": POSTGRESQL_MAJOR,
                    "kind_version": kind_version,
                    "kubectl_version": kubectl_version,
                    "kubernetes_server_version": server_version,
                    "kind_node_image_id": KIND_NODE_IMAGE_ID,
                },
                "topology": {
                    "members": 3,
                    "primaries": 1,
                    "replicas": 2,
                    "synchronous_mode": True,
                    "synchronous_mode_strict": True,
                    "restricted_pod_security": True,
                    "namespace_scoped_rbac": True,
                    "pod_disruption_budget_min_available": 2,
                },
                "checks": {
                    "both_replicas_replayed_committed_state": True,
                    "primary_failure_was_forced": True,
                    "automatic_new_primary_elected": new_primary != initial_primary,
                    "old_primary_identity_terminated": True,
                    "replaced_primary_rejoined_as_replica": True,
                    "single_primary_after_recovery": True,
                    "stable_service_address_unchanged": True,
                    "stable_service_endpoint_changed": True,
                    "stable_service_query_recovered": True,
                    "committed_application_state_survived": before == after,
                    "post_failover_application_write_succeeded": appended
                    == {"post_failover_write": True},
                    "audit_chain_valid_after_failover": bool(final and final["audit_chain_valid"]),
                    "service_recovery_ms": service_recovery_ms,
                    "automatic_failover_and_full_replica_recovery_ms": automatic_failover_ms,
                    "dcs_egress_partition_injected": True,
                    "database_data_path_remained_reachable_at_partition_start": True,
                    "isolated_primary_kubernetes_api_unreachable": True,
                    "isolated_primary_stopped_writes": isolated_primary_stopped_writes,
                    "partition_replacement_primary_elected": partition_new_primary
                    != partition_primary,
                    "maximum_simultaneous_writable_primaries": maximum_writable_primaries,
                    "partition_stable_service_address_unchanged": True,
                    "partition_stable_service_endpoint_changed": partition_endpoint_during
                    != partition_endpoint_before,
                    "partition_service_query_recovered": True,
                    "partition_committed_application_state_survived": partition_before
                    == partition_after,
                    "partition_post_failover_write_succeeded": partition_appended
                    == {"post_failover_write": True},
                    "partition_audit_chain_valid": bool(
                        partition_final and partition_final["audit_chain_valid"]
                    ),
                    "partition_healed_to_one_primary_two_replicas": healed_primary
                    == partition_new_primary,
                    "partition_service_recovery_ms": partition_service_recovery_ms,
                    "partition_full_topology_recovery_ms": partition_full_recovery_ms,
                },
                "limits": {
                    "single_machine_test_cluster": True,
                    "durable_persistent_volumes_tested": False,
                    "primary_to_dcs_egress_partition_self_demote_tested": True,
                    "hardware_watchdog_or_node_fencing_tested": False,
                    "arbitrary_host_or_zone_partition_tested": False,
                    "cross_zone_failure_tested": False,
                    "database_tls_tested": False,
                    "production_image_signature_verified": False,
                    "host_port_forward_is_stable_endpoint": False,
                },
                "privacy": {
                    "captures_database_credentials": False,
                    "captures_database_urls": False,
                    "captures_application_content": False,
                },
            }
            if arguments.artifact:
                arguments.artifact.parent.mkdir(parents=True, exist_ok=True)
                arguments.artifact.write_text(
                    json.dumps(report, indent=2) + "\n", encoding="utf-8"
                )
            print(json.dumps(report, separators=(",", ":")))
            succeeded = True
        finally:
            _stop_process(port_forward)
            if not arguments.retain_cluster:
                _delete_cluster(arguments.kind, cluster, kind_environment)
    if not succeeded:
        raise RuntimeError("Patroni automatic failover verification did not complete")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True)
    parser.add_argument("--kubectl", required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--retain-cluster", action="store_true")
    _main_verification(parser.parse_args())


if __name__ == "__main__":
    main()
