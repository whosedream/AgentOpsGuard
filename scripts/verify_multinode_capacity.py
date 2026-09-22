#!/usr/bin/env python3
"""Disposable kind capacity/fault evaluation. Setup, phases, and cleanup are separate.

Credentials stay inside this trusted controller/Kubernetes Secrets. Reports never
contain requests, responses, tokens, connection strings, or kubeconfig contents.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextlib import asynccontextmanager
import csv
from datetime import UTC, datetime
import hashlib
import json
import io
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from uuid import uuid4, uuid5, NAMESPACE_URL

import httpx
import yaml

from verify_patroni_kubernetes_failover import (
    ROOT, KIND_NODE_IMAGE, PATRONI_IMAGE, CLUSTER_NAME, _cluster_documents,
    _free_port, _safe_environment, _delete_cluster, PATRONI_TIMING_PROFILES,
    _set_dcs_proxy_enabled,
)
from verify_opa_runtime import _build_signed_bundle, OPA_IMAGE, SIGNING_KEY_ID, SIGNING_SCOPE
from agentops_guard.benchmarks.llmail_inject import DEFAULT_MODEL_SHA256
from verify_clock_consistency import measure_clock

KIND = ROOT / "artifacts/tools/multinode/kind"
KUBECTL = ROOT / "artifacts/tools/multinode/kubectl"
IMAGE = "agentops-multinode-candidate:20260909-scoring-queue2"
PROXY_IMAGE = "haproxy:3.0-alpine"
PREFIX = "agentops-mn-"
INOTIFY_INSTANCES_PATH = Path("/proc/sys/fs/inotify/max_user_instances")
HOST_PROC = Path("/proc")


def run(command, *, input_text=None, timeout=180, environment=None):
    result = subprocess.run([str(value) for value in command], cwd=ROOT,
        env=environment or _safe_environment(), input=input_text, text=True,
        stdin=None if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode:
        # Command arguments can name credential delivery destinations. Never echo them.
        raise RuntimeError(f"multinode command failed: program={Path(command[0]).name}, exit={result.returncode}")
    return result.stdout


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def frozen_inputs():
    paths = sorted((ROOT / "src").rglob("*.py"))
    paths += sorted((ROOT / "policies").rglob("*.json"))
    paths += sorted((ROOT / "policies").glob("*.rego"))
    paths += sorted((ROOT / "alembic").rglob("*.py"))
    paths += sorted(path for path in (ROOT / "deploy/helm/agentops-guard").rglob("*") if path.is_file())
    paths += [Path(__file__), ROOT / "evals/multinode-runtime/runtime.py",
              ROOT / "evals/multinode-runtime/Dockerfile", ROOT / "uv.lock",
              ROOT / "evals/multinode-runtime/Dockerfile.overlay", ROOT / "pyproject.toml",
              ROOT / "evals/multinode-runtime/revision_race.py",
              ROOT / "scripts/verify_patroni_kubernetes_failover.py",
              ROOT / "scripts/verify_clock_consistency.py",
              ROOT / "scripts/verify_opa_runtime.py"]
    paths += [ROOT / "scripts/verify_multinode_invocations.py"]
    paths += [ROOT / "tests/fixtures/receipt_mcp_server.py", ROOT / "scripts/verify_multinode_receipts.py"]
    paths += [ROOT / "scripts/verify_multinode_admission.py", ROOT / "scripts/run_two_layer_cluster_verification.py"]
    paths += [ROOT / "scripts/collect_multinode_evidence.py"]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def kubectl(state, *args, input_text=None, timeout=180):
    return run([KUBECTL, "--kubeconfig", state["kubeconfig"], "--namespace", state["namespace"], *args],
               input_text=input_text, timeout=timeout)


def apply(state, documents):
    kubectl(state, "apply", "-f", "-", input_text=yaml.safe_dump_all(documents))


def deployment(name, image, command, *, replicas=1, env=None, port=None, control=False):
    labels = {"app": name}
    container = {"name": name, "image": image, "imagePullPolicy": "Never", "command": command,
        "env": env or [], "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
        "limits": {"cpu": "1", "memory": "512Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}
    spec = {"automountServiceAccountToken": False, "containers": [container],
            "nodeSelector": {"eval-role": "control" if control else "worker"}}
    if control:
        spec["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}]
    if replicas > 1:
        spec["affinity"] = spread(name)
    if port:
        container["ports"] = [{"containerPort": port}]
        container["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 2}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
        "spec": {"replicas": replicas, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": spec}}}


def spread(app):
    return {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
        {"topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {"app": app}}}]}}


def service(name, port):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
            "spec": {"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]}}


def wait_deployment(state, name, seconds=240):
    kubectl(state, "rollout", "status", "deployment/" + name, f"--timeout={seconds}s", timeout=seconds+10)


def driver(state, role, data):
    return json.loads(kubectl(state, "exec", "-i", "deployment/eval-driver", "--",
        "python", "/app/eval_runtime.py", role, input_text=json.dumps(data), timeout=120))


def check_host_limits():
    limit = int(INOTIFY_INSTANCES_PATH.read_text().strip())
    if limit < 512:
        raise RuntimeError("kind evaluation requires fs.inotify.max_user_instances >= 512; "
                           "raise it temporarily with host administrator approval and restore it after cleanup")


def patroni_configuration(state):
    document = json.loads(kubectl(state, "get", "endpoints", CLUSTER_NAME + "-config", "-o", "json"))
    config = json.loads(document["metadata"]["annotations"]["config"])
    expected = {**PATRONI_TIMING_PROFILES[state["patroni_timing_profile"]],
        "synchronous_mode": True, "synchronous_mode_strict": True,
        "synchronous_node_count": 1, "maximum_lag_on_failover": 0}
    if "patroni_failsafe" in state:
        expected["failsafe_mode"] = state["patroni_failsafe"]
    actual = {key: config.get(key) for key in expected}
    if actual != expected:
        raise RuntimeError("Patroni effective timing or durability differs from the frozen profile")
    return actual  # No arbitrary configuration, credentials or connection strings.


def parse_etcd_disk_metrics(raw):
    metrics = []
    pattern = (r'^(etcd_disk_(?:wal_fsync|backend_commit)_duration_seconds_(?:bucket|sum|count))'
               r'(?:\{le="(\+Inf|[0-9.eE+-]+)"\})? ([0-9.eE+-]+)$')
    for line in raw.splitlines():
        match = re.fullmatch(pattern, line)
        if match and math.isfinite(value := float(match[3])):
            metrics.append({"name": match[1], "le": match[2], "value": value})
    return metrics


def etcd_disk_metrics(state):
    """Read the kind control-plane's local metrics; never arbitrary etcd logs."""
    node = state["cluster"] + "-control-plane"
    started = time.monotonic()
    try:
        label = run(["docker", "inspect", node, "--format", '{{index .Config.Labels "io.x-k8s.kind.cluster"}}'], timeout=3).strip()
        if label != state["cluster"]:
            raise ValueError("not the disposable control-plane")
        raw = run(["docker", "exec", node, "curl", "--silent", "--fail", "--max-time", "2",
                   "http://127.0.0.1:2381/metrics"], timeout=3)
        metrics = parse_etcd_disk_metrics(raw)
        return {"available": bool(metrics), "histograms": metrics,
                "duration_ms": round((time.monotonic()-started)*1000, 3)}
    except (RuntimeError, subprocess.TimeoutExpired):
        return {"available": False, "error": "disk_metrics_unavailable"}


def node_profiles(resource_profile, cpus):
    """Test overlays: distinct logical CPUs, NOT distinct hosts or storage."""
    if resource_profile == "shared":
        return [{"role": "control", "cpus": "2", "memory": "3g"}] + [
            {"role": "worker", "cpus": "2.5", "memory": "5g"} for _ in range(3)]
    if resource_profile != "isolated" or len(cpus) < 12:
        raise ValueError("isolated profile requires at least 12 available logical CPUs")
    groups = {"control": cpus[:2], "worker": cpus[2:9], "database": cpus[9:]}
    return [{"role": role, "cpus": quota, "memory": memory,
             "cpuset": ",".join(map(str, groups[role]))}
        for role, quota, memory in [("control", "2", "3g")]
        + [("worker", "2", "4g")] * 3 + [("database", "1", "2g")] * 3]


def setup(directory, timing_profile="conservative", durable_queue=False, concurrency=1,
          resource_profile="shared", failsafe=False, receipts=False, independent_admission=False,
          cluster_name=None):
    cluster = cluster_name if cluster_name is not None else PREFIX + uuid4().hex[:8]
    if not re.fullmatch(re.escape(PREFIX) + r"[0-9a-f]{8}", cluster):
        raise ValueError("Invalid disposable cluster name")
    if timing_profile not in PATRONI_TIMING_PROFILES:
        raise ValueError("unknown Patroni timing profile")
    if concurrency not in {1, 2, 4}:
        raise ValueError("controlled concurrency must be 1, 2 or 4")
    profiles = node_profiles(resource_profile, sorted(os.sched_getaffinity(0)))
    if independent_admission:
        if resource_profile != "isolated" or not durable_queue:
            raise ValueError("Independent admission requires isolated nodes and the real queue workers")
        profiles += [{**profiles[-1], "role": "admission-database"} for _ in range(3)]
    check_host_limits()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    port = _free_port()
    admission_port = _free_port() if independent_admission else None
    state = {"cluster": cluster, "namespace": cluster, "kubeconfig": str(directory / "kubeconfig"),
             "entrypoint": f"http://127.0.0.1:{port}", "image": IMAGE,
             "created_at": datetime.now(UTC).isoformat(), "source": frozen_inputs(),
             "patroni_timing_profile": timing_profile, "durable_queue_enabled": durable_queue,
             "patroni_failsafe": failsafe, "resource_profile": resource_profile,
             "node_count": len(profiles), "node_profiles": profiles, "receipts_enabled": receipts,
             "gateway_concurrency": concurrency}
    if independent_admission:
        state.update(independent_admission=True, admission_namespace=cluster + "-admission",
                     admission_entrypoint=f"http://127.0.0.1:{admission_port}")
    save(directory / "state.json", state)
    image_sources = json.loads(run(["docker", "run", "--rm", "--network=none", IMAGE, "python", "-c",
        "import json,hashlib; from pathlib import Path; print(json.dumps({str(p.relative_to('/app')):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/app/src').rglob('*.py')}))"]))
    if any(state["source"].get(name) != sha for name, sha in image_sources.items()) or len(image_sources) != len(list((ROOT/"src").rglob("*.py"))):
        raise RuntimeError("candidate image does not contain the current source; rebuild before deployment")
    runtime_sha = run(["docker", "run", "--rm", "--network=none", IMAGE, "sha256sum", "/app/eval_runtime.py"]).split()[0]
    if runtime_sha != state["source"]["evals/multinode-runtime/runtime.py"]:
        raise RuntimeError("candidate image contains a different evaluation runtime")
    receipt_sha = run(["docker", "run", "--rm", "--network=none", IMAGE,
                       "sha256sum", "/app/receipt_mcp_server.py"]).split()[0]
    if receipt_sha != state["source"]["tests/fixtures/receipt_mcp_server.py"]:
        raise RuntimeError("candidate image contains a different receipt fixture")
    expected_proxy = yaml.safe_load((ROOT / "deploy/helm/agentops-guard/values.yaml").read_text())["gatewayProxy"]["image"]
    proxy_digests = json.loads(run(["docker", "image", "inspect", PROXY_IMAGE, "--format", "{{json .RepoDigests}}"] ))
    if "haproxy@" + expected_proxy.split("@")[1] not in proxy_digests:
        raise RuntimeError("local HAProxy image differs from the reviewed official digest")
    docker_config = directory / "docker-config"
    docker_config.mkdir(mode=0o700)
    save(docker_config / "config.json", {})
    environment = _safe_environment(DOCKER_CONFIG=str(docker_config))
    nodes = [{"role": "control-plane", "labels": {"eval-role": "control"},
              "extraPortMappings": [{"containerPort": 30081, "hostPort": port, "listenAddress": "127.0.0.1"}]}]
    if independent_admission:
        nodes[0]["extraPortMappings"].append({"containerPort": 30083,
            "hostPort": admission_port, "listenAddress": "127.0.0.1"})
    for profile in profiles[1:]:
        node = {"role": "worker", "labels": {"eval-role": profile["role"]}}
        if profile["role"] == "worker":
            node["extraMounts"] = [{"hostPath": str(ROOT / "models/semantic-guard"),
                                   "containerPath": "/reviewed-model", "readOnly": True}]
        nodes.append(node)
    config = directory / "kind.yaml"
    config.write_text(yaml.safe_dump({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": nodes}))
    print("setup=create_cluster", flush=True)
    run([KIND, "create", "cluster", "--name", cluster, "--image", KIND_NODE_IMAGE,
         "--config", config, "--kubeconfig", state["kubeconfig"], "--wait", "180s"],
        environment=environment, timeout=300)
    os.chmod(state["kubeconfig"], 0o600)
    node_names = run([KIND, "get", "nodes", "--name", cluster], environment=environment).splitlines()
    expected_nodes = [cluster + "-control-plane"] + [cluster + "-worker" + (str(i) if i > 1 else "")
        for i in range(1, len(profiles))]
    if set(node_names) != set(expected_nodes):
        raise RuntimeError("unexpected disposable node inventory")
    for node, profile in zip(expected_nodes, profiles, strict=True):
        command = ["docker", "update", "--cpus", profile["cpus"], "--memory", profile["memory"],
                   "--memory-swap", profile["memory"]]
        if "cpuset" in profile:
            command += ["--cpuset-cpus", profile["cpuset"]]
        run([*command, node])
    print("setup=load_images", flush=True)
    for image in (IMAGE, PATRONI_IMAGE, "redis:7", OPA_IMAGE, PROXY_IMAGE):
        # Export only this host's platform: cached multi-platform indices may
        # reference foreign architecture blobs that are intentionally absent.
        if image == OPA_IMAGE:
            run(["docker", "tag", OPA_IMAGE, "agentops-mn-opa:1.8.0"])
            image = "agentops-mn-opa:1.8.0"
        print("setup=image " + image, flush=True)
        archive = directory / (image.replace(":", "-") + "-amd64.tar")
        run(["docker", "image", "save", "--platform", "linux/amd64", "--output", archive, image], timeout=300)
        run([KIND, "load", "image-archive", "--name", cluster, archive], environment=environment, timeout=300)
    apply(state, [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": cluster}}])
    # Namespace deliberately permits the reviewed read-only model hostPath for
    # this local simulation. It is NOT production PSA/PVC acceptance evidence.
    password, replication = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
    pg_documents = _cluster_documents(cluster, superuser_password=password, replication_password=replication,
                                      timing_profile=timing_profile, failsafe_mode=failsafe)
    pg_documents = [doc for doc in pg_documents if doc["kind"] != "Pod"]
    for doc in pg_documents:
        if doc["kind"] == "StatefulSet":
            pod = doc["spec"]["template"]["spec"]
            pod["nodeSelector"] = {"eval-role": "database" if resource_profile == "isolated" else "worker"}
            pod["affinity"] = {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
                "topologyKey": "kubernetes.io/hostname", "labelSelector": {
                    "matchLabels": {"application": "patroni", "cluster-name": CLUSTER_NAME}}}]}}
    apply(state, pg_documents)
    kubectl(state, "rollout", "status", "statefulset/"+CLUSTER_NAME, "--timeout=240s", timeout=250)
    runtime_secret = {"AGENTOPS_DATABASE_URL": f"postgresql+psycopg://postgres:{password}@{CLUSTER_NAME}:5432/postgres",
        "AGENTOPS_REDIS_URL": "redis://redis:6379/0",
        "AGENTOPS_API_KEY": secrets.token_urlsafe(32), "AGENTOPS_OPERATOR_API_KEY": secrets.token_urlsafe(32),
        "AGENTOPS_SERVER_API_KEY": secrets.token_urlsafe(32)}
    apply(state, [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "agentops-guard-runtime"},
                   "stringData": runtime_secret}])
    if durable_queue:
        from cryptography.fernet import Fernet
        apply(state, [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "eval-invocation-key"},
            "stringData": {"AGENTOPS_INVOCATION_ENCRYPTION_KEY": Fernet.generate_key().decode()}}])
    driver_env = [{"name": "AGENTOPS_ENV", "value": "test"},
        {"name": "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", "value": "false"},
        {"name": "AGENTOPS_DATABASE_URL", "valueFrom": {"secretKeyRef": {"name": "agentops-guard-runtime", "key": "AGENTOPS_DATABASE_URL"}}}]
    apply(state, [deployment("eval-driver", IMAGE, ["sleep", "86400"], env=driver_env, control=True),
                  deployment("redis", "redis:7", ["redis-server", "--save", "", "--appendonly", "no"], port=6379, control=True),
                  service("redis", 6379)])
    wait_deployment(state, "eval-driver")
    kubectl(state, "exec", "deployment/eval-driver", "--", "alembic", "upgrade", "head")
    kubectl(state, "exec", "deployment/eval-driver", "--", "python", "-c",
            "from eval_runtime import tables; tables()")
    source = ROOT / "artifacts/datasets/boundary-pairs-a5682e7/test.jsonl"
    if digest(source) != "034523eefaec18c291f9daa7699037acb0e7a91b1aeb1b205878b124f6e18f10":
        raise RuntimeError("public attack corpus digest changed")
    attacks = [json.loads(line)["text"] for line in source.read_text().splitlines() if json.loads(line)["label"] == 1]
    apply(state, [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "eval-payloads"},
                   "data": {"payloads.json": json.dumps({"attacks": attacks})}}])
    upstream = deployment("upstream", IMAGE, ["python", "/app/eval_runtime.py", "upstream"],
                          replicas=2, env=driver_env, port=8091)
    spec = upstream["spec"]["template"]["spec"]
    spec["containers"][0]["readinessProbe"] = {
        "httpGet": {"path": "/readyz", "port": 8091}, "periodSeconds": 2,
        "timeoutSeconds": 2, "failureThreshold": 2}
    spec["volumes"] = [{"name": "payloads", "configMap": {"name": "eval-payloads"}}]
    spec["containers"][0]["volumeMounts"] = [{"name": "payloads", "mountPath": "/eval-data", "readOnly": True}]
    apply(state, [upstream, service("upstream", 8091)])
    if receipts:
        receipt_server = deployment("receipt-upstream", IMAGE,
            ["python", "/app/receipt_mcp_server.py", "--database", "/receipt-data/ledger.db",
             "--port", "8092", "--cluster-listen", "--payloads", "/eval-data/payloads.json"], port=8092)
        pod = receipt_server["spec"]["template"]["spec"]
        pod["securityContext"] = {"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001}
        pod["volumes"] = [{"name": "ledger", "emptyDir": {}},
                          {"name": "payloads", "configMap": {"name": "eval-payloads"}}]
        pod["containers"][0]["volumeMounts"] = [{"name": "ledger", "mountPath": "/receipt-data"},
            {"name": "payloads", "mountPath": "/eval-data", "readOnly": True}]
        apply(state, [receipt_server, service("receipt-upstream", 8092)])
    # Reuse the real reviewed signed OPA policy bundle, never unsigned test policies.
    runtime, _ = _build_signed_bundle(directory / "opa")
    import base64
    apply(state, [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "opa-bundle"},
                   "data": {p.name: base64.b64encode(p.read_bytes()).decode() for p in runtime.iterdir() if p.is_file()}}])
    values = {"image": {"repository": IMAGE.split(":")[0], "tag": IMAGE.split(":")[1], "pullPolicy": "Never"},
        "env": {"AGENTOPS_ENV": "test"}, "replicaCount": {"api": 2, "gateway": 3, "worker": 3 if durable_queue else 0,
            "outboxDispatcher": 2 if durable_queue else 0, "dashboard": 0, "semanticScanner": 3},
        "invocationEncryption": {"existingSecret": "eval-invocation-key" if durable_queue else ""},
        "gatewayConcurrency": {"backend": "redis", "maxPerServer": concurrency, "waitSeconds": 1},
        "gatewayCallTimeoutSeconds": 5,
        "gatewayProxy": {"enabled": True, "replicas": 1, "pullPolicy": "Never",
            "upstreams": [{"name": "upstream", "app": "upstream", "port": 8091, "healthPath": "/readyz"}]},
        "mcp": {"publicUrl": state["entrypoint"]+"/mcp", "allowedHosts": "127.0.0.1,127.0.0.1:*,localhost,localhost:*,agentops-guard-gateway,agentops-guard-gateway:*", "allowedOrigins": "http://localhost:3000"},
        "semanticScanner": {"mode": "shadow", "modelSha256": DEFAULT_MODEL_SHA256, "hostPath": "/reviewed-model", "timeoutSeconds": 2},
        "opa": {"enabled": True, "image": {"repository": "agentops-mn-opa", "tag": "1.8.0", "pullPolicy": "Never"},
            "bundle": {"enabled": True, "existingSecret": "opa-bundle", "verificationKeyId": SIGNING_KEY_ID,
                       "scope": SIGNING_SCOPE, "expectedPolicyRevision": "agentops-guard-v1"}}}
    rendered = run(["helm", "template", "agentops-guard", ROOT / "deploy/helm/agentops-guard",
                    "--namespace", state["namespace"], "-f", "-"],
                   input_text=yaml.safe_dump(values))
    documents = []
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc["kind"] == "Job":
            continue  # Migration already executed once, under the same lock.
        if doc["kind"] == "Deployment":
            name = doc["metadata"]["name"]
            if doc["spec"]["replicas"] == 0:
                continue
            pod = doc["spec"]["template"]["spec"]
            pod["nodeSelector"] = {"eval-role": "worker"}
            pod["affinity"] = spread(doc["spec"]["template"]["metadata"]["labels"]["app"])
            if name.endswith("-gateway-proxy"):
                pod["nodeSelector"] = {"eval-role": "control"}
                pod.pop("affinity", None)
                pod["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}]
                # kind's platform-only image archive has a different index digest.
                # The official pulled digest and actual runtime imageID are recorded.
                pod["containers"][0]["image"] = PROXY_IMAGE
            if name.endswith("-opa"):
                doc["spec"]["replicas"] = 2
            for container in pod["containers"]:
                if name.endswith("-gateway"):
                    container["command"] = ["python", "/app/eval_runtime.py", "gateway"]
                if name == "agentops-guard-worker":
                    container["command"] = ["python", "/app/eval_runtime.py", "worker"]
                if not name.endswith("-semantic-scanner"):
                    container.setdefault("env", []).append({"name": "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", "value": "false"})
                    container["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"},
                                              "limits": {"cpu": "1", "memory": "640Mi"}}
                if "readinessProbe" in container:
                    container["readinessProbe"].update(periodSeconds=2, timeoutSeconds=2, failureThreshold=2)
        if doc["kind"] == "Service" and doc["metadata"]["name"].endswith("-gateway-proxy"):
            doc["spec"]["type"] = "NodePort"
            doc["spec"]["ports"][0]["nodePort"] = 30081
        documents.append(doc)
    apply(state, documents)
    if receipts:
        reconciler = deployment("receipt-reconciler", IMAGE,
            ["python", "/app/eval_runtime.py", "receipt_worker"],
            env=[*driver_env, {"name": "AGENTOPS_COMPONENT", "value": "worker"},
                 {"name": "AGENTOPS_REDIS_URL", "valueFrom": {"secretKeyRef": {
                     "name": "agentops-guard-runtime", "key": "AGENTOPS_REDIS_URL"}}}])
        reconciler["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [
            {"configMapRef": {"name": "agentops-guard-config"}}]
        worker_document = next(doc for doc in documents if doc["kind"] == "Deployment"
                               and doc["metadata"]["name"] == "agentops-guard-worker") if durable_queue else None
        if worker_document:
            client_env = worker_document["spec"]["template"]["spec"]["containers"][0]["env"]
            reconciler["spec"]["template"]["spec"]["containers"][0]["env"] += [
                item for item in client_env if item["name"].startswith(("AGENTOPS_SEMANTIC_", "AGENTOPS_OPA_"))
                or item["name"] == "AGENTOPS_POLICY_FAIL_MODE"]
        # v2 returns a rescanned, encrypted result but still cannot dispatch jobs.
        if durable_queue:
            reconciler["spec"]["template"]["spec"]["containers"][0]["env"].append({
                "name": "AGENTOPS_INVOCATION_ENCRYPTION_KEY", "valueFrom": {"secretKeyRef": {
                    "name": "eval-invocation-key", "key": "AGENTOPS_INVOCATION_ENCRYPTION_KEY"}}})
        apply(state, [reconciler])
        wait_deployment(state, "receipt-upstream")
        wait_deployment(state, "receipt-reconciler")
    for name in ("upstream", "agentops-guard-gateway-proxy", "agentops-guard-opa", "agentops-guard-semantic-scanner", "agentops-guard-api", "agentops-guard-gateway"):
        print("setup=wait " + name, flush=True)
        wait_deployment(state, name)
    if durable_queue:
        for name in ("agentops-guard-worker", "agentops-guard-outbox-dispatcher"):
            wait_deployment(state, name)
    if independent_admission:
        from verify_multinode_admission import setup_admission
        setup_admission(state, directory)
    deadline = time.monotonic() + 15
    with httpx.Client(timeout=2, trust_env=False) as probe:
        while time.monotonic() < deadline:
            if probe.get(state["entrypoint"] + "/readyz").status_code == 200:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("proxy has no ready gateway; do not start capacity measurement")
    pods = json.loads(kubectl(state, "get", "pods", "-o", "json"))["items"]
    placements = [{"name": pod["metadata"]["name"], "node": pod["spec"]["nodeName"],
                   "labels": pod["metadata"]["labels"]} for pod in pods]
    for app in ("agentops-guard-gateway", "agentops-guard-semantic-scanner"):
        located = [p["node"] for p in placements if p["labels"].get("app") == app]
        if len(located) != 3 or len(set(located)) != 3:
            raise RuntimeError("replicas did not spread across three worker nodes")
    if frozen_inputs() != state["source"]:
        raise RuntimeError("source changed during deployment")
    save(directory / "setup.json", {"placements": placements,
        "image_id": run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"] ).strip(),
        "rendered_chart_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "proxy_image": json.loads(run(["docker", "image", "inspect", PROXY_IMAGE, "--format", "{{json .RepoDigests}}"])),
        "tool_timeout_seconds": 5, "outer_client_timeout_seconds": 10,
        "pod_resources_and_replica_placement_are_test_overlays": True,
        "production_scope": False, "api_authentication": "real_project_api_keys",
        "durable_queue_enabled": durable_queue,
        "gateway_concurrency": concurrency,
        "storage": "Patroni emptyDir; read-only reviewed model hostPath",
        "single_points": ["control-plane and NodePort entrance", "Redis", "physical WSL host"],
        "model_sha256": DEFAULT_MODEL_SHA256, "threshold": 0.9,
        "patroni_configuration": patroni_configuration(state)})
    print("setup=ready", flush=True)


def percentile(values, p):
    import math
    return round(sorted(values)[max(0, math.ceil(len(values)*p)-1)], 3)


def proxy_snapshot(state):
    pods = json.loads(kubectl(state, "get", "pods", "-l", "app=agentops-guard-gateway-proxy", "-o", "json"))["items"]
    pod = pods[0]["metadata"]["name"]
    raw = kubectl(state, "get", "--raw", f"/api/v1/namespaces/{state['namespace']}/pods/{pod}:8404/proxy/stats;csv", timeout=10)
    rows = list(csv.DictReader(io.StringIO(raw.removeprefix("# "))))
    return [{key: row[key] for key in ("pxname", "svname", "status", "check_status", "lastchg", "qcur", "scur", "lbtot", "addr")}
            for row in rows if row["svname"].startswith("replica") and not row["status"].startswith("MAINT")]


def response_error(status, body):
    """Allowlisted categories only, never persist upstream messages or details."""
    if status != 200:
        known = {"Database temporarily unavailable": "database_unavailable",
                 "Gateway capacity coordination unavailable": "capacity_store_unavailable",
                 "MCP server capacity exceeded": "capacity_exceeded"}
        detail = body.get("detail")
        if isinstance(detail, dict) and detail.get("code") == "post_tool_database_unavailable":
            return "post_tool_database_unavailable"
        return known.get(detail, "http_error") if isinstance(detail, str) else "http_error"
    error = body.get("upstreamError")
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        return "upstream_" + code if isinstance(code, str) and code in {"timeout", "http_error", "invalid_result"} else "upstream_error"
    return "tool_or_policy_error" if body.get("isError") else None


def tool_execution_outcome(body):
    detail = body.get("detail")
    if not isinstance(detail, dict) or detail.get("code") != "post_tool_database_unavailable":
        return None
    outcome = detail.get("tool_execution")
    if not isinstance(outcome, dict) or not isinstance(outcome.get("state"), str):
        return None
    if outcome["state"] not in {"response_received", "outcome_unknown"}:
        return None
    # Fixed state only: do not save upstream output or an arbitrary error body.
    return outcome["state"]


def runtime_events(state, phase, *, since=None):
    collected = []
    for app in ("upstream", "agentops-guard-gateway", "agentops-guard-worker"):
        pods = json.loads(kubectl(state, "get", "pods", "-l", "app=" + app, "-o", "json"))["items"]
        for pod in pods:
            log_options = ["--tail=-1", "--since-time=" + since] if since else ["--tail=10000"]
            raw = kubectl(state, "logs", pod["metadata"]["name"], *log_options)
            for line in raw.splitlines():
                if line.startswith("EVAL_EVENT "):
                    entry = json.loads(line.removeprefix("EVAL_EVENT "))
                    if re.fullmatch(re.escape(phase) + r":\d+", entry["id"]):
                        collected.append(entry)
    return collected


def proxy_transitions(state):
    raw = kubectl(state, "logs", "deployment/agentops-guard-gateway-proxy",
                  "--tail=10000", "--timestamps")
    rows = []
    for line in raw.splitlines():
        match = re.match(r"(\d{4}-\d{2}-\d{2}T[0-9:.]+Z) .*Server "
                         r"(gateway|semantic|opa|upstream)/(replica\d+) is (DOWN|UP),", line)
        if match:
            duration = re.search(r"check duration: (\d+)ms", line)
            rows.append({"timestamp": match[1], "backend": match[2], "replica": match[3],
                         "status": match[4], "check_ms": int(duration[1]) if duration else None})
    return rows  # Never store arbitrary health-check messages or response text.


def scoring_proxy_events(state, since):
    """Collect fixed proxy outcomes, not request text, URLs, headers or IDs."""
    rows = []
    pods = json.loads(kubectl(state, "get", "pods", "-l",
                             "app=agentops-guard-gateway-proxy", "-o", "json"))["items"]
    for pod in pods:
        raw = kubectl(state, "logs", pod["metadata"]["name"], "--timestamps",
                      "--tail=-1", "--since-time=" + since)
        for line in raw.splitlines():
            match = re.fullmatch(
                r"(\d{4}-\d{2}-\d{2}T[0-9:.]+Z) SCORING_PROXY status=(\d{3}) "
                r"termination=([A-Za-z-]{2}) queue_ms=(-?\d+) connect_ms=(-?\d+) "
                r"response_ms=(-?\d+) total_ms=(\d+)", line)
            if match:
                rows.append({"timestamp": match[1], "status": int(match[2]), "termination": match[3],
                             **{key: int(match[index]) for index, key in enumerate(
                                 ("queue_ms", "connect_ms", "response_ms", "total_ms"), start=4)}})
    return rows


def host_resource_snapshot():
    """Fixed aggregate counters only; never inspect processes, SQL or payloads."""
    pressure = {}
    for resource in ("cpu", "io", "memory"):
        entries = {}
        for line in (HOST_PROC / "pressure" / resource).read_text().splitlines():
            kind, *values = line.split()
            if kind not in {"some", "full"}:
                continue
            fields = dict(value.split("=", 1) for value in values)
            entries[kind] = {"total_us": int(fields["total"]), "avg10_percent": float(fields["avg10"])}
        pressure[resource] = entries
    wanted = {"pgmajfault", "pswpin", "pswpout", "nr_dirty", "nr_writeback"}
    vmstat = {key: int(value) for key, value in
              (line.split() for line in (HOST_PROC / "vmstat").read_text().splitlines()) if key in wanted}
    if set(vmstat) != wanted:
        raise ValueError("Required aggregate VM counters are absent")
    return {"available": True, "pressure": pressure, "vmstat": vmstat}


@asynccontextmanager
async def database_timeline(state, directory, name, database_target="business"):
    """A bounded control-node probe; failed probes stay visible in the evidence."""
    if database_target not in {"business", "admission"}:
        raise ValueError("Unknown controlled database target")
    probe_role = "admission_database_probe" if database_target == "admission" else "database_probe"
    stop = asyncio.Event()
    started, observations, host_observations = time.monotonic(), [], []

    async def monitor_host():
        while not stop.is_set():
            at = time.monotonic() - started
            try:
                value = await asyncio.to_thread(host_resource_snapshot)
            except (OSError, ValueError, KeyError) as error:
                value = {"available": False, "error_type": type(error).__name__}
            host_observations.append({"at": round(at, 3), **value,
                "finished_at": round(time.monotonic() - started, 3)})
            try:
                await asyncio.wait_for(stop.wait(), timeout=1)
            except TimeoutError:
                continue

    async def monitor():
        while not stop.is_set():
            at = time.monotonic() - started
            disk = asyncio.create_task(asyncio.to_thread(etcd_disk_metrics, state))
            try:
                raw = await asyncio.to_thread(kubectl, state, "exec", "-i", "deployment/eval-driver", "--",
                    "python", "/app/eval_runtime.py", probe_role, input_text="{}", timeout=10)
                value = json.loads(raw)
            except (RuntimeError, subprocess.TimeoutExpired, ValueError):
                value = {"probe_unavailable": True, "commit_confirmed": False}
            observations.append({"at": round(at, 3), **value})
            observations[-1]["finished_at"] = round(time.monotonic() - started, 3)
            observations[-1]["etcd_disk"] = await disk
            try:
                await asyncio.wait_for(stop.wait(), timeout=3)
            except TimeoutError:
                continue

    task = asyncio.create_task(monitor())
    host_task = asyncio.create_task(monitor_host())
    try:
        yield
    finally:
        stop.set()
        await asyncio.gather(task, host_task)
        save(directory / (name + "_database_timeline.json"), {
            "origin_monotonic": started, "probe_interval_seconds": 3,
            "independent_load_generator": False, "database_target": database_target, "observations": observations})
        save(directory / (name + "_host_timeline.json"), {
            "origin_monotonic": started, "probe_interval_seconds": 1,
            "scope": "WSL guest aggregate counters; not Windows physical disk telemetry",
            "counters_are_cumulative": True, "independent_load_generator": False,
            "observations": host_observations})


async def load_phase(state, directory, name, rps, seconds, fault):
    phase = "mn_" + uuid4().hex[:12]
    database_config = await asyncio.to_thread(patroni_configuration, state)
    save(directory/(name+"_started.json"), {"phase": phase, "target_rps": rps,
        "seconds": seconds, "fault": fault, "started_at": datetime.now(UTC).isoformat()})
    clock_before = await measure_clock()
    save(directory / (name+"_clock_before.json"), clock_before)
    if not clock_before["passed"]:
        raise RuntimeError("clock reference check failed; do not start a capacity phase")
    seed = await asyncio.to_thread(driver, state, "seed", {"phase": phase})
    rows, faults = [], []
    health = [{"at": 0, "servers": await asyncio.to_thread(proxy_snapshot, state)}]
    started = time.monotonic()
    wall_started = time.time()
    log_since = datetime.fromtimestamp(wall_started, UTC).isoformat().replace("+00:00", "Z")
    save(directory / (name+"_load_clock_origin.json"), {"monotonic": started, "wall": wall_started})
    total = int(seconds*rps)
    clock_during = asyncio.create_task(measure_clock(math.ceil((seconds + 10) / 10), 10))

    async def disrupt():
        if fault == "none":
            return
        await asyncio.sleep(seconds/3)
        async def observe():
            while time.monotonic() - started < seconds:
                requested_at = time.monotonic()-started
                snapshot = await asyncio.to_thread(proxy_snapshot, state)
                health.append({"at": time.monotonic()-started, "requested_at": requested_at,
                               "servers": snapshot})
                await asyncio.sleep(1)

        observation = asyncio.create_task(observe())
        if fault == "node":
            pods = json.loads(await asyncio.to_thread(kubectl, state, "get", "pods", "-l", "app=agentops-guard-gateway", "-o", "json"))["items"]
            node = sorted(pod["spec"]["nodeName"] for pod in pods)[0]
            label = (await asyncio.to_thread(run, ["docker", "inspect", node, "--format", '{{index .Config.Labels "io.x-k8s.kind.cluster"}}'])).strip()
            if label != state["cluster"]:
                raise RuntimeError("refusing to stop a node outside this test cluster")
            faults.append({"kind": "node_stop", "node": node, "at": time.monotonic()-started})
            save(directory/(name+"_fault.json"), faults[-1])
            await asyncio.to_thread(run, ["docker", "stop", "--time", "0", node])
            try:
                await asyncio.sleep(min(60, seconds/6))
            finally:
                await asyncio.to_thread(run, ["docker", "start", node])
                faults[-1]["restarted_at"] = time.monotonic()-started
        elif fault == "dcs":
            pods = json.loads(await asyncio.to_thread(kubectl, state, "get", "pods", "-l", "cluster-name=agentops-pg", "-o", "json"))["items"]
            leader = [p["metadata"]["name"] for p in pods if p["metadata"]["labels"].get("role") == "primary"]
            if len(leader) != 1:
                raise RuntimeError("could not identify exactly one Patroni leader")
            faults.append({"kind": "primary_dcs_only_disconnect", "pod": leader[0], "at": time.monotonic()-started})
            save(directory/(name+"_fault.json"), faults[-1])
            command = [str(KUBECTL), "--kubeconfig", state["kubeconfig"]]
            try:
                await asyncio.to_thread(_set_dcs_proxy_enabled, command, state["namespace"], leader[0], enabled=False)
                await asyncio.sleep(min(30, seconds/3))
            finally:
                await asyncio.to_thread(_set_dcs_proxy_enabled, command, state["namespace"], leader[0], enabled=True)
                faults[-1]["reconnected_at"] = time.monotonic()-started
        elif fault == "database":
            pods = json.loads(await asyncio.to_thread(kubectl, state, "get", "pods", "-l", "cluster-name=agentops-pg", "-o", "json"))["items"]
            leader = [p["metadata"]["name"] for p in pods if p["metadata"]["labels"].get("role") == "primary"]
            if len(leader) != 1:
                raise RuntimeError("could not identify exactly one Patroni leader")
            faults.append({"kind": "database_leader_delete", "at": time.monotonic()-started})
            save(directory/(name+"_fault.json"), faults[-1])
            await asyncio.to_thread(kubectl, state, "delete", "pod", leader[0], "--grace-period=0", "--force", "--wait=false")
        elif fault in {"network", "primary_network"}:
            # Isolate a worker's node network, not the host or user's networks.
            node = state["cluster"] + "-worker3"
            if fault == "primary_network":
                pods = json.loads(await asyncio.to_thread(kubectl, state, "get", "pods", "-l", "cluster-name=agentops-pg", "-o", "json"))["items"]
                leaders = [p for p in pods if p["metadata"]["labels"].get("role") == "primary"]
                if len(leaders) != 1:
                    raise RuntimeError("could not identify exactly one primary network target")
                node = leaders[0]["spec"]["nodeName"]
            info = json.loads(await asyncio.to_thread(run, ["docker", "inspect", node]))[0]
            if info["Config"]["Labels"].get("io.x-k8s.kind.cluster") != state["cluster"]:
                raise RuntimeError("network target is not a test node")
            address = info["NetworkSettings"]["Networks"]["kind"]["IPAddress"]
            faults.append({"kind": "worker_network_disconnect", "node": node,
                           "targets_current_primary": fault == "primary_network", "at": time.monotonic()-started})
            save(directory/(name+"_fault.json"), {**faults[-1], "network": "kind", "address": address})
            await asyncio.to_thread(run, ["docker", "network", "disconnect", "kind", node])
            try:
                await asyncio.sleep(min(30, seconds/6))
            finally:
                await asyncio.to_thread(run, ["docker", "network", "connect", "--ip", address, "kind", node])
                faults[-1]["reconnected_at"] = time.monotonic()-started
        print("fault=" + fault, flush=True)
        await observation

    async with database_timeline(state, directory, name), httpx.AsyncClient(timeout=10, trust_env=False, limits=httpx.Limits(max_connections=128)) as client:
        async def request(index, scheduled):
            variant = "write" if index % 100 == 99 else "attack" if index % 20 == 19 else "long" if index % 5 == 4 else "short"
            request_id = f"{phase}:{index}"
            invocation_id = str(uuid5(NAMESPACE_URL, "agentops-eval:" + request_id))
            arguments = {"request_id": request_id}
            if variant == "write":
                arguments.update(path="/controlled/probe.txt", content="controlled probe")
            else:
                arguments["variant"] = variant
            sent = time.monotonic()
            status, ok, decision = 0, False, None
            error, instance, execution_outcome = None, None, None
            try:
                response = await client.post(state["entrypoint"]+"/mcp/tools/call",
                    headers={"Authorization": "Bearer " + seed["token"], "X-Eval-Request": request_id},
                    json={"requestId": invocation_id, "serverId": seed["server_id"], "name": "write_file" if variant == "write" else "read_status", "arguments": arguments})
                status = response.status_code
                instance_value = response.headers.get("X-Eval-Instance", "")
                if re.fullmatch(r"agentops-guard-gateway-[a-z0-9-]+", instance_value):
                    instance = instance_value
                try:
                    body = response.json()
                except ValueError:
                    body = {}
                if not isinstance(body, dict):
                    body = {}
                error = response_error(status, body)
                execution_outcome = tool_execution_outcome(body)
                if status == 200:
                    policy = body.get("policyDecision") or {}
                    decision = policy.get("id")
                    if variant == "write":
                        ok = policy.get("action") in {"deny", "require_approval", "quarantine"}
                    elif variant == "attack":
                        # Quarantine is valid; a failed upstream call is not.
                        ok = bool(decision) and not body.get("upstreamError")
                    else:
                        ok = not body.get("isError", False)
            except httpx.TimeoutException:
                status = 0
                error = "client_timeout"
            except httpx.RemoteProtocolError:
                status = 0
                error = "client_connection_closed"
            except (httpx.TransportError, ValueError):
                status = 0
                error = "client_transport_or_decode_error"
            finished = time.monotonic()
            rows.append({"id": request_id, "variant": variant, "status": status, "ok": ok,
                "invocation_id": invocation_id,
                "decision": decision, "error": error, "instance": instance,
                "tool_execution_outcome": execution_outcome,
                "latency_ms": (finished-sent)*1000,
                "scheduled_latency_ms": (finished-scheduled)*1000,
                "schedule_delay_ms": (sent-scheduled)*1000, "at": finished-started})
        disruption = asyncio.create_task(disrupt())
        pending = []
        for index in range(total):
            scheduled = started+index/rps
            await asyncio.sleep(max(0, scheduled-time.monotonic()))
            pending.append(asyncio.create_task(request(index, scheduled)))
            if index and index % max(1,int(rps*60)) == 0:
                progress = {"phase": name, "sent": index, "completed": len(rows), "failed": sum(not row["ok"] for row in rows)}
                save(directory/f"{name}_progress_{index}.json", progress)
                print(json.dumps(progress), flush=True)
        await asyncio.gather(*pending, disruption)
    save(directory / (name+"_requests.json"), rows)
    save(directory / (name+"_proxy_health.json"), health)
    clock_report = {"before": clock_before, "during": await clock_during, "after": await measure_clock()}
    clock_report["passed"] = all(clock_report[key]["passed"] for key in ("before", "during", "after"))
    save(directory / (name+"_clock.json"), clock_report)
    # Give recovered services a bounded recovery period before reconciling the ledger.
    for deployment_name in ("agentops-guard-gateway", "upstream", "agentops-guard-semantic-scanner"):
        await asyncio.to_thread(wait_deployment, state, deployment_name)
    acknowledged = [row["id"] for row in rows if row["ok"] and row["variant"] != "write"]
    decisions = [row["decision"] for row in rows if row["decision"]]
    reconciliation = await asyncio.to_thread(driver, state, "stats", {"phase": phase,
        "acknowledged_reads": acknowledged, "decision_ids": decisions,
        "explicit_response_confirmations": [row["id"] for row in rows
            if row["tool_execution_outcome"] == "response_received"]})
    # A recovered receipt is additional evidence, never a rewritten success.
    from verify_multinode_invocations import query_statuses
    async with httpx.AsyncClient(timeout=5, trust_env=False) as query_client:
        recovery = await query_statuses(query_client, state, seed["token"], rows)
    save(directory / (name+"_recovered_invocations.json"), recovery)
    save(directory / (name+"_runtime_events.json"), await asyncio.to_thread(runtime_events, state, phase, since=log_since))
    proxy_scores = await asyncio.to_thread(scoring_proxy_events, state, log_since)
    save(directory / (name+"_scoring_proxy.json"), proxy_scores)
    save(directory / (name+"_proxy_transitions.json"), await asyncio.to_thread(proxy_transitions, state))
    if await asyncio.to_thread(patroni_configuration, state) != database_config:
        raise RuntimeError("Patroni configuration changed during measurement")
    failed = sum(not row["ok"] for row in rows)
    model_incomplete = (reconciliation["completed_scans"] != reconciliation["scan_attempts"]
        or reconciliation["scan_attempts"] < reconciliation["upstream_reads"])
    scheduling_p95 = percentile([row["schedule_delay_ms"] for row in rows], 0.95)
    latency_p95 = percentile([row["latency_ms"] for row in rows], 0.95)
    passed = (clock_report["passed"] and len(rows) == total and failed/total < 0.001 and not model_incomplete and scheduling_p95 <= 100
        and latency_p95 <= 1000
        and not reconciliation["semantic_error_events"] and not reconciliation["duplicate_executions"]
        and not reconciliation["unauthorized_writes"] and not reconciliation["missing_persisted_decisions"]
        and not reconciliation["acknowledged_missing_receipts"] and not reconciliation["executed_without_acknowledgement"]
        and reconciliation["audit_valid"] and all(row["decision"] for row in rows if row["status"] == 200))
    result = {"name": name, "scope": "single_host_kind_nodes_full_scanning_path",
        "node_count": state.get("node_count", 4), "resource_profile": state.get("resource_profile", "shared"),
        "production_sla_verified": False, "business_peak_rps": None, "phase": phase,
        "clock_validated": clock_report["passed"], "clock_report": name+"_clock.json",
        "target_rps": rps, "seconds": seconds, "attempted": len(rows), "failed": failed,
        "load_duration_seconds": round(max(row["at"] for row in rows),3),
        "completed_rps": round(len(rows)/max(row["at"] for row in rows),3),
        "arrival_schedule_delay_p95_ms": scheduling_p95,
        "latency_p95_gate_ms": 1000,
        "error_rate": failed/total, "passed": passed, "faults": faults,
        "status_counts": dict(Counter(str(row["status"]) for row in rows)),
        "mix": dict(Counter(row["variant"] for row in rows)),
        "latency_ms": {str(p): percentile([row["latency_ms"] for row in rows],p/100) for p in (50,95,99)},
        "scheduled_latency_ms": {str(p): percentile([row["scheduled_latency_ms"] for row in rows],p/100) for p in (95,99)},
        "max_scheduling_delay_ms": round(max(row["schedule_delay_ms"] for row in rows),3),
        "per_minute": [{"minute": minute, "requests": len(selected), "failed": sum(not row["ok"] for row in selected)}
            for minute in range(int(seconds/60)+1)
            if (selected := [row for row in rows if int(row["at"]/60) == minute])],
        "scoring_proxy_observation": {"rows": len(proxy_scores),
            "status_counts": dict(Counter(str(row["status"]) for row in proxy_scores)),
            "termination_counts": dict(Counter(row["termination"] for row in proxy_scores)),
            "limit": "phase-scoped fixed fields; excludes health probes; logs may be lost on pod restart or rotation"},
        "client_retries": 0, "reconciliation": reconciliation, "implementation_sha256": state["source"],
        "recovered_invocation_states": dict(Counter(item["state"] for item in recovery)),
        "patroni_configuration": database_config,
        "stores_raw_text_or_credentials": False, "complete_agent_evaluation": False,
        "limits": ["single WSL host and disk", "single control-plane, Redis and ingress node",
            "test-only scan receipt writes add latency", "fixed 1024-character model input bound retained",
            "legacy tools/call entry through real MCP upstream; not full protocol conformance",
            "API replicas deployed but tool load is on the gateway's existing direct database policy path"]}
    save(directory / (name+".json"), result)
    # Per-request evidence remains in the immutable report, not a multi-megabyte
    # progress line during a sustained run.
    print(json.dumps({**{key: result[key] for key in ("name", "attempted", "failed", "passed", "latency_ms")},
        "reconciliation": {key: value for key, value in reconciliation.items() if not isinstance(value, list)}}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("setup", "phase", "cleanup"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--name", default="phase")
    parser.add_argument("--rps", type=float, default=2)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--fault", choices=("none", "node", "database", "network", "primary_network", "dcs"), default="none")
    parser.add_argument("--resource-profile", choices=("shared", "isolated"), default="shared")
    parser.add_argument("--patroni-failsafe", action="store_true", help="setup only; opt-in DCS-outage comparison")
    parser.add_argument("--receipts", action="store_true", help="setup only; independent synthetic receipt server and query worker")
    parser.add_argument("--independent-admission", action="store_true", help="setup only; three separate admission DB nodes and live importers")
    parser.add_argument("--patroni-timing", choices=tuple(PATRONI_TIMING_PROFILES), default="conservative",
                        help="setup only; responsive is a measured test profile, not a production default")
    parser.add_argument("--durable-queue", action="store_true", help="setup only; enable reviewed test workers and encrypted admission")
    parser.add_argument("--concurrency", type=int, choices=(1, 2, 4), default=1,
                        help="setup only; controlled upstream ablation, not a production default")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if args.mode == "setup":
        setup(directory, args.patroni_timing, args.durable_queue, args.concurrency,
              args.resource_profile, args.patroni_failsafe, args.receipts, args.independent_admission)
        return
    state = json.loads((directory / "state.json").read_text())
    if not state["cluster"].startswith(PREFIX):
        raise ValueError("not a disposable multinode cluster")
    if args.mode == "cleanup":
        _delete_cluster(str(KIND), state["cluster"], _safe_environment(DOCKER_CONFIG=str(directory/"docker-config")))
        print("cleanup=completed")
        return
    if not (0 < args.rps <= 100 and 12 <= args.seconds <= 3600 and int(args.rps*args.seconds) >= 1) or not args.name.replace("_", "").isalnum():
        raise ValueError("invalid bounded load parameters")
    if (directory / (args.name+"_started.json")).exists():
        raise FileExistsError("phase was already started; preserve interrupted attempts and choose a new phase name")
    if frozen_inputs() != state["source"]:
        raise RuntimeError("source changed since deployment; rebuild and use a new test cluster")
    asyncio.run(load_phase(state, directory, args.name, args.rps, args.seconds, args.fault))


if __name__ == "__main__":
    main()
