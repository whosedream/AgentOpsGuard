from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml


CHART_PATH = Path("deploy/helm/agentops-guard")
LOCAL_HELM = Path(os.environ.get("TEMP", "")) / "helm-v3.18.4" / "windows-amd64" / "helm.exe"
CREDENTIAL_RENDER_ARGS = [
    "--set",
    "credentialEncryption.existingSecret=agentops-credential-test",
]
AUDIT_RENDER_ARGS = [
    "--set",
    "auditCheckpoints.backend=openbao",
    "--set",
    "credentialStore.openbaoUrl=https://openbao.internal",
    "--set",
    "credentialStore.openbaoExistingSecret=agentops-openbao-client",
    "--set",
    "credentialStore.openbaoAppRoleRoleId=api-role-id",
]
AUDIT_ANCHOR_RENDER_ARGS = [
    *AUDIT_RENDER_ARGS,
    "--set",
    "auditAnchorExporter.enabled=true",
    "--set",
    "auditAnchorExporter.serviceAccountName=agentops-audit-export",
    "--set",
    "auditAnchorExporter.databaseExistingSecret=agentops-audit-readonly-db",
    "--set",
    "auditAnchorExporter.openbaoExistingSecret=agentops-openbao-audit-readonly",
    "--set",
    "openbaoProxy.image.digest=sha256:" + "4" * 64,
    "--set",
    "auditAnchorExporter.bucket=agentops-audit-lock",
    "--set",
    "auditAnchorExporter.region=us-east-1",
    "--set",
    "auditAnchorExporter.expectedBucketOwner=123456789012",
]
TEST_IMAGE_DIGEST = "sha256:" + "1" * 64
TEST_DASHBOARD_IMAGE_DIGEST = "sha256:" + "2" * 64
TEST_OPA_IMAGE_DIGEST = "sha256:" + "3" * 64
TEST_OPENBAO_PROXY_IMAGE_DIGEST = "sha256:" + "4" * 64
TEST_IMAGE_SIGNATURE_GLOBS = {
    "ghcr.io/example/agentops-guard@sha256:*",
    "ghcr.io/example/agentops-guard-dashboard@sha256:*",
}
TEST_IMAGE_SIGNATURE_ISSUER = "https://token.actions.githubusercontent.com"
TEST_IMAGE_SIGNATURE_SUBJECT = (
    "https://github.com/example/agentops-guard/.github/workflows/supply-chain.yml@refs/heads/main"
)
IMAGE_SIGNATURE_RENDER_ARGS = [
    "--set-string",
    "imageVerification.trustRootRef=agentops-public-sigstore",
    "--set-string",
    "imageVerification.imageGlobs[0]=ghcr.io/example/agentops-guard@sha256:*",
    "--set-string",
    "imageVerification.imageGlobs[1]=ghcr.io/example/agentops-guard-dashboard@sha256:*",
    "--set-string",
    f"imageVerification.keyless.issuer={TEST_IMAGE_SIGNATURE_ISSUER}",
    "--set-string",
    f"imageVerification.keyless.subject={TEST_IMAGE_SIGNATURE_SUBJECT}",
]
TEST_EXTERNAL_EGRESS = {
    "api": ("10.20.1.0/24", 443),
    "gateway": ("10.20.2.0/24", 443),
    "worker": ("10.20.3.0/24", 5432),
    "outboxDispatcher": ("10.20.4.0/24", 6379),
    "auditAnchorExporter": ("10.20.5.0/24", 443),
    "migration": ("10.20.6.0/24", 5432),
}
TEST_INGRESS_NAMESPACE_SELECTOR = {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}
TEST_INGRESS_POD_SELECTOR = {"matchLabels": {"app.kubernetes.io/name": "ingress-nginx"}}
NETWORK_POLICY_RENDER_ARGS = [
    "--set-json",
    'networkPolicy.ingressController.namespaceSelector={"matchLabels":'
    '{"kubernetes.io/metadata.name":"ingress-nginx"}}',
    "--set-json",
    'networkPolicy.ingressController.podSelector={"matchLabels":'
    '{"app.kubernetes.io/name":"ingress-nginx"}}',
]
for _network_workload, (_network_cidr, _network_port) in TEST_EXTERNAL_EGRESS.items():
    NETWORK_POLICY_RENDER_ARGS.extend(
        [
            "--set-json",
            f"networkPolicy.externalEgress.{_network_workload}="
            f'[{{"to":[{{"ipBlock":{{"cidr":"{_network_cidr}"}}}}],'
            f'"ports":[{{"protocol":"TCP","port":{_network_port}}}]}}]',
        ]
    )
OPA_BUNDLE_RENDER_ARGS = [
    "--set",
    "opa.bundle.enabled=true",
    "--set",
    "opa.bundle.existingSecret=agentops-opa-policy",
    "--set-string",
    "opa.bundle.expectedPolicyRevision=agentops-guard-v1",
]
RUNTIME_SECRET_VARIABLES = {
    "AGENTOPS_DATABASE_URL",
    "AGENTOPS_REDIS_URL",
    "AGENTOPS_API_KEY",
    "AGENTOPS_OPERATOR_API_KEY",
    "AGENTOPS_SERVER_API_KEY",
}
EXPECTED_RUNTIME_SECRET_SCOPE = {
    "agentops-guard-api": {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_REDIS_URL",
        "AGENTOPS_API_KEY",
        "AGENTOPS_OPERATOR_API_KEY",
    },
    "agentops-guard-gateway": {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_API_KEY",
    },
    "agentops-guard-worker": {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_REDIS_URL",
    },
    "agentops-guard-outbox-dispatcher": {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_REDIS_URL",
    },
    "agentops-guard-dashboard": {"AGENTOPS_SERVER_API_KEY"},
    "agentops-guard-migration": {"AGENTOPS_DATABASE_URL"},
}
PRODUCTION_RUNTIME_SECRET_SCOPE = {
    **EXPECTED_RUNTIME_SECRET_SCOPE,
    "agentops-guard-gateway": {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_REDIS_URL",
        "AGENTOPS_API_KEY",
    },
}
AUDIT_ANCHOR_RUNTIME_SECRET_SCOPE = {
    **PRODUCTION_RUNTIME_SECRET_SCOPE,
    "agentops-guard-audit-anchor-exporter": {"AGENTOPS_DATABASE_URL"},
}


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _render(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def _assert_render_failure(command: list[str], expected_error: str) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    combined = f"{result.stdout}\n{result.stderr}"
    if result.returncode == 0 or expected_error not in combined:
        raise SystemExit(f"expected Helm render rejection containing: {expected_error}")


def _validate_credential_mount(rendered: str) -> None:
    workloads_with_key: set[str] = set()
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict) or document.get("kind") not in {
            "Deployment",
            "Job",
        }:
            continue
        pod_spec = document["spec"]["template"]["spec"]
        if any(
            variable.get("name") == "AGENTOPS_CREDENTIAL_ENCRYPTION_KEY"
            for container in pod_spec.get("containers", [])
            for variable in container.get("env", [])
        ):
            workloads_with_key.add(document["metadata"]["name"])
    if workloads_with_key != {"agentops-guard-api"}:
        raise SystemExit(
            f"credential key mounted into unexpected workloads: {sorted(workloads_with_key)}"
        )


def _validate_runtime_secret_scope(
    rendered: str,
    expected: dict[str, set[str]] = EXPECTED_RUNTIME_SECRET_SCOPE,
) -> None:
    actual: dict[str, set[str]] = {}
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict):
            continue
        if document.get("kind") == "Secret":
            raise SystemExit("chart must not render credential values into a Secret")
        if document.get("kind") not in {"Deployment", "Job"}:
            continue
        name = document["metadata"]["name"]
        pod_spec = document["spec"]["template"]["spec"]
        variables = {
            variable.get("name")
            for container in pod_spec.get("containers", [])
            for variable in container.get("env", [])
            if variable.get("name") in RUNTIME_SECRET_VARIABLES
        }
        if name in expected:
            actual[name] = variables
    if actual != expected:
        raise SystemExit(f"runtime secret scope mismatch: {actual}")


def _validate_audit_signer_render(
    rendered: str,
    expected_token_workloads: set[str] | None = None,
    expected_approle_workloads: set[str] | None = None,
    expected_proxy_workloads: set[str] | None = None,
) -> None:
    workloads_with_token: set[str] = set()
    workloads_with_approle: set[str] = set()
    workloads_with_proxy: set[str] = set()
    config: dict[str, str] = {}
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict):
            continue
        if (
            document.get("kind") == "ConfigMap"
            and document.get("metadata", {}).get("name") == "agentops-guard-config"
        ):
            config = document.get("data", {})
        if document.get("kind") not in {"Deployment", "Job"}:
            continue
        pod_spec = document["spec"]["template"]["spec"]
        environment = {
            variable.get("name"): variable
            for container in pod_spec.get("containers", [])
            for variable in container.get("env", [])
        }
        if "AGENTOPS_OPENBAO_TOKEN" in environment:
            workloads_with_token.add(document["metadata"]["name"])
        if environment.get("AGENTOPS_OPENBAO_AUTH_METHOD", {}).get("value") == "approle":
            name = document["metadata"]["name"]
            workloads_with_approle.add(name)
            if "AGENTOPS_OPENBAO_TOKEN" in environment:
                raise SystemExit(f"AppRole workload also received a static token: {name}")
            secret_path = environment.get("AGENTOPS_OPENBAO_APPROLE_SECRET_ID_FILE", {}).get(
                "value"
            )
            mounted = any(
                mount.get("name") == "openbao-approle-secret-id" and mount.get("readOnly") is True
                for container in pod_spec.get("containers", [])
                for mount in container.get("volumeMounts", [])
            )
            secret_volume = next(
                (
                    volume.get("secret")
                    for volume in pod_spec.get("volumes", [])
                    if volume.get("name") == "openbao-approle-secret-id"
                ),
                None,
            )
            secret_items = (secret_volume or {}).get("items", [])
            secret_file_is_readable = (secret_volume or {}).get("defaultMode") == 0o440 and any(
                item.get("path") == "secret-id" for item in secret_items
            )
            if (
                secret_path != "/var/run/secrets/agentops/openbao/secret-id"
                or not mounted
                or not secret_file_is_readable
            ):
                raise SystemExit(f"AppRole SecretID file mount is incomplete: {name}")
        if environment.get("AGENTOPS_OPENBAO_AUTH_METHOD", {}).get("value") == "proxy":
            name = document["metadata"]["name"]
            workloads_with_proxy.add(name)
            direct_credentials = {
                "AGENTOPS_OPENBAO_TOKEN",
                "AGENTOPS_OPENBAO_APPROLE_ROLE_ID",
                "AGENTOPS_OPENBAO_APPROLE_SECRET_ID_FILE",
            }
            if direct_credentials.intersection(environment):
                raise SystemExit(f"OpenBao Proxy application received direct credentials: {name}")
            app_containers = [
                container
                for container in pod_spec.get("containers", [])
                if container.get("name") != "openbao-proxy"
            ]
            proxy_containers = [
                container
                for container in pod_spec.get("containers", [])
                if container.get("name") == "openbao-proxy"
            ]
            app_mounts = {
                mount.get("name")
                for container in app_containers
                for mount in container.get("volumeMounts", [])
            }
            proxy_mounts = {
                mount.get("name"): mount
                for container in proxy_containers
                for mount in container.get("volumeMounts", [])
            }
            identity_volume = next(
                (
                    volume.get("secret")
                    for volume in pod_spec.get("volumes", [])
                    if volume.get("name") == "openbao-proxy-identity"
                ),
                None,
            )
            identity_paths = {item.get("path") for item in (identity_volume or {}).get("items", [])}
            if (
                len(proxy_containers) != 1
                or "openbao-proxy-identity" in app_mounts
                or proxy_mounts.get("openbao-proxy-identity", {}).get("readOnly") is not True
                or (identity_volume or {}).get("defaultMode") != 0o440
                or identity_paths != {"role-id", "wrapped-secret-id"}
            ):
                raise SystemExit(f"OpenBao Proxy identity isolation is incomplete: {name}")
    expected_tokens = (
        {"agentops-guard-api"} if expected_token_workloads is None else expected_token_workloads
    )
    if workloads_with_token != expected_tokens:
        raise SystemExit(f"OpenBao token scope mismatch: {sorted(workloads_with_token)}")
    expected_approles = expected_approle_workloads or set()
    if workloads_with_approle != expected_approles:
        raise SystemExit(f"OpenBao AppRole scope mismatch: {sorted(workloads_with_approle)}")
    expected_proxies = expected_proxy_workloads or set()
    if workloads_with_proxy != expected_proxies:
        raise SystemExit(f"OpenBao Proxy scope mismatch: {sorted(workloads_with_proxy)}")
    if config.get("AGENTOPS_AUDIT_CHECKPOINT_BACKEND") != "openbao":
        raise SystemExit("audit checkpoint backend was not rendered")
    if config.get("AGENTOPS_OPENBAO_TRANSIT_MOUNT") != "transit":
        raise SystemExit("OpenBao Transit mount was not rendered")
    if config.get("AGENTOPS_AUDIT_CHECKPOINT_KEY_NAME") != "agentops-audit":
        raise SystemExit("audit checkpoint key name was not rendered")


def _validate_audit_anchor_exporter(rendered: str) -> None:
    exporter: dict | None = None
    for document in yaml.safe_load_all(rendered):
        if (
            isinstance(document, dict)
            and document.get("kind") == "Deployment"
            and document.get("metadata", {}).get("name") == "agentops-guard-audit-anchor-exporter"
        ):
            exporter = document
            break
    if exporter is None:
        raise SystemExit("audit anchor exporter was not rendered")
    pod_spec = exporter["spec"]["template"]["spec"]
    if pod_spec.get("serviceAccountName") != "agentops-audit-export":
        raise SystemExit("audit anchor exporter workload identity is missing")
    container = pod_spec["containers"][0]
    environment = {item["name"]: item for item in container.get("env", [])}
    expected_values = {
        "AGENTOPS_COMPONENT": "audit_anchor_exporter",
        "AGENTOPS_AUDIT_CHECKPOINT_BACKEND": "openbao",
        "AGENTOPS_AUDIT_ANCHOR_BACKEND": "s3_object_lock",
        "AGENTOPS_AUDIT_ANCHOR_S3_BUCKET": "agentops-audit-lock",
        "AGENTOPS_AUDIT_ANCHOR_S3_EXPECTED_BUCKET_OWNER": "123456789012",
    }
    if any(
        environment.get(name, {}).get("value") != value for name, value in expected_values.items()
    ):
        raise SystemExit("audit anchor exporter configuration is incomplete")
    if any(name.startswith("AWS_") and "KEY" in name for name in environment):
        raise SystemExit("audit anchor exporter must use workload identity, not static AWS keys")
    secret_names = {
        name: item.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
        for name, item in environment.items()
        if "valueFrom" in item
    }
    if secret_names.get("AGENTOPS_DATABASE_URL") != "agentops-audit-readonly-db":
        raise SystemExit("audit anchor exporter does not use its read-only database secret")
    secret_volumes = {
        volume.get("name"): (volume.get("secret") or {}).get("secretName")
        for volume in pod_spec.get("volumes", [])
    }
    if secret_volumes.get("openbao-proxy-identity") != "agentops-openbao-audit-readonly":
        raise SystemExit("audit anchor exporter does not use its OpenBao Proxy identity files")


def _validate_workload_security(rendered: str) -> None:
    checked = 0
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict) or document.get("kind") not in {
            "Deployment",
            "Job",
        }:
            continue
        checked += 1
        name = document["metadata"]["name"]
        pod_spec = document["spec"]["template"]["spec"]
        if not pod_spec.get("serviceAccountName"):
            raise SystemExit(f"workload does not use a dedicated ServiceAccount: {name}")
        if pod_spec.get("automountServiceAccountToken") is not False:
            raise SystemExit(f"workload automatically mounts a Kubernetes API token: {name}")
        pod_security = pod_spec.get("securityContext", {})
        if pod_security.get("runAsNonRoot") is not True:
            raise SystemExit(f"workload does not require non-root execution: {name}")
        if (pod_security.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
            raise SystemExit(f"workload does not use the runtime seccomp profile: {name}")
        if pod_security.get("fsGroup") != 10001:
            raise SystemExit(f"workload does not use the restricted volume group: {name}")
        for container in pod_spec.get("containers", []):
            security = container.get("securityContext", {})
            mounts = container.get("volumeMounts", [])
            if (
                security.get("allowPrivilegeEscalation") is not False
                or security.get("readOnlyRootFilesystem") is not True
                or "ALL" not in (security.get("capabilities", {}).get("drop") or [])
                or not any(mount.get("mountPath") == "/tmp" for mount in mounts)
            ):
                raise SystemExit(f"container security context is incomplete: {name}")
    if not checked:
        raise SystemExit("no workloads were rendered for security validation")


def _validate_service_accounts(rendered: str) -> None:
    documents = [
        document for document in yaml.safe_load_all(rendered) if isinstance(document, dict)
    ]
    accounts = {
        document.get("metadata", {}).get("name"): document
        for document in documents
        if document.get("kind") == "ServiceAccount"
    }
    expected = {
        "agentops-guard-api",
        "agentops-guard-dashboard",
        "agentops-guard-gateway",
        "agentops-guard-migration",
        "agentops-guard-opa",
        "agentops-guard-outbox-dispatcher",
        "agentops-guard-semantic-scanner",
        "agentops-guard-worker",
    }
    forbidden = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
    rendered_rbac = {document.get("kind") for document in documents}.intersection(forbidden)
    if rendered_rbac:
        raise SystemExit(
            f"application chart rendered unexpected Kubernetes API access: {rendered_rbac}"
        )
    if set(accounts) != expected:
        raise SystemExit(f"dedicated ServiceAccount set mismatch: {sorted(accounts)}")
    if any(
        account.get("automountServiceAccountToken") is not False for account in accounts.values()
    ):
        raise SystemExit("a dedicated ServiceAccount automatically mounts Kubernetes API tokens")


def _validate_opa_network_policy(rendered: str) -> None:
    policy = next(
        (
            document
            for document in yaml.safe_load_all(rendered)
            if isinstance(document, dict)
            and document.get("kind") == "NetworkPolicy"
            and document.get("metadata", {}).get("name") == "agentops-guard-opa"
        ),
        None,
    )
    if policy is None:
        raise SystemExit("enabled OPA is missing its NetworkPolicy")
    spec = policy["spec"]
    if set(spec.get("policyTypes") or []) != {"Ingress", "Egress"} or spec.get("egress") != []:
        raise SystemExit("OPA NetworkPolicy must deny all egress")
    ingress = spec.get("ingress") or []
    if len(ingress) != 1 or ingress[0].get("ports") != [{"protocol": "TCP", "port": 8181}]:
        raise SystemExit("OPA NetworkPolicy exposes an unexpected port")
    allowed = {
        entry.get("podSelector", {}).get("matchLabels", {}).get("app")
        for entry in ingress[0].get("from") or []
    }
    if allowed != {
        "agentops-guard-api",
        "agentops-guard-gateway",
        "agentops-guard-worker",
    }:
        raise SystemExit("OPA NetworkPolicy allows an unexpected caller")


def _validate_opa_signed_bundle(rendered: str) -> None:
    documents = [
        document for document in yaml.safe_load_all(rendered) if isinstance(document, dict)
    ]
    if any(
        document.get("kind") == "ConfigMap"
        and document.get("metadata", {}).get("name") == "agentops-guard-opa-policy"
        for document in documents
    ):
        raise SystemExit("production OPA rendered unsigned policy files")
    deployment = next(
        (
            document
            for document in documents
            if document.get("kind") == "Deployment"
            and document.get("metadata", {}).get("name") == "agentops-guard-opa"
        ),
        None,
    )
    if deployment is None:
        raise SystemExit("production OPA deployment is missing")
    pod_spec = deployment["spec"]["template"]["spec"]
    opa = next(container for container in pod_spec["containers"] if container["name"] == "opa")
    ordered_args = opa.get("args") or []
    args = set(ordered_args)
    required_args = {
        "--disable-telemetry",
        "--bundle",
        "--verification-key=/policy/public.pem",
        "--verification-key-id=agentops-policy-v1",
        "--scope=agentops.guard",
    }
    bundle_position = ordered_args.index("--bundle") if "--bundle" in args else -1
    if (not required_args.issubset(args) or bundle_position < 0
            or ordered_args[bundle_position + 1:bundle_position + 2] != ["/policy/bundle.tar.gz"]):
        raise SystemExit("production OPA is missing signed bundle verification arguments")
    policy = next(volume for volume in pod_spec["volumes"] if volume["name"] == "policy")
    secret = policy.get("secret") or {}
    if secret.get("secretName") != "agentops-opa-policy":
        raise SystemExit("production OPA does not use the expected signed bundle Secret")
    mounted_items = {item.get("key"): item.get("path") for item in secret.get("items") or []}
    if mounted_items != {
        "bundle.tar.gz": "bundle.tar.gz",
        "public.pem": "public.pem",
    }:
        raise SystemExit("production OPA must mount only the signed bundle and public key")
    if opa.get("env"):
        raise SystemExit(
            "production OPA must not receive policy material through environment values"
        )
    for deployment_name in (
        "agentops-guard-api",
        "agentops-guard-gateway",
        "agentops-guard-worker",
    ):
        workload = next(
            document
            for document in documents
            if document.get("kind") == "Deployment"
            and document.get("metadata", {}).get("name") == deployment_name
        )
        application = next(
            container
            for container in workload["spec"]["template"]["spec"]["containers"]
            if container["name"] == deployment_name.removeprefix("agentops-guard-")
        )
        environment = {item["name"]: item.get("value") for item in application.get("env") or []}
        if environment.get("AGENTOPS_OPA_EXPECTED_POLICY_REVISION") != "agentops-guard-v1":
            raise SystemExit("policy clients do not pin the approved OPA policy revision")


def _validate_production_image_digests(rendered: str) -> None:
    expected_app = f"agentops-guard@{TEST_IMAGE_DIGEST}"
    expected_dashboard = f"agentops-guard-dashboard@{TEST_DASHBOARD_IMAGE_DIGEST}"
    expected_opa = f"openpolicyagent/opa@{TEST_OPA_IMAGE_DIGEST}"
    expected_openbao_proxy = f"ghcr.io/openbao/openbao@{TEST_OPENBAO_PROXY_IMAGE_DIGEST}"
    images: dict[str, list[str]] = {}
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict) or document.get("kind") not in {
            "Deployment",
            "Job",
        }:
            continue
        name = document["metadata"]["name"]
        images[name] = [
            str(container.get("image", ""))
            for container in document["spec"]["template"]["spec"].get("containers", [])
        ]
    if not images:
        raise SystemExit("production workload image is not digest-pinned: no workloads")
    for name, workload_images in images.items():
        expected = {
            "agentops-guard-dashboard": expected_dashboard,
            "agentops-guard-opa": expected_opa,
        }.get(name, expected_app)
        expected_images = [expected]
        if any(image.startswith("ghcr.io/openbao/openbao") for image in workload_images):
            expected_images.append(expected_openbao_proxy)
        if sorted(workload_images) != sorted(expected_images):
            raise SystemExit(f"production workload image is not digest-pinned: {images}")


def _validate_image_signature_policy(rendered: str) -> None:
    policies = [
        document
        for document in yaml.safe_load_all(rendered)
        if isinstance(document, dict) and document.get("kind") == "ClusterImagePolicy"
    ]
    if len(policies) != 1:
        raise SystemExit("production render must contain exactly one ClusterImagePolicy")
    policy = policies[0]
    if policy.get("apiVersion") != "policy.sigstore.dev/v1beta1":
        raise SystemExit("production image policy uses an unexpected API version")
    spec = policy.get("spec") or {}
    if spec.get("mode") != "enforce":
        raise SystemExit("production image signature policy must enforce rejection")
    actual_globs = {
        entry.get("glob") for entry in spec.get("images") or [] if isinstance(entry, dict)
    }
    if actual_globs != TEST_IMAGE_SIGNATURE_GLOBS:
        raise SystemExit(f"production image signature scope mismatch: {sorted(actual_globs)}")
    authorities = spec.get("authorities") or []
    if len(authorities) != 1:
        raise SystemExit("production image policy must have one approved authority")
    authority = authorities[0]
    keyless = authority.get("keyless") or {}
    identities = keyless.get("identities") or []
    expected_identity = {
        "issuer": TEST_IMAGE_SIGNATURE_ISSUER,
        "subject": TEST_IMAGE_SIGNATURE_SUBJECT,
    }
    if (
        authority.get("name") != "approved-keyless-builder"
        or keyless.get("url") != "https://fulcio.sigstore.dev"
        or keyless.get("trustRootRef") != "agentops-public-sigstore"
        or identities != [expected_identity]
        or authority.get("ctlog")
        != {
            "url": "https://rekor.sigstore.dev",
            "trustRootRef": "agentops-public-sigstore",
        }
    ):
        raise SystemExit("production image policy does not bind the approved keyless signer")
    if any(key in identity for identity in identities for key in ("issuerRegExp", "subjectRegExp")):
        raise SystemExit("production image policy must not use wildcard signing identities")


def _validate_network_isolation(rendered: str, *, opa_enabled: bool = False) -> None:
    documents = [
        document for document in yaml.safe_load_all(rendered) if isinstance(document, dict)
    ]
    policies_list = [document for document in documents if document.get("kind") == "NetworkPolicy"]
    policies = {document["metadata"]["name"]: document for document in policies_list}
    if len(policies) != len(policies_list):
        raise SystemExit("production render contains duplicate NetworkPolicy names")

    required = {
        "agentops-guard-default-deny",
        "agentops-guard-gateway-ingress",
        "agentops-guard-dashboard-ingress",
        "agentops-guard-api-ingress",
        "agentops-guard-dns-egress",
        "agentops-guard-dashboard-egress",
        "agentops-guard-gateway-internal-egress",
    }
    missing = required.difference(policies)
    if missing:
        raise SystemExit(f"production network isolation policies are missing: {sorted(missing)}")

    default_deny = policies["agentops-guard-default-deny"]["spec"]
    if (
        default_deny.get("podSelector") != {}
        or set(default_deny.get("policyTypes") or []) != {"Ingress", "Egress"}
        or default_deny.get("ingress") != []
        or default_deny.get("egress") != []
    ):
        raise SystemExit("production namespace does not default-deny ingress and egress")

    expected_ingress_source = [
        {
            "namespaceSelector": TEST_INGRESS_NAMESPACE_SELECTOR,
            "podSelector": TEST_INGRESS_POD_SELECTOR,
        }
    ]
    for workload, port in (("gateway", 8001), ("dashboard", 3000)):
        public = policies[f"agentops-guard-{workload}-ingress"]["spec"]
        public_rules = public.get("ingress") or []
        if (
            public.get("podSelector") != {"matchLabels": {"app": f"agentops-guard-{workload}"}}
            or len(public_rules) != 1
            or public_rules[0].get("from") != expected_ingress_source
            or public_rules[0].get("ports") != [{"protocol": "TCP", "port": port}]
        ):
            raise SystemExit(
                f"{workload} ingress is not limited to the reviewed controller and port"
            )

    api = policies["agentops-guard-api-ingress"]["spec"]
    api_rule = (api.get("ingress") or [None])[0] or {}
    api_sources = {
        peer.get("podSelector", {}).get("matchLabels", {}).get("app")
        for peer in api_rule.get("from") or []
    }
    if (
        api.get("podSelector") != {"matchLabels": {"app": "agentops-guard-api"}}
        or api_sources != {"agentops-guard-dashboard", "agentops-guard-gateway"}
        or api_rule.get("ports") != [{"protocol": "TCP", "port": 8000}]
    ):
        raise SystemExit("API ingress is not limited to Dashboard and Gateway")

    dns = policies["agentops-guard-dns-egress"]["spec"]
    dns_apps = set(dns["podSelector"]["matchExpressions"][0].get("values") or [])
    expected_dns_apps = {
        "agentops-guard-api",
        "agentops-guard-audit-anchor-exporter",
        "agentops-guard-dashboard",
        "agentops-guard-gateway",
        "agentops-guard-migration",
        "agentops-guard-outbox-dispatcher",
        "agentops-guard-worker",
    }
    dns_rule = (dns.get("egress") or [None])[0] or {}
    dns_ports = {
        (entry.get("protocol"), entry.get("port")) for entry in dns_rule.get("ports") or []
    }
    if (
        dns_apps != expected_dns_apps
        or dns_rule.get("to")
        != [
            {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                },
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }
        ]
        or dns_ports != {("UDP", 53), ("TCP", 53)}
    ):
        raise SystemExit("DNS egress is not limited to the reviewed cluster DNS selectors")

    dashboard = policies["agentops-guard-dashboard-egress"]["spec"]
    if dashboard.get("egress") != [
        {
            "to": [{"podSelector": {"matchLabels": {"app": "agentops-guard-api"}}}],
            "ports": [{"protocol": "TCP", "port": 8000}],
        }
    ]:
        raise SystemExit("Dashboard egress is not limited to the API")

    gateway = policies["agentops-guard-gateway-internal-egress"]["spec"]
    gateway_destinations = {
        (
            rule["to"][0]["podSelector"]["matchLabels"]["app"],
            rule["ports"][0]["port"],
        )
        for rule in gateway.get("egress") or []
    }
    expected_gateway_destinations = {("agentops-guard-api", 8000)}
    if opa_enabled:
        expected_gateway_destinations.add(("agentops-guard-opa", 8181))
    if gateway_destinations != expected_gateway_destinations:
        raise SystemExit("Gateway internal egress scope is unexpected")

    policy_names = {
        "api": "api",
        "gateway": "gateway",
        "worker": "worker",
        "outboxDispatcher": "outbox-dispatcher",
        "auditAnchorExporter": "audit-anchor-exporter",
        "migration": "migration",
    }
    app_names = {
        "api": "agentops-guard-api",
        "gateway": "agentops-guard-gateway",
        "worker": "agentops-guard-worker",
        "outboxDispatcher": "agentops-guard-outbox-dispatcher",
        "auditAnchorExporter": "agentops-guard-audit-anchor-exporter",
        "migration": "agentops-guard-migration",
    }
    for workload, (cidr, port) in TEST_EXTERNAL_EGRESS.items():
        name = f"agentops-guard-{policy_names[workload]}-external-egress"
        policy = policies.get(name, {}).get("spec")
        expected = [
            {
                "to": [{"ipBlock": {"cidr": cidr}}],
                "ports": [{"protocol": "TCP", "port": port}],
            }
        ]
        if (
            policy is None
            or policy.get("podSelector") != {"matchLabels": {"app": app_names[workload]}}
            or policy.get("egress") != expected
        ):
            raise SystemExit(f"external egress scope mismatch for {workload}")

    pod_apps: set[str] = set()
    for document in documents:
        if document.get("kind") not in {"Deployment", "Job"}:
            continue
        app = (
            document.get("spec", {})
            .get("template", {})
            .get("metadata", {})
            .get("labels", {})
            .get("app")
        )
        if not app:
            raise SystemExit(
                f"workload lacks the app label required by NetworkPolicy: "
                f"{document.get('metadata', {}).get('name')}"
            )
        pod_apps.add(app)
    if "agentops-guard-migration" not in pod_apps:
        raise SystemExit("migration workload is not selected by its egress policy")


def _production_render_args(
    helm: str,
    image_digest: str | None = TEST_IMAGE_DIGEST,
    dashboard_image_digest: str | None = TEST_DASHBOARD_IMAGE_DIGEST,
) -> list[str]:
    command = [
        helm,
        "template",
        "agentops-guard",
        str(CHART_PATH),
        "-f",
        str(CHART_PATH / "values.yaml"),
        "-f",
        str(CHART_PATH / "values.prod.yaml"),
        *CREDENTIAL_RENDER_ARGS,
        *IMAGE_SIGNATURE_RENDER_ARGS,
        *NETWORK_POLICY_RENDER_ARGS,
    ]
    if image_digest is not None:
        command.extend(["--set", f"image.digest={image_digest}"])
    if dashboard_image_digest is not None:
        command.extend(["--set", f"dashboardImage.digest={dashboard_image_digest}"])
    return command


def _validate_signature_render_failures(helm: str) -> None:
    _assert_render_failure(
        [*_production_render_args(helm), "--set", "imageVerification.enabled=false"],
        "imageVerification.enabled is required",
    )
    _assert_render_failure(
        [*_production_render_args(helm), "--set-string", "imageVerification.keyless.subject="],
        "imageVerification.keyless.subject is required",
    )
    _assert_render_failure(
        [*_production_render_args(helm), "--set-string", "imageVerification.trustRootRef="],
        "imageVerification.trustRootRef is required",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-string",
            "imageVerification.keyless.subject=https://github.com/example/*",
        ],
        "imageVerification.keyless.subject must be an exact non-wildcard signing identity",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-string",
            "imageVerification.imageGlobs[0]=**",
        ],
        "identify one repository",
    )
    _assert_render_failure(
        [*_production_render_args(helm), "--set", "imageVerification.mode=warn"],
        "imageVerification.mode must be enforce when image signatures are required",
    )


def _validate_network_policy_render_failures(helm: str) -> None:
    _assert_render_failure(
        [*_production_render_args(helm), "--set", "networkPolicy.enabled=false"],
        "networkPolicy.enabled is required",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-json",
            "networkPolicy.externalEgress.api=[]",
        ],
        "networkPolicy.externalEgress.api must explicitly declare",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-json",
            "networkPolicy.ingressController.podSelector={}",
        ],
        "networkPolicy.ingressController.podSelector is required",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-json",
            'networkPolicy.ingressController.podSelector={"matchLabels":{}}',
        ],
        "podSelector must use at least one exact matchLabel",
    )
    _assert_render_failure(
        [
            *_production_render_args(helm),
            "--set-json",
            'networkPolicy.externalEgress.api=[{"to":[{"ipBlock":'
            '{"cidr":"0.0.0.0/0"}}],"ports":[{"protocol":"TCP","port":443}]}]',
        ],
        "must not allow an all-address CIDR",
    )


def _validate_service_account_render_failures(helm: str) -> None:
    _assert_render_failure(
        [*_production_render_args(helm), "--set-string", "serviceAccounts.api="],
        "all serviceAccounts names are required",
    )


def main() -> int:
    helm = shutil.which("helm")
    if helm:
        _run([helm, "lint", str(CHART_PATH)])
        rendered = _render(
            [
                helm,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        _validate_runtime_secret_scope(rendered)
        _validate_workload_security(rendered)
        _validate_service_accounts(rendered)
        production = _render(_production_render_args(helm))
        _validate_credential_mount(production)
        _validate_runtime_secret_scope(production, PRODUCTION_RUNTIME_SECRET_SCOPE)
        _validate_production_image_digests(production)
        _validate_image_signature_policy(production)
        _validate_network_isolation(production)
        _validate_workload_security(production)
        _validate_service_accounts(production)
        _validate_signature_render_failures(helm)
        _validate_network_policy_render_failures(helm)
        _validate_service_account_render_failures(helm)
        _assert_render_failure(
            _production_render_args(helm, None),
            "image.digest is required",
        )
        _assert_render_failure(
            _production_render_args(helm, "sha256:invalid"),
            "image.digest must be sha256",
        )
        _assert_render_failure(
            _production_render_args(helm, dashboard_image_digest=None),
            "dashboardImage.digest is required",
        )
        _assert_render_failure(
            [*_production_render_args(helm), "--set", "opa.enabled=true"],
            "opa.bundle.enabled is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm),
                "--set",
                "opa.enabled=true",
                *OPA_BUNDLE_RENDER_ARGS,
            ],
            "opa.image.digest is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm),
                "--set",
                "opa.enabled=true",
                "--set",
                f"opa.image.digest={TEST_OPA_IMAGE_DIGEST}",
                "--set",
                "opa.bundle.enabled=true",
                "--set",
                "opa.bundle.existingSecret=agentops-opa-policy",
            ],
            "opa.bundle.expectedPolicyRevision is required",
        )
        production_with_opa = _render(
            [
                *_production_render_args(helm),
                "--set",
                "opa.enabled=true",
                "--set",
                f"opa.image.digest={TEST_OPA_IMAGE_DIGEST}",
                *OPA_BUNDLE_RENDER_ARGS,
            ]
        )
        _validate_production_image_digests(production_with_opa)
        _validate_workload_security(production_with_opa)
        _validate_opa_network_policy(production_with_opa)
        _validate_opa_signed_bundle(production_with_opa)
        _validate_network_isolation(production_with_opa, opa_enabled=True)
        _validate_service_accounts(production_with_opa)
        audit = _render(
            [
                helm,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                *CREDENTIAL_RENDER_ARGS,
                *AUDIT_RENDER_ARGS,
            ]
        )
        _validate_audit_signer_render(audit)
        audit_anchor = _render([*_production_render_args(helm), *AUDIT_ANCHOR_RENDER_ARGS])
        _validate_credential_mount(audit_anchor)
        _validate_runtime_secret_scope(audit_anchor, AUDIT_ANCHOR_RUNTIME_SECRET_SCOPE)
        _validate_audit_signer_render(
            audit_anchor,
            set(),
            set(),
            {"agentops-guard-api", "agentops-guard-audit-anchor-exporter"},
        )
        _validate_audit_anchor_exporter(audit_anchor)
        _validate_production_image_digests(audit_anchor)
        _validate_network_isolation(audit_anchor)
        _validate_workload_security(audit_anchor)
        _validate_service_accounts(audit_anchor)
        _assert_render_failure(
            [
                *_production_render_args(helm),
                *AUDIT_ANCHOR_RENDER_ARGS,
                "--set",
                "openbaoProxy.image.digest=",
            ],
            "openbaoProxy.image.digest is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm),
                *AUDIT_ANCHOR_RENDER_ARGS,
                "--set",
                "credentialStore.openbaoUrl=https://user:password@openbao.internal",
            ],
            "credentialStore.openbaoUrl must be a credential-free HTTPS base URL",
        )
        return 0

    if LOCAL_HELM.exists():
        helm_cmd = str(LOCAL_HELM)
        _run([helm_cmd, "lint", str(CHART_PATH)])
        rendered = _render(
            [
                helm_cmd,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        _validate_runtime_secret_scope(rendered)
        _validate_workload_security(rendered)
        _validate_service_accounts(rendered)
        production = _render(_production_render_args(helm_cmd))
        _validate_credential_mount(production)
        _validate_runtime_secret_scope(production, PRODUCTION_RUNTIME_SECRET_SCOPE)
        _validate_production_image_digests(production)
        _validate_image_signature_policy(production)
        _validate_network_isolation(production)
        _validate_workload_security(production)
        _validate_service_accounts(production)
        _validate_signature_render_failures(helm_cmd)
        _validate_network_policy_render_failures(helm_cmd)
        _validate_service_account_render_failures(helm_cmd)
        _assert_render_failure(
            _production_render_args(helm_cmd, None),
            "image.digest is required",
        )
        _assert_render_failure(
            _production_render_args(helm_cmd, "sha256:invalid"),
            "image.digest must be sha256",
        )
        _assert_render_failure(
            _production_render_args(helm_cmd, dashboard_image_digest=None),
            "dashboardImage.digest is required",
        )
        _assert_render_failure(
            [*_production_render_args(helm_cmd), "--set", "opa.enabled=true"],
            "opa.bundle.enabled is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm_cmd),
                "--set",
                "opa.enabled=true",
                *OPA_BUNDLE_RENDER_ARGS,
            ],
            "opa.image.digest is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm_cmd),
                "--set",
                "opa.enabled=true",
                "--set",
                f"opa.image.digest={TEST_OPA_IMAGE_DIGEST}",
                "--set",
                "opa.bundle.enabled=true",
                "--set",
                "opa.bundle.existingSecret=agentops-opa-policy",
            ],
            "opa.bundle.expectedPolicyRevision is required",
        )
        production_with_opa = _render(
            [
                *_production_render_args(helm_cmd),
                "--set",
                "opa.enabled=true",
                "--set",
                f"opa.image.digest={TEST_OPA_IMAGE_DIGEST}",
                *OPA_BUNDLE_RENDER_ARGS,
            ]
        )
        _validate_production_image_digests(production_with_opa)
        _validate_workload_security(production_with_opa)
        _validate_opa_network_policy(production_with_opa)
        _validate_opa_signed_bundle(production_with_opa)
        _validate_network_isolation(production_with_opa, opa_enabled=True)
        _validate_service_accounts(production_with_opa)
        audit = _render(
            [
                helm_cmd,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                *CREDENTIAL_RENDER_ARGS,
                *AUDIT_RENDER_ARGS,
            ]
        )
        _validate_audit_signer_render(audit)
        audit_anchor = _render([*_production_render_args(helm_cmd), *AUDIT_ANCHOR_RENDER_ARGS])
        _validate_credential_mount(audit_anchor)
        _validate_runtime_secret_scope(audit_anchor, AUDIT_ANCHOR_RUNTIME_SECRET_SCOPE)
        _validate_audit_signer_render(
            audit_anchor,
            set(),
            set(),
            {"agentops-guard-api", "agentops-guard-audit-anchor-exporter"},
        )
        _validate_audit_anchor_exporter(audit_anchor)
        _validate_production_image_digests(audit_anchor)
        _validate_network_isolation(audit_anchor)
        _validate_workload_security(audit_anchor)
        _validate_service_accounts(audit_anchor)
        _assert_render_failure(
            [
                *_production_render_args(helm_cmd),
                *AUDIT_ANCHOR_RENDER_ARGS,
                "--set",
                "openbaoProxy.image.digest=",
            ],
            "openbaoProxy.image.digest is required",
        )
        _assert_render_failure(
            [
                *_production_render_args(helm_cmd),
                *AUDIT_ANCHOR_RENDER_ARGS,
                "--set",
                "credentialStore.openbaoUrl=https://user:password@openbao.internal",
            ],
            "credentialStore.openbaoUrl must be a credential-free HTTPS base URL",
        )
        return 0

    image = os.environ.get("AGENTOPS_HELM_IMAGE")
    if image:
        mount = f"{Path.cwd()}:/workspace"
        _run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "lint",
                str(CHART_PATH),
            ]
        )
        rendered = _render(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        _validate_runtime_secret_scope(rendered)
        _validate_workload_security(rendered)
        _validate_service_accounts(rendered)
        production = _render(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.prod.yaml"),
                *CREDENTIAL_RENDER_ARGS,
                "--set",
                f"image.digest={TEST_IMAGE_DIGEST}",
                "--set",
                f"dashboardImage.digest={TEST_DASHBOARD_IMAGE_DIGEST}",
                *IMAGE_SIGNATURE_RENDER_ARGS,
                *NETWORK_POLICY_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(production)
        _validate_runtime_secret_scope(production, PRODUCTION_RUNTIME_SECRET_SCOPE)
        _validate_production_image_digests(production)
        _validate_image_signature_policy(production)
        _validate_network_isolation(production)
        _validate_workload_security(production)
        _validate_service_accounts(production)
        audit = _render(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                *CREDENTIAL_RENDER_ARGS,
                *AUDIT_RENDER_ARGS,
            ]
        )
        _validate_audit_signer_render(audit)
        audit_anchor = _render(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.prod.yaml"),
                *CREDENTIAL_RENDER_ARGS,
                "--set",
                f"image.digest={TEST_IMAGE_DIGEST}",
                "--set",
                f"dashboardImage.digest={TEST_DASHBOARD_IMAGE_DIGEST}",
                *IMAGE_SIGNATURE_RENDER_ARGS,
                *NETWORK_POLICY_RENDER_ARGS,
                *AUDIT_ANCHOR_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(audit_anchor)
        _validate_runtime_secret_scope(audit_anchor, AUDIT_ANCHOR_RUNTIME_SECRET_SCOPE)
        _validate_audit_signer_render(
            audit_anchor,
            set(),
            set(),
            {"agentops-guard-api", "agentops-guard-audit-anchor-exporter"},
        )
        _validate_audit_anchor_exporter(audit_anchor)
        _validate_production_image_digests(audit_anchor)
        _validate_network_isolation(audit_anchor)
        _validate_workload_security(audit_anchor)
        _validate_service_accounts(audit_anchor)
        return 0

    raise SystemExit(
        "No Helm execution path found. Install helm, place helm.exe at %TEMP%/helm-v3.18.4/windows-amd64/helm.exe, "
        "or set AGENTOPS_HELM_IMAGE."
    )


if __name__ == "__main__":
    raise SystemExit(main())
