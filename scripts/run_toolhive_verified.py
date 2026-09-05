from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess


DEFAULT_PROFILE = Path("deploy/toolhive/permission-profiles/no-access.json")


def validate_profile(path: Path) -> str:
    profile = json.loads(path.read_text(encoding="utf-8"))
    if profile.get("privileged") is not False:
        raise ValueError("ToolHive profile must explicitly disable privileged mode")
    network = profile.get("network")
    if not isinstance(network, dict):
        raise ValueError("ToolHive profile must define network permissions")
    mode = network.get("mode")
    if mode not in {"none", "bridge"}:
        raise ValueError("ToolHive network mode must be none or bridge")
    outbound = network.get("outbound") or {}
    if outbound.get("insecure_allow_all") is not False:
        raise ValueError("ToolHive profile must explicitly deny unrestricted outbound access")
    hosts = outbound.get("allow_host") or []
    if any("*" in host for host in hosts):
        raise ValueError("ToolHive outbound hosts must be exact names, not wildcards")
    if mode == "none" and (hosts or outbound.get("allow_port")):
        raise ValueError("ToolHive network mode none cannot declare outbound exceptions")
    return mode


def build_command(
    *,
    executable: str,
    server: str,
    workload_name: str,
    proxy_port: int,
    profile_path: Path,
) -> list[str]:
    network_mode = validate_profile(profile_path)
    return [
        executable,
        "run",
        server,
        "--name",
        workload_name,
        "--permission-profile",
        str(profile_path),
        "--network",
        network_mode,
        "--isolate-network",
        "--proxy-mode",
        "streamable-http",
        "--proxy-port",
        str(proxy_port),
        "--host",
        "127.0.0.1",
        "--strict-protocol-validation",
        "--enable-audit",
        "--image-verification",
        "enabled",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Start one catalogued ToolHive workload with the AgentOps production guardrails."
    )
    parser.add_argument("server", help="ToolHive registry server name with provenance metadata")
    parser.add_argument("--name", required=True, help="Local ToolHive workload name")
    parser.add_argument("--proxy-port", required=True, type=int)
    parser.add_argument("--permission-profile", type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args()

    executable = shutil.which("thv")
    if executable is None:
        raise RuntimeError("ToolHive CLI is not installed")
    command = build_command(
        executable=executable,
        server=args.server,
        workload_name=args.name,
        proxy_port=args.proxy_port,
        profile_path=args.permission_profile,
    )
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
