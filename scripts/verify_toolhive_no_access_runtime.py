from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any


def verify_runtime(run_config: dict[str, Any], inspect: dict[str, Any]) -> dict[str, Any]:
    profile = run_config.get("permission_profile") or {}
    host_config = inspect.get("HostConfig") or {}
    declared_network = (profile.get("network") or {}).get("mode")
    actual_network = host_config.get("NetworkMode")
    image_digest_pinned = "@sha256:" in str(run_config.get("image", ""))
    checks = {
        "image_digest_pinned": image_digest_pinned,
        "declared_no_network": declared_network == "none",
        "actual_no_network": actual_network == "none",
        "declared_no_read_mounts": not profile.get("read"),
        "declared_no_write_mounts": not profile.get("write"),
        "actual_no_host_mounts": not host_config.get("Binds"),
        "actual_not_privileged": host_config.get("Privileged") is False,
        "actual_drops_all_capabilities": "ALL" in (host_config.get("CapDrop") or []),
        "actual_no_host_pid_namespace": host_config.get("PidMode") != "host",
        "actual_no_host_ipc_namespace": host_config.get("IpcMode") != "host",
        "actual_no_host_devices": not host_config.get("Devices"),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise RuntimeError(f"ToolHive no-access runtime mismatch: {','.join(failed)}")
    return {
        "workload": run_config.get("name"),
        "image_digest_pinned": image_digest_pinned,
        "declared_network_mode": declared_network,
        "actual_network_mode": actual_network,
        "host_mounts": 0,
        "privileged": False,
        "capabilities_dropped": "ALL",
        "host_namespaces_used": False,
        "host_devices": 0,
    }


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {command[0]} {command[1]}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare a running ToolHive no-access workload with its declared permissions."
    )
    parser.add_argument("workload")
    args = parser.parse_args()
    thv = shutil.which("thv")
    docker = shutil.which("docker")
    if thv is None or docker is None:
        raise RuntimeError("ToolHive CLI and Docker are required")

    with tempfile.TemporaryDirectory(prefix="agentops-toolhive-verify-") as temp_dir:
        export_path = Path(temp_dir) / "run-config.json"
        _run([thv, "export", args.workload, str(export_path)])
        run_config = json.loads(export_path.read_text(encoding="utf-8"))
    container_name = str(run_config.get("container_name") or args.workload)
    inspect_rows = json.loads(_run([docker, "inspect", container_name]))
    if len(inspect_rows) != 1:
        raise RuntimeError("ToolHive workload did not resolve to exactly one container")
    result = verify_runtime(run_config, inspect_rows[0])
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
