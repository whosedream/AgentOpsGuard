"""Authorized temporary WSL limit increase; always clean up and restore it.

No production deployment, image pull, permanent host setting or arbitrary fault
targets. The frozen controlled topology reuses existing local images and models.
"""
import argparse
import asyncio
import json
from pathlib import Path
import shutil
import subprocess
from datetime import UTC, datetime
from uuid import uuid4

import verify_multinode_capacity as cluster
import verify_multinode_admission as admission
import verify_multinode_receipts as receipts
import collect_multinode_evidence as evidence
from verify_patroni_kubernetes_failover import _delete_cluster, _safe_environment

WSL = "/mnt/c/Windows/System32/wsl.exe"
POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
# Conservative headroom for this ten-node local experiment, not a production SLO.
MIN_HOST_FREE_BYTES = 50 * 1024**3
MIN_SYSTEM_FREE_BYTES = 10 * 1024**3


def check_runtime_tools():
    resolved = {name: shutil.which(name) for name in ("helm", "docker")}
    missing = [name for name, path in resolved.items() if path is None]
    if missing:
        raise RuntimeError("Required test tools absent from PATH: " + ", ".join(missing))
    return resolved


def check_host_storage():
    # df in the guest reports virtual capacity, not the Windows volume backing
    # the expanding VHD. Resolve the actual distro volume before any mutation.
    script = r"""
$ErrorActionPreference = 'Stop'
$distro = @(Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss |
    Get-ItemProperty | Where-Object DistributionName -eq 'Ubuntu-24.04')
if ($distro.Count -ne 1) { throw 'Expected exactly one distribution' }
$drive = (Get-Item -LiteralPath $distro[0].BasePath).PSDrive.Name
$disk = Get-PSDrive -Name $drive
$system = Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')
@{ host_drive = $drive; host_free_bytes = $disk.Free;
   system_drive = $system.Name; system_free_bytes = $system.Free } | ConvertTo-Json -Compress
"""
    raw = cluster.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script], timeout=30)
    storage = json.loads(raw)
    for field in ("host_free_bytes", "system_free_bytes"):
        if type(storage.get(field)) is not int or storage[field] < 0:
            raise ValueError("Windows storage probe did not return valid free space")
    if storage["host_free_bytes"] < MIN_HOST_FREE_BYTES or storage["system_free_bytes"] < MIN_SYSTEM_FREE_BYTES:
        raise RuntimeError("Insufficient Windows disk headroom: require 50 GiB on the WSL backing volume "
                           "and 10 GiB on the system volume before the ten-node experiment")
    return storage


def set_listener_limit(value):
    if value not in {128, 512}:
        raise ValueError("Only the explicitly approved temporary listener limits are allowed")
    # Windows error output is not necessarily UTF-8; do not let decoding hide
    # the command's real exit status during restoration.
    result = subprocess.run([WSL, "-d", "Ubuntu-24.04", "-u", "root", "--", "/usr/sbin/sysctl", "-w",
        f"fs.inotify.max_user_instances={value}"], env=_safe_environment(),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"WSL listener update failed: exit={result.returncode}")
    if int(cluster.INOTIFY_INSTANCES_PATH.read_text()) != value:
        raise RuntimeError("WSL listener setting did not change in the current distribution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--allow-temporary-listener-increase", action="store_true")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--recovery-only", action="store_true",
                        help="Supplemental recovery scenarios only; never a replacement for failed baselines")
    scope.add_argument("--baseline-only", action="store_true",
                       help="Original synchronous baselines/conditional fixed target on the same ten-node topology")
    parser.add_argument("--result-recovery-admission", action="store_true",
                        help="Use explicitly reviewed v2 result queries for admission reads")
    parser.add_argument("--soak-seconds", type=int, choices=(0, 600, 1800), default=0,
                        help="Baseline-only: diagnostic 5 RPS sustained phase; never replaces short baseline failures")
    args = parser.parse_args()
    if args.baseline_only and args.result_recovery_admission:
        raise ValueError("Baseline-only mode cannot claim admission result recovery")
    if args.soak_seconds and not args.baseline_only:
        raise ValueError("Sustained baseline requires --baseline-only")
    if not args.allow_temporary_listener_increase:
        raise ValueError("Explicit host administrator authorization is required")
    original = int(cluster.INOTIFY_INSTANCES_PATH.read_text())
    if original != 128:
        raise ValueError("The approved original listener value changed; do not override it")
    storage = check_host_storage()
    runtime_tools = check_runtime_tools()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    deployment = directory / "cluster"
    owned_cluster = cluster.PREFIX + uuid4().hex[:8]
    summary = {"started_at": datetime.now(UTC).isoformat(), "listener_before": original,
               "cluster": owned_cluster, "storage_before": storage,
               "production_sla_verified": False, "phases": [],
               "recovery_only": args.recovery_only, "baseline_only": args.baseline_only,
               "soak_seconds": args.soak_seconds,
               "soak_role": "same_load_diagnostic_not_replacement" if args.soak_seconds else None,
               "runtime_tools": runtime_tools, "evidence": [],
               "admission_result_recovery": args.result_recovery_admission}
    cluster.save(directory / "scope.json", {**summary, "host_authorization": "temporary 128 to 512 then restore",
        "nodes": 10, "same_physical_host": True, "business_and_admission_patroni_groups": 2,
        "small_model_mode": "shadow", "sync_baseline": (
            "not rerun; prior baseline failures remain" if args.recovery_only else "3 x 600 requests at 5 RPS"),
        "no_peak_if_baselines_fail": True})
    source = cluster.frozen_inputs()
    for relative in source:
        destination = directory / "source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cluster.ROOT / relative, destination)
    try:
        set_listener_limit(512)
        cluster.setup(deployment, timing_profile="responsive", durable_queue=True,
            concurrency=1, resource_profile="isolated", failsafe=True, receipts=True,
            independent_admission=True, cluster_name=owned_cluster)
        state = json.loads((deployment / "state.json").read_text())
        # Keep the original synchronous workload/criteria, never replace failures
        # with accepted-only metrics from the new asynchronous path.
        baselines = [] if args.recovery_only else [(f"baseline_{i}", 5, 120) for i in range(1, 4)]
        for name, rps, seconds in [("warmup", 1, 30)] + baselines:
            print("verification_phase=" + name, flush=True)
            asyncio.run(cluster.load_phase(state, deployment, name, rps, seconds, "none"))
            value = json.loads((deployment / (name + ".json")).read_text())
            summary["phases"].append({"name": name, "passed": value["passed"], "failed": value["failed"]})
            summary["evidence"].append(evidence.collect_phase(state, deployment, name, expected_cluster=owned_cluster))
        baselines_passed = bool(baselines) and all(
            row["passed"] for row in summary["phases"] if row["name"].startswith("baseline_")) and all(
            row["complete"] for row in summary["evidence"])
        soak_passed = True
        # Same-load diagnostics may expose intermittent faults after a short
        # failure. Never erase that failure or use this to authorize higher load.
        if args.soak_seconds:
            name = "sustained_5rps"
            print("verification_phase=" + name, flush=True)
            asyncio.run(cluster.load_phase(state, deployment, name, 5, args.soak_seconds, "none"))
            value = json.loads((deployment / (name + ".json")).read_text())
            summary["phases"].append({"name": name, "passed": value["passed"], "failed": value["failed"]})
            extra = evidence.collect_phase(state, deployment, name, expected_cluster=owned_cluster)
            summary["evidence"].append(extra)
            soak_passed = value["passed"] and extra["complete"]
        if baselines_passed and soak_passed:
            asyncio.run(cluster.load_phase(state, deployment, "fixed_target_10rps", 10, 120, "none"))
            value = json.loads((deployment / "fixed_target_10rps.json").read_text())
            summary["phases"].append({"name": "fixed_target_10rps", "passed": value["passed"], "failed": value["failed"]})
            summary["evidence"].append(evidence.collect_phase(state, deployment, "fixed_target_10rps", expected_cluster=owned_cluster))
            summary["peak_test"] = "fixed_target_only_not_production_peak"
        else:
            summary["peak_test"] = "not_in_recovery_scope" if args.recovery_only else "skipped_baseline_failed"
        for i in ([] if args.recovery_only or args.baseline_only else range(1, 4)):
            name = f"result_recovery_{i}"
            value = receipts.verify(state, deployment, name, result_recovery=True)
            summary["phases"].append({"name": name, "passed": value["passed"]})
            summary["evidence"].append(evidence.collect_phase(state, deployment, name, expected_cluster=owned_cluster))
        business_faults = [(f"business_loss_{i}", "business_primary") for i in range(1, 4)]
        other_faults = [("backlog", "backlog"), ("admission_primary_loss", "admission_primary")]
        # Complete the previously unrun scenarios first in a supplemental run.
        phases = other_faults + business_faults if args.recovery_only else business_faults + other_faults
        if args.baseline_only:
            phases = []
        if args.result_recovery_admission:
            name = "admission_result_recovery"
            print("verification_phase=" + name, flush=True)
            value = asyncio.run(admission.phase(state, deployment, name, fault="none", seconds=1,
                rps=1, result_recovery=True, crash_after_commit_index=0))
            summary["phases"].append({"name": name, "passed": value["passed"],
                "accepted": value["accepted"], "admission_failed": value["admission_failed"],
                "accepted_not_completed": value["accepted_not_completed"]})
            summary["evidence"].append(evidence.collect_phase(state, deployment, name, expected_cluster=owned_cluster))
        for name, fault in phases:
            print("verification_phase=" + name, flush=True)
            value = asyncio.run(admission.phase(state, deployment, name, fault=fault,
                                               result_recovery=args.result_recovery_admission))
            summary["phases"].append({"name": name, "passed": value["passed"],
                "accepted": value["accepted"], "admission_failed": value["admission_failed"],
                "accepted_not_completed": value["accepted_not_completed"]})
            summary["evidence"].append(evidence.collect_phase(state, deployment, name, expected_cluster=owned_cluster))
        summary["evidence_complete"] = all(row["complete"] for row in summary["evidence"])
        summary["frozen_inputs_unchanged"] = cluster.frozen_inputs() == source
    except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as error:
        summary["controller_error"] = type(error).__name__
        raise  # Visible failure, never an invented passing report.
    finally:
        cleanup_errors = []
        try:
            # Keep ownership in memory: state.json itself may be unreadable after
            # a disk I/O failure. Never discover targets using a broad prefix.
            _delete_cluster(str(cluster.KIND), owned_cluster, _safe_environment())
            remaining = cluster.run(["docker", "ps", "-a", "--filter",
                "label=io.x-k8s.kind.cluster=" + owned_cluster, "--format", "{{.Names}}"])
            summary["test_containers_remaining"] = len(remaining.splitlines())
            if summary["test_containers_remaining"]:
                raise RuntimeError("Owned test containers remain after cleanup")
        except (RuntimeError, subprocess.SubprocessError, OSError) as error:
            summary["cleanup_error"] = type(error).__name__
            cleanup_errors.append(error)
        try:
            set_listener_limit(original)
            summary["listener_after"] = int(cluster.INOTIFY_INSTANCES_PATH.read_text())
        except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as error:
            summary["listener_restore_error"] = type(error).__name__
            cleanup_errors.append(error)
        summary["finished_at"] = datetime.now(UTC).isoformat()
        # If the report filesystem is unavailable, retain the sanitized recovery
        # status in controller output without pretending the file was saved.
        print(json.dumps(summary), flush=True)
        try:
            cluster.save(directory / "summary.json", summary)
        except OSError as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise ExceptionGroup("Verification cleanup or report persistence failed", cleanup_errors)


if __name__ == "__main__":
    main()
