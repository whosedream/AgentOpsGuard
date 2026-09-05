#!/usr/bin/env python3
"""Run a digest-pinned llama.cpp model through the trusted Inspect/Gateway harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import tomllib
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "verify_inspect_agent_eval.py"
QWEN_TOOL_ADAPTER = ROOT / "evals" / "local-model-runtime" / "qwen_tool_adapter.py"
INSPECT_TASK = ROOT / "evals" / "inspect" / "agentops_guard_task.py"
INSPECT_RUNNER = ROOT / "evals" / "inspect" / "run_local_model_smoke.py"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
LLAMA_CPP_PYTHON_PACKAGE = "llama-cpp-python"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pinned_file(path: Path, expected_sha256: str, kind: str) -> tuple[Path, int]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{kind} must be a regular file")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ValueError(f"{kind} SHA-256 must contain 64 lowercase hexadecimal characters")
    if _sha256(resolved) != expected_sha256:
        raise ValueError(f"{kind} SHA-256 does not match")
    return resolved, resolved.stat().st_size


def _locked_python_runtime(
    lock_path: Path,
    expected_lock_sha256: str,
    expected_version: str,
    expected_source_sha256: str,
) -> tuple[Path, int]:
    lock, lock_size = _pinned_file(lock_path, expected_lock_sha256, "runtime lock")
    if not SHA256_PATTERN.fullmatch(expected_source_sha256):
        raise ValueError("runtime source SHA-256 must contain 64 lowercase hexadecimal characters")
    packages = tomllib.loads(lock.read_text(encoding="utf-8"))["package"]
    matches = [package for package in packages if package["name"] == LLAMA_CPP_PYTHON_PACKAGE]
    if len(matches) != 1:
        raise ValueError("runtime lock must contain exactly one llama-cpp-python package")
    package = matches[0]
    if package["version"] != expected_version:
        raise ValueError("runtime package version does not match the lock")
    if package["sdist"]["hash"] != f"sha256:{expected_source_sha256}":
        raise ValueError("runtime source SHA-256 does not match the lock")
    return lock, lock_size


def _python_distribution_metadata(python: Path, expected_version: str) -> dict[str, object]:
    script = r'''
import hashlib
from importlib.metadata import distribution
import json

dist = distribution("llama-cpp-python")
digest = hashlib.sha256()
total_size = 0
file_count = 0
for entry in sorted(dist.files or [], key=str):
    path = dist.locate_file(entry)
    if not path.is_file():
        continue
    digest.update(str(entry).encode("utf-8"))
    digest.update(b"\0")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            total_size += len(chunk)
    file_count += 1
print(json.dumps({
    "version": dist.version,
    "sha256": digest.hexdigest(),
    "size_bytes": total_size,
    "file_count": file_count,
}, separators=(",", ":")))
'''
    completed = subprocess.run(
        [str(python), "-c", script],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("llama-cpp-python runtime inspection failed")
    metadata = json.loads(completed.stdout.decode("utf-8"))
    if metadata["version"] != expected_version:
        raise ValueError("installed runtime package version does not match")
    return metadata


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _wait_for_model(process: subprocess.Popen[bytes], port: int, health_path: str) -> None:
    deadline = time.monotonic() + 120
    health_url = f"http://127.0.0.1:{port}{health_path}"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("llama.cpp exited before the model became ready")
        try:
            with urlopen(health_url, timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            pass
        time.sleep(0.25)
    raise RuntimeError("llama.cpp model did not become ready")


def _adapter_metrics(port: int) -> dict[str, int]:
    with urlopen(f"http://127.0.0.1:{port}/adapter-metrics", timeout=2) as response:  # noqa: S310
        metrics = json.load(response)
    if not isinstance(metrics, dict) or not all(
        isinstance(name, str) and isinstance(value, int) for name, value in metrics.items()
    ):
        raise RuntimeError("model adapter metrics are invalid")
    return metrics


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def _write_new_report(report: dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    runtime = parser.add_mutually_exclusive_group(required=True)
    runtime.add_argument("--llama-server", type=Path)
    runtime.add_argument("--llama-cpp-python", type=Path)
    parser.add_argument("--llama-server-sha256")
    parser.add_argument("--runtime-lock", type=Path)
    parser.add_argument("--runtime-lock-sha256")
    parser.add_argument("--runtime-package-version")
    parser.add_argument("--runtime-source-sha256")
    parser.add_argument("--model-artifact", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not MODEL_ID_PATTERN.fullmatch(args.model_id):
        raise ValueError("model id has an unsupported format")
    model, model_size = _pinned_file(
        args.model_artifact,
        args.model_sha256,
        "model artifact",
    )

    runtime_report: dict[str, object]
    use_tool_adapter = False
    if args.llama_server is not None:
        if args.llama_server_sha256 is None:
            raise ValueError("llama.cpp server SHA-256 is required")
        server, server_size = _pinned_file(
            args.llama_server,
            args.llama_server_sha256,
            "llama.cpp server",
        )
        if not os.access(server, os.X_OK):
            raise ValueError("llama.cpp server is not executable")
        server_command = [
            str(server),
            "--model",
            str(model),
            "--host",
            "127.0.0.1",
            "--port",
            "{port}",
            "--jinja",
            "--ctx-size",
            "4096",
            "--parallel",
            "1",
            "--n-gpu-layers",
            "99",
        ]
        runtime_report = {
            "runtime": "llama.cpp",
            "runtime_sha256": args.llama_server_sha256,
            "runtime_size_bytes": server_size,
        }
        health_path = "/health"
    else:
        required = {
            "runtime lock": args.runtime_lock,
            "runtime lock SHA-256": args.runtime_lock_sha256,
            "runtime package version": args.runtime_package_version,
            "runtime source SHA-256": args.runtime_source_sha256,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise ValueError(f"missing llama-cpp-python provenance: {', '.join(missing)}")
        python = args.llama_cpp_python.absolute()
        if not python.is_file() or not os.access(python, os.X_OK):
            raise ValueError("llama-cpp-python interpreter is not executable")
        lock, lock_size = _locked_python_runtime(
            args.runtime_lock,
            args.runtime_lock_sha256,
            args.runtime_package_version,
            args.runtime_source_sha256,
        )
        distribution = _python_distribution_metadata(python, args.runtime_package_version)
        server_command = [
            str(python),
            "-m",
            "llama_cpp.server",
            "--model",
            str(model),
            "--model_alias",
            args.model_id,
            "--host",
            "127.0.0.1",
            "--port",
            "{port}",
            "--chat_template_kwargs",
            '{"enable_thinking":false}',
            "--n_ctx",
            "4096",
            "--n_threads",
            "-1",
            "--n_threads_batch",
            "-1",
            "--n_gpu_layers",
            "0",
            "--use_mlock",
            "False",
            "--verbose",
            "False",
        ]
        runtime_report = {
            "runtime": "llama-cpp-python",
            "runtime_sha256": distribution["sha256"],
            "runtime_size_bytes": distribution["size_bytes"],
            "runtime_file_count": distribution["file_count"],
            "runtime_package_version": distribution["version"],
            "runtime_source_sha256": args.runtime_source_sha256,
            "runtime_lock_sha256": args.runtime_lock_sha256,
            "runtime_lock_size_bytes": lock_size,
            "runtime_lock_verified": lock == args.runtime_lock.resolve(),
            "tool_call_adapter_sha256": _sha256(QWEN_TOOL_ADAPTER),
        }
        health_path = "/v1/models"
        use_tool_adapter = True

    port = _free_port()
    server_command[server_command.index("{port}")] = str(port)
    process = subprocess.Popen(
        server_command,
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    adapter: subprocess.Popen[bytes] | None = None
    adapter_port: int | None = None
    evaluation_port = port
    try:
        _wait_for_model(process, port, health_path)
        if use_tool_adapter:
            adapter_port = _free_port()
            adapter_environment = {
                **_safe_environment(),
                "AGENTOPS_LOCAL_MODEL_UPSTREAM": f"http://127.0.0.1:{port}",
            }
            adapter = subprocess.Popen(
                [
                    str(python),
                    "-m",
                    "uvicorn",
                    "qwen_tool_adapter:app",
                    "--app-dir",
                    str(QWEN_TOOL_ADAPTER.parent),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(adapter_port),
                    "--no-access-log",
                    "--log-level",
                    "error",
                ],
                cwd=ROOT,
                env=adapter_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            _wait_for_model(adapter, adapter_port, "/v1/models")
            evaluation_port = adapter_port
        completed = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "--local-model-url",
                f"http://127.0.0.1:{evaluation_port}/v1",
                "--local-model-id",
                args.model_id,
            ],
            cwd=ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=240,
            check=False,
        )
        if completed.returncode != 0:
            lines = completed.stdout.decode("utf-8").splitlines()
            diagnostic = json.loads(lines[-1]) if lines else {"evaluation_failed": True}
            if adapter is not None:
                diagnostic["adapter_process_running"] = adapter.poll() is None
                if adapter.poll() is None and adapter_port is not None:
                    diagnostic["adapter_metrics"] = _adapter_metrics(adapter_port)
            raise RuntimeError(
                "real llama.cpp Agent evaluation failed: "
                + json.dumps(diagnostic, separators=(",", ":"))
            )
        summary = json.loads(completed.stdout.decode("utf-8").splitlines()[-1])
        if not summary.get("local_model_endpoint_execution"):
            raise RuntimeError("evaluation did not use the local model endpoint")
    finally:
        if adapter is not None:
            _stop_process_group(adapter)
        _stop_process_group(process)

    report = {
        **summary,
        **runtime_report,
        "implementation_sha256": {
            "launcher": _sha256(Path(__file__)),
            "gateway_harness": _sha256(HARNESS),
            "inspect_task": _sha256(INSPECT_TASK),
            "inspect_runner": _sha256(INSPECT_RUNNER),
            **(
                {"qwen_tool_adapter": _sha256(QWEN_TOOL_ADAPTER)}
                if use_tool_adapter
                else {}
            ),
        },
        "model_artifact_sha256": args.model_sha256,
        "model_artifact_size_bytes": model_size,
        "real_model_execution": True,
        "real_model_quality_result": False,
        "report_contains_prompt_or_tool_content": False,
        "report_contains_credentials": False,
    }
    _write_new_report(report, args.output)
    print("llama_cpp_agent_evaluation=passed report_created=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
