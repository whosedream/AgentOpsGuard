#!/usr/bin/env python3
"""Prepare a content-addressed bare checkout of the public Microsoft BIPIA source."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from agentops_guard.benchmarks.bipia import (
    DEFAULT_REPOSITORY,
    load_source_lock,
    validate_repository,
)


WINDOWS_GIT = Path("/mnt/d/Git/cmd/git.exe")


def _command_path(path: Path, *, windows_git: bool) -> str:
    if not windows_git:
        return str(path)
    completed = subprocess.run(
        ["wslpath", "-w", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_REPOSITORY)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists():
        validate_repository(output)
        print(f"bipia_source=verified path={output}")
        return 0

    lock = load_source_lock()
    output.parent.mkdir(parents=True, exist_ok=True)
    windows_git = WINDOWS_GIT.is_file() and os.access(WINDOWS_GIT, os.X_OK)
    git = str(WINDOWS_GIT) if windows_git else shutil.which("git")
    if not git:
        raise RuntimeError("Git is required to prepare the BIPIA evaluation source")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent)
    )
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
    }
    target = _command_path(temporary, windows_git=windows_git)
    try:
        commands = (
            [git, "init", "--bare", target],
            [git, "-C", target, "remote", "add", "origin", lock["repository"]],
            [
                git,
                "-C",
                target,
                "fetch",
                "--no-tags",
                "--depth=1",
                "origin",
                lock["commit"],
            ],
            [git, "-C", target, "update-ref", "refs/heads/pinned", "FETCH_HEAD"],
            [git, "-C", target, "symbolic-ref", "HEAD", "refs/heads/pinned"],
        )
        for command in commands:
            subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=True,
            )
        validate_repository(temporary)
        temporary.rename(output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(f"bipia_source=prepared path={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
