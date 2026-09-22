"""Run a bounded real-PG activity lock comparison without exposed ports/secrets."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from uuid import uuid4
import xml.etree.ElementTree as ET

import psycopg

ROOT = Path(__file__).resolve().parents[1]


def docker(*arguments):
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Controlled Docker operation failed: " + arguments[0])
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--include-admission", action="store_true")
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    name = "agentops-auth-lock-" + uuid4().hex[:12]
    result = {"test": "api_key_activity_real_pg", "container": name, "network": "none", "passed": False}
    created = False
    try:
        with TemporaryDirectory(prefix="agentops-auth-lock-", dir="/tmp") as scratch:
            socket = Path(scratch) / "socket"
            socket.mkdir(mode=0o777)
            socket.chmod(0o777)  # Confined by private 0700 parent directory.
            try:
                docker("run", "-d", "--pull=never", "--name", name, "--network=none",
                       "--user", f"{os.getuid()}:{os.getgid()}", "--label", "agentops.test-owner=" + name,
                       "--tmpfs", f"/var/lib/postgresql/data:rw,size=256m,uid={os.getuid()},gid={os.getgid()}",
                       "--mount", f"type=bind,source={socket},target=/var/run/postgresql",
                       "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16", "-c", "listen_addresses=")
                created = True
                for _ in range(100):
                    if docker("exec", name, "head", "-n1", "/proc/1/comm") == "postgres":
                        try:
                            with psycopg.connect(host=str(socket), user="postgres", dbname="postgres",
                                                 connect_timeout=1, autocommit=True) as db:
                                result["postgresql_version"] = db.execute("SHOW server_version").fetchone()[0]
                                break
                        except psycopg.OperationalError:
                            pass
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Private PostgreSQL startup")
                report = directory / "tests.xml"
                test_paths = ["tests/test_api_key_activity_postgres.py"]
                if args.include_admission:
                    test_paths.append("tests/test_admission_query_capacity_postgres.py")
                run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "junit_family=xunit1",
                    *test_paths, "--junitxml=" + str(report)],
                    cwd=ROOT, env={**os.environ, "AGENTOPS_ACTIVITY_TEST_SOCKET": str(socket)},
                    capture_output=True, text=True, timeout=60)
                result["test_exit_code"] = run.returncode
                if report.exists():
                    xml = ET.parse(report).getroot()
                    result["tests"] = [{key: suite.get(key) for key in ("tests", "failures", "errors", "skipped")}
                                       for suite in xml.iter("testsuite")]
                    result["lock_trials"] = [
                        {prop.get("name"): prop.get("value") for prop in case.findall("./properties/property")}
                        for case in xml.iter("testcase") if case.find("./properties") is not None]
                    result["passed"] = run.returncode == 0 and all(
                        suite["skipped"] == "0" and int(suite["tests"]) == 11 + 2 * int(args.include_admission)
                        for suite in result["tests"])
            finally:
                if created:
                    owner = docker("inspect", "--format", '{{index .Config.Labels "agentops.test-owner"}}', name)
                    if owner != name:
                        raise RuntimeError("Refusing cleanup of a non-owned container")
                    docker("rm", "--force", name)
                result["owned_containers_remaining"] = int(bool(docker("ps", "-aq", "--filter", "name=^/" + name + "$")))
    finally:
        (directory / "report.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    return 0 if result["passed"] and result["owned_containers_remaining"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
