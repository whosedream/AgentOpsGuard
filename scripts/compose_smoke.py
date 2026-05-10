from __future__ import annotations

import json
import time
import urllib.error
import urllib.request


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def assert_ok(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def wait_for_text(url: str, expected: str, timeout_seconds: int = 120) -> str:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            body = fetch_text(url)
            if expected in body or "AgentOps Guard" in body:
                return body
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(5)
    raise SystemExit(f"Timed out waiting for {url}: {last_error}")


def main() -> int:
    ready = fetch_json("http://127.0.0.1:8000/readyz")
    assert_ok(ready["status"]["status"] == "ok", "API readyz is not ok")

    metrics = fetch_text("http://127.0.0.1:8000/metrics")
    assert_ok("agentops_api_requests_total" in metrics, "metrics output is incomplete")

    gateway = fetch_json("http://127.0.0.1:8001/mcp/tools/list")
    assert_ok("tools" in gateway, "gateway tools list is unavailable")

    dashboard = wait_for_text("http://127.0.0.1:3000/setup", "System Setup")
    assert_ok("System Setup" in dashboard or "AgentOps Guard" in dashboard, "dashboard setup page is unavailable")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        raise SystemExit(f"compose smoke failed: {exc}") from exc
