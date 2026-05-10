from __future__ import annotations

import json
import subprocess
from threading import Lock
from typing import Any


class StdioTransport:
    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        timeout: float = 10.0,
        max_response_bytes: int = 262_144,
        max_stderr_bytes: int = 4_096,
    ) -> None:
        self.command = command
        self.args = args or []
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_stderr_bytes = max_stderr_bytes

    def list_tools(self) -> list[dict[str, Any]]:
        response = self._request("tools/list", {})
        return response.get("result", {}).get("tools", [])

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self._request("tools/call", {"name": tool_name, "arguments": arguments})
        if "error" in response:
            return _transport_error(str(response["error"]), response["error"])
        return response.get("result", {})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        manager = StdioProcessManager(
            self.command,
            self.args,
            self.timeout,
            max_response_bytes=self.max_response_bytes,
            max_stderr_bytes=self.max_stderr_bytes,
        )
        try:
            return manager.request(method, params)
        finally:
            manager.close()


class StdioProcessManager:
    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        timeout: float = 10.0,
        *,
        max_response_bytes: int = 262_144,
        max_stderr_bytes: int = 4_096,
    ) -> None:
        self.command = command
        self.args = args or []
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_stderr_bytes = max_stderr_bytes
        self._process: subprocess.Popen[bytes] | None = None
        self._request_id = 0
        self._lock = Lock()
        self.last_stderr = ""

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._request_id += 1
            process = self._ensure_process()
            payload = json.dumps({"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}).encode("utf-8")
            framed = b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
            try:
                assert process.stdin is not None
                process.stdin.write(framed)
                process.stdin.flush()
                return _read_framed(process, self.timeout, self.max_response_bytes, self.max_stderr_bytes)
            except (BrokenPipeError, OSError, TimeoutError, ValueError) as exc:
                self.restart()
                return {"error": {"code": "stdio_error", "message": str(exc)}}

    def close(self) -> None:
        process = self._process
        self._process = None
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()

    def restart(self) -> None:
        self.close()
        self._process = self._start_process()

    def _ensure_process(self) -> subprocess.Popen[bytes]:
        if self._process is None or self._process.poll() is not None:
            self._process = self._start_process()
        return self._process

    def _start_process(self) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [self.command, *self.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


_MANAGERS: dict[str, StdioProcessManager] = {}


def get_stdio_manager(
    server_id: str,
    command: str,
    args: list[str] | None = None,
    timeout: float = 10.0,
    *,
    max_response_bytes: int = 262_144,
    max_stderr_bytes: int = 4_096,
) -> StdioProcessManager:
    manager = _MANAGERS.get(server_id)
    if (
        manager is None
        or manager.command != command
        or manager.args != (args or [])
        or manager.timeout != timeout
        or manager.max_response_bytes != max_response_bytes
        or manager.max_stderr_bytes != max_stderr_bytes
    ):
        if manager is not None:
            manager.close()
        manager = StdioProcessManager(
            command,
            args,
            timeout,
            max_response_bytes=max_response_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        _MANAGERS[server_id] = manager
    return manager


def _decode_framed(data: bytes) -> dict[str, Any]:
    if not data:
        return {"error": {"code": "empty_response", "message": "MCP stdio server returned no data"}}
    marker = b"\r\n\r\n"
    if marker in data:
        _, body = data.split(marker, 1)
    else:
        body = data
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": {"code": "invalid_json", "message": str(exc)}}


def _read_framed(process: subprocess.Popen[bytes], timeout: float, max_response_bytes: int, max_stderr_bytes: int) -> dict[str, Any]:
    assert process.stdout is not None
    header = _read_until(process.stdout, b"\r\n\r\n", timeout, max_response_bytes)
    if not header:
        stderr = _read_available_stderr(process, max_stderr_bytes)
        return {"error": {"code": "empty_response", "message": stderr or "MCP stdio server returned no data"}}
    length = 0
    for line in header.decode("ascii", errors="ignore").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
            break
    if length <= 0:
        return {"error": {"code": "invalid_frame", "message": "Missing Content-Length"}}
    if length > max_response_bytes:
        raise ValueError(f"MCP stdio response exceeds limit: {length} > {max_response_bytes}")
    body = process.stdout.read(length)
    return _decode_framed(body)


def _read_until(stream, marker: bytes, timeout: float, max_bytes: int) -> bytes:
    import time

    deadline = time.monotonic() + timeout
    data = b""
    while marker not in data:
        if time.monotonic() > deadline:
            raise TimeoutError(f"MCP stdio request timed out after {timeout}s")
        chunk = stream.read(1)
        if not chunk:
            break
        data += chunk
        if len(data) > max_bytes:
            raise ValueError(f"MCP stdio header exceeds limit: {len(data)} > {max_bytes}")
    return data


def _read_available_stderr(process: subprocess.Popen[bytes], max_stderr_bytes: int) -> str:
    if process.stderr is None or process.poll() is None:
        return ""
    try:
        return process.stderr.read(max_stderr_bytes).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _transport_error(message: str, upstream_error: dict[str, Any]) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "policyDecision": None,
        "risk": None,
        "upstreamError": upstream_error,
    }
