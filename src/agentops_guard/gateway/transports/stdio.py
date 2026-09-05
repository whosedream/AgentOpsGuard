from __future__ import annotations

import json
from queue import Empty, Queue
import subprocess
from threading import Lock, Thread
from typing import Any


SAFE_STDIO_ERROR_CODES = frozenset(
    {
        "empty_response",
        "invalid_frame",
        "invalid_json",
        "protocol_error",
        "stdio_error",
        "timeout",
    }
)


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
            code = safe_stdio_error_code(response["error"])
            return _transport_error("MCP stdio request failed", {"code": code})
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
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}
            ).encode("utf-8")
            framed = b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
            try:
                assert process.stdin is not None
                process.stdin.write(framed)
                process.stdin.flush()
                return _read_framed(
                    process, self.timeout, self.max_response_bytes, self.max_stderr_bytes
                )
            except TimeoutError:
                self.restart()
                return {"error": {"code": "timeout"}}
            except ValueError:
                self.restart()
                return {"error": {"code": "protocol_error"}}
            except (BrokenPipeError, OSError):
                self.restart()
                return {"error": {"code": "stdio_error"}}

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


def close_stdio_managers() -> None:
    for manager in _MANAGERS.values():
        manager.close()
    _MANAGERS.clear()


def safe_stdio_error_code(error: object) -> str:
    if isinstance(error, dict) and error.get("code") in SAFE_STDIO_ERROR_CODES:
        return str(error["code"])
    return "stdio_error"


def _decode_framed(data: bytes) -> dict[str, Any]:
    if not data:
        return {"error": {"code": "empty_response"}}
    marker = b"\r\n\r\n"
    if marker in data:
        _, body = data.split(marker, 1)
    else:
        body = data
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return {"error": {"code": "invalid_json"}}


def _read_framed(
    process: subprocess.Popen[bytes], timeout: float, max_response_bytes: int, max_stderr_bytes: int
) -> dict[str, Any]:
    outcomes: Queue[tuple[dict[str, Any] | None, BaseException | None]] = Queue(maxsize=1)

    def read() -> None:
        try:
            outcomes.put((_read_framed_blocking(process, max_response_bytes, max_stderr_bytes), None))
        except BaseException as exc:
            outcomes.put((None, exc))

    reader = Thread(target=read, name="agentops-stdio-read", daemon=True)
    reader.start()
    try:
        result, error = outcomes.get(timeout=timeout)
    except Empty:
        raise TimeoutError(f"MCP stdio request timed out after {timeout}s") from None
    if error is not None:
        raise error
    assert result is not None
    return result


def _read_framed_blocking(
    process: subprocess.Popen[bytes], max_response_bytes: int, max_stderr_bytes: int
) -> dict[str, Any]:
    assert process.stdout is not None
    header = _read_until(process.stdout, b"\r\n\r\n", max_response_bytes)
    if not header:
        _read_available_stderr(process, max_stderr_bytes)
        return {"error": {"code": "empty_response"}}
    length = 0
    for line in header.decode("ascii", errors="ignore").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
            break
    if length <= 0:
        return {"error": {"code": "invalid_frame"}}
    if length > max_response_bytes:
        raise ValueError(f"MCP stdio response exceeds limit: {length} > {max_response_bytes}")
    body = process.stdout.read(length)
    return _decode_framed(body)


def _read_until(stream, marker: bytes, max_bytes: int) -> bytes:
    data = b""
    while marker not in data:
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
    except OSError:
        return ""


def _transport_error(message: str, upstream_error: dict[str, Any]) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "policyDecision": None,
        "risk": None,
        "upstreamError": upstream_error,
    }
