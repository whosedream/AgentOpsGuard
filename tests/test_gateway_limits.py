import sys
from pathlib import Path

from agentops_guard.gateway.transports.stdio import StdioTransport


def test_SPEC_P0_004_stdio_transport_returns_standardized_upstream_error_on_timeout(tmp_path: Path):
    server = tmp_path / "slow_mcp.py"
    server.write_text(
        """
import time

time.sleep(2)
""".strip(),
        encoding="utf-8",
    )
    result = StdioTransport(sys.executable, [str(server)], timeout=0.05).call_tool("bad", {})
    assert result["isError"] is True
    assert "upstreamError" in result
    assert result["upstreamError"]["code"] in {"stdio_error", "timeout", "empty_response"}
