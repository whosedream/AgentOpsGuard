from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19091)
    args = parser.parse_args()
    if not args.database.is_absolute():
        raise ValueError("--database must be an absolute path")

    os.environ.update(
        {
            "ENVIRONMENT": "development",
            "DATABASE_URL": f"sqlite:///{args.database}",
            "JWT_SECRET_KEY": secrets.token_urlsafe(64),
            "AUTH_ENCRYPTION_SECRET": secrets.token_urlsafe(64),
            "BASIC_AUTH_PASSWORD": secrets.token_urlsafe(32),
            "PLATFORM_ADMIN_PASSWORD": secrets.token_urlsafe(32),
            "AUTH_REQUIRED": "false",
            "ALLOW_UNAUTHENTICATED_ADMIN": "true",
            "MCP_REQUIRE_AUTH": "false",
            "MCPGATEWAY_UI_ENABLED": "false",
            "MCPGATEWAY_ADMIN_API_ENABLED": "true",
            "SSRF_ALLOW_LOCALHOST": "true",
            "SSRF_PROTECTION_ENABLED": "true",
            "RATE_LIMITING_ENABLED": "false",
            "LOG_LEVEL": "WARNING",
        }
    )
    executable = Path(sys.executable).parent / "mcpgateway"
    os.execv(
        executable,
        [
            "mcpgateway",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--no-access-log",
            "--log-level",
            "warning",
        ],
    )


if __name__ == "__main__":
    main()
