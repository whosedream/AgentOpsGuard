from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AgentOpsClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = "dev-agentops-key",
        timeout: float = 5.0,
        trust_env: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=timeout,
            headers={"X-AgentOps-Api-Key": api_key},
            trust_env=trust_env,
        )

    def create_run(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/runs", payload)

    def update_run(self, run_id: str, **payload: Any) -> dict[str, Any] | None:
        return self._patch(f"/v1/runs/{run_id}", payload)

    def record_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        return self._post("/v1/events", {"events": events})

    def evaluate_policy(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/policies/evaluate", payload)

    def scan(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/scanner/scan", payload)

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        try:
            response = self._client.post(f"{self.base_url}{path}", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            logger.warning("AgentOps Guard request failed: %s", exc)
            return None

    def _patch(self, path: str, payload: dict[str, Any]) -> Any:
        try:
            response = self._client.patch(f"{self.base_url}{path}", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            logger.warning("AgentOps Guard request failed: %s", exc)
            return None
