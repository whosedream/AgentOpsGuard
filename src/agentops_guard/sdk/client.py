from __future__ import annotations

import logging
from collections import deque
from threading import Event, Lock, Thread
from time import sleep
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
        *,
        batch_size: int = 25,
        flush_interval: float = 1.0,
        max_retries: int = 3,
        fail_closed: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.fail_closed = fail_closed
        self._client = httpx.Client(
            timeout=timeout,
            headers={"X-AgentOps-Api-Key": api_key},
            trust_env=trust_env,
        )
        self._event_queue: deque[dict[str, Any]] = deque()
        self._queue_lock = Lock()
        self._stop_event = Event()
        self._worker: Thread | None = None

    def create_run(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/runs", payload)

    def update_run(self, run_id: str, **payload: Any) -> dict[str, Any] | None:
        return self._patch(f"/v1/runs/{run_id}", payload)

    def record_events(self, events: list[dict[str, Any]], *, immediate: bool = True) -> list[dict[str, Any]] | None:
        if immediate:
            return self._post("/v1/events", {"events": events})
        with self._queue_lock:
            self._event_queue.extend(events)
        self._ensure_worker()
        if len(self._event_queue) >= self.batch_size:
            self.flush()
        return events

    def evaluate_policy(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/policies/evaluate", payload)

    def scan(self, **payload: Any) -> dict[str, Any] | None:
        return self._post("/v1/scanner/scan", payload)

    def flush(self) -> None:
        attempts = 0
        while True:
            batch = self._pop_batch()
            if not batch:
                return
            result = self._post("/v1/events", {"events": batch})
            if result is not None:
                attempts = 0
                continue
            attempts += 1
            if attempts > self.max_retries:
                if self.fail_closed:
                    raise RuntimeError("AgentOps event export failed after retries")
                logger.warning("AgentOps event export dropped after retries: %s events", len(batch))
                attempts = 0
                continue
            with self._queue_lock:
                for item in reversed(batch):
                    self._event_queue.appendleft(item)
            sleep(min(0.2 * attempts, 1.0))

    def close(self) -> None:
        self.flush()
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=1.0)
        self._client.close()

    def _ensure_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._worker = Thread(target=self._run_export_loop, daemon=True)
        self._worker.start()

    def _run_export_loop(self) -> None:
        while not self._stop_event.wait(self.flush_interval):
            if self._event_queue:
                self.flush()

    def _pop_batch(self) -> list[dict[str, Any]]:
        with self._queue_lock:
            batch: list[dict[str, Any]] = []
            while self._event_queue and len(batch) < self.batch_size:
                batch.append(self._event_queue.popleft())
            return batch

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        try:
            response = self._client.post(f"{self.base_url}{path}", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            logger.warning("AgentOps Guard request failed: %s", exc)
            if self.fail_closed and path != "/v1/events":
                raise
            return None

    def _patch(self, path: str, payload: dict[str, Any]) -> Any:
        try:
            response = self._client.patch(f"{self.base_url}{path}", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            logger.warning("AgentOps Guard request failed: %s", exc)
            if self.fail_closed:
                raise
            return None
