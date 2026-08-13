from collections.abc import Callable
from typing import Any

import httpx

DEEPSEEK_CHAT_COMPLETIONS_URL = "https://api.deepseek.com/chat/completions"


class DeepSeekTransport:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def chat_completions(
        self,
        *,
        credential_ref: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int | None,
        resolve_credential: Callable[[str], str],
    ) -> dict[str, Any]:
        secret = resolve_credential(credential_ref)
        body: dict[str, Any] = {"model": model, "messages": messages}
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if _contains_exact_secret(body, secret):
            raise ValueError("request contains a managed credential")
        authorization = f"Bearer {secret}"
        if self._client is None:
            with httpx.Client(
                timeout=30.0,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.post(
                    DEEPSEEK_CHAT_COMPLETIONS_URL,
                    headers={"Authorization": authorization},
                    json=body,
                )
        else:
            request = self._client.build_request(
                "POST",
                DEEPSEEK_CHAT_COMPLETIONS_URL,
                headers={"Authorization": authorization},
                json=body,
            )
            response = self._client.send(request, follow_redirects=False)
        response.raise_for_status()
        response_body = response.json()
        if _contains_exact_secret(response_body, secret):
            raise ValueError("response contains a managed credential")
        return response_body


def _contains_exact_secret(value: Any, secret: str) -> bool:
    if isinstance(value, str):
        return secret in value
    if isinstance(value, list):
        return any(_contains_exact_secret(item, secret) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_exact_secret(key, secret)
            or _contains_exact_secret(item, secret)
            for key, item in value.items()
        )
    return False
