import json

import httpx
import pytest

from agentops_guard.backend.services import deepseek as deepseek_service
from agentops_guard.backend.services.deepseek import DeepSeekTransport


DEEPSEEK_CHAT_COMPLETIONS_URL = "https://api.deepseek.com/chat/completions"
CANARY_SECRET = "deepseek-canary-6df115c1-4d44-48e5-NEVER-LOG"


def resolve_credential(credential_ref: str) -> str:
    assert credential_ref == "cred_transport_test"
    return CANARY_SECRET


def test_chat_completions_posts_to_fixed_deepseek_origin_and_path():
    requests: list[httpx.Request] = []
    provider_response = {"id": "chatcmpl-fixed-target", "choices": []}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=provider_response)

    messages = [{"role": "user", "content": "Say hello"}]
    with httpx.Client(
        base_url="https://attacker.invalid",
        transport=httpx.MockTransport(handler),
    ) as client:
        result = DeepSeekTransport(client=client).chat_completions(
            credential_ref="cred_transport_test",
            resolve_credential=resolve_credential,
            model="deepseek-chat",
            messages=messages,
            max_tokens=16,
        )

    assert result == provider_response
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == DEEPSEEK_CHAT_COMPLETIONS_URL
    assert json.loads(request.content) == {
        "model": "deepseek-chat",
        "messages": messages,
        "max_tokens": 16,
    }


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_chat_completions_never_follows_redirects(status_code: int):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if str(request.url) == DEEPSEEK_CHAT_COMPLETIONS_URL:
            return httpx.Response(
                status_code,
                headers={"Location": "https://attacker.invalid/steal"},
                json={"detail": "redirect"},
            )
        return httpx.Response(200, json={"stolen": True})

    caught: httpx.HTTPStatusError | None = None
    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as client:
        try:
            DeepSeekTransport(client=client).chat_completions(
                credential_ref="cred_transport_test",
                resolve_credential=resolve_credential,
                model="deepseek-chat",
                messages=[{"role": "user", "content": "Do not redirect"}],
                max_tokens=8,
            )
        except httpx.HTTPStatusError as exc:
            caught = exc

    assert caught is not None
    assert caught.response.status_code == status_code
    assert [str(request.url) for request in requests] == [DEEPSEEK_CHAT_COMPLETIONS_URL]


def test_secret_is_only_in_final_authorization_header():
    requests: list[httpx.Request] = []
    provider_response = {
        "id": "chatcmpl-no-leak",
        "choices": [{"message": {"role": "assistant", "content": "safe"}}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=provider_response)

    messages = [{"role": "user", "content": "Return a safe answer"}]
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = DeepSeekTransport(client=client).chat_completions(
            credential_ref="cred_transport_test",
            resolve_credential=resolve_credential,
            model="deepseek-chat",
            messages=messages,
            max_tokens=32,
        )

    assert len(requests) == 1
    request = requests[0]
    assert request.headers.get_list("authorization") == [f"Bearer {CANARY_SECRET}"]

    other_headers = [
        (name, value)
        for name, value in request.headers.multi_items()
        if name.lower() != "authorization"
    ]
    request_body = json.loads(request.content)

    assert str(request.url) == DEEPSEEK_CHAT_COMPLETIONS_URL
    assert request.url.query == b""
    assert CANARY_SECRET not in json.dumps(other_headers)
    assert CANARY_SECRET not in json.dumps(request_body)
    assert CANARY_SECRET not in json.dumps(result)
    assert request_body == {
        "model": "deepseek-chat",
        "messages": messages,
        "max_tokens": 32,
    }
    assert result == provider_response


def test_managed_secret_in_messages_is_rejected_before_network_io():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError) as caught:
            DeepSeekTransport(client=client).chat_completions(
                credential_ref="cred_transport_test",
                resolve_credential=resolve_credential,
                model="deepseek-chat",
                messages=[{"role": "user", "content": CANARY_SECRET}],
                max_tokens=16,
            )

    assert requests == []
    assert CANARY_SECRET not in str(caught.value)


def test_json_escaping_cannot_hide_managed_secret_in_messages():
    requests: list[httpx.Request] = []
    quoted_secret = 'deepseek-canary-with-"-quote'

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError) as caught:
            DeepSeekTransport(client=client).chat_completions(
                credential_ref="cred_transport_test",
                resolve_credential=lambda _credential_ref: quoted_secret,
                model="deepseek-chat",
                messages=[{"role": "user", "content": quoted_secret}],
                max_tokens=16,
            )

    assert requests == []
    assert quoted_secret not in str(caught.value)


def test_managed_secret_in_provider_response_is_rejected_without_echo():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": CANARY_SECRET}}]},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError) as caught:
            DeepSeekTransport(client=client).chat_completions(
                credential_ref="cred_transport_test",
                resolve_credential=resolve_credential,
                model="deepseek-chat",
                messages=[{"role": "user", "content": "safe"}],
                max_tokens=16,
            )

    assert CANARY_SECRET not in str(caught.value)


def test_unicode_escaping_cannot_hide_managed_secret_in_provider_response():
    escaped_secret = "".join(f"\\u{ord(char):04x}" for char in CANARY_SECRET)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                '{"choices":[{"message":{"content":"'
                + escaped_secret
                + '"}}]}'
            ).encode(),
            headers={"content-type": "application/json"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError) as caught:
            DeepSeekTransport(client=client).chat_completions(
                credential_ref="cred_transport_test",
                resolve_credential=resolve_credential,
                model="deepseek-chat",
                messages=[{"role": "user", "content": "safe"}],
                max_tokens=16,
            )

    assert CANARY_SECRET not in str(caught.value)


def test_production_client_ignores_environment_proxy_configuration(
    monkeypatch: pytest.MonkeyPatch,
):
    client_options: dict[str, object] = {}
    real_client = httpx.Client

    def client_factory(**kwargs: object) -> httpx.Client:
        client_options.update(kwargs)
        return real_client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"choices": []})
            ),
            **kwargs,
        )

    monkeypatch.setattr(deepseek_service.httpx, "Client", client_factory)

    result = DeepSeekTransport().chat_completions(
        credential_ref="cred_transport_test",
        resolve_credential=resolve_credential,
        model="deepseek-chat",
        messages=[{"role": "user", "content": "safe"}],
        max_tokens=16,
    )

    assert result == {"choices": []}
    assert client_options["follow_redirects"] is False
    assert client_options["trust_env"] is False
