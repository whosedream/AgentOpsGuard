from types import SimpleNamespace

import openai
import pytest

from .mimo_client import MiMoClient, MiMoConfig


@pytest.mark.parametrize(
    ("base_url", "expects_thinking_extension"),
    [
        ("https://code.mmkg.cloud/v1", True),
        ("https://api.deepseek.com/v1", False),
    ],
)
def test_thinking_extension_is_only_sent_to_mimo(monkeypatch, base_url, expects_thinking_extension):
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
            )

    monkeypatch.setattr(
        openai,
        "OpenAI",
        lambda **_kwargs: SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())
        ),
    )
    client = MiMoClient(MiMoConfig(api_key="test-key", base_url=base_url, model="test-model"))

    assert client._call_api([{"role": "user", "content": "hello"}]) == "ok"
    assert ("extra_body" in captured) is expects_thinking_extension
