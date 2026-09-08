"""learning-harness task 1.2: the chat endpoint resolves independently of embeddings (offline)."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from openultrasast.config import ResolvedConfig
from openultrasast.provider import openrouter as provider


class _Recorder:
    """Stands in for OpenRouterChatClient.complete_chat and records what the adapter asked for."""

    def __init__(self, replies: list[dict[str, object]]) -> None:
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    def complete_chat(self, **kwargs: Any) -> dict[str, object]:
        self.calls.append(kwargs)
        return self.replies[min(len(self.calls) - 1, len(self.replies) - 1)]


def _endpoint_env(monkeypatch: pytest.MonkeyPatch, **values: str | None) -> None:
    for name in ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "OPENULTRASAST_HUNTER_CLIENT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        if value is not None:
            monkeypatch.setenv(name, value)


def test_deepseek_wins_over_openrouter_and_never_touches_the_embedding_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.model.endpoint import DEEPSEEK_BASE_URL, resolve_chat_endpoint

    _endpoint_env(monkeypatch, DEEPSEEK_API_KEY="ds-key", OPENROUTER_API_KEY="or-key", OPENROUTER_BASE_URL="https://openrouter.ai/api/v1")
    resolved = resolve_chat_endpoint(ResolvedConfig())
    assert resolved is not None
    _client, endpoint = resolved
    assert endpoint.provider == "deepseek" and endpoint.base_url == DEEPSEEK_BASE_URL
    assert not endpoint.base_url.endswith("/v1")  # DeepSeek rejects the version suffix
    assert "api_key" not in {field for field in endpoint.__dict__}  # the key stays on the client, never in a journaled record
    embedding = provider.OpenRouterEmbeddingClient.from_env()
    assert embedding.base_url == "https://openrouter.ai/api/v1" and embedding.api_key == "or-key"


def test_resolution_order_override_then_scripted_then_openrouter_then_none(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.model.endpoint import resolve_chat_endpoint
    from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient

    injected = ScriptedChatClient([ChatResponse(content="{}")])
    _endpoint_env(monkeypatch, DEEPSEEK_API_KEY="ds-key")
    resolved = resolve_chat_endpoint(ResolvedConfig(), override=injected)
    assert resolved is not None and resolved[0] is injected and resolved[1].provider == "scripted"

    _endpoint_env(monkeypatch, DEEPSEEK_API_KEY="ds-key", OPENULTRASAST_HUNTER_CLIENT="scripted")
    resolved = resolve_chat_endpoint(ResolvedConfig())
    assert resolved is not None and resolved[1].provider == "scripted"

    _endpoint_env(monkeypatch, OPENROUTER_API_KEY="or-key")
    resolved = resolve_chat_endpoint(ResolvedConfig())
    assert resolved is not None and resolved[1].provider == "openrouter" and resolved[1].base_url.endswith("/api/v1")

    _endpoint_env(monkeypatch)
    assert resolve_chat_endpoint(ResolvedConfig()) is None


def test_a_provider_that_refuses_to_build_degrades_to_no_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.model.endpoint import resolve_chat_endpoint

    _endpoint_env(monkeypatch, OPENROUTER_API_KEY="or-key")

    def _refuse() -> provider.OpenRouterChatClient:
        raise provider.OpenRouterError("no key after all")

    monkeypatch.setattr(provider.OpenRouterChatClient, "from_env", staticmethod(_refuse))
    assert resolve_chat_endpoint(ResolvedConfig()) is None  # a caller degrades; nothing raises into a scan


def test_the_config_can_point_the_chat_endpoint_somewhere_else(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    from openultrasast.config import load_config
    from openultrasast.model.endpoint import resolve_chat_endpoint, resolve_models

    _endpoint_env(monkeypatch, MY_KEY="local-key")
    monkeypatch.setenv("MY_KEY", "local-key")
    (tmp_path / "ousast.toml").write_text(
        '[models]\njudge = "deepseek-v4-pro"\nchat_base_url = "http://localhost:11434/v1"\nchat_api_key_env = "MY_KEY"\n'
    )
    config = load_config(tmp_path / "ousast.toml")
    resolved = resolve_chat_endpoint(config)
    assert resolved is not None and resolved[1].base_url == "http://localhost:11434/v1"
    detector, judge = resolve_models(config)
    assert detector == "deepseek-v4-flash" and judge == "deepseek-v4-pro"


def test_the_adapter_disables_thinking_asks_for_json_and_keeps_the_reasoning_field() -> None:
    from openultrasast.model.endpoint import DeepSeekChatClient

    recorder = _Recorder([{"content": '{"intent": "public"}', "reasoning_content": "step one"}])
    client = DeepSeekChatClient(recorder)  # type: ignore[arg-type]
    response = client.complete(model="deepseek-v4-flash", messages=[{"role": "user", "content": "json please"}], tools=[], json_object=True)
    assert response.content == '{"intent": "public"}' and response.reasoning == "step one"
    body = recorder.calls[0]["extra_body"]
    assert body["thinking"] == {"type": "disabled"}  # otherwise temperature is silently ignored
    assert body["response_format"] == {"type": "json_object"} and "logprobs" not in body


def test_the_adapter_retries_once_on_empty_json_content_then_gives_up() -> None:
    from openultrasast.model.endpoint import DeepSeekChatClient

    recorder = _Recorder([{"content": ""}, {"content": '{"ok": true}'}])
    client = DeepSeekChatClient(recorder)  # type: ignore[arg-type]
    assert client.complete(model="m", messages=[], tools=[], json_object=True).content == '{"ok": true}'
    assert len(recorder.calls) == 2
    empty = _Recorder([{"content": ""}, {"content": ""}])
    client = DeepSeekChatClient(empty)  # type: ignore[arg-type]
    assert client.complete(model="m", messages=[], tools=[], json_object=True).content == ""
    assert len(empty.calls) == 2  # one retry, never a loop


def test_log_probabilities_are_requested_only_when_asked_for() -> None:
    from openultrasast.model.endpoint import DeepSeekChatClient

    recorder = _Recorder([{"content": "{}", "logprobs": {"content": [{"logprob": -0.1}, {"logprob": -0.3}]}}])
    client = DeepSeekChatClient(recorder)  # type: ignore[arg-type]
    response = client.complete(model="m", messages=[], tools=[], json_object=True, logprobs=True)
    assert recorder.calls[0]["extra_body"]["logprobs"] is True
    assert response.mean_logprob is not None and -0.3 < response.mean_logprob < -0.1


def test_cost_comes_from_the_providers_own_usage_fields() -> None:
    from openultrasast.model.endpoint import ChatEndpoint, price_of

    flash = ChatEndpoint(provider="deepseek", base_url="https://api.deepseek.com", thinking=False, prices=price_of("deepseek-v4-flash"))
    cost = flash.cost({"prompt_cache_hit_tokens": 1_000_000, "prompt_cache_miss_tokens": 1_000_000, "completion_tokens": 1_000_000})
    assert cost is not None and abs(cost - (0.014 + 0.44 + 1.32)) < 1e-9
    openrouter_shape = flash.cost({"prompt_tokens": 1_000_000, "completion_tokens": 0})
    assert openrouter_shape is not None and abs(openrouter_shape - 0.44) < 1e-9  # no cache split reported: all miss
    unpriced = ChatEndpoint(provider="openrouter", base_url="x", thinking=False, prices=price_of("some/unknown-model"))
    assert unpriced.cost({"prompt_tokens": 10}) is None  # never claim a cost we cannot source


def test_the_underlying_client_forwards_extra_body_and_keeps_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, object] = {}

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"choices": [{"message": {"content": "hi", "reasoning_content": "because"}}], "usage": {"prompt_tokens": 7}}
            ).encode()

    def _urlopen(request: Any, timeout: int = 0) -> _Response:  # noqa: ARG001
        sent.update(json.loads(request.data.decode()))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    client = provider.OpenRouterChatClient(api_key="k", base_url="https://api.deepseek.com")
    payload = client.complete_chat_raw(
        model="deepseek-v4-flash", messages=[{"role": "user", "content": "x"}], extra_body={"thinking": {"type": "disabled"}}
    )
    assert sent["thinking"] == {"type": "disabled"} and sent["temperature"] == 0
    assert payload["usage"] == {"prompt_tokens": 7}
    message = provider._extract_message(payload)
    assert message["reasoning_content"] == "because"  # retained for the caller to replay


def test_logprobs_are_read_off_the_choice_where_the_provider_puts_them() -> None:
    """OpenAI-shaped providers put `logprobs` on the choice, not on the message.

    `_message_of` returned only `choices[0].message`, so the confidence signal the classifier is supposed to
    abstain on was always `None` — a knob that reads as "never unsure" whatever the model said."""
    from openultrasast.model.endpoint import _message_of

    payload = {
        "choices": [
            {
                "message": {"content": "yes", "role": "assistant"},
                "logprobs": {"content": [{"token": "yes", "logprob": -0.5}, {"token": "!", "logprob": -1.5}]},
            }
        ]
    }
    message = _message_of(payload)
    assert message["content"] == "yes"
    from openultrasast.tool_hunter import chat_response_from_message

    assert chat_response_from_message(message).mean_logprob == pytest.approx(-1.0)


def test_a_reply_without_logprobs_reports_none_rather_than_a_number() -> None:
    from openultrasast.model.endpoint import _message_of
    from openultrasast.tool_hunter import chat_response_from_message

    message = _message_of({"choices": [{"message": {"content": "yes"}}]})
    assert chat_response_from_message(message).mean_logprob is None


def test_thinking_is_a_measured_condition_on_the_models_section() -> None:
    """The knob moved from `[learning]` to `[models]` with the noise architecture's removal.

    Thinking is off by default because that is what the committed baseline was measured under — the provider
    silently ignores `temperature` while thinking — not because it is known to be better.
    """
    from openultrasast.config import load_config

    assert load_config(None).models.thinking is False


def test_the_config_can_turn_thinking_on(tmp_path: Path) -> None:
    from openultrasast.config import load_config

    path = tmp_path / "ousast.toml"
    path.write_text("[models]\nthinking = true\n")
    assert load_config(path).models.thinking is True
    path.write_text("[models]\nthinking = false\n")
    assert load_config(path).models.thinking is False
