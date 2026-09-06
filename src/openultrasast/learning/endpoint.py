"""The chat endpoint, resolved independently of embeddings (learning-harness, Req 6.6).

Detectors, the classifier's model tier, the proposer and the judge all talk to one chat endpoint;
prove-order retrieval keeps its own embedding endpoint, because the chat provider we default to has
none. Resolution order is explicit override, the scripted client flag, an endpoint named in the
config, DeepSeek, then OpenRouter. ``DeepSeekChatClient`` adapts the provider's quirks: thinking is
on by default there and silently ignores ``temperature``, so it is disabled explicitly; the reasoning
field is kept on the reply for the caller to replay across tool turns; JSON mode has no schema and
occasionally returns empty content, so one retry is built in. Prices are data, and an unpriced model
reports no cost rather than a made-up one.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ..config import ResolvedConfig
from ..provider.openrouter import OpenRouterChatClient, OpenRouterError
from ..tool_hunter import CLIENT_ENV, ChatClient, ChatResponse, chat_response_from_message, scripted_hunter_client

DEEPSEEK_BASE_URL = "https://api.deepseek.com"  # no version suffix: the platform rejects /v1
DEEPSEEK_KEY_ENV = "DEEPSEEK_API_KEY"
DEEPSEEK_BASE_ENV = "DEEPSEEK_BASE_URL"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_DETECTOR_MODEL = "deepseek-v4-flash"
DEFAULT_JUDGE_MODEL = "deepseek-v4-pro"
Provider = Literal["deepseek", "openrouter", "custom", "scripted"]
_SCRIPTED_FLAGS = frozenset({"scripted", "script", "dump", "dump-only", "unsafe", "unsafe-snippet"})


@dataclass(frozen=True)
class Prices:
    """USD per million tokens. DeepSeek platform pricing, peak rate, recorded 2026-09-06."""

    cache_hit_per_m: float
    input_per_m: float
    output_per_m: float


_PRICES: dict[str, Prices] = {
    "deepseek-v4-flash": Prices(cache_hit_per_m=0.014, input_per_m=0.44, output_per_m=1.32),
    "deepseek-v4-flash-vision-exp": Prices(cache_hit_per_m=0.014, input_per_m=0.44, output_per_m=1.32),
    "deepseek-v4-pro": Prices(cache_hit_per_m=0.044, input_per_m=1.32, output_per_m=3.96),
}


def price_of(model: str) -> Prices | None:
    return _PRICES.get(model.strip())


@dataclass(frozen=True)
class ChatEndpoint:
    """What the run should record about where the model calls went. Never holds the key."""

    provider: Provider
    base_url: str
    thinking: bool  # the provider's models reason by default, so the adapter disables it explicitly
    prices: Prices | None = None

    def cost(self, usage: Mapping[str, object] | None) -> float | None:
        """Dollars for one call from the provider's own usage fields, or None when the model has no recorded price."""
        if self.prices is None or not isinstance(usage, Mapping):
            return None
        cache_hit = _tokens(usage.get("prompt_cache_hit_tokens"))
        miss = usage.get("prompt_cache_miss_tokens")
        input_tokens = _tokens(miss) if miss is not None else max(_tokens(usage.get("prompt_tokens")) - cache_hit, 0)
        output_tokens = _tokens(usage.get("completion_tokens"))
        return (
            cache_hit * self.prices.cache_hit_per_m + input_tokens * self.prices.input_per_m + output_tokens * self.prices.output_per_m
        ) / 1_000_000


class DeepSeekChatClient:
    """Adapt an OpenAI-shaped chat client to what detectors and the classifier need."""

    def __init__(self, client: OpenRouterChatClient, *, disable_thinking: bool = True, endpoint: ChatEndpoint | None = None) -> None:
        self._client = client
        self._disable_thinking = disable_thinking
        self.endpoint = endpoint
        self.usage: list[dict[str, object]] = []  # one entry per call, for the round's cost meter

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
        json_object: bool = False,
        logprobs: bool = False,
    ) -> ChatResponse:
        response = self._call(
            model=model, messages=messages, tools=tools, timeout_seconds=timeout_seconds, json_object=json_object, logprobs=logprobs
        )
        if json_object and not (response.content or "").strip():
            response = self._call(
                model=model, messages=messages, tools=tools, timeout_seconds=timeout_seconds, json_object=json_object, logprobs=logprobs
            )  # documented behaviour: JSON mode occasionally returns empty content. One retry, never a loop.
        return response

    def cost_usd(self) -> float:
        """Recorded cost of the calls made so far; calls whose model has no price contribute nothing."""
        if self.endpoint is None:
            return 0.0
        return sum(self.endpoint.cost(entry) or 0.0 for entry in self.usage)

    def _call(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, object]],
        tools: Sequence[Mapping[str, object]],
        timeout_seconds: int,
        json_object: bool,
        logprobs: bool,
    ) -> ChatResponse:
        extra: dict[str, object] = {}
        if self._disable_thinking:
            extra["thinking"] = {"type": "disabled"}  # otherwise temperature is silently ignored
        if json_object:
            extra["response_format"] = {"type": "json_object"}
        if logprobs:
            extra["logprobs"] = True
            extra["top_logprobs"] = 1
        raw = getattr(self._client, "complete_chat_raw", None)
        if callable(raw):
            payload = raw(
                model=model, messages=list(messages), tools=list(tools) or None, timeout_seconds=timeout_seconds, extra_body=extra
            )
            usage = payload.get("usage") if isinstance(payload, dict) else None
            if isinstance(usage, dict):
                self.usage.append(dict(usage))
            message = _message_of(payload)
        else:  # a stub or a client without the raw call
            message = self._client.complete_chat(
                model=model, messages=list(messages), tools=list(tools) or None, timeout_seconds=timeout_seconds, extra_body=extra
            )
        return chat_response_from_message(message)


def resolve_chat_endpoint(config: ResolvedConfig, *, override: ChatClient | None = None) -> tuple[ChatClient, ChatEndpoint] | None:
    """The chat client for detectors, classifier, proposer and judge, with what to record about it."""
    if override is not None:
        return override, ChatEndpoint(provider="scripted", base_url="", thinking=False)
    flag = os.environ.get(CLIENT_ENV, "").strip().lower()
    if flag in _SCRIPTED_FLAGS:
        return scripted_hunter_client(flag), ChatEndpoint(provider="scripted", base_url="", thinking=False)
    model = resolve_models(config)[0]
    configured = config.models.chat_base_url
    key_env = config.models.chat_api_key_env
    if configured or key_env:
        key = os.environ.get(key_env or DEEPSEEK_KEY_ENV, "")
        base_url = configured or DEEPSEEK_BASE_URL
        return _deepseek_client(key, base_url, model, provider=_provider_of(base_url))
    deepseek_key = os.environ.get(DEEPSEEK_KEY_ENV)
    if deepseek_key:
        return _deepseek_client(deepseek_key, os.environ.get(DEEPSEEK_BASE_ENV, DEEPSEEK_BASE_URL), model, provider="deepseek")
    if os.environ.get("OPENROUTER_API_KEY"):
        try:
            client = OpenRouterChatClient.from_env()
        except OpenRouterError:
            return None
        endpoint = ChatEndpoint(provider="openrouter", base_url=client.base_url, thinking=False, prices=price_of(model))
        return DeepSeekChatClient(client, disable_thinking=False, endpoint=endpoint), endpoint
    return None


def resolve_models(config: ResolvedConfig) -> tuple[str, str]:
    """(detector model, judge model). `[learning]` wins, then `[models]`, then the shipped defaults."""
    detector = config.learning.detector_model or config.models.hunter or DEFAULT_DETECTOR_MODEL
    judge = config.learning.judge_model or config.models.judge or DEFAULT_JUDGE_MODEL
    return detector, judge


def _deepseek_client(key: str, base_url: str, model: str, *, provider: Provider) -> tuple[ChatClient, ChatEndpoint]:
    endpoint = ChatEndpoint(provider=provider, base_url=base_url.rstrip("/"), thinking=True, prices=price_of(model))
    client = OpenRouterChatClient(api_key=key, base_url=endpoint.base_url)
    return DeepSeekChatClient(client, endpoint=endpoint), endpoint


def _provider_of(base_url: str) -> Provider:
    host = base_url.lower()
    if "deepseek" in host:
        return "deepseek"
    return "openrouter" if "openrouter" in host else "custom"


def _message_of(payload: object) -> Mapping[str, object]:
    if isinstance(payload, Mapping):
        choices = payload.get("choices")
        if isinstance(choices, Sequence) and choices and isinstance(choices[0], Mapping):
            message = choices[0].get("message")
            if isinstance(message, Mapping):
                return message
    return {}


def _tokens(value: object) -> int:
    return int(value) if isinstance(value, int | float) else 0


__all__ = [
    "DEEPSEEK_BASE_URL",
    "DEFAULT_DETECTOR_MODEL",
    "DEFAULT_JUDGE_MODEL",
    "ChatEndpoint",
    "DeepSeekChatClient",
    "Prices",
    "price_of",
    "resolve_chat_endpoint",
    "resolve_models",
]
