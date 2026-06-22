from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar, cast


class OpenRouterError(RuntimeError):
    """Raised when an OpenRouter request or response is invalid."""


_TRANSIENT_STATUS = {429, 500, 502, 503, 504}
_T = TypeVar("_T")


def _is_transient(exc: Exception) -> bool:
    """A network failure worth retrying (rate-limit, 5xx, connection error, timeout)."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _TRANSIENT_STATUS
    return isinstance(exc, urllib.error.URLError | TimeoutError)


def call_with_retry(
    operation: Callable[[], _T],
    *,
    attempts: int = 3,
    base_delay: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
) -> _T:
    """Run ``operation`` with exponential backoff on transient network failures."""
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001 — retry only transient failures; re-raise the rest
            last = exc
            if attempt + 1 < attempts and _is_transient(exc):
                sleep(base_delay * (2**attempt))
                continue
            raise
    raise last if last is not None else OpenRouterError("retry exhausted")


@dataclass(frozen=True)
class OpenRouterChatClient:
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"
    max_attempts: int = 3
    retry_base_delay: float = 0.5

    @classmethod
    def from_env(cls) -> OpenRouterChatClient:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise OpenRouterError("OPENROUTER_API_KEY is required for OpenRouter chat calls")
        return cls(api_key=api_key, base_url=os.environ.get("OPENROUTER_BASE_URL", cls.base_url))

    def complete_json(self, *, model: str, messages: list[dict[str, str]], timeout_seconds: int = 60) -> object:
        payload = json.dumps({"model": model, "messages": messages, "temperature": 0}).encode()
        request = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        def _do() -> dict[str, object]:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return cast(dict[str, object], json.loads(response.read().decode()))

        try:
            response_payload = call_with_retry(_do, attempts=self.max_attempts, base_delay=self.retry_base_delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OpenRouterError(f"OpenRouter chat request failed: {exc}") from exc

        content = _extract_message_content(response_payload)
        return parse_json_content(content)


@dataclass(frozen=True)
class OpenRouterEmbeddingClient:
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"
    max_attempts: int = 3
    retry_base_delay: float = 0.5

    @classmethod
    def from_env(cls) -> OpenRouterEmbeddingClient:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise OpenRouterError("OPENROUTER_API_KEY is required for OpenRouter embedding calls")
        return cls(api_key=api_key, base_url=os.environ.get("OPENROUTER_BASE_URL", cls.base_url))

    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
        payload = json.dumps({"model": model, "input": inputs}).encode()
        request = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/embeddings",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        def _do() -> dict[str, object]:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return cast(dict[str, object], json.loads(response.read().decode()))

        try:
            response_payload = call_with_retry(_do, attempts=self.max_attempts, base_delay=self.retry_base_delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OpenRouterError(f"OpenRouter embedding request failed: {exc}") from exc
        return parse_embedding_response(response_payload)


def parse_embedding_response(payload: object) -> list[list[float]]:
    if not isinstance(payload, dict):
        raise OpenRouterError("embedding response must be a JSON object")
    data = payload.get("data")
    if not isinstance(data, list):
        raise OpenRouterError("embedding response must include data list")
    vectors: list[list[float]] = []
    for item in data:
        if not isinstance(item, dict):
            raise OpenRouterError("embedding data item must be an object")
        embedding = item.get("embedding")
        if not isinstance(embedding, list) or not embedding:
            raise OpenRouterError("embedding data item must include embedding list")
        vector: list[float] = []
        for value in embedding:
            if not isinstance(value, int | float) or isinstance(value, bool):
                raise OpenRouterError("embedding values must be numeric")
            vector.append(float(value))
        vectors.append(vector)
    return vectors


def parse_json_content(content: str) -> object:
    stripped = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL)
    if fenced is not None:
        stripped = fenced.group(1).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise OpenRouterError(f"model response was not valid JSON: {exc}") from exc


def _extract_message_content(payload: object) -> str:
    if not isinstance(payload, dict):
        raise OpenRouterError("OpenRouter response must be a JSON object")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise OpenRouterError("OpenRouter response did not include choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise OpenRouterError("OpenRouter choice must be an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise OpenRouterError("OpenRouter choice did not include a message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise OpenRouterError("OpenRouter message content was empty")
    return content
