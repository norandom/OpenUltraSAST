from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass


class OpenRouterError(RuntimeError):
    """Raised when an OpenRouter request or response is invalid."""


@dataclass(frozen=True)
class OpenRouterChatClient:
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"

    @classmethod
    def from_env(cls) -> "OpenRouterChatClient":
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
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                response_payload = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OpenRouterError(f"OpenRouter chat request failed: {exc}") from exc

        content = _extract_message_content(response_payload)
        return parse_json_content(content)


@dataclass(frozen=True)
class OpenRouterEmbeddingClient:
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"

    @classmethod
    def from_env(cls) -> "OpenRouterEmbeddingClient":
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
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                response_payload = json.loads(response.read().decode())
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
