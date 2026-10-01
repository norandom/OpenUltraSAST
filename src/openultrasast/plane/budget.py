"""Budget metering for a task's model calls (ai-service-plane, Requirement 2.3 / 2.4).

`MeteredClient` wraps any `ChatClient`, sums the provider's usage fields per call, prices them from a Model
manifest's parameters, and stops the task at its ceiling. Two failure shapes are distinct on purpose: a ceiling
is `BudgetExhausted` (the task is `unfinished` and resumes under a larger budget), an account or authentication
failure is `AccountError` (the task is `failed` and the run starts nothing further). A model without prices is
`unpriced`, which is not zero dollars: such a client refuses a usd budget rather than reporting a clean 0.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from ..model.endpoint import Prices
from ..tool_hunter import ChatClient, ChatResponse

_ACCOUNT_MARKERS = ("HTTP Error 401", "HTTP Error 402", "Insufficient Balance")
_USAGE_FIELDS = ("prompt_tokens", "prompt_cache_hit_tokens", "completion_tokens")


class BudgetExhausted(RuntimeError):
    """Raised before a call would start once the usd or calls ceiling is reached."""

    def __init__(self, message: str, *, usd: float | None, calls: int) -> None:
        super().__init__(message)
        self.usd = usd
        self.calls = calls


class AccountError(RuntimeError):
    """Raised when the provider refuses the account: 401, 402 or an insufficient-balance body."""

    def __init__(self, provider_message: str) -> None:
        super().__init__(provider_message)
        self.provider_message = provider_message


def is_account_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker.lower() in text for marker in _ACCOUNT_MARKERS)


def prices_from(parameters: Mapping[str, object] | Prices | None) -> Prices | None:
    """Prices from a Model manifest's `spec.parameters` (or an existing `Prices`); None when any rate is missing."""
    if parameters is None or isinstance(parameters, Prices):
        return parameters
    values: list[float] = []
    for key in ("cache_hit_per_m", "input_per_m", "output_per_m"):
        value = parameters.get(key)
        if not isinstance(value, int | float) or isinstance(value, bool):
            return None
        values.append(float(value))
    return Prices(cache_hit_per_m=values[0], input_per_m=values[1], output_per_m=values[2])


def cost_of(usage: Mapping[str, object], prices: Prices) -> float:
    """Dollars for one call from the provider's usage fields, the arithmetic of `ChatEndpoint.cost`."""
    cache_hit = _tokens(usage.get("prompt_cache_hit_tokens"))
    miss = usage.get("prompt_cache_miss_tokens")
    input_tokens = _tokens(miss) if miss is not None else max(_tokens(usage.get("prompt_tokens")) - cache_hit, 0)
    output_tokens = _tokens(usage.get("completion_tokens"))
    return (cache_hit * prices.cache_hit_per_m + input_tokens * prices.input_per_m + output_tokens * prices.output_per_m) / 1_000_000


class MeteredClient:
    """A `ChatClient` that meters spend from the wrapped client's provider usage rows.

    The wrapped client is expected to record one usage dict per call in a `usage` list (as `DeepSeekChatClient`
    does); rows appended during a call are attributed to it. A client without that list still has its calls
    counted, with zero tokens.
    """

    def __init__(
        self,
        inner: ChatClient,
        *,
        prices: Mapping[str, object] | Prices | None = None,
        budget_usd: float | None = None,
        budget_calls: int | None = None,
    ) -> None:
        self.inner = inner
        self.prices = prices_from(prices)
        if budget_usd is not None and self.prices is None:
            raise ValueError("unpriced model cannot run under a usd budget")
        if budget_usd is not None and budget_usd < 0:
            raise ValueError("budget_usd must not be negative")
        if budget_calls is not None and budget_calls < 0:
            raise ValueError("budget_calls must not be negative")
        self.budget_usd = budget_usd
        self.budget_calls = budget_calls
        self.calls = 0
        self.usage: dict[str, int] = dict.fromkeys(_USAGE_FIELDS, 0)
        self._usd = 0.0
        self._seen_rows = len(self._inner_rows())

    @property
    def priced(self) -> bool:
        return self.prices is not None

    @property
    def usd(self) -> float | None:
        return self._usd if self.prices is not None else None

    def check(self) -> None:
        """Raise `BudgetExhausted` when the next call must not start."""
        if self.budget_usd is not None and self._usd >= self.budget_usd:
            raise BudgetExhausted(
                f"usd budget exhausted: spent {self._usd:.6f} of {self.budget_usd:.6f} after {self.calls} calls",
                usd=self._usd,
                calls=self.calls,
            )
        if self.budget_calls is not None and self.calls >= self.budget_calls:
            raise BudgetExhausted(f"calls budget exhausted: {self.calls} of {self.budget_calls}", usd=self.usd, calls=self.calls)

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
        json_object: bool = False,
        temperature: float | None = None,
        logprobs: bool = False,
    ) -> ChatResponse:
        """One metered call. ``temperature`` and ``logprobs`` pass through only when set, so a wrapped client that
        does not take them (a scripted one) is called as before."""
        self.check()
        extra: dict[str, Any] = {}
        if temperature is not None:
            extra["temperature"] = temperature
        if logprobs:
            extra["logprobs"] = True
        try:
            response = self.inner.complete(
                model=model, messages=messages, tools=tools, timeout_seconds=timeout_seconds, json_object=json_object, **extra
            )
        except Exception as exc:
            self._absorb_rows()
            if is_account_error(exc):
                raise AccountError(str(exc)) from exc
            raise
        self.calls += 1
        self._absorb_rows()
        return response

    def summary(self) -> dict[str, Any]:
        """The spend block of a task's `summary.json`: `usd` is None, not 0, for an unpriced model."""
        return {"usd": self.usd, "calls": self.calls, "usage": dict(self.usage), "priced": self.priced}

    def _inner_rows(self) -> list[Any]:
        rows = getattr(self.inner, "usage", None)
        return rows if isinstance(rows, list) else []

    def _absorb_rows(self) -> None:
        rows = self._inner_rows()
        for row in rows[self._seen_rows :]:
            if not isinstance(row, Mapping):
                continue
            for field in _USAGE_FIELDS:
                self.usage[field] += _tokens(row.get(field))
            if self.prices is not None:
                self._usd += cost_of(row, self.prices)
        self._seen_rows = len(rows)


def _tokens(value: object) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0


class EmbeddingClient(Protocol):
    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]: ...


class UnmeteredUsage(RuntimeError):
    """A priced embedding call whose provider reported no tokens: a working-looking zero, never a free call."""


class MeteredEmbeddingClient:
    """An embedding client metered like :class:`MeteredClient`: the wrapped client records one usage dict per call
    in a ``usage`` list (``OpenRouterEmbeddingClient`` does), ``prompt_tokens`` are priced at the Model manifest's
    ``input_per_m``, and the usd/calls ceilings stop the next call. A priced call that reports no tokens raises
    :class:`UnmeteredUsage` (the 2026-09 lesson: a silent zero is an instrument failure)."""

    def __init__(
        self,
        inner: EmbeddingClient,
        *,
        prices: Mapping[str, object] | Prices | None = None,
        budget_usd: float | None = None,
        budget_calls: int | None = None,
        require_usage: bool = True,
    ) -> None:
        self.inner = inner
        self.prices = prices_from(prices)
        if budget_usd is not None and self.prices is None:
            raise ValueError("unpriced model cannot run under a usd budget")
        self.budget_usd, self.budget_calls, self.require_usage = budget_usd, budget_calls, require_usage
        self.calls = 0
        self.tokens = 0
        self._usd = 0.0
        self._seen_rows = len(self._inner_rows())

    @property
    def usd(self) -> float | None:
        return self._usd if self.prices is not None else None

    def check(self) -> None:
        if self.budget_usd is not None and self._usd >= self.budget_usd:
            raise BudgetExhausted(f"usd budget exhausted: spent {self._usd:.6f} of {self.budget_usd:.6f}", usd=self._usd, calls=self.calls)
        if self.budget_calls is not None and self.calls >= self.budget_calls:
            raise BudgetExhausted(f"calls budget exhausted: {self.calls} of {self.budget_calls}", usd=self.usd, calls=self.calls)

    def embed(self, *, model: str, inputs: list[str], timeout_seconds: int = 60) -> list[list[float]]:
        self.check()
        try:
            vectors = self.inner.embed(model=model, inputs=inputs, timeout_seconds=timeout_seconds)
        except Exception as exc:
            self._absorb_rows()
            if is_account_error(exc):
                raise AccountError(str(exc)) from exc
            raise
        self.calls += 1
        tokens = self._absorb_rows()
        if self.require_usage and self.prices is not None and tokens == 0 and inputs:
            raise UnmeteredUsage(
                f"embedding call {self.calls} reported no prompt tokens for {len(inputs)} inputs: the meter cannot price it"
            )
        return vectors

    def summary(self) -> dict[str, Any]:
        return {"usd": self.usd, "calls": self.calls, "usage": {"prompt_tokens": self.tokens}, "priced": self.prices is not None}

    def _inner_rows(self) -> list[Any]:
        rows = getattr(self.inner, "usage", None)
        return rows if isinstance(rows, list) else []

    def _absorb_rows(self) -> int:
        rows = self._inner_rows()
        tokens = 0
        for row in rows[self._seen_rows :]:
            if isinstance(row, Mapping):
                tokens += _tokens(row.get("prompt_tokens") or row.get("total_tokens"))
        self._seen_rows = len(rows)
        self.tokens += tokens
        if self.prices is not None:
            self._usd += tokens * self.prices.input_per_m / 1_000_000
        return tokens


__all__ = [
    "AccountError", "BudgetExhausted", "EmbeddingClient", "MeteredClient", "MeteredEmbeddingClient", "UnmeteredUsage", "cost_of",
    "is_account_error", "prices_from",
]  # fmt: skip
