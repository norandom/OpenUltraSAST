"""Budget metering (ai-service-plane task 2): ceilings, account errors, unpriced refusal, cache-hit pricing."""

from __future__ import annotations

import pytest

from openultrasast.model.endpoint import Prices
from openultrasast.plane.budget import AccountError, BudgetExhausted, MeteredClient, cost_of, prices_from
from openultrasast.tool_hunter import ChatResponse

FLASH = {"cache_hit_per_m": 0.014, "input_per_m": 0.44, "output_per_m": 1.32}
MESSAGES: list[dict[str, object]] = [{"role": "user", "content": "hi"}]


class UsageClient:
    """Records provider usage rows like DeepSeekChatClient; a scripted step may raise instead."""

    def __init__(self, steps: list[dict[str, object] | Exception]) -> None:
        self.steps = list(steps)
        self.usage: list[dict[str, object]] = []
        self.calls = 0

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
        json_object: bool = False,
    ) -> ChatResponse:
        self.calls += 1
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        self.usage.append(dict(step))
        return ChatResponse(content="ok")


def _row(prompt: int, cache_hit: int, completion: int) -> dict[str, object]:
    return {"prompt_tokens": prompt, "prompt_cache_hit_tokens": cache_hit, "completion_tokens": completion}


def _call(client: MeteredClient) -> ChatResponse:
    return client.complete(model="m", messages=MESSAGES, tools=[])


def test_cache_hit_pricing_is_exact_dollars() -> None:
    # 1_000_000 prompt tokens of which 250_000 hit the cache, 100_000 completion tokens:
    # 250_000 * 0.014/M + 750_000 * 0.44/M + 100_000 * 1.32/M = 0.0035 + 0.33 + 0.132
    inner = UsageClient([_row(1_000_000, 250_000, 100_000)])
    metered = MeteredClient(inner, prices=FLASH)
    _call(metered)
    assert metered.usd == pytest.approx(0.4655, abs=1e-12)
    assert metered.calls == 1
    assert metered.usage == {"prompt_tokens": 1_000_000, "prompt_cache_hit_tokens": 250_000, "completion_tokens": 100_000}


def test_cost_of_honours_explicit_cache_miss_field() -> None:
    prices = Prices(cache_hit_per_m=1.0, input_per_m=10.0, output_per_m=100.0)
    row = {"prompt_tokens": 30, "prompt_cache_hit_tokens": 10, "prompt_cache_miss_tokens": 20, "completion_tokens": 5}
    assert cost_of(row, prices) == pytest.approx((10 * 1.0 + 20 * 10.0 + 5 * 100.0) / 1_000_000)


def test_usage_sums_across_calls() -> None:
    inner = UsageClient([_row(100, 40, 10), _row(200, 0, 20)])
    metered = MeteredClient(inner, prices=FLASH)
    _call(metered)
    _call(metered)
    assert metered.usage == {"prompt_tokens": 300, "prompt_cache_hit_tokens": 40, "completion_tokens": 30}
    expected = (40 * 0.014 + 60 * 0.44 + 10 * 1.32 + 200 * 0.44 + 20 * 1.32) / 1_000_000
    assert metered.usd == pytest.approx(expected)


def test_usd_ceiling_stops_before_the_next_call() -> None:
    # each call costs exactly 1.32 usd (1M completion tokens); the budget of 2.0 admits two calls, not three
    inner = UsageClient([_row(0, 0, 1_000_000)] * 3)
    metered = MeteredClient(inner, prices=FLASH, budget_usd=2.0)
    _call(metered)
    _call(metered)
    with pytest.raises(BudgetExhausted) as info:
        _call(metered)
    assert inner.calls == 2, "the third call must not reach the provider"
    assert info.value.calls == 2
    assert info.value.usd == pytest.approx(2.64)
    assert isinstance(info.value, RuntimeError)


def test_calls_ceiling_stops_before_the_next_call() -> None:
    inner = UsageClient([_row(1, 0, 1)] * 3)
    metered = MeteredClient(inner, prices=FLASH, budget_calls=2)
    _call(metered)
    _call(metered)
    with pytest.raises(BudgetExhausted) as info:
        _call(metered)
    assert inner.calls == 2
    assert info.value.calls == 2


def test_zero_calls_budget_refuses_the_first_call() -> None:
    inner = UsageClient([_row(1, 0, 1)])
    metered = MeteredClient(inner, budget_calls=0)
    with pytest.raises(BudgetExhausted):
        _call(metered)
    assert inner.calls == 0


@pytest.mark.parametrize(
    "message",
    [
        'OpenRouter chat request failed: HTTPError: HTTP Error 402: Payment Required: {"error":{"message":"Insufficient credits"}}',
        "OpenRouter chat request failed: HTTPError: HTTP Error 401: Unauthorized",
        'DeepSeek chat request failed: {"error":{"message":"Insufficient Balance","type":"unknown_error"}}',
    ],
)
def test_account_errors_are_distinct_and_carry_the_provider_message(message: str) -> None:
    inner = UsageClient([RuntimeError(message)])
    metered = MeteredClient(inner, prices=FLASH, budget_usd=5.0)
    with pytest.raises(AccountError) as info:
        _call(metered)
    assert info.value.provider_message == message
    assert isinstance(info.value.__cause__, RuntimeError)
    assert metered.calls == 0


def test_other_provider_errors_pass_through_unchanged() -> None:
    inner = UsageClient([RuntimeError("OpenRouter chat request failed: HTTPError: HTTP Error 503: Service Unavailable")])
    metered = MeteredClient(inner, prices=FLASH)
    with pytest.raises(RuntimeError, match="503") as info:
        _call(metered)
    assert not isinstance(info.value, AccountError)


def test_unpriced_model_refuses_a_usd_budget() -> None:
    with pytest.raises(ValueError, match="unpriced model cannot run under a usd budget"):
        MeteredClient(UsageClient([]), budget_usd=1.0)
    with pytest.raises(ValueError, match="unpriced"):
        MeteredClient(UsageClient([]), prices={"input_per_m": 0.44}, budget_usd=1.0)


def test_unpriced_model_reports_none_not_zero_under_a_calls_budget() -> None:
    inner = UsageClient([_row(500, 100, 50)])
    metered = MeteredClient(inner, budget_calls=3)
    _call(metered)
    assert metered.priced is False
    assert metered.usd is None
    assert metered.usage["prompt_tokens"] == 500
    assert metered.summary() == {
        "usd": None,
        "calls": 1,
        "usage": {"prompt_tokens": 500, "prompt_cache_hit_tokens": 100, "completion_tokens": 50},
        "priced": False,
    }


def test_summary_shape_for_a_priced_model() -> None:
    inner = UsageClient([_row(1_000_000, 0, 0)])
    metered = MeteredClient(inner, prices=Prices(**FLASH), budget_usd=10.0)
    _call(metered)
    summary = metered.summary()
    assert set(summary) == {"usd", "calls", "usage", "priced"}
    assert summary["priced"] is True
    assert summary["calls"] == 1
    assert summary["usd"] == pytest.approx(0.44)
    assert summary["usage"] == {"prompt_tokens": 1_000_000, "prompt_cache_hit_tokens": 0, "completion_tokens": 0}


def test_prices_from_accepts_manifest_parameters_and_rejects_partial_ones() -> None:
    assert prices_from(FLASH) == Prices(cache_hit_per_m=0.014, input_per_m=0.44, output_per_m=1.32)
    assert prices_from({"cache_hit_per_m": 0.014, "input_per_m": 0.44}) is None
    assert prices_from({"cache_hit_per_m": "0.014", "input_per_m": 0.44, "output_per_m": 1.32}) is None
    assert prices_from(None) is None


def test_client_without_usage_rows_still_counts_calls() -> None:
    class Bare:
        def complete(
            self,
            *,
            model: str,
            messages: list[dict[str, object]],
            tools: list[dict[str, object]],
            timeout_seconds: int = 60,
            json_object: bool = False,
        ) -> ChatResponse:
            return ChatResponse(content="ok")

    metered = MeteredClient(Bare(), prices=FLASH, budget_calls=1)
    _call(metered)
    assert metered.calls == 1
    assert metered.usd == 0.0
    with pytest.raises(BudgetExhausted):
        _call(metered)
