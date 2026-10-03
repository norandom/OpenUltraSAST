"""Fill rule-experiment responses without writing scores or changing the frozen population.

Estimates use the family's mean billed cached response cost when usage is available.
Otherwise they use Prompt.estimated_tokens and 300 output tokens. Unknown answers may require one retry;
dry-run counts those separately as conditional requests, never fabricating an answer.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..model.endpoint import DeepSeekChatClient
from ..plane.budget import BudgetExhausted, MeteredClient, cost_of, prices_from
from ..plane.memory import MemoryStore
from ..tool_hunter import ChatClient, ChatResponse
from . import experiments as ex
from .examples import Example
from .program import Caller, Program, Prompt, parse_answer, request_key

DEFAULT_OUTPUT_TOKENS = 300
DEFAULT_MARGIN_USD = 0.01


@dataclass(frozen=True)
class Request:
    family: str
    prompt: Prompt
    temperature: float
    sample: str

    def key(self, caller: Caller) -> str:
        return request_key(caller.model, caller.params_digest, self.prompt.messages, self.temperature, self.sample, True)

    def ask(self, caller: Caller) -> str:
        return caller.ask(self.prompt.messages, temperature=self.temperature, sample=self.sample)

    def retry(self) -> Request:
        return Request(self.family, self.prompt, 0.0, f"{self.sample}:retry")


class FillMeter(MeteredClient):
    """Reserve a whole call before admission, including the first (smoke) call.

    The fixed cent is a floor, never replaced by a smaller observed cost. For the
    production adapter, UTF-8 bytes conservatively bound input tokens (plus 256 framing
    tokens per message), and the provider enforces the output limit. Injected clients
    must honour the same token/usage contract. No hidden transport retries are allowed.
    """

    def __init__(self, client: ChatClient, parameters: Mapping[str, Any], budget: float, output_limit: int) -> None:
        super().__init__(client, prices=parameters, budget_usd=budget)
        self.limit = budget
        self.output_limit = output_limit
        self.largest_call_usd = 0.0

    def complete(self, **kwargs: Any) -> ChatResponse:
        assert self.prices is not None
        messages = kwargs["messages"]
        input_bound = sum(len(str(m["content"]).encode("utf-8")) + 256 for m in messages)
        bound = (
            input_bound * max(self.prices.input_per_m, self.prices.cache_hit_per_m) + self.output_limit * self.prices.output_per_m
        ) / 1_000_000
        reserve = max(DEFAULT_MARGIN_USD, self.largest_call_usd, bound)
        self.budget_usd = max(0.0, self.limit - reserve)
        before = self.usd or 0.0
        tokens_before = sum(self.usage.values())
        try:
            response = super().complete(**kwargs)
        except BudgetExhausted:
            raise
        except Exception:
            self.calls += 1  # attempted provider calls count even when no response was returned
            raise
        finally:
            self.largest_call_usd = max(self.largest_call_usd, (self.usd or 0.0) - before)
        if sum(self.usage.values()) <= tokens_before:
            raise RuntimeError("provider returned no metered token usage")
        return response


def fill_rule(
    store: MemoryStore,
    manifest: ex.Manifest,
    memory: Sequence[Example],
    parameters: Mapping[str, Any],
    excerpt_text: Callable[[str], str | None],
    vectors: Mapping[str, Sequence[float]] | None = None,
    *,
    client: ChatClient | None = None,
    client_factory: Callable[[], ChatClient] | None = None,
    budget_usd: float | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Inspect or fill every frozen unit. The first cache miss is the smoke call.

    A successful smoke is retained in the cache; any provider error stops immediately
    and is reported without its message, which may contain credentials. A factory is
    resolved only after validation, and only when a paid request is actually missing.
    """
    from .evaluate import candidate_from_example

    if manifest.kind != "rule":
        raise ex.ExperimentError("experiment fill supports kind: rule only")
    if not dry_run and (budget_usd is None or not math.isfinite(budget_usd) or budget_usd < 0):
        raise ex.ExperimentError("--budget-usd must be a finite non-negative number (or use --dry-run)")
    prices = prices_from(parameters)
    if prices is None or any(not math.isfinite(p) or p < 0 for p in (prices.input_per_m, prices.output_per_m, prices.cache_hit_per_m)):
        raise ex.ExperimentError("fill requires finite, non-negative Model prices")
    ex.check_registered(store, manifest)
    units, folds, _ = ex._checked_units(manifest, memory)
    programs = {f: Program(ex.arm_spec(manifest, manifest.arms["A"], f, store), memory, excerpt_text, vectors) for f in manifest.families}
    models = {p.spec.model for p in programs.values()}
    if len(models) != 1:
        raise ex.ExperimentError("the rule programs must use the same model")
    caller = Caller(None, next(iter(models)), parameters, store=store)
    index = {e.id: e for e in memory}
    candidate_of = candidate_from_example(excerpt_text, vectors)
    requests: list[Request] = []
    for unit in sorted(units, key=lambda u: (u.group, u.family, u.unit)):
        candidate = candidate_of(index[unit.unit])
        if candidate is None:
            raise ex.ExperimentError(f"{manifest.id}: unit {unit.unit[:12]} has no excerpt in the store")
        for prompt, _, temperature, sample in programs[unit.family].prepare_samples(
            candidate, folds[unit.fold], seed=int(manifest.folds.get("seed", 0))
        ):
            requests.append(Request(unit.family, prompt, temperature, sample))

    # Request counts are distinct cache keys per family, even when multiple units share one.
    def inventory() -> dict[str, dict[str, Request]]:
        result: dict[str, dict[str, Request]] = {f: {} for f in manifest.families}
        for req in requests:
            result[req.family][req.key(caller)] = req
            entry = caller._cached(req.key(caller))
            if entry is not None and parse_answer(entry.get("content"), req.prompt.valid_lines) is None:
                retry = req.retry()
                result[req.family][retry.key(caller)] = retry
        return result

    initial = inventory()
    initially_cached = {key for cells in initial.values() for key in cells if caller._cached(key) is not None}
    families: dict[str, Any] = {}
    for family, cells in initial.items():
        usages = [
            usage
            for key in cells
            if (entry := caller._cached(key)) is not None and isinstance(usage := entry.get("usage"), Mapping) and usage
        ]
        outputs = [float(usage["completion_tokens"]) for usage in usages if "completion_tokens" in usage]
        mean_output = sum(outputs) / len(outputs) if outputs else DEFAULT_OUTPUT_TOKENS
        missing = [req for key, req in cells.items() if key not in initially_cached]
        families[family] = {
            "units": sum(u.family == family for u in units),
            "requests": len(cells),
            "cached": len(cells) - len(missing),
            "missing": len(missing),
            "filled": 0,
            "still_missing": len(missing),
            "estimate_method": "measured" if usages else "estimated",
            "estimated_usd": len(missing) * sum(cost_of(usage, prices) for usage in usages) / len(usages)
            if usages
            else sum((r.prompt.estimated_tokens * prices.input_per_m + mean_output * prices.output_per_m) / 1_000_000 for r in missing),
            "estimated_output_tokens": mean_output,
            "conditional_retries": sum(not r.sample.endswith(":retry") for r in missing),
        }
    report: dict[str, Any] = {
        "experiment": manifest.id,
        "status": "dry_run" if dry_run else "done",
        "families": families,
        "client_calls": 0,
        "usd": 0.0,
        "reason": "",
    }
    if dry_run or not any(c["missing"] for c in families.values()):
        return report
    meter: FillMeter | None = None
    try:
        if client is None and client_factory is not None:
            client = client_factory()
        if client is None:
            raise ex.ExperimentError("no chat endpoint configured; nothing was spent")
        output_limit = max(p.spec.max_output_tokens for p in programs.values())
        if isinstance(client, DeepSeekChatClient):
            client = client.bounded(output_limit)
        assert budget_usd is not None
        meter = FillMeter(client, parameters, budget_usd, output_limit)
        caller.client = meter
        for req in requests:
            content = req.ask(caller)
            if parse_answer(content, req.prompt.valid_lines) is None:
                req.retry().ask(caller)
    except BudgetExhausted:
        report.update(status="unfinished", reason="budget exhausted; resume with a new fill budget")
    except ex.ExperimentError:
        raise
    except Exception:
        # Never echo provider exceptions: response bodies and URLs may contain secrets.
        report.update(status="failed", reason="provider or cache failure; fill stopped")
    final = inventory()
    for family, cells in final.items():
        cached = {key for key in cells if caller._cached(key) is not None}
        families[family].update(requests=len(cells), filled=len(cached - initially_cached), still_missing=len(cells) - len(cached))
    if meter is not None:
        report.update(client_calls=meter.calls, usd=meter.usd)
    return report
