"""Shared fixtures for the decision-engine tests: example rows with valid feature records, and scripted clients."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from openultrasast.learn.examples import Example
from openultrasast.learn.features import NOT_APPLICABLE, Part, engine_part, quick_part, record
from openultrasast.tool_hunter import ChatResponse


def x_record(*, hits: int = 0, engine: str = "ran", findings: int = 0, language: str = "python", prior_hits: int = 0) -> dict[str, Any]:
    """A valid ``static`` record: ``hits`` enabled quick hits, the engine in state ``engine`` with ``findings``."""
    quick = quick_part([("r", "enabled")] * hits, {})
    quick = Part("ran", {**quick.values, "qr.prior_hits": prior_hits}, None)
    parts: dict[str, Part] = {"quick": quick, "delta": NOT_APPLICABLE, "facts": NOT_APPLICABLE}
    if engine == "ran":
        parts["engine"] = engine_part([{"rung": "suspicion"}] * findings, completion=1.0, degraded=False)
    elif engine != "none":
        parts["engine"] = Part(engine)
    return record("a.py::f", "injection", language, "static", parts)


def example(
    name: str,
    *,
    group: str,
    label: int,
    family: str = "injection",
    source: str = "pairs",
    frameworks: Sequence[str] = (),
    hits: int = 0,
    engine: str = "ran",
    findings: int = 0,
    license: str = "",
) -> Example:
    rec = x_record(hits=hits, engine=engine, findings=findings)
    return Example(
        id=hashlib.sha256(name.encode()).hexdigest(), group=group, source=source, frameworks=tuple(frameworks), family=family, label=label,
        language="python", profile="static", unit="pin", x=rec["x"], instruments=rec["instruments"], roles=(),
        excerpt_sha=hashlib.sha256(f"excerpt:{name}".encode()).hexdigest(), license=license,
    )  # fmt: skip


def corpus(groups: int = 12, per_group: int = 4) -> list[Example]:
    """``groups`` repository groups over three sources and two frameworks, each with positives and negatives."""
    out: list[Example] = []
    for g in range(groups):
        source = ("pairs", "population-v1", "population-v2")[g % 3]
        frameworks = ("flask",) if g % 4 == 0 else ("django",) if g % 4 == 1 else ()
        family = ("injection", "path")[g % 2]
        for i in range(per_group):
            out.append(
                example(
                    f"g{g}-e{i}", group=f"org{g}/repo{g}", label=i % 2, family=family, source=source, frameworks=frameworks,
                    hits=(g + i) % 5, findings=i % 3,
                )
            )  # fmt: skip
    return out


def by_id(examples: Sequence[Example]) -> Mapping[str, Example]:
    return {e.id: e for e in examples}


def candidate_lines(messages: Sequence[Mapping[str, object]]) -> list[int]:
    """The line numbers of the candidate's code in a rendered prompt."""
    text = str(messages[-1]["content"]).rsplit("Candidate:\n", 1)[1]
    code = text.split("Code:\n", 1)[1].split("\nSignals:\n", 1)[0]
    return [int(line.split()[0]) for line in code.splitlines() if line.strip() and line.split()[0].isdigit()]


def default_answer(messages: Sequence[Mapping[str, object]], temperature: float | None) -> str:
    """Vulnerable when the candidate's code executes something, else not; cites the candidate's first line."""
    text = str(messages[-1]["content"]).rsplit("Candidate:\n", 1)[1]
    vulnerable = "execute(" in text
    lines = candidate_lines(messages)
    return json.dumps(
        {
            "verdict": "vulnerable" if vulnerable else "not_vulnerable", "family": "injection", "confidence": 0.8 if vulnerable else 0.7,
            "rationale": "The value reaches the call on the cited line.", "cited_lines": lines[:1],
        }
    )  # fmt: skip


class ScriptedChat:
    """A chat client whose answers a function of the prompt scripts; records every call and a usage row per call."""

    def __init__(self, answer: Callable[[Sequence[Mapping[str, object]], float | None], str] = default_answer) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []
        self.usage: list[dict[str, object]] = []

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
        json_object: bool = False,
        temperature: float | None = None,
    ) -> ChatResponse:
        self.calls.append({"model": model, "messages": messages, "temperature": temperature, "json_object": json_object})
        prompt = sum(len(str(m["content"])) for m in messages) // 4
        self.usage.append({"prompt_tokens": prompt, "prompt_cache_hit_tokens": prompt // 2, "completion_tokens": 60})
        return ChatResponse(content=self.answer(messages, temperature))
