"""The LLM proposes; the model disposes (model-grounded-detection, Req 8).

This module is where the prior architecture's premise is inverted. There, the LLM was an oracle whose noise
had to be averaged over K runs, floored per family, and gated by a sign test. Here it answers one bounded,
typed question about a candidate it was *handed*, and its answer is checked against the CPG. Three outcomes,
and they are exhaustive:

    the model entails it       report `model_entailed`, and never call the model at all
    the model contradicts it   drop the claim, recording the contradiction
    the model cannot decide    report `suspicion`, honestly

Nothing here averages, votes, retries for agreement, or maintains a budget: a deterministic arbiter removes
the need for every one of those. The LLM is consulted only for the residual the graph cannot settle — whether
a sanitizer on a real flow is actually sufficient — and even that answer only ever *confirms* a flow the CPG
already found. It can never conjure one.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

from ..cpg.backend import CpgResult
from ..redaction import redact_secrets
from .ladder import Rung, Verdict
from .specs import TaintSpec
from .taint import verdict as taint_verdict

logger = logging.getLogger(__name__)

QUESTION = """You are judging ONE candidate a static model already found. Do not look for other issues.

A dataflow analysis resolved this path in {language} code:

  source: {source}
  sink:   {sink}   (line {line}, function {function})
  a sanitizer appears on the path: {sanitized}

The graph has established that the value reaches the sink. The only open question is whether the sanitizer on
that path actually makes it safe for the {family} weakness class.

Answer ONLY with JSON: {{"vulnerable": true|false, "why": "<one sentence>"}}"""


def judge(
    cpg: CpgResult,
    spec: TaintSpec,
    *,
    function: str = "",
    client: Any | None = None,
    model: str = "",
    parameter_sources: bool = False,
) -> Verdict:
    """Arbitrate one candidate. Always returns a verdict; ``suspicion`` is a real answer, not a failure."""
    answer = taint_verdict(cpg, spec, function=function, parameter_sources=parameter_sources)

    if answer is not None and answer.rung is Rung.ENTAILED:
        return answer  # the graph decided; the model is not consulted

    if answer is None:
        # No resolved flow. Whatever anyone claims about this site, the model saw nothing to support it.
        return Verdict(
            rung=Rung.SUSPICION,
            family=spec.family,
            contradiction="the model resolved no flow: no source reaches this sink",
        )

    # A real flow through a sanitizer. Whether that sanitizer suffices is a semantic judgement the graph
    # cannot make, so it is the one thing the LLM is asked -- about evidence the model itself produced.
    if client is None:
        return Verdict(
            rung=Rung.SUSPICION,
            family=spec.family,
            witness=answer.witness,
            contradiction="no chat endpoint: the sanitizer's sufficiency was never judged",
        )

    said_vulnerable = _ask(client, model, spec, answer.witness, function)
    if said_vulnerable is None:
        return Verdict(rung=Rung.SUSPICION, family=spec.family, witness=answer.witness, contradiction="the judge returned no usable answer")
    if not said_vulnerable:
        return Verdict(
            rung=Rung.SUSPICION,
            family=spec.family,
            witness=answer.witness,
            contradiction="the judge held the sanitizer on this path sufficient",
        )
    return answer  # CORROBORATED: a real flow the judge agrees is not neutralised


def _ask(client: Any, model: str, spec: TaintSpec, witness: str, function: str) -> bool | None:
    """One question, one answer. No tools, no retries for agreement, no second opinion."""
    source, _, sink = witness.partition(" -> ")
    line = ""
    if "(line " in sink:
        sink, _, tail = sink.partition(" (line ")
        line = tail.split(",")[0].strip(") ")
    prompt = redact_secrets(
        QUESTION.format(
            language=spec.language,
            source=source.strip(),
            sink=sink.strip(),
            line=line or "?",
            function=function or "?",
            sanitized="yes",
            family=spec.family,
        )
    )
    try:
        response = client.complete(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            tools=[],  # the candidate is given; the model never searches for it
            json_object=True,
        )
    except Exception as exc:  # noqa: BLE001 -- an endpoint failure is a degradation, never a verdict
        logger.warning("judge call failed: %s", exc)
        return None
    return _vulnerable(getattr(response, "content", None))


def _vulnerable(content: object) -> bool | None:
    if not isinstance(content, str) or not content.strip():
        return None
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, Mapping) and isinstance(payload.get("vulnerable"), bool):
        return bool(payload["vulnerable"])
    return None


__all__ = ["QUESTION", "judge"]
