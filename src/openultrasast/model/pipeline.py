"""The detector: the enumerator proposes, the LLM answers, the model disposes (Req 8).

Everything before this module built an *arbiter* — something that judges a flow taint reachability had already
found on its own. Nothing proposed candidates to it, which is why the arbiter's recall was never comparable to
a detector's: it could only report what it happened to find unaided.

This is the wiring the architecture was designed around, and it turns on a distinction that `judge` alone
conflated:

    the model CONTRADICTS    it has coverage at this site and says no — a sanitizer lies on the path, or the
                             sink is written in its declared-safe shape. The claim is dropped (Req 8.2).
    the model CANNOT DECIDE  no modelled sink or source reaches the site at all. The model is *silent*, not
                             negative, so the LLM's claim is reported at `suspicion` (Req 8.4).

Treating silence as refutation is the tempting mistake, and it would be wrong here: 23 of the 39 misses in the
entailment ceiling were sinks simply absent from the fact tables. "No flow" usually means the model cannot see
it, not that nothing is there. The rung is what carries that uncertainty honestly, rather than a confidence
score nobody can act on.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..cpg.backend import CpgResult
from ..redaction import redact_secrets
from .config_value import verdict as config_verdict
from .dominance import verdict as dominance_verdict
from .ladder import Rung, Verdict
from .specs import ConfigSpec, DominanceSpec, TaintSpec
from .taint import verdict as taint_verdict

logger = logging.getLogger(__name__)

# A region with many candidate sites must not become an unbounded spend. The enumerator already orders them,
# so this takes the strongest few rather than a random slice.
MAX_JUDGED_CANDIDATES = 8

CANDIDATE_QUESTION = """You are judging ONE site a static enumerator selected. Do not look for other issues.

A dataflow model examined this {language} code and could NOT resolve a source-to-sink path here — which means
its sink table may simply not cover this API, not that the site is safe.

  site: {site}
  code: {text}

Is this site a {family} vulnerability?

Answer ONLY with JSON: {{"vulnerable": true|false, "why": "<one sentence>"}}"""


@dataclass(frozen=True)
class ModelFinding:
    """One reported site, carrying what established it."""

    site: str
    family: str
    rung: Rung
    witness: str = ""
    contradiction: str = ""


def _arbitrate(
    cpg: CpgResult, spec: TaintSpec | DominanceSpec | ConfigSpec, *, function: str, parameter_sources: bool
) -> Verdict | None:
    """Route a family to the arbiter that can actually decide it.

    Dispatching on the spec type rather than on a family name keeps this honest: a family without an arbiter
    cannot be silently routed to the wrong one. The pipeline first shipped taint-only, so access_control and
    config_secrets -- whose arbiters had worked since group 4 -- produced nothing, and every one of their
    pairs read as `both_silent` on the first end-to-end run.
    """
    if isinstance(spec, DominanceSpec):
        return dominance_verdict(cpg, spec, function=function)
    if isinstance(spec, ConfigSpec):
        return config_verdict(cpg, spec, function=function)
    return taint_verdict(cpg, spec, function=function, parameter_sources=parameter_sources)


def scan_region(
    cpg: CpgResult,
    spec: TaintSpec | DominanceSpec | ConfigSpec,
    *,
    function: str = "",
    client: Any | None = None,
    model: str = "",
    candidates: Sequence[Mapping[str, object]] = (),
    parameter_sources: bool = False,
) -> list[ModelFinding]:
    """Findings for one region and family, ordered strongest first."""
    answer = _arbitrate(cpg, spec, function=function, parameter_sources=parameter_sources)

    if answer is not None and answer.rung is Rung.ENTAILED:
        # The graph decided. No model call, and no candidate needs asking about: this region has its finding.
        return [ModelFinding(site=_site(function, answer.witness), family=spec.family, rung=Rung.ENTAILED,
                             witness=answer.witness)]

    if answer is not None:
        # A real flow through a sanitizer. Whether it suffices is the residual, and the model HAS coverage
        # here — so a "no" from the judge is a genuine contradiction and the claim is dropped.
        if client is None:
            return []
        said = _ask(client, model, residual_question(spec, answer.witness, function))
        if said:
            return [ModelFinding(site=_site(function, answer.witness), family=spec.family,
                                 rung=Rung.CORROBORATED, witness=answer.witness)]
        return []

    # The model resolved nothing. It is SILENT, not negative — so the enumerator's candidates are put to the
    # judge, and anything it affirms is reported at `suspicion` with that uncertainty on its face.
    if client is None:
        return []
    findings: list[ModelFinding] = []
    for candidate in list(candidates)[:MAX_JUDGED_CANDIDATES]:
        question = CANDIDATE_QUESTION.format(
            language=spec.language,
            site=str(candidate.get("id", "")),
            text=str(candidate.get("text", ""))[:400],
            family=spec.family,
        )
        if _ask(client, model, question):
            findings.append(
                ModelFinding(
                    site=str(candidate.get("id", "")),
                    family=spec.family,
                    rung=Rung.SUSPICION,
                    contradiction="the model resolved no flow here; its sink table may not cover this API",
                )
            )
    return findings


def residual_question(spec: TaintSpec | DominanceSpec | ConfigSpec, witness: str, function: str) -> str:
    """The one question the arbiter could not settle -- phrased for the arbiter that raised it.

    Asking a sanitizer question about a missing guard is not merely odd, it silently loses findings: the judge
    answers "no" to a question that does not apply and the claim is dropped. Every vibe-py access_control pair
    was lost this way.
    """
    if isinstance(spec, DominanceSpec):
        return (
            f"You are judging ONE finding a static model already made. Do not look for other issues.\n\n"
            f"A dominance analysis of {spec.language} code found an obligated operation that NO discharging\n"
            f"guard governs, in a file where sibling handlers are guarded:\n\n"
            f"  {witness}\n  function: {function or '?'}\n\n"
            f"The model has established the asymmetry. The open question is whether this operation genuinely\n"
            f"needs the guard its siblings have -- or is legitimately public.\n\n"
            'Answer ONLY with JSON: {"vulnerable": true|false, "why": "<one sentence>"}'
        )
    if isinstance(spec, ConfigSpec):
        return (
            f"You are judging ONE finding a static model already made. Do not look for other issues.\n\n"
            f"Constant evaluation of {spec.language} code found a security setting given a value the model\n"
            f"could not read as safe:\n\n  {witness}\n  function: {function or '?'}\n\n"
            f"The open question is whether this setting is genuinely permissive in a deployed configuration.\n\n"
            'Answer ONLY with JSON: {"vulnerable": true|false, "why": "<one sentence>"}'
        )
    source, _, sink = witness.partition(" -> ")
    return (
        f"You are judging ONE candidate a static model already found. Do not look for other issues.\n\n"
        f"A dataflow analysis resolved this path in {spec.language} code:\n\n"
        f"  source: {source.strip()}\n  sink:   {sink.strip()}\n  function: {function or '?'}\n"
        f"  a sanitizer appears on the path: yes\n\n"
        f"The graph has established that the value reaches the sink. The only open question is whether the\n"
        f"sanitizer on that path actually makes it safe for the {spec.family} weakness class.\n\n"
        'Answer ONLY with JSON: {"vulnerable": true|false, "why": "<one sentence>"}'
    )


def _ask(client: Any, model: str, question: str) -> bool | None:
    """One bounded question, no tools, no retry for agreement."""
    try:
        response = client.complete(
            model=model,
            messages=[{"role": "user", "content": redact_secrets(question)}],
            tools=[],
            json_object=True,
        )
    except Exception as exc:  # noqa: BLE001 — an endpoint failure is a degradation, never a verdict
        logger.warning("judge call failed: %s", exc)
        return None
    content = getattr(response, "content", None)
    if not isinstance(content, str) or not content.strip():
        return None
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return None
    return bool(payload["vulnerable"]) if isinstance(payload, Mapping) and isinstance(payload.get("vulnerable"), bool) else None


def _site(function: str, witness: str) -> str:
    line = witness.partition("(line ")[2].split(",")[0].strip(") ") if "(line " in witness else "?"
    return f"{function or '?'}:{line}"


__all__ = ["CANDIDATE_QUESTION", "MAX_JUDGED_CANDIDATES", "ModelFinding", "residual_question", "scan_region"]
