"""Hunter adjudication of intent (authorization-obligations, Req 6.3).

The hunter answers one closed question per route-bearing finding: is this route meant to be public? The answer is recorded
on the finding as `intent` (public | protected | unknown) with its rationale, and nothing else changes: not the label, not
the evidence, not the evidence level. Without a client one `intent_adjudication_unavailable` degradation is recorded.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import replace

from ...redaction import redact_secrets
from .check import ObligationFinding, ObligationResult

INTENTS = ("public", "protected", "unknown")
_SYSTEM = (
    "You review web handlers for an application security tool. Answer one closed question about intent only. "
    'Reply with JSON of the form {"intent": "public" | "protected" | "unknown", "rationale": "<one sentence>"}. '
    "Do not assess exploitability and do not propose code."
)


def adjudicate_intent(result: ObligationResult, *, client: object | None, model: str, texts: Mapping[str, str]) -> ObligationResult:
    """Annotate route-bearing findings with the hunter's intent verdict; identical findings when no client is available."""
    if not any(finding.route for finding in result.findings):
        return result  # nothing to adjudicate: no degradation for a run with no route-bearing obligation finding
    if client is None or not model:
        degradation: dict[str, object] = {
            "stage": "obligations",
            "reason": "intent_adjudication_unavailable",
            "detail": "no hunter client or model",
        }
        return replace(result, degradations=(*result.degradations, degradation))
    findings: list[ObligationFinding] = []
    for finding in result.findings:
        if not finding.route:
            findings.append(finding)
            continue
        intent, rationale = _ask(client, model, finding, texts.get(finding.operation.path, ""))
        findings.append(replace(finding, intent=intent, intent_rationale=rationale))
    return replace(result, findings=tuple(findings))


def _ask(client: object, model: str, finding: ObligationFinding, text: str) -> tuple[str, str | None]:
    siblings = ", ".join(item for item in finding.evidence if "::" in item) or "none recorded"
    handler = _handler_excerpt(text, finding.operation.function)
    question = (
        f"Route {finding.route} is served by {finding.operation.function} in {finding.operation.path}. "
        f"It performs {finding.operation.kind} on {finding.operation.resource or 'a resource'} without {finding.missing}. "
        f"Sibling handlers that discharge it: {siblings}. Is this route meant to be public?\n\n{handler}"
    )
    question = redact_secrets(question)  # design Security Considerations: the hunter receives redacted handler text
    try:
        response = client.complete(  # type: ignore[attr-defined]
            model=model,
            messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": question}],
            tools=[],
            timeout_seconds=30,
        )
    except Exception:  # noqa: BLE001 - the hunter is advisory; a failed call records unknown
        return "unknown", None
    return _parse(getattr(response, "content", None))


def _parse(content: object) -> tuple[str, str | None]:
    if not isinstance(content, str) or not content.strip():
        return "unknown", None
    match = re.search(r"\{.*\}", content, re.S)
    if not match:
        return "unknown", None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return "unknown", None
    intent = str(payload.get("intent", "unknown")).strip().lower()
    rationale = payload.get("rationale")
    return (intent if intent in INTENTS else "unknown"), (str(rationale)[:200] if rationale else None)


def _handler_excerpt(text: str, function: str) -> str:
    """The handler's own lines: its decorators through the end of its indented body, never another handler's."""
    lines = text.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if re.match(rf"\s*(?:async\s+)?(?:def|function)\s+{re.escape(function)}\b", line)), None
    )
    if start is None:
        return ""
    head = start
    while head > 0 and lines[head - 1].strip().startswith("@"):
        head -= 1
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
        end += 1
    return "\n".join(lines[head:end][:60])


__all__ = ["INTENTS", "adjudicate_intent"]
