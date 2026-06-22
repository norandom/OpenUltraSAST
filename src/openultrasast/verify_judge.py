"""Verifier dispatcher: HarnessX llm-judge when available, structural fallback otherwise.

The default path (no extra) is the existing :func:`verification.verify_findings`
verbatim — same ``list[VerificationResult]``, same rejection of unknown reachability —
so behaviour is byte-identical without HarnessX. The judge path is lazy/guarded.
"""

from __future__ import annotations

from .findings import StaticFinding
from .harness_ext import build_provider, has_harnessx
from .verification import (
    EvidenceLevel,
    VerificationResult,
    VerificationStatus,
    build_independent_verifier_context,
    is_report_verified,
    verify_findings,
)


def verify_findings_dispatch(
    findings: list[StaticFinding],
    *,
    verifier_model: str | None = None,
    verifier_provider: str = "anthropic",
    use_harnessx: bool = False,
) -> list[VerificationResult]:
    """Drop-in superset of :func:`verification.verify_findings`.

    Falls back to the structural verifier unless the HarnessX extra is present, a
    verifier model is configured, and ``use_harnessx`` is set.
    """
    if not (use_harnessx and verifier_model and has_harnessx()):
        return verify_findings(findings)
    return _verify_with_judge(findings, verifier_model, verifier_provider)


def _verify_with_judge(findings: list[StaticFinding], verifier_model: str, verifier_provider: str) -> list[VerificationResult]:
    import asyncio

    return asyncio.run(_judge_all(findings, verifier_model, verifier_provider))


async def _judge_all(findings: list[StaticFinding], verifier_model: str, verifier_provider: str) -> list[VerificationResult]:
    from harnessx.core.events import Message
    from harnessx.processors.evaluation.llm_judge import build_judge_prompt, parse_judge_response

    provider = build_provider(verifier_model, verifier_provider)
    results: list[VerificationResult] = []
    for finding in findings:
        prompt = build_judge_prompt(
            task_description=f"Is this a real, exploitable security issue: {finding.title}? Judge on evidence only.",
            trajectory_summary=_finding_summary(finding),
            extracted_answer=finding.rationale,
        )
        try:
            response = await provider.complete(messages=[Message(role="user", content=prompt)], tools=[])
            verdict = parse_judge_response(_text(response.content))
        except Exception:  # noqa: BLE001 — judge/provider failure must never auto-reject a finding
            verdict = {"verdict": "no_answer", "confidence": 0.0}
        results.append(_verdict_to_verification(finding, verdict))
    return results


def _verdict_to_verification(finding: StaticFinding, verdict: dict[str, object]) -> VerificationResult:
    """Map an llm-judge verdict onto a VerificationResult (infra failure never auto-rejects)."""
    label = str(verdict.get("verdict", "no_answer"))
    raw_confidence = verdict.get("confidence", 0.0)
    confidence = 0.0
    if isinstance(raw_confidence, (int, float)):
        confidence = float(raw_confidence)
    elif isinstance(raw_confidence, str):
        try:
            confidence = float(raw_confidence)
        except ValueError:
            confidence = 0.0
    cause = str(verdict.get("cause", "")).strip()
    lesson = str(verdict.get("lesson", "")).strip()
    missing = str(verdict.get("missing", "")).strip() or _missing_capability_summary(verdict)
    level = EvidenceLevel(finding.evidence_level)

    if label == "plausible" and confidence >= 0.6:
        status = VerificationStatus.ACCEPTED
    elif label in ("unsupported", "refused"):
        status = VerificationStatus.REJECTED
    else:  # hedging / format_wrong / no_answer / low-confidence plausible
        status = VerificationStatus.NEEDS_EVIDENCE

    if status == VerificationStatus.ACCEPTED:
        pro_case = cause or "The judge found the issue plausible on the available evidence."
        counter_case = "Impact and exploitability still require deeper verifier or dynamic evidence."
    else:
        pro_case = "A candidate issue exists from the finding's evidence."
        counter_case = cause or "The judge could not confirm the issue from the available evidence."

    return VerificationResult(
        finding_id=finding.finding_id,
        status=status,
        evidence_level=level,
        verified=is_report_verified(level, status),
        pro_case=pro_case,
        counter_case=counter_case,
        tie_breaker=lesson or "Confirm attacker control, sanitizer absence, and impact.",
        required_next_step=missing or "Collect corroborating evidence before reporting as verified.",
        context_sources=sorted(build_independent_verifier_context(finding).keys()),
    )


def _finding_summary(finding: StaticFinding) -> str:
    return (
        f"{finding.title} at {finding.path}:{finding.line} (function={finding.function_name or 'unknown'}); "
        f"reachability={finding.reachability_status}; tags={', '.join(finding.tags) or 'none'}"
    )


def _missing_capability_summary(verdict: dict[str, object]) -> str:
    capability = verdict.get("missing_capability")
    if isinstance(capability, dict):
        return str(capability.get("summary", "")).strip()
    return ""


def _text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [str(block.get("text", "")) if isinstance(block, dict) else str(block) for block in content]
        return "".join(parts)
    return str(content)
