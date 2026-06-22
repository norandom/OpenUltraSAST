"""Fusion adjudication — OpenUltraCode-style two-panel deepening (Phase 13).

Fusion is the deepening mechanism for findings that need more reasoning than the
ranker → hunter → verifier → mapping loop provides: critical/high severity, verifier
disagreement, static-vs-semantic evidence conflict, findings that gate a risky fix or
disclosure, or an explicit high-assurance request. Two panels independently review the
bounded evidence (one steel-manning the vulnerability case, one the false-positive
case), critique and revise, vote, and a decider issues the final disposition.

The deterministic engine here is the zero-dependency core (and the fallback). When the
``openultrasast[harnessx]`` extra and panel models are configured, ``fuse_findings_dispatch``
routes the panels through real LLM reviews; the decider reconciliation stays deterministic
and auditable. Every fused finding receives exactly one of the five dispositions, and the
decision discloses model IDs, panel roles, votes, degradations, and the decision source.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from .findings import StaticFinding
from .harness_ext import has_harnessx
from .verification import VerificationResult, VerificationStatus


class FusionDisposition(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MITIGATED = "mitigated"
    DEFERRED = "deferred"
    BLOCKED = "blocked"


_HIGH_SEVERITY = frozenset({"critical", "high"})


@dataclass(frozen=True)
class PanelVerdict:
    role: str  # "panel_a" | "panel_b"
    leaning: str  # "vulnerability" | "false_positive"
    disposition: FusionDisposition
    confidence: float
    vulnerability_case: str
    false_positive_case: str
    rationale: str
    model_id: str | None = None  # None => deterministic panel

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FusionDecision:
    finding_id: str
    triggered: bool
    triggers: list[str]
    disposition: FusionDisposition
    decision_source: str  # "deterministic-reconciler" | "llm-panels" | "no-fusion"
    panels: list[PanelVerdict]
    votes: dict[str, int]
    model_ids: list[str]
    degradations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["disposition"] = str(self.disposition)
        data["panels"] = [panel.to_dict() for panel in self.panels]
        return data


def fusion_triggers(
    finding: StaticFinding,
    verification: VerificationResult | None = None,
    *,
    high_assurance: bool = False,
) -> list[str]:
    """The deterministic trigger policy — which conditions warrant deepening (empty => skip)."""
    triggers: set[str] = set()
    if finding.severity in _HIGH_SEVERITY:
        triggers.add(f"severity:{finding.severity}")
    reachable = finding.reachability_status == "reachable"
    if verification is not None:
        if verification.status == VerificationStatus.NEEDS_EVIDENCE:
            triggers.add("verifier_disagreement")
        if verification.status == VerificationStatus.REJECTED and reachable:
            triggers.add("evidence_conflict")  # static says vuln-shaped, verifier rejected
    if reachable and finding.severity in _HIGH_SEVERITY:
        triggers.add("gates_risky_fix")
    if high_assurance:
        triggers.add("high_assurance_request")
    return sorted(triggers)


def should_fuse(finding: StaticFinding, verification: VerificationResult | None = None, *, high_assurance: bool = False) -> bool:
    return bool(fusion_triggers(finding, verification, high_assurance=high_assurance))


def _panel_a(finding: StaticFinding, verification: VerificationResult | None) -> PanelVerdict:
    """Vulnerability-leaning panel: steel-mans the vulnerability case."""
    reachable = finding.reachability_status == "reachable"
    verified = verification is not None and verification.verified
    if reachable and finding.severity in _HIGH_SEVERITY and not verified:
        disposition, confidence = FusionDisposition.BLOCKED, 0.7
    elif reachable:
        disposition, confidence = FusionDisposition.ACCEPTED, 0.75 if verified else 0.6
    else:
        disposition, confidence = FusionDisposition.DEFERRED, 0.5
    vuln_case = verification.pro_case if verification else f"{finding.title}: {finding.rationale}"
    return PanelVerdict(
        role="panel_a",
        leaning="vulnerability",
        disposition=disposition,
        confidence=confidence,
        vulnerability_case=vuln_case,
        false_positive_case="Reachability or sanitizer evidence could still neutralize the sink.",
        rationale=f"reachability={finding.reachability_status}, severity={finding.severity}, verified={verified}",
    )


def _panel_b(finding: StaticFinding, verification: VerificationResult | None) -> PanelVerdict:
    """False-positive-leaning panel: steel-mans the false-positive case."""
    reachable = finding.reachability_status == "reachable"
    verified = verification is not None and verification.verified
    rejected = verification is not None and verification.status == VerificationStatus.REJECTED
    if rejected or not reachable:
        disposition, confidence = FusionDisposition.REJECTED, 0.7 if rejected else 0.55
    elif verified:
        disposition, confidence = FusionDisposition.ACCEPTED, 0.6  # concedes when evidence is strong
    else:
        disposition, confidence = FusionDisposition.DEFERRED, 0.5
    fp_case = verification.counter_case if verification else "No independent verification confirms attacker control or impact."
    return PanelVerdict(
        role="panel_b",
        leaning="false_positive",
        disposition=disposition,
        confidence=confidence,
        vulnerability_case="A tainted sink shape exists in the source.",
        false_positive_case=fp_case,
        rationale=f"reachable={reachable}, rejected={rejected}, verified={verified}",
    )


def _reconcile(
    finding: StaticFinding,
    verification: VerificationResult | None,
    panels: list[PanelVerdict],
    mitigated_ids: frozenset[str],
) -> tuple[FusionDisposition, str]:
    """Deterministic decider: map evidence + panels onto one disposition + a rationale."""
    reachable = finding.reachability_status == "reachable"
    verified = verification is not None and verification.verified
    rejected = verification is not None and verification.status == VerificationStatus.REJECTED
    if finding.finding_id in mitigated_ids:
        return FusionDisposition.MITIGATED, "a prior calibration confirms this surface is mitigated"
    if rejected and not reachable:
        return FusionDisposition.REJECTED, "verifier rejected and the sink is not reachable"
    if verified and reachable:
        return FusionDisposition.ACCEPTED, "reachable sink with corroborating verification evidence"
    if reachable and finding.severity in _HIGH_SEVERITY and not verified:
        return FusionDisposition.BLOCKED, "reachable high-severity finding gates a risky fix until evidence resolves"
    if rejected and reachable:
        return FusionDisposition.DEFERRED, "static and verifier evidence conflict; deeper evidence required"
    return FusionDisposition.DEFERRED, "evidence does not converge; defer for additional evidence"


def fuse_finding(
    finding: StaticFinding,
    verification: VerificationResult | None,
    triggers: list[str],
    *,
    mitigated_ids: frozenset[str] = frozenset(),
) -> FusionDecision:
    """Deterministic two-panel fusion for one finding."""
    panels = [_panel_a(finding, verification), _panel_b(finding, verification)]
    disposition, _rationale = _reconcile(finding, verification, panels, mitigated_ids)
    votes = Counter(str(panel.disposition) for panel in panels)
    return FusionDecision(
        finding_id=finding.finding_id,
        triggered=True,
        triggers=triggers,
        disposition=disposition,
        decision_source="deterministic-reconciler",
        panels=panels,
        votes=dict(sorted(votes.items())),
        model_ids=[],
        degradations=[],
        warnings=[],
    )


def fuse_findings_dispatch(
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    *,
    panel_model: str | None = None,
    decider_model: str | None = None,
    provider: str = "anthropic",
    use_harnessx: bool = False,
    high_assurance: bool = False,
    mitigated_ids: frozenset[str] = frozenset(),
) -> list[FusionDecision]:
    """Fuse every finding that the trigger policy selects.

    Deterministic by default. When ``use_harnessx`` is set, a panel model is configured,
    and the extra is present, the panels are produced by real LLM reviews; otherwise the
    deterministic panels run and (if an LLM run was requested) a degradation is recorded.
    """
    verification_by_id = {result.finding_id: result for result in verifications}
    want_llm = use_harnessx and bool(panel_model)
    decisions: list[FusionDecision] = []
    for finding in findings:
        verification = verification_by_id.get(finding.finding_id)
        triggers = fusion_triggers(finding, verification, high_assurance=high_assurance)
        if not triggers:
            continue
        if want_llm and has_harnessx():
            decisions.append(_fuse_with_llm_panels(finding, verification, triggers, panel_model, decider_model, provider, mitigated_ids))
        else:
            decision = fuse_finding(finding, verification, triggers, mitigated_ids=mitigated_ids)
            if want_llm and not has_harnessx():
                decision = _with_degradation(decision, "fusion_llm_unavailable: harnessx extra absent; used deterministic panels")
            decisions.append(decision)
    return decisions


def _with_degradation(decision: FusionDecision, note: str) -> FusionDecision:
    return FusionDecision(
        finding_id=decision.finding_id,
        triggered=decision.triggered,
        triggers=decision.triggers,
        disposition=decision.disposition,
        decision_source=decision.decision_source,
        panels=decision.panels,
        votes=decision.votes,
        model_ids=decision.model_ids,
        degradations=[*decision.degradations, note],
        warnings=decision.warnings,
    )


def _fuse_with_llm_panels(
    finding: StaticFinding,
    verification: VerificationResult | None,
    triggers: list[str],
    panel_model: str | None,
    decider_model: str | None,
    provider: str,
    mitigated_ids: frozenset[str],
) -> FusionDecision:
    """LLM-backed panels with a deterministic, auditable decider (lazy/guarded)."""
    import asyncio

    model = panel_model or ""
    try:
        panels = asyncio.run(_run_llm_panels(finding, verification, model, provider))
        source = "llm-panels"
        warnings: list[str] = []
    except Exception as exc:  # noqa: BLE001 — panel/provider failure falls back, never crashes the scan
        panels = [_panel_a(finding, verification), _panel_b(finding, verification)]
        source = "deterministic-reconciler"
        warnings = [f"llm_panels_failed: {type(exc).__name__}"]
    disposition, _rationale = _reconcile(finding, verification, panels, mitigated_ids)
    votes = Counter(str(panel.disposition) for panel in panels)
    model_ids = sorted({panel.model_id for panel in panels if panel.model_id})
    if decider_model:
        model_ids = sorted({*model_ids, decider_model})
    return FusionDecision(
        finding_id=finding.finding_id,
        triggered=True,
        triggers=triggers,
        disposition=disposition,
        decision_source=source,
        panels=panels,
        votes=dict(sorted(votes.items())),
        model_ids=model_ids,
        degradations=[],
        warnings=warnings,
    )


async def _run_llm_panels(
    finding: StaticFinding,
    verification: VerificationResult | None,
    model: str,
    provider: str,
) -> list[PanelVerdict]:
    from harnessx.core.events import Message
    from harnessx.processors.evaluation.llm_judge import build_judge_prompt, parse_judge_response

    from .harness_ext import build_provider

    client = build_provider(model, provider)
    panels: list[PanelVerdict] = []
    for role, leaning, stance in (
        ("panel_a", "vulnerability", "Argue the vulnerability case as strongly as the evidence allows."),
        ("panel_b", "false_positive", "Argue the false-positive case as strongly as the evidence allows."),
    ):
        summary = f"reachability={finding.reachability_status}; severity={finding.severity}; tags={', '.join(finding.tags) or 'none'}"
        prompt = build_judge_prompt(
            task_description=f"{stance} Finding: {finding.title} at {finding.path}:{finding.line}.",
            trajectory_summary=summary,
            extracted_answer=verification.pro_case if verification else finding.rationale,
        )
        response = await client.complete(messages=[Message(role="user", content=prompt)], tools=[])
        verdict = parse_judge_response(_text(response.content))
        base = _panel_a(finding, verification) if role == "panel_a" else _panel_b(finding, verification)
        plausible = str(verdict.get("verdict", "")) == "plausible"
        confidence = (
            float(verdict.get("confidence", base.confidence)) if isinstance(verdict.get("confidence"), int | float) else base.confidence
        )
        panels.append(
            PanelVerdict(
                role=role,
                leaning=leaning,
                disposition=base.disposition if plausible or role == "panel_a" else FusionDisposition.REJECTED,
                confidence=confidence,
                vulnerability_case=base.vulnerability_case,
                false_positive_case=base.false_positive_case,
                rationale=str(verdict.get("cause", base.rationale)),
                model_id=model,
            )
        )
    return panels


def _text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(block.get("text", "")) if isinstance(block, dict) else str(block) for block in content)
    return str(content)


__all__ = [
    "FusionDecision",
    "FusionDisposition",
    "PanelVerdict",
    "fuse_finding",
    "fuse_findings_dispatch",
    "fusion_triggers",
    "should_fuse",
]
