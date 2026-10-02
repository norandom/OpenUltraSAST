"""Fusion adjudication — OpenUltraCode-style two-panel deepening (Phase 13 of the retired openrouter-sast-harness plan).

Fusion is the deepening mechanism for findings that need more reasoning than the
ranker → hunter → verifier → mapping loop provides: critical/high severity, verifier
disagreement, static-vs-semantic evidence conflict, findings that gate a risky fix or
disclosure, or an explicit high-assurance request. Two panels independently review the
bounded evidence (one steel-manning the vulnerability case, one the false-positive
case) and vote, and a decider issues the final disposition.

The panels and the decider are deterministic and auditable. Every fused finding receives
exactly one of the five dispositions, and the decision discloses panel roles, votes and the
decision source. Independent LLM agreement is the plane's ``agree`` task, not this module.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from .findings import StaticFinding
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
    decision_source: str  # "deterministic-reconciler" | "no-fusion"
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


def fuse_findings(
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    *,
    high_assurance: bool = False,
    mitigated_ids: frozenset[str] = frozenset(),
) -> list[FusionDecision]:
    """Fuse every finding that the trigger policy selects, with the deterministic panels."""
    verification_by_id = {result.finding_id: result for result in verifications}
    decisions: list[FusionDecision] = []
    for finding in findings:
        verification = verification_by_id.get(finding.finding_id)
        triggers = fusion_triggers(finding, verification, high_assurance=high_assurance)
        if triggers:
            decisions.append(fuse_finding(finding, verification, triggers, mitigated_ids=mitigated_ids))
    return decisions


__all__ = [
    "FusionDecision",
    "FusionDisposition",
    "PanelVerdict",
    "fuse_finding",
    "fuse_findings",
    "fusion_triggers",
    "should_fuse",
]
