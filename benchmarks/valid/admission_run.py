"""Admission measurement runner (Task 13.4, Reqs 12.1-12.9).

Consumes a reviewed admission manifest for the valid-detection-benchmark
pilot population (authored and attested by the benchmark workflow, never by
this module), proves both sides of every vulnerable/fixed twin plus every
reviewed ordinary change on the strict judgment lane with nonzero-read
instrumentation, and returns the paired admission report. Judgment mapping
onto the three-way vocabulary: ``unguarded`` is a finding at the labelled
site; ``indeterminate`` is incomplete site evidence (an incomplete trace, a
degraded site file, or a fixed-side locator miss); every other completed
site is ``discharged`` -- Req 12.5's "quiet or discharged" behaviour. The
runner never modifies facts, strategies or thresholds, and never produces,
mutates or re-labels the manifest it consumes.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from benchmarks.valid.admission_scoring import AdmissionCase, OrdinaryChange, score_v2_admission
from benchmarks.valid.population_custody import AdmissionSpendAuthority, GuardedPopulationCustodian, ReleaseReview
from openultrasast.core.admission_case import AdmissionCaseResult
from openultrasast.core.admission_report import AdmissionReplay
from openultrasast.core.admission_spend import authorize_admission

__all__ = [
    "admission_ordinary",
    "admission_pair_cases",
    "coverage_share",
    "fixed_side_change",
    "locate_function",
    "run_v2_admission",
    "V2AdmissionRunInput",
    "site_judgment",
]

ARM_NAME = "access-control-admission"


@dataclass(frozen=True)
class V2AdmissionRunInput:
    authority: AdmissionSpendAuthority
    custodian: GuardedPopulationCustodian
    load_labels: Callable[[], bytes]
    analyze_labels: Callable[[bytes], Sequence[AdmissionCaseResult]]
    review_release: ReleaseReview


def run_v2_admission(value: V2AdmissionRunInput) -> AdmissionReplay:
    """Run one synthetic v2 admission through guarded custody and core scoring."""
    authority = value.authority
    preparation = authorize_admission(
        authority.manifest,
        authority.denominator,
        authority.readiness,
        authority.context,
        value.custodian,
        authority.resolver,
    )
    guarded = value.custodian.spend_and_release_labels(authority, preparation, value.load_labels)
    cases = tuple(value.analyze_labels(guarded.labels))
    release = value.custodian.release_cases(
        authority,
        preparation,
        guarded.receipt,
        cases,
        value.review_release,
    )
    return score_v2_admission(
        authority.manifest,
        authority.denominator,
        authority.readiness,
        preparation,
        guarded.receipt,
        release,
        cases,
        authority.context,
        value.custodian,
        authority.resolver,
    )


def _site_traces(record: dict[str, Any], path: str, start: int, end: int) -> list[dict[str, Any]]:
    """Traces whose operation site falls inside the labelled range."""
    matched = []
    for trace in record.get("traces", ()):
        fact_id = str(trace.get("fact_id", ""))
        marker = f":{path}:"
        index = fact_id.find(marker)
        if index < 0:
            continue
        line_text = fact_id[index + len(marker) :].split(":", 1)[0]
        if line_text.isdigit() and start <= int(line_text) <= end:
            matched.append(trace)
    return matched


def site_judgment(record: dict[str, Any], *, path: str, start: int, end: int) -> str:
    """Three-way judgment of one labelled site (Req 12.5 pair semantics)."""
    findings = record.get("findings", ())
    if any(finding.get("path") == path and start <= int(finding.get("line", 0)) <= end for finding in findings):
        return "unguarded"
    judgments = [trace["abstract_state"]["path_judgment"] for trace in _site_traces(record, path, start, end)]
    if any(judgment.get("judgment") == "unguarded" for judgment in judgments):
        return "unguarded"
    incomplete = any(
        judgment.get("judgment") == "indeterminate" or not judgment.get("completeness", {}).get("is_complete", True)
        for judgment in judgments
    )
    if incomplete:
        return "indeterminate"
    if any(degradation.get("path") == path for degradation in record.get("degradations", ())):
        return "indeterminate"
    return "discharged"


def locate_function(functions: Any, *, name: str) -> tuple[int, int] | None:
    """Inclusive line range of ``name`` among function ranges, or None."""
    for function in functions:
        label = function[0] if isinstance(function, tuple) else function.name
        if label == name:
            start = function[1] if isinstance(function, tuple) else function.start
            end = function[2] if isinstance(function, tuple) else function.end
            return int(start), int(end)
    return None


def fixed_side_change(change: dict[str, Any], *, fixed_lines: tuple[int, int] | None, fixed_operation: str) -> dict[str, Any]:
    """The twin proof target: the fix commit checked out with its own site lines.

    ``fixed_operation`` is "located" with lines, or one of "missed" (the
    function name is present at the fix but the locator could not name it --
    const-arrows, getters, moved imports) and "removed" (the name is absent
    from the fixed revision entirely). Only "removed" counts as quiet.
    """
    site = str(change.get("path") or change["files"][0]["path"])
    fixed: dict[str, Any] = {
        **change,
        "base": str(change["head"]),
        "head": str(change["base"]),
        "fixed_operation": fixed_operation,
        "files": [{"path": site, "head_lines": [list(fixed_lines)]}] if fixed_lines else [],
    }
    if fixed_lines:
        fixed["fixed_lines"] = list(fixed_lines)
    return fixed


def classify_fixed_site(lines: tuple[int, int] | None, *, name_in_text: bool) -> str:
    """Located, or missed (name present, locator failed) vs removed (name absent)."""
    if lines is not None:
        return "located"
    return "missed" if name_in_text else "removed"


def _fixed_judgment(record: dict[str, Any]) -> str:
    if record.get("fixed_operation") == "removed":
        return "discharged"
    if "fixed_lines" not in record:
        return "indeterminate"
    start, end = (int(value) for value in record["fixed_lines"])
    return site_judgment(record, path=str(record["path"]), start=start, end=end)


def admission_pair_cases(vulnerable: tuple[dict[str, Any], ...], fixed: tuple[dict[str, Any], ...]) -> tuple[AdmissionCase, ...]:
    """Build one scored twin pair per vulnerable case (Req 12.5)."""
    fixed_by_id = {str(record["id"]): record for record in fixed}
    cases = []
    for record in vulnerable:
        counterpart = fixed_by_id[str(record["id"])]
        start, end = (int(value) for value in record["function_lines"])
        path = str(record["path"])
        verified = any(
            finding.get("path") == path and start <= int(finding.get("line", 0)) <= end and finding.get("family") == record.get("family")
            for finding in record.get("findings", ())
        )
        cases.append(
            AdmissionCase(
                case_id=str(record["id"]),
                vulnerable_judgment=site_judgment(record, path=path, start=start, end=end),
                fixed_judgment=_fixed_judgment(counterpart),
                location_verified=bool(verified),
                seconds=float(record.get("seconds", 0.0)) + float(counterpart.get("seconds", 0.0)),
            )
        )
    return tuple(cases)


def admission_ordinary(records: tuple[dict[str, Any], ...]) -> tuple[OrdinaryChange, ...]:
    """Reviewed ordinary changes form the false-alarm denominator (Req 12.4)."""
    changes = []
    for record in records:
        if record.get("findings"):
            judgment = "unguarded"
        elif int(record.get("stage_funnel", {}).get("judgment", {}).get("indeterminate", 0)) > 0:
            judgment = "indeterminate"
        else:
            judgment = "discharged"
        changes.append(OrdinaryChange(change_id=str(record["id"]), judgment=judgment, mislabeled_defect=False))
    return tuple(changes)


def coverage_share(records: tuple[dict[str, Any], ...]) -> float:
    """Share of population repositories with any recognised framework."""
    per_repository: dict[str, int] = {}
    for record in records:
        recognised = record.get("stage_funnel", {}).get("entry_recognition", {}).get("frameworks_recognised", {})
        total = sum(recognised.values()) if isinstance(recognised, dict) else int(recognised)
        per_repository[str(record["repo"])] = per_repository.get(str(record["repo"]), 0) + int(total)
    if not per_repository:
        return 0.0
    covered = sum(1 for total in per_repository.values() if total > 0)
    return covered / len(per_repository)
