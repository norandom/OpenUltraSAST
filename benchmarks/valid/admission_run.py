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

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

from benchmarks.unseen.replay import canonical
from benchmarks.valid.admission_scoring import AdmissionCase, OrdinaryChange, admission_report
from benchmarks.valid.arm_regression import BundleDigests, _input_digest, _prove_one
from benchmarks.valid.prover_admission import AdmissionManifest, validate_admission_manifest
from openultrasast.preprocess import detect_language
from openultrasast.source import canonical_language, ranges

__all__ = [
    "admission_ordinary",
    "admission_pair_cases",
    "assemble_admission_report",
    "coverage_share",
    "fixed_side_change",
    "load_admission_population",
    "locate_function",
    "run_admission",
    "site_judgment",
]

ARM_NAME = "access-control-admission"


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


def load_admission_population(
    payload: dict[str, object], pool_path: Path, freeze_path: Path
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Validate the manifest and the reviewed freeze before opening labels (Req 12.1)."""
    manifest = validate_admission_manifest(payload)
    pool = tomllib.loads(Path(pool_path).read_text(encoding="utf-8"))
    freeze = json.loads(Path(freeze_path).read_text(encoding="utf-8"))
    digest = hashlib.sha256(canonical(pool)).hexdigest()
    if digest != freeze.get("freeze_digest"):
        raise ValueError(f"population: pool digest {digest[:12]} does not match the reviewed freeze")
    if freeze.get("guard_result") != 0:
        raise ValueError("guard: held-out guard failed for this population")
    if manifest.population_digest != digest:
        raise ValueError("population: manifest names a different population than the reviewed freeze")
    changes = tuple(
        {**change, "id": _change_identity(repository, change), "repo": str(repository["id"])}
        for repository in pool.get("repository", [])
        for change in repository.get("changes", [])
    )
    vulnerable = tuple(change for change in changes if change.get("kind") == "vulnerability")
    ordinary = tuple(change for change in changes if change.get("kind") == "ordinary")
    return vulnerable, ordinary


def _change_identity(repository: dict[str, Any], change: dict[str, Any]) -> str:
    """The pool's canonical change identity, as ``replay.load_slice`` derives it."""
    payload = [repository["id"], change["kind"], change["base"], change["head"]]
    return hashlib.sha256(canonical(payload)).hexdigest()


def assemble_admission_report(
    manifest: AdmissionManifest,
    vulnerable: tuple[dict[str, Any], ...],
    fixed: tuple[dict[str, Any], ...],
    ordinary: tuple[dict[str, Any], ...],
    *,
    criteria: dict[str, float] | None,
    budget_seconds: float = 120.0,
) -> dict[str, Any]:
    """Bridge measured records to the paired admission report (Reqs 12.7, 12.8).

    Every change is budget-gated: pairs by their combined seconds, ordinary
    changes individually (design.md:370 "fails any change over 120 seconds").
    """
    failures = sum(1 for record in (*vulnerable, *fixed, *ordinary) if record.get("status") == "instrument_failure")
    report = admission_report(
        manifest,
        admission_pair_cases(vulnerable, fixed),
        admission_ordinary(ordinary),
        coverage=coverage_share((*vulnerable, *fixed, *ordinary)),
        instrument_failures=failures,
        budget_seconds=budget_seconds,
        criteria=criteria,
    )
    overruns = [
        f"budget:{record['id']}:{float(record.get('seconds', 0.0)):g}s>{budget_seconds:g}s"
        for record in ordinary
        if float(record.get("seconds", 0.0)) > budget_seconds
    ]
    if overruns:
        report["failed_gates"] = [*report["failed_gates"], *overruns]
        report["decision"] = "NO-GO"
    return report


def _resume_or_prove(
    bundle: BundleDigests,
    population: str,
    change: dict[str, Any],
    repo_path: Path,
    side_dir: Path,
) -> dict[str, Any]:
    from benchmarks.valid.prover_arm import _write_json

    side_dir.mkdir(parents=True, exist_ok=True)
    path = side_dir / f"{change['id']}.json"
    if path.is_file():
        previous: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if previous.get("input_digest") == _input_digest(change, ARM_NAME):
            return previous
        raise ValueError(f"existing record for {change['id']} does not match this arm's inputs")
    record = _prove_one(bundle, ARM_NAME, population, change, repo_path)
    _write_json(path, record)
    return record


def run_admission(
    *,
    payload: dict[str, object],
    pool_path: Path,
    freeze_path: Path,
    repos: dict[str, str],
    bundle: BundleDigests,
    out_dir: Path,
    criteria: dict[str, float] | None,
    budget_seconds: float = 120.0,
) -> dict[str, Any]:
    """Consume the reviewed manifest, prove the population, return GO/NO-GO."""
    vulnerable, ordinary = load_admission_population(payload, pool_path, freeze_path)
    manifest = validate_admission_manifest(payload)
    out_dir.mkdir(parents=True, exist_ok=True)
    vulnerable_records = tuple(
        _resume_or_prove(bundle, manifest.population_digest, change, Path(repos[change["repo"]]).expanduser(), out_dir / "vulnerable")
        for change in vulnerable
    )
    fixed_records = tuple(
        _resume_or_prove(
            bundle,
            manifest.population_digest,
            _fixed_side_change(Path(repos[change["repo"]]).expanduser(), change),
            Path(repos[change["repo"]]).expanduser(),
            out_dir / "fixed",
        )
        for change in vulnerable
    )
    ordinary_records = tuple(
        _resume_or_prove(bundle, manifest.population_digest, change, Path(repos[change["repo"]]).expanduser(), out_dir / "ordinary")
        for change in ordinary
    )
    return assemble_admission_report(
        manifest, vulnerable_records, fixed_records, ordinary_records, criteria=criteria, budget_seconds=budget_seconds
    )


def _fixed_side_change(repo_path: Path, change: dict[str, Any]) -> dict[str, Any]:
    lines, operation = _fixed_site(repo_path, change)
    return fixed_side_change(change, fixed_lines=lines, fixed_operation=operation)


def _fixed_site(repo_path: Path, change: dict[str, Any]) -> tuple[tuple[int, int] | None, str]:
    """(lines, operation) for the labelled function at the fixed revision.

    A locator miss (the name is present but ``ranges`` could not name it) is
    "missed" and can never become a clean judgment (design.md:371).
    """
    from benchmarks.valid.catalog import local_git

    git = local_git(repo_path)
    text = git.runner(
        ["git", "-C", str(repo_path), "show", f"{change['base']}:{change['path']}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    name = str(change.get("function"))
    try:
        functions = ranges(str(change["path"]), text, canonical_language(detect_language(repo_path / change["path"])))
    except ValueError:
        functions = ()
    lines = locate_function(functions, name=name)
    return lines, classify_fixed_site(lines, name_in_text=name in text)
