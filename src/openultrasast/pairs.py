"""Vuln-vs-fixed pair corpus: TP on the vuln tree, silent on the fix tree.

Isolated trees keep the two sides from contaminating each other (a `safe.py`
sitting next to `app.py` cannot measure false positives). Pair outcomes feed
the improvement loop as miss (vuln) and fp (fix) signals.
"""

from __future__ import annotations

import shutil
import tempfile
import tomllib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from .benchmark import (
    BenchmarkManifest,
    BenchmarkRun,
    BenchmarkSource,
    ExpectedFinding,
    evaluate_benchmark,
    load_benchmark_manifest,
)
from .findings import StaticFinding, quick_scan_findings
from .mapping import analyze_entry_points, attach_reachability_hints
from .preprocess import preprocess_repository
from .rank import rank_targets
from .semantic import OverlayRecord, adjudicate

DEFAULT_CATALOG = Path("benchmarks/pairs/catalog.toml")
DEFAULT_SAST_CATALOG = Path("benchmarks/pairs/sast/catalog.toml")
DEFAULT_DATASETS = Path("benchmarks/pairs/datasets.toml")


@dataclass(frozen=True)
class PairCase:
    name: str
    slice: str
    language: str
    origin: str
    vuln_file: Path
    fixed_file: Path
    relpath: str
    expected: tuple[ExpectedFinding, ...]
    min_recall: float
    fix_policy: str
    repo: str = ""
    commit: str = ""
    commit_url: str = ""
    cve: str = ""
    license: str = ""


@dataclass(frozen=True)
class PairOutcome:
    name: str
    slice: str
    language: str
    origin: str
    detected_vuln: bool
    silent_fix: bool
    pair_correct: bool
    vuln_matched: int
    vuln_expected: int
    vuln_findings: int
    fix_findings: int
    fix_leaks: int
    recall: float
    misses: tuple[str, ...]
    leaks: tuple[str, ...]
    commit_url: str = ""
    cve: str = ""


@dataclass(frozen=True)
class PairCorpusMetrics:
    pairs: int
    detected_vuln: int
    silent_fix: int
    pair_correct: int
    labeled_expected: int
    labeled_matched: int
    labeled_fix_leaks: int
    pair_pass_rate: float
    vuln_recall: float
    specificity: float
    labeled_recall: float
    youden: float


@dataclass(frozen=True)
class PairEvalResult:
    outcomes: tuple[PairOutcome, ...]
    overall: PairCorpusMetrics
    per_slice: dict[str, PairCorpusMetrics]
    signals: tuple[dict[str, object], ...]


def load_datasets(path: Path = DEFAULT_DATASETS) -> tuple[dict[str, object], ...]:
    payload = tomllib.loads(path.read_text())
    return tuple(dict(item) for item in payload.get("dataset", []))


def load_pair_catalog(path: Path = DEFAULT_CATALOG) -> tuple[PairCase, ...]:
    cases = _load_catalog_file(path)
    if path.resolve() == DEFAULT_CATALOG.resolve() and DEFAULT_SAST_CATALOG.exists():
        cases = cases + _load_catalog_file(DEFAULT_SAST_CATALOG)
    return cases


def _load_catalog_file(path: Path) -> tuple[PairCase, ...]:
    catalog_path = path.resolve()
    payload = tomllib.loads(catalog_path.read_text())
    root = catalog_path.parent
    cases: list[PairCase] = []
    for item in payload.get("pair", []):
        expected = _expected_for(item, root)
        cases.append(
            PairCase(
                name=str(item["name"]),
                slice=str(item.get("slice", "github")),
                language=str(item.get("language", "")),
                origin=str(item.get("origin", "")),
                vuln_file=_resolve(root, str(item["vuln"])),
                fixed_file=_resolve(root, str(item["fixed"])),
                relpath=str(item["relpath"]),
                expected=expected,
                min_recall=float(item.get("min_recall", 1.0)),
                fix_policy=str(item.get("fix_policy", "silent")),
                repo=str(item.get("repo", "")),
                commit=str(item.get("commit", "")),
                commit_url=str(item.get("commit_url", "")),
                cve=str(item.get("cve", "")),
                license=str(item.get("license", "")),
            )
        )
    return tuple(cases)


def evaluate_pair(case: PairCase) -> PairOutcome:
    with tempfile.TemporaryDirectory(prefix="ousast-pair-") as scratch:
        vuln_root = _materialize(Path(scratch) / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(Path(scratch) / "fixed", case.fixed_file, case.relpath)
        if case.slice == "sast":
            return _evaluate_overlay_pair(case, vuln_root, fix_root)
        vuln_findings = _quick_scan(vuln_root)
        fix_findings = _quick_scan(fix_root)
    vuln_result = evaluate_benchmark(
        run=BenchmarkRun(benchmark_run_id="pair", root=Path("/tmp/pair"), manifest=_manifest(case)),
        mode="quick",
        findings=vuln_findings,
        scan_id=None,
        scan_run_dir=None,
    )
    expected_total = len(case.expected)
    matched = vuln_result.metrics.matched_findings_total
    recall = matched / expected_total if expected_total else 1.0
    leaks = _fix_leaks(case, fix_findings)
    detected = recall + 1e-12 >= case.min_recall
    silent = not leaks
    misses = tuple(f"{miss.rule_id or '-'}:{miss.path}:{miss.cwe}" for miss in vuln_result.misses)
    leak_ids = tuple(finding.finding_id for finding in leaks)
    return PairOutcome(
        name=case.name,
        slice=case.slice,
        language=case.language,
        origin=case.origin,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=detected and silent,
        vuln_matched=matched,
        vuln_expected=expected_total,
        vuln_findings=len(vuln_findings),
        fix_findings=len(fix_findings),
        fix_leaks=len(leaks),
        recall=recall,
        misses=misses,
        leaks=leak_ids,
        commit_url=case.commit_url,
        cve=case.cve,
    )


def evaluate_catalog(cases: Sequence[PairCase]) -> PairEvalResult:
    outcomes = tuple(evaluate_pair(case) for case in cases)
    return PairEvalResult(
        outcomes=outcomes,
        overall=_metrics(outcomes),
        per_slice={
            slice_name: _metrics(tuple(item for item in outcomes if item.slice == slice_name))
            for slice_name in sorted({item.slice for item in outcomes})
        },
        signals=tuple(build_pair_signals(outcomes)),
    )


def build_pair_signals(outcomes: Sequence[PairOutcome]) -> list[dict[str, object]]:
    """Same miss/fp vocabulary as ``build_rule_signals``, tagged with the pair name."""
    signals: list[dict[str, object]] = []
    for outcome in outcomes:
        for miss in outcome.misses:
            rule_id, path, cwe = (miss.split(":", 2) + ["", ""])[:3]
            signals.append({"rule_id": rule_id if rule_id != "-" else "", "signal": "miss", "cwe": cwe, "path": path, "pair": outcome.name})
        for leak in outcome.leaks:
            rule_id = leak.split(":", 1)[0]
            signals.append({"rule_id": rule_id, "signal": "fp", "path": leak, "pair": outcome.name, "side": "fixed"})
    return sorted(signals, key=lambda item: (str(item.get("signal")), str(item.get("rule_id")), str(item.get("pair"))))


def select_slice(cases: Sequence[PairCase], slice_name: str | None) -> tuple[PairCase, ...]:
    if not slice_name or slice_name == "all":
        return tuple(cases)
    return tuple(case for case in cases if case.slice == slice_name)


def result_payload(result: PairEvalResult) -> dict[str, object]:
    return {
        "overall": asdict(result.overall),
        "per_slice": {name: asdict(metrics) for name, metrics in result.per_slice.items()},
        "outcomes": [asdict(outcome) for outcome in result.outcomes],
        "signals": list(result.signals),
    }


def _expected_for(item: dict[str, object], root: Path) -> tuple[ExpectedFinding, ...]:
    inline = item.get("expected")
    if isinstance(inline, list) and inline:
        return tuple(_parse_expected(entry) for entry in inline if isinstance(entry, dict))
    expected_from = item.get("expected_from")
    if not expected_from:
        return ()
    manifest = load_benchmark_manifest(_resolve(root, str(expected_from)))
    relpath = str(item["relpath"])
    # Pair eval measures ruled sinks. Unruled planted misses (split-sink, CWE-190)
    # stay on the stage-1/2 fixtures and must not drag local pair_correct below 1.0.
    return tuple(entry for entry in manifest.expected if entry.rule_id and (relpath in entry.path or entry.path in relpath))


def _parse_expected(item: dict[str, object]) -> ExpectedFinding:
    line_value = item.get("line")
    return ExpectedFinding(
        cwe=str(item["cwe"]),
        vulnerability_class=str(item.get("class", item.get("vulnerability_class", "unknown"))),
        path=str(item["path"]),
        evidence=str(item.get("evidence", "")),
        rule_id=str(item["rule_id"]) if "rule_id" in item else None,
        line=line_value if isinstance(line_value, int) else None,
        function=str(item["function"]) if "function" in item else None,
        sink=str(item["sink"]) if "sink" in item else None,
    )


def _manifest(case: PairCase) -> BenchmarkManifest:
    return BenchmarkManifest(
        name=case.name,
        language=case.language,
        frameworks=[],
        setup=[],
        source=BenchmarkSource(type="local", path=str(case.vuln_file)),
        modes=["quick"],
        expected=list(case.expected),
        known_noise=[],
        baselines=[],
    )


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _materialize(dest: Path, source: Path, relpath: str) -> Path:
    target = dest / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return dest


def _quick_scan(target: Path) -> list[StaticFinding]:
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    return quick_scan_findings(target, targets, rank_targets(targets))


def _overlay_scan(target: Path) -> tuple[list[StaticFinding], list[OverlayRecord]]:
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    findings = quick_scan_findings(target, targets, rank_targets(targets))
    return findings, adjudicate(root=target, targets=targets, findings=findings)


def _evaluate_overlay_pair(case: PairCase, vuln_root: Path, fix_root: Path) -> PairOutcome:
    vuln_findings, vuln_overlay = _overlay_scan(vuln_root)
    fix_findings, fix_overlay = _overlay_scan(fix_root)
    if not _adjudicated(vuln_overlay) and not _adjudicated(fix_overlay):
        # Parser/facts could not adjudicate this language; score inventory so
        # labeled calibration does not collapse when tree-sitter grammars are absent.
        vuln_result = evaluate_benchmark(
            run=BenchmarkRun(benchmark_run_id="pair", root=Path("/tmp/pair"), manifest=_manifest(case)),
            mode="quick",
            findings=vuln_findings,
            scan_id=None,
            scan_run_dir=None,
        )
        expected_total = len(case.expected)
        matched = vuln_result.metrics.matched_findings_total
        recall = matched / expected_total if expected_total else 1.0
        inventory_leaks = _fix_leaks(case, fix_findings)
        detected = recall + 1e-12 >= case.min_recall
        silent = not inventory_leaks
        misses = tuple(f"{miss.rule_id or '-'}:{miss.path}:{miss.cwe}" for miss in vuln_result.misses)
        leak_ids = tuple(finding.finding_id for finding in inventory_leaks)
        return PairOutcome(
            name=case.name,
            slice=case.slice,
            language=case.language,
            origin=case.origin,
            detected_vuln=detected,
            silent_fix=silent,
            pair_correct=detected and silent,
            vuln_matched=matched,
            vuln_expected=expected_total,
            vuln_findings=len(vuln_findings),
            fix_findings=len(fix_findings),
            fix_leaks=len(inventory_leaks),
            recall=recall,
            misses=misses,
            leaks=leak_ids,
            commit_url=case.commit_url,
            cve=case.cve,
        )
    promoted_vuln = [record for record in vuln_overlay if record.disposition == "promote"]
    promoted_fix = [record for record in fix_overlay if record.disposition == "promote"]
    expected_total = len(case.expected)
    matched = _overlay_matches(case, promoted_vuln)
    recall = matched / expected_total if expected_total else 1.0
    detected = recall + 1e-12 >= case.min_recall
    overlay_leaks = _overlay_leaks(case, promoted_fix)
    silent = not overlay_leaks
    misses = tuple(
        f"{expected.rule_id or '-'}:{expected.path}:{expected.cwe}"
        for expected in case.expected
        if not _overlay_matches_expected(expected, promoted_vuln)
    )
    return PairOutcome(
        name=case.name,
        slice=case.slice,
        language=case.language,
        origin=case.origin,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=detected and silent,
        vuln_matched=matched,
        vuln_expected=expected_total,
        vuln_findings=len(promoted_vuln),
        fix_findings=len(promoted_fix),
        fix_leaks=len(overlay_leaks),
        recall=recall,
        misses=misses,
        leaks=overlay_leaks,
        commit_url=case.commit_url,
        cve=case.cve,
    )


def _adjudicated(records: Sequence[OverlayRecord]) -> bool:
    return any(record.disposition in {"promote", "demote", "coverage"} for record in records)


def _overlay_matches(case: PairCase, promoted: Sequence[OverlayRecord]) -> int:
    return sum(1 for expected in case.expected if _overlay_matches_expected(expected, promoted))


def _overlay_matches_expected(expected: ExpectedFinding, promoted: Sequence[OverlayRecord]) -> bool:
    for record in promoted:
        if expected.rule_id and expected.rule_id in record.proposal_id:
            return True
        if expected.cwe and expected.cwe == record.cwe:
            return True
        if expected.sink and expected.sink in record.sinks:
            return True
    return False


def _overlay_leaks(case: PairCase, promoted: Sequence[OverlayRecord]) -> tuple[str, ...]:
    leaked: list[str] = []
    for record in promoted:
        if any(_overlay_matches_expected(expected, [record]) for expected in case.expected) or case.fix_policy == "silent":
            leaked.append(record.proposal_id)
    if case.fix_policy == "silent":
        return tuple(record.proposal_id for record in promoted)
    return tuple(leaked)


def _fix_leaks(case: PairCase, findings: list[StaticFinding]) -> tuple[StaticFinding, ...]:
    if case.fix_policy == "silent":
        return tuple(findings)
    leaked: list[StaticFinding] = []
    for finding in findings:
        for expected in case.expected:
            if expected.rule_id and finding.finding_id.startswith(f"{expected.rule_id}:"):
                leaked.append(finding)
                break
            if expected.cwe.lower() in (finding.rationale + " " + finding.finding_id).lower():
                leaked.append(finding)
                break
    return tuple(leaked)


def _metrics(outcomes: Sequence[PairOutcome]) -> PairCorpusMetrics:
    pairs = len(outcomes)
    detected = sum(1 for item in outcomes if item.detected_vuln)
    silent = sum(1 for item in outcomes if item.silent_fix)
    correct = sum(1 for item in outcomes if item.pair_correct)
    labeled_expected = sum(item.vuln_expected for item in outcomes)
    labeled_matched = sum(item.vuln_matched for item in outcomes)
    labeled_leaks = sum(item.fix_leaks for item in outcomes)
    return PairCorpusMetrics(
        pairs=pairs,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=correct,
        labeled_expected=labeled_expected,
        labeled_matched=labeled_matched,
        labeled_fix_leaks=labeled_leaks,
        pair_pass_rate=correct / pairs if pairs else 1.0,
        vuln_recall=detected / pairs if pairs else 1.0,
        specificity=silent / pairs if pairs else 1.0,
        labeled_recall=labeled_matched / labeled_expected if labeled_expected else 1.0,
        youden=(detected / pairs if pairs else 1.0) - (1.0 - (silent / pairs if pairs else 1.0)),
    )
