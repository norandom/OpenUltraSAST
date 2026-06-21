"""Detection-quality gate for the in-scope languages.

Runs quick-mode scans against the C/C++, Python, and JavaScript benchmark
corpora and asserts the project goal: at least 90% recall of known
vulnerabilities and under a 10% false-positive rate per language.
"""

from pathlib import Path

import pytest

from openultrasast.benchmark import (
    BenchmarkRun,
    evaluate_benchmark,
    load_benchmark_manifest,
    resolve_benchmark_source,
)
from openultrasast.findings import quick_scan_findings
from openultrasast.mapping import analyze_entry_points, attach_reachability_hints
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets

LANGUAGE_MANIFESTS = {
    "c_cpp": ["c-cpp-smoke", "cpp-damn-vulnerable"],
    "python": ["python-web-smoke", "python-vulnerable"],
    "javascript": ["javascript-node-web-smoke", "javascript-vulnerable"],
    "java": ["java-web-smoke", "java-spring-boot-vulnerable"],
}

RECALL_FLOOR = 0.90
FALSE_POSITIVE_CEILING = 0.10


def _quick_scan(target: Path):  # type: ignore[no-untyped-def]
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    rankings = rank_targets(targets)
    return quick_scan_findings(target, targets, rankings)


def _language_metrics(manifest_names: list[str]) -> tuple[int, int, int, int]:
    expected = matched = actual = false_positives = 0
    for name in manifest_names:
        manifest_path = Path(f"benchmarks/manifests/{name}.toml")
        manifest = load_benchmark_manifest(manifest_path)
        target = resolve_benchmark_source(manifest_path, manifest)
        findings = _quick_scan(target)
        run = BenchmarkRun(benchmark_run_id="gate", root=Path("/tmp/gate"), manifest=manifest)
        result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
        metrics = result.metrics
        expected += metrics.expected_findings_total
        matched += metrics.matched_findings_total
        actual += metrics.actual_findings_total
        false_positives += metrics.false_positive_findings_total
    return expected, matched, actual, false_positives


@pytest.mark.parametrize("language", sorted(LANGUAGE_MANIFESTS))
def test_language_meets_recall_and_false_positive_goal(language: str) -> None:
    expected, matched, actual, false_positives = _language_metrics(LANGUAGE_MANIFESTS[language])

    recall = matched / expected
    false_positive_rate = false_positives / actual if actual else 0.0

    assert recall >= RECALL_FLOOR, f"{language} recall {recall:.2%} below {RECALL_FLOOR:.0%} ({matched}/{expected})"
    assert false_positive_rate < FALSE_POSITIVE_CEILING, (
        f"{language} false-positive rate {false_positive_rate:.2%} at or above {FALSE_POSITIVE_CEILING:.0%} ({false_positives}/{actual})"
    )


def test_overall_detection_goal_is_met() -> None:
    totals = [_language_metrics(names) for names in LANGUAGE_MANIFESTS.values()]
    expected = sum(t[0] for t in totals)
    matched = sum(t[1] for t in totals)
    actual = sum(t[2] for t in totals)
    false_positives = sum(t[3] for t in totals)

    assert matched / expected >= RECALL_FLOOR
    assert (false_positives / actual) < FALSE_POSITIVE_CEILING
