"""Detection-quality gate — the hard feasibility constraint (Phase 4 task 8).

Aggregate recall and false-positive rate over the benchmark corpus must clear the
project goal: recall >= 90% AND false-positive rate < 10%. This gate is computed
**independently of the project score** so a score improvement can never unblock a
gate-breaching change — the recall/FP constraint is never folded into the score
reward. ``merge_gate`` composes this hard constraint with the (advisory-first)
score gate by AND, so the score can only *add* a block, never remove one.

Run as a module to evaluate the corpus and exit non-zero on a breach::

    python -m openultrasast.gate
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .benchmark import BenchmarkRun, evaluate_benchmark, load_benchmark_manifest, resolve_benchmark_source
from .findings import quick_scan_findings
from .mapping import analyze_entry_points, attach_reachability_hints
from .preprocess import preprocess_repository
from .rank import rank_targets

# The in-scope corpus: language -> benchmark manifest names (smoke + real repo).
# Single source of truth shared by the CI gate and the detection-benchmark test.
LANGUAGE_MANIFESTS: dict[str, list[str]] = {
    "c_cpp": ["c-cpp-smoke", "cpp-damn-vulnerable"],
    "python": ["python-web-smoke", "python-vulnerable"],
    "javascript": ["javascript-node-web-smoke", "javascript-vulnerable"],
    "java": ["java-web-smoke", "java-spring-boot-vulnerable"],
}

RECALL_FLOOR = 0.90
FALSE_POSITIVE_CEILING = 0.10
DEFAULT_MANIFEST_DIR = Path("benchmarks/manifests")


@dataclass(frozen=True)
class DetectionMetrics:
    """Aggregate detection counts and the two rates derived from them."""

    expected: int
    matched: int
    actual: int
    false_positives: int

    @property
    def recall(self) -> float:
        return self.matched / self.expected if self.expected else 1.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.actual if self.actual else 0.0

    def __add__(self, other: DetectionMetrics) -> DetectionMetrics:
        return DetectionMetrics(
            expected=self.expected + other.expected,
            matched=self.matched + other.matched,
            actual=self.actual + other.actual,
            false_positives=self.false_positives + other.false_positives,
        )


@dataclass(frozen=True)
class DetectionGateVerdict:
    """Score-independent verdict: pass only if recall and FP both clear the goal."""

    passed: bool
    overall: DetectionMetrics
    per_language: dict[str, DetectionMetrics]
    recall_floor: float
    fp_ceiling: float
    reasons: list[str]


def _quick_scan(target: Path):  # type: ignore[no-untyped-def]
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    rankings = rank_targets(targets)
    return quick_scan_findings(target, targets, rankings)


def language_metrics(manifest_names: list[str], manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> DetectionMetrics:
    """Aggregate detection metrics across one language's manifests."""
    total = DetectionMetrics(0, 0, 0, 0)
    for name in manifest_names:
        manifest_path = manifest_dir / f"{name}.toml"
        manifest = load_benchmark_manifest(manifest_path)
        target = resolve_benchmark_source(manifest_path, manifest)
        findings = _quick_scan(target)
        run = BenchmarkRun(benchmark_run_id="gate", root=Path("/tmp/gate"), manifest=manifest)
        result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
        m = result.metrics
        total = total + DetectionMetrics(
            expected=m.expected_findings_total,
            matched=m.matched_findings_total,
            actual=m.actual_findings_total,
            false_positives=m.false_positive_findings_total,
        )
    return total


def evaluate_corpus(
    corpus: Mapping[str, list[str]] = LANGUAGE_MANIFESTS, manifest_dir: Path = DEFAULT_MANIFEST_DIR
) -> dict[str, DetectionMetrics]:
    """Compute per-language detection metrics across the whole corpus."""
    return {language: language_metrics(names, manifest_dir) for language, names in sorted(corpus.items())}


def detection_gate(
    per_language: Mapping[str, DetectionMetrics],
    *,
    recall_floor: float = RECALL_FLOOR,
    fp_ceiling: float = FALSE_POSITIVE_CEILING,
) -> DetectionGateVerdict:
    """Evaluate the hard recall/FP gate. No score input — it cannot be unblocked by score."""
    overall = DetectionMetrics(0, 0, 0, 0)
    for metrics in per_language.values():
        overall = overall + metrics
    reasons: list[str] = []
    for language, metrics in sorted(per_language.items()):
        if metrics.recall < recall_floor:
            reasons.append(f"{language} recall {metrics.recall:.2%} below {recall_floor:.0%} ({metrics.matched}/{metrics.expected})")
        if metrics.false_positive_rate >= fp_ceiling:
            reasons.append(
                f"{language} FP rate {metrics.false_positive_rate:.2%} at or above {fp_ceiling:.0%} "
                f"({metrics.false_positives}/{metrics.actual})"
            )
    if overall.recall < recall_floor:
        reasons.append(f"overall recall {overall.recall:.2%} below {recall_floor:.0%} ({overall.matched}/{overall.expected})")
    if overall.false_positive_rate >= fp_ceiling:
        reasons.append(
            f"overall FP rate {overall.false_positive_rate:.2%} at or above {fp_ceiling:.0%} ({overall.false_positives}/{overall.actual})"
        )
    return DetectionGateVerdict(
        passed=not reasons,
        overall=overall,
        per_language=dict(sorted(per_language.items())),
        recall_floor=recall_floor,
        fp_ceiling=fp_ceiling,
        reasons=reasons,
    )


def merge_gate(detection: DetectionGateVerdict, score_gate: Mapping[str, object] | None = None) -> dict[str, object]:
    """Compose the hard detection gate with the (advisory-first) score gate by AND.

    The merge blocks if detection fails OR a *blocking* score gate fails. A passing
    score gate (however high the score) can never flip a failed detection gate to
    pass — the recall/FP constraint is hard and never folded into the score reward.
    """
    score_passed = True if score_gate is None else bool(score_gate.get("passed", True))
    return {
        "passed": detection.passed and score_passed,
        "detection_passed": detection.passed,
        "score_passed": score_passed,
        "reasons": list(detection.reasons),
    }


def within_tolerance(
    baseline: DetectionMetrics,
    candidate: DetectionMetrics,
    *,
    recall_tolerance: float = 0.05,
    fp_tolerance: float = 0.05,
) -> bool:
    """True if ``candidate`` recall/FP stay within tolerance of ``baseline``.

    Used to confirm a HarnessX-backed stage does not drift detection beyond the
    configured band of the zero-dependency baseline. Recall may not fall more than
    ``recall_tolerance`` below baseline; FP may not rise more than ``fp_tolerance``
    above it.
    """
    recall_ok = candidate.recall >= baseline.recall - recall_tolerance
    fp_ok = candidate.false_positive_rate <= baseline.false_positive_rate + fp_tolerance
    return recall_ok and fp_ok


def main() -> int:
    verdict = detection_gate(evaluate_corpus())
    o = verdict.overall
    print(
        f"detection gate: recall {o.recall:.2%} ({o.matched}/{o.expected}), FP {o.false_positive_rate:.2%} ({o.false_positives}/{o.actual})"
    )
    for language, m in verdict.per_language.items():
        print(
            f"  {language:<11} recall {m.recall:>6.2%} ({m.matched}/{m.expected})  "
            f"FP {m.false_positive_rate:>6.2%} ({m.false_positives}/{m.actual})"
        )
    if verdict.passed:
        print("detection gate: PASS")
        return 0
    print("detection gate: FAIL", file=sys.stderr)
    for reason in verdict.reasons:
        print(f"  - {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
