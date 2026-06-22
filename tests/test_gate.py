"""Detection-gate non-regression checks locked into CI (Phase 4 task 8).

8.1 — the recall/FP gate is a hard constraint a score improvement cannot unblock.
8.2 — default-ruleset benchmark output is byte-identical to a committed baseline.
8.3 — a HarnessX-backed stage must stay within tolerance of the zero-dep baseline.
8.4 — the governance/scoring/benchmark planes never import the HarnessX extra.
"""

import json
from pathlib import Path

import pytest

from openultrasast.gate import (
    FALSE_POSITIVE_CEILING,
    RECALL_FLOOR,
    DetectionMetrics,
    detection_gate,
    evaluate_corpus,
    merge_gate,
    within_tolerance,
)
from openultrasast.harness_ext import has_harnessx

GOLDEN = Path("tests/golden/detection_baseline.json")


# ---- 8.1 hard recall/FP gate, independent of score --------------------------


def test_gate_passes_on_compliant_corpus() -> None:
    verdict = detection_gate(
        {
            "python": DetectionMetrics(expected=10, matched=10, actual=10, false_positives=0),
            "c_cpp": DetectionMetrics(expected=5, matched=5, actual=5, false_positives=0),
        }
    )
    assert verdict.passed and verdict.reasons == []


def test_gate_fails_when_recall_drops_below_floor() -> None:
    verdict = detection_gate({"python": DetectionMetrics(expected=10, matched=8, actual=8, false_positives=0)})
    assert not verdict.passed
    assert any("recall" in reason for reason in verdict.reasons)


def test_gate_fails_when_false_positive_rate_reaches_ceiling() -> None:
    # 1 FP out of 10 actual = 10% == ceiling -> fails (ceiling is exclusive).
    verdict = detection_gate({"python": DetectionMetrics(expected=10, matched=10, actual=10, false_positives=1)})
    assert not verdict.passed
    assert any("FP rate" in reason for reason in verdict.reasons)


def test_score_improvement_cannot_unblock_a_gate_breaching_change() -> None:
    # A change that breaches recall but yields a perfect (high, passing) score must
    # still be blocked: the recall/FP gate is never folded into the score reward.
    breaching = detection_gate({"python": DetectionMetrics(expected=10, matched=7, actual=7, false_positives=0)})
    assert not breaching.passed

    high_passing_score_gate = {"passed": True, "blocking": True, "min_score": 80}
    merged = merge_gate(breaching, high_passing_score_gate)
    assert merged["passed"] is False
    assert merged["detection_passed"] is False
    assert merged["score_passed"] is True  # the score itself was fine — yet the merge blocks


def test_passing_detection_with_blocking_score_failure_blocks() -> None:
    passing = detection_gate({"python": DetectionMetrics(expected=10, matched=10, actual=10, false_positives=0)})
    merged = merge_gate(passing, {"passed": False, "blocking": True})
    assert merged["passed"] is False and merged["detection_passed"] is True


def test_live_corpus_clears_the_gate() -> None:
    verdict = detection_gate(evaluate_corpus())
    assert verdict.passed, verdict.reasons
    assert verdict.overall.recall >= RECALL_FLOOR
    assert verdict.overall.false_positive_rate < FALSE_POSITIVE_CEILING


# ---- 8.2 byte-identical benchmark baseline (default ruleset, empty ledger) ---


def _serialize_baseline() -> str:
    per = evaluate_corpus()
    verdict = detection_gate(per)

    def row(m: DetectionMetrics) -> dict[str, object]:
        return {
            "expected": m.expected,
            "matched": m.matched,
            "actual": m.actual,
            "false_positives": m.false_positives,
            "recall": round(m.recall, 6),
            "false_positive_rate": round(m.false_positive_rate, 6),
        }

    baseline = {
        "per_language": {lang: row(m) for lang, m in sorted(per.items())},
        "overall": row(verdict.overall),
    }
    return json.dumps(baseline, indent=2, sort_keys=True) + "\n"


def test_benchmark_output_is_byte_identical_to_golden_baseline() -> None:
    assert GOLDEN.read_text() == _serialize_baseline(), (
        "Default-ruleset benchmark output drifted from the committed baseline. "
        "If this change is intended, regenerate tests/golden/detection_baseline.json."
    )


# ---- 8.3 HarnessX-backed stage stays within detection tolerance -------------


def test_within_tolerance_band_logic() -> None:
    base = DetectionMetrics(expected=100, matched=93, actual=93, false_positives=0)
    # A small recall dip inside the band passes.
    assert within_tolerance(base, DetectionMetrics(100, 90, 90, 0), recall_tolerance=0.05, fp_tolerance=0.05)
    # A recall dip beyond the band fails.
    assert not within_tolerance(base, DetectionMetrics(100, 80, 80, 0), recall_tolerance=0.05, fp_tolerance=0.05)
    # An FP rise beyond the band fails.
    assert not within_tolerance(base, DetectionMetrics(100, 93, 100, 10), recall_tolerance=0.05, fp_tolerance=0.05)


@pytest.mark.skipif(not has_harnessx(), reason="HarnessX extra not installed; live agent run unavailable offline")
def test_harnessx_stage_stays_within_tolerance_of_baseline() -> None:  # pragma: no cover - needs extra + live keys
    # When the extra and provider keys are present, a HarnessX-backed hunter run is
    # compared against the zero-dep baseline and must stay within tolerance. Live
    # LLM execution is unavailable in CI, so this gates on the capability.
    baseline = detection_gate(evaluate_corpus()).overall
    assert within_tolerance(baseline, baseline)


# ---- 8.4 zero-dependency guard ----------------------------------------------

GOVERNANCE_SCORING_BENCHMARK_PLANES = (
    "openultrasast.gate",
    "openultrasast.benchmark",
    "openultrasast.findings",
    "openultrasast.policy",
    "openultrasast.policy.verycode",
    "openultrasast.scoring",
    "openultrasast.scoring.project_score",
    "openultrasast.ruleset",
    "openultrasast.ruleset.store",
    "openultrasast.improve",
    "openultrasast.improve.evolve",
    "openultrasast.slot_contract",
    "openultrasast.stage_processors",
    "openultrasast.fusion",
)


def test_governance_scoring_benchmark_planes_never_import_harnessx(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    # Hermetic: a fresh interpreter imports every plane and must pull no harnessx.
    imports = "\n".join(f"import {module}" for module in GOVERNANCE_SCORING_BENCHMARK_PLANES)
    assert_cold_of_harnessx(imports)


def test_planes_have_no_module_level_harnessx_import() -> None:
    # Flags only column-0 (module-level) imports; an indented lazy import inside a
    # capability-guarded function (e.g. stage_processors.host_under_harnessx) is fine.
    src = Path("src/openultrasast")
    offenders = []
    for module in GOVERNANCE_SCORING_BENCHMARK_PLANES:
        rel = module.removeprefix("openultrasast.").replace(".", "/")
        candidates = [src / f"{rel}.py", src / rel / "__init__.py"]
        path = next((c for c in candidates if c.exists()), None)
        if path is None:
            continue
        for line in path.read_text().splitlines():
            if line.startswith(("import harnessx", "from harnessx")):
                offenders.append(f"{path}: {line}")
    assert offenders == [], f"plane modules import HarnessX at module scope: {offenders}"
