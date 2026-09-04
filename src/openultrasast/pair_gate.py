"""Pair-efficiency gate: local fixtures must fire on vuln and stay silent on fix.

The stage-1 smoke gate stays on cheat-sheet trees. This module measures
differential detection and only *fails CI* on the local slice. GitHub/SVEN
pairs are printed as the honesty dashboard (real VFC misses become improve
signals, they do not block merge).

    python -m openultrasast.pair_gate
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass

from .pairs import (
    DEFAULT_CATALOG,
    PairCase,
    PairEvalResult,
    evaluate_catalog,
    load_pair_catalog,
    select_slice,
)


@dataclass(frozen=True)
class PairGateVerdict:
    passed: bool
    reasons: tuple[str, ...]
    result: PairEvalResult


def pair_gate(cases: Sequence[PairCase] | None = None) -> PairGateVerdict:
    catalog = tuple(cases) if cases is not None else load_pair_catalog(DEFAULT_CATALOG)
    local = select_slice(catalog, "local")
    if not local:
        return PairGateVerdict(passed=False, reasons=("no local pairs in catalog",), result=evaluate_catalog(()))
    result = evaluate_catalog(catalog)
    local_metrics = result.per_slice.get("local")
    reasons: list[str] = []
    if local_metrics is None:
        reasons.append("local slice produced no outcomes")
    elif local_metrics.pair_pass_rate < 1.0:
        failed = [outcome.name for outcome in result.outcomes if outcome.slice == "local" and not outcome.pair_correct]
        reasons.append("local pair_pass_rate below 100%: " + ", ".join(failed))
    return PairGateVerdict(passed=not reasons, reasons=tuple(reasons), result=result)


def print_pair_metrics(label: str, result: PairEvalResult) -> None:
    overall = result.overall
    print(
        f"{label}: pair_pass {overall.pair_pass_rate:.2%} ({overall.pair_correct}/{overall.pairs}), "
        f"vuln_recall {overall.vuln_recall:.2%}, silent_fix {overall.specificity:.2%}, "
        f"Youden {overall.youden:+.2%}, "
        f"labeled_recall {overall.labeled_recall:.2%} ({overall.labeled_matched}/{overall.labeled_expected}), "
        f"fix_leaks {overall.labeled_fix_leaks}"
    )
    for slice_name, metrics in result.per_slice.items():
        print(
            f"  {slice_name:<8} pair_pass {metrics.pair_pass_rate:>6.2%} ({metrics.pair_correct}/{metrics.pairs})  "
            f"vuln {metrics.vuln_recall:>6.2%}  silent {metrics.specificity:>6.2%}  "
            f"Youden {metrics.youden:>+7.2%}  labeled {metrics.labeled_recall:>6.2%}"
        )
    for outcome in result.outcomes:
        mark = "PASS" if outcome.pair_correct else "MISS" if not outcome.detected_vuln else "LEAK"
        print(
            f"    {mark:<4} {outcome.name:<32} vuln {outcome.vuln_matched}/{outcome.vuln_expected} "
            f"fix_findings={outcome.fix_findings} leaks={outcome.fix_leaks}"
        )


def main() -> int:
    verdict = pair_gate()
    print_pair_metrics("pair gate", verdict.result)
    if verdict.passed:
        print("pair gate: PASS (local slice)")
        return 0
    print("pair gate: FAIL", file=sys.stderr)
    for reason in verdict.reasons:
        print(f"  - {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
