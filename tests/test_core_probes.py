"""Anti-shortcut probe tests for detection-core tasks 5.1-5.2 (Req 8, 9)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collections.abc import Mapping
from typing import Any

from openultrasast.core.probes import (  # noqa: E402
    FittedComponentBlocked,
    ShortcutDetected,
    assert_no_shortcut,
    require_admission_evidence,
    reversed_pair_probe,
)

FIX: dict[str, Any] = {"id": "fix", "files": [{"path": "a.py", "head_lines": [[1, 10]]}], "seconds": 1.0}
REVERSED: dict[str, Any] = {"id": "reversed", "files": [{"path": "a.py", "head_lines": [[1, 50]]}], "seconds": 1.0}


def test_reversed_pair_probe_detects_shape_shortcut() -> None:
    # deletion-count style component: score = lines removed -> separates fix from reversed
    def shape_score(change: Mapping[str, Any]) -> float:
        return float(50.0 - change["files"][0]["head_lines"][0][1])

    result = reversed_pair_probe(shape_score, FIX, REVERSED)
    assert result.separated is True
    try:
        assert_no_shortcut(shape_score, FIX, REVERSED)
        raise AssertionError("shape shortcut must be detected")
    except ShortcutDetected:
        pass


def test_reversed_pair_probe_passes_relation_based_component() -> None:
    def relation_score(change: Mapping[str, Any]) -> float:
        return float(bool(change.get("has_guard")))

    assert reversed_pair_probe(relation_score, {**FIX, "has_guard": True}, {**REVERSED, "has_guard": True}).separated is False
    assert_no_shortcut(relation_score, {**FIX, "has_guard": True}, {**REVERSED, "has_guard": True})


def test_fitted_component_requires_holdout_and_admission_go() -> None:
    require_admission_evidence(holdout_passed=True, admission_decision="GO")
    for holdout, decision in ((False, "GO"), (True, "NO-GO"), (False, "NO-GO")):
        try:
            require_admission_evidence(holdout_passed=holdout, admission_decision=decision)
            raise AssertionError(f"holdout={holdout} decision={decision} must block the claim")
        except FittedComponentBlocked:
            pass
