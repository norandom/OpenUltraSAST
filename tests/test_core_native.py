"""Legacy test conformance after production adapters leave the v1 surface."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.hunt.prover import Coverage, PairJudgmentCounts  # noqa: E402


def test_hunt_coverage_retires_its_legacy_core_projection() -> None:
    coverage = Coverage(
        files_by_language={"java": 2},
        frameworks_recognised={"jenkins": 1},
        entry_points=3,
        reached=2,
        unreached=1,
        operations_checked=4,
        operations_discharged=1,
        unchecked_by_reason={"unreached": 1},
        pair_judgments=PairJudgmentCounts(unguarded=1, discharged=1, indeterminate=2),
        resolution_counts={"complete_calls": 5, "incomplete_calls": 3, "unresolved_calls": 2},
    )

    assert coverage.resolution_counts == {"complete_calls": 5, "incomplete_calls": 3, "unresolved_calls": 2}
    assert not hasattr(coverage, "to_core")
