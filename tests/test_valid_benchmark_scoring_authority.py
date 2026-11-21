"""Replacement scoring authority routed through the V3 core facade (task 9.2).

The replacement admission path must have no alternative scorer: metrics,
gates, case validation, proof validation, and replay delegate exclusively to
the pinned detection-core V3 facade. The legacy aggregate helpers remain
available only for frozen historical V2 replay, and pooled or target-specific
aggregate output is structurally refused as a replacement admission root.
"""

from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_core_evaluation_end_to_end import _complete_replay

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import benchmarks.valid.admission_run as admission_run  # noqa: E402
from benchmarks.valid import admission_scoring  # noqa: E402
from benchmarks.valid.admission_scoring import (  # noqa: E402
    V3_EVALUATION_SCHEMA,
    AdmissionCase,
    AdmissionScoringError,
    OrdinaryChange,
    ReplacementScoringRefusal,
    ReplacementScoringRefusalReason,
    admission_report,
    decode_replacement_root,
    preflight_replacement_gates,
    score_replacement_replay,
    validate_replacement_replay,
)
from benchmarks.valid.core_conformance import decode_scoped_admission_v3  # noqa: E402
from benchmarks.valid.historical_authorization import PINNED_HISTORICAL_DIGESTS  # noqa: E402
from openultrasast.core import evaluation_admission  # noqa: E402
from openultrasast.core.evaluation_admission import EvaluationAdmissionV3Error  # noqa: E402
from openultrasast.core.evaluation_replay import EvaluationReplayV3  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _historical_manifest() -> SimpleNamespace:
    return SimpleNamespace(
        population_role="admission",
        analyzer_revision="prover-fixture-1",
        fact_set_digest="a" * 64,
        acquisition_record_digest="b" * 64,
        configuration_digest="c" * 64,
        population_digest="d" * 64,
        families=("access_control",),
    )


def _historical_cases() -> tuple[AdmissionCase, ...]:
    return (AdmissionCase("pair-1", "unguarded", "discharged", True, 1.0),)


def _historical_ordinary() -> tuple[OrdinaryChange, ...]:
    return (OrdinaryChange("ordinary-1", "discharged", False),)


def _ordered_readiness(bundle: tuple) -> tuple:
    readiness_by_digest = {item.result_digest: item for item in bundle[5][3]}
    return tuple(readiness_by_digest[digest] for digest in bundle[3].plan_manifest.readiness_digests)


def test_replacement_seam_delegates_exclusively_to_the_pinned_core_facade(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, replay, *_ = _complete_replay(monkeypatch)
    reviewed_case = bundle[5]

    feasibility = preflight_replacement_gates(bundle[3].plan_manifest, reviewed_case[0].context, bundle[4])
    assert feasibility == evaluation_admission.preflight_evaluation(bundle[3].plan_manifest, reviewed_case[0].context, bundle[4])

    scored = score_replacement_replay(
        bundle[3],
        feasibility,
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        bundle[2],
        _ordered_readiness(bundle),
        reviewed_case[0].context,
        reviewed_case[0].port,
        bundle[4],
    )
    assert scored == replay
    assert scored.replay_digest == replay.replay_digest

    reports = validate_replacement_replay(scored, reviewed_case[0].context, reviewed_case[0].port, bundle[4])
    assert reports == replay.reports
    assert decode_replacement_root(V3_EVALUATION_SCHEMA, scored, EvaluationReplayV3) is scored


def test_replacement_path_has_no_alternative_scorer(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("legacy aggregate scoring or access-control site judgment participated in replacement scoring")

    monkeypatch.setattr(admission_scoring, "admission_report", forbidden)
    monkeypatch.setattr(admission_scoring, "_refuse_inputs", forbidden)
    monkeypatch.setattr(admission_scoring, "score_v2_admission", forbidden)
    monkeypatch.setattr(admission_scoring.score, "rate", forbidden)
    monkeypatch.setattr(admission_run, "site_judgment", forbidden)
    monkeypatch.setattr(admission_run, "admission_pair_cases", forbidden)
    monkeypatch.setattr(admission_run, "admission_ordinary", forbidden)

    bundle, replay, *_ = _complete_replay(monkeypatch)
    reviewed_case = bundle[5]
    feasibility = preflight_replacement_gates(bundle[3].plan_manifest, reviewed_case[0].context, bundle[4])
    scored = score_replacement_replay(
        bundle[3],
        feasibility,
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        bundle[2],
        _ordered_readiness(bundle),
        reviewed_case[0].context,
        reviewed_case[0].port,
        bundle[4],
    )
    assert scored == replay
    assert validate_replacement_replay(scored, reviewed_case[0].context, reviewed_case[0].port, bundle[4]) == replay.reports


def test_legacy_aggregate_output_is_refused_as_replacement_admission_root(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, replay, *_ = _complete_replay(monkeypatch)
    legacy = admission_report(
        _historical_manifest(),
        _historical_cases(),
        _historical_ordinary(),
        coverage=1.0,
        criteria={"min_fix_recall": 0.5},
    )
    assert legacy["decision"] == "GO"

    for candidate in (legacy, dict(legacy, schema_version="openultrasast.detection-core.admission-report.v2")):
        with pytest.raises(ReplacementScoringRefusal) as refusal:
            decode_replacement_root(V3_EVALUATION_SCHEMA, candidate, EvaluationReplayV3)
        assert refusal.value.reason is ReplacementScoringRefusalReason.LEGACY_AGGREGATE_ROOT
        # The refusal fires before any context, custody, or resolver is consulted.
        with pytest.raises(ReplacementScoringRefusal):
            validate_replacement_replay(candidate, None, None, None)
        with pytest.raises(EvaluationAdmissionV3Error):
            decode_scoped_admission_v3(V3_EVALUATION_SCHEMA, candidate, EvaluationReplayV3)

    assert decode_replacement_root(V3_EVALUATION_SCHEMA, replay, EvaluationReplayV3) is replay


def test_pooled_and_target_specific_aggregate_output_cannot_authorize_v3() -> None:
    target_specific = admission_report(
        _historical_manifest(),
        _historical_cases(),
        _historical_ordinary(),
        coverage=1.0,
    )
    pooled = {
        "aggregate": target_specific,
        "constituents": ["access_control"],
        "sample_counts": [1],
        "weighting": [1.0],
    }
    wrapped = {"arms": [target_specific], "whole_population": pooled}

    for candidate in (target_specific, pooled, wrapped):
        with pytest.raises(ReplacementScoringRefusal) as refusal:
            decode_replacement_root(V3_EVALUATION_SCHEMA, candidate, EvaluationReplayV3)
        assert refusal.value.reason is ReplacementScoringRefusalReason.LEGACY_AGGREGATE_ROOT
        with pytest.raises(ReplacementScoringRefusal):
            validate_replacement_replay(candidate, None, None, None)


def test_legacy_aggregate_helpers_remain_available_for_frozen_historical_replay() -> None:
    report = admission_report(
        _historical_manifest(),
        _historical_cases(),
        _historical_ordinary(),
        coverage=1.0,
        criteria={"min_fix_recall": 0.5},
    )
    assert report["pairs"] == {"n": 1, "correct": 1}
    assert report["decision"] == "GO"
    assert report["failed_gates"] == []

    bad_judgment = (AdmissionCase("pair-2", "nonsense", "discharged", True, 1.0),)
    with pytest.raises(AdmissionScoringError, match="judgment"):
        admission_report(_historical_manifest(), bad_judgment, _historical_ordinary(), coverage=1.0)
    mislabeled = (OrdinaryChange("ordinary-2", "discharged", True),)
    with pytest.raises(AdmissionScoringError, match="mislabeled"):
        admission_report(_historical_manifest(), _historical_cases(), mislabeled, coverage=1.0)


def test_v2_and_historical_fixture_bytes_remain_byte_identical() -> None:
    for relative, expected in sorted(PINNED_HISTORICAL_DIGESTS.items()):
        content = (ROOT / relative).read_bytes()
        assert content, f"historical fixture read zero bytes: {relative}"
        assert sha256(content).hexdigest() == expected, f"historical fixture bytes changed: {relative}"


def test_replacement_modules_do_not_bind_legacy_scoring_or_site_judgment_helpers() -> None:
    import benchmarks.valid.admission_execution as execution  # noqa: F401
    import benchmarks.valid.admission_orchestrator as orchestrator

    forbidden = frozenset(
        {"admission_report", "score_v2_admission", "site_judgment", "run_v2_admission", "admission_pair_cases", "admission_ordinary"}
    )
    for module in (orchestrator, execution):
        bound = forbidden & set(vars(module))
        assert not bound, f"{module.__name__} binds legacy scoring helpers: {sorted(bound)}"
