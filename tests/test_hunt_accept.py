"""Each acceptance clause has an independent numerical counterexample."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from openultrasast.hunt.accept import FoldResult, Rule, decide, record_rejection
from openultrasast.hunt.artifact import RunArtifact
from openultrasast.hunt.propose import Candidate


def estimate(diff=0.2):
    """A synthetic paired estimate with counts and a finite interval."""
    return {"diff": diff, "ci": [diff - 0.1, diff + 0.1], "units": 20, "groups": 4}


@pytest.fixture
def candidate(tmp_path):
    """A single instruction edit, with its baseline available for comparison."""
    base = {"hunt": {"signature": {"instructions": "old", "fields": []}, "demos": []}}
    state = deepcopy(base)
    state["hunt"]["signature"]["instructions"] = "new"
    return Candidate(
        "candidate",
        "instruction",
        {"instruction": {"hunt": "new"}},
        {"recall": 0.7, "ci": [0.5, 0.9]},
        state,
        "current",
        base,
        (),
        (),
        str(tmp_path),
    )


@pytest.fixture
def results():
    """Two scopes containing pooled and family differences."""
    return (
        {family: FoldResult("compile", family, estimate(), estimate(0)) for family in ("pooled", "injection")},
        {family: FoldResult("holdout", family, estimate(), estimate(0)) for family in ("pooled", "injection")},
    )


def rule(**kwargs):
    """A fixed rule with no permitted family regression by default."""
    return Rule(**({"tolerance": 0.01, "regression_budget": {"default": 0, "injection": -0.1}, "instruction_cap": 100} | kwargs))


def difference(results, scope, family, value):
    """Change one measured recall difference."""
    results[scope][family] = replace(results[scope][family], recall=estimate(value))


@pytest.mark.parametrize("scope,reason", [(0, "compile_recall_negative"), (1, "holdout_recall_negative")])
def test_negative_pooled_difference_rejects(candidate, results, scope, reason):
    """Either negative pooled result defeats an otherwise acceptable proposal."""
    assert decide("current", candidate, *results, rule()).accepted
    difference(results, scope, "pooled", -0.01)
    decision = decide("current", candidate, *results, rule())
    assert not decision.accepted and reason in decision.reasons


def test_both_zero_rejects(candidate, results):
    """Zero gain in both scopes is insufficient and is a held-out tie."""
    difference(results, 0, "pooled", 0)
    difference(results, 1, "pooled", 0)
    decision = decide("current", candidate, *results, rule())
    assert not decision.accepted
    assert {"no_positive_recall_difference", "holdout_tie"} <= set(decision.reasons)


def test_compile_zero_holdout_positive_accepts(candidate, results):
    """A positive held-out gain can accept when compile recall is unchanged."""
    difference(results, 0, "pooled", 0)
    assert decide("current", candidate, *results, rule()).accepted


def test_heldout_tolerance_rejects_even_with_compile_gain(candidate, results):
    """The tolerance boundary is inclusive and applies to held-out recall."""
    difference(results, 1, "pooled", 0.01)
    assert "holdout_tie" in decide("current", candidate, *results, rule()).reasons
    difference(results, 1, "pooled", 0.0101)
    assert decide("current", candidate, *results, rule()).accepted


def test_family_budget_overrides_pooled_gain(candidate, results):
    """A family at its allowed floor passes; below it rejects."""
    difference(results, 1, "injection", -0.1)
    assert decide("current", candidate, *results, rule()).accepted
    difference(results, 1, "injection", -0.101)
    assert "family_regression:injection" in decide("current", candidate, *results, rule()).reasons


def test_unlisted_family_uses_default_budget(candidate, results):
    """Families without an override still have a regression floor."""
    for scope, name in enumerate(("compile", "holdout")):
        results[scope]["path"] = FoldResult(name, "path", estimate(-0.01), estimate(0))
    assert "family_regression:path" in decide("current", candidate, *results, rule()).reasons
    assert decide("current", candidate, *results, rule(regression_budget={"default": -0.02})).accepted


def test_instruction_cap_uses_saved_instruction(candidate, results):
    """The state is authoritative even when the reported change is short."""
    assert decide("current", candidate, *results, rule(instruction_cap=3)).accepted
    decision = decide("current", candidate, *results, rule(instruction_cap=2))
    assert not decision.accepted and "instruction_cap" in decision.reasons


@pytest.mark.parametrize("scope,family,metric", [(0, "pooled", "recall"), (1, "injection", "recall"), (1, "pooled", "suspicions_per_push")])
def test_missing_interval_rejects(candidate, results, scope, family, metric):
    """Neither a family nor a suspicion point estimate can stand in for an interval."""
    result = results[scope][family]
    results[scope][family] = replace(result, **{metric: {**getattr(result, metric), "ci": None}})
    assert not decide("current", candidate, *results, rule()).accepted
    assert any(r.startswith("missing_interval:") for r in decide("current", candidate, *results, rule()).reasons)


def test_multiple_changes_reject_even_when_kind_claims_instruction(candidate, results):
    """Saved demos reveal an undeclared second edit."""
    state = deepcopy(candidate.state)
    state["hunt"]["demos"] = [{"findings": []}]
    decision = decide("current", replace(candidate, state=state), *results, rule())
    assert not decision.accepted and "multiple_or_invalid_changes" in decision.reasons


def test_comparison_is_saved_and_fits_existing_artifact(candidate, results, tmp_path):
    """Both IDs, scopes and the rule survive an artifact round trip."""
    decision = decide("current", candidate, *results, rule())
    assert decision.comparison["current_id"] == "current"
    assert decision.comparison["candidate_id"] == "candidate"
    assert decision.comparison["compile_results"]["pooled"]["recall"]["diff"] == 0.2
    assert decision.comparison["holdout_results"]["injection"]["recall"]["ci"]
    assert decision.comparison["rule"]["version"] == "accept-v1"
    assert json.loads((tmp_path / "comparison.json").read_text()) == decision.comparison
    artifact = RunArtifact("candidate", 1, (), {}, [], {}, {}, "fixture")
    decision.record(tmp_path, artifact=artifact)
    assert artifact.configurations == [{"comparison": decision.comparison}]
    path = artifact.write(tmp_path)
    assert RunArtifact.read(path).configurations == artifact.configurations


def test_rejection_omits_heldout_numbers(candidate, results, tmp_path):
    """The rejection journal discloses reasons and compile measurements only."""
    difference(results, 1, "pooled", -0.987654)
    decision = decide("current", candidate, *results, rule())
    record_rejection(tmp_path, candidate, decision)
    record_rejection(tmp_path, candidate, decision)
    rows = [json.loads(line) for line in (tmp_path / "rejected.jsonl").read_text().splitlines()]
    assert len(rows) == 2 and rows[0]["reasons"] == decision.reasons
    assert rows[0]["compile_score"] == candidate.compile_score
    assert "-0.987654" not in json.dumps(rows)
    assert set(rows[0]) == {"program_id", "kind", "change", "compile_score", "reasons"}


def test_missing_family_and_wrong_scope_cannot_accept(candidate, results):
    """Incomplete or mislabelled comparisons are not usable evidence."""
    del results[1]["injection"]
    assert not decide("current", candidate, *results, rule()).accepted
    results[1]["pooled"] = replace(results[1]["pooled"], scope="compile")
    assert not decide("current", candidate, *results, rule()).accepted
