"""Ecosystem-scoped ordinary projection and whole-push deduplication for V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_evaluation_case_validation import (
    _bundle,
    _digest,
    _multi_scope_authority_case,
    _ordinary_projection_authority_case,
)

from openultrasast.core.evaluation_measurement import ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_plan import EcosystemOrdinaryCensusV3


def _project(bundle):
    from openultrasast.core.evaluation_ordinary_projection import project_ordinary_pushes_v3

    reviewed_case = bundle[5]
    return project_ordinary_pushes_v3(
        bundle[3],
        bundle[6],
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        bundle[2],
        reviewed_case[0].context,
        reviewed_case[0].port,
        bundle[4],
    )


def _valid_bundle():
    return _bundle(
        authority_case=_ordinary_projection_authority_case(),
        shared_underlying_by_ecosystem=True,
    )


def _identity(key: ArmScopeKey, label: str, push: str):
    from openultrasast.core.evaluation_ordinary_projection import OrdinaryPushCaseV3

    return OrdinaryPushCaseV3(key, _digest(f"case-{label}"), _digest(f"binding-{label}"), _digest(push), "")


def _derive(census, keys, identities, whole):
    from openultrasast.core.evaluation_ordinary_projection import _derive_ordinary_push_projection_v3

    return _derive_ordinary_push_projection_v3(census, keys, identities, whole)


def test_reviewed_projection_reconciles_each_scope_and_deduplicates_whole_pushes() -> None:
    bundle = _valid_bundle()
    projection = _project(bundle)

    assert tuple(row.key for row in projection.scoped_projections) == (
        ArmScopeKey("arm-a", ScopeKey("reference-family", "python")),
        ArmScopeKey("arm-b", ScopeKey("reference-family", "javascript")),
        ArmScopeKey("arm-combined", ScopeKey("reference-family", "python")),
    )
    assert all(row.ordinary_push_count == 1 for row in projection.scoped_projections)
    python_rows = tuple(row for row in projection.scoped_projections if row.key.scope.ecosystem == "python")
    javascript_row = next(row for row in projection.scoped_projections if row.key.scope.ecosystem == "javascript")
    assert {row.cases[0].underlying_push_digest for row in python_rows} == {_digest("underlying-push-python-2")}
    assert javascript_row.cases[0].underlying_push_digest == _digest("underlying-push-javascript-2")
    assert projection.whole_population.underlying_push_count == 6
    assert len(projection.whole_population.underlying_push_digests) == 6
    assert projection.census_digest == bundle[3].plan_manifest.census.census_digest


def test_one_arm_projects_the_same_ordinary_push_once_into_each_same_ecosystem_family() -> None:
    bundle = _valid_bundle()
    census = replace(
        bundle[3].plan_manifest.census,
        scope_rows=bundle[3].plan_manifest.census.scope_rows[:1],
        ordinary_rows=(EcosystemOrdinaryCensusV3("python", 1),),
        whole_underlying_push_count=1,
    )
    first = ArmScopeKey("arm-a", ScopeKey("family-a", "python"))
    second = ArmScopeKey("arm-a", ScopeKey("family-b", "python"))
    push = "same-ecosystem-ordinary"

    projection = _derive(
        census,
        (first, second),
        (_identity(first, "a", push), _identity(second, "b", push)),
        (_digest(push),),
    )

    assert tuple(row.ordinary_push_count for row in projection.scoped_projections) == (1, 1)
    assert projection.whole_population.underlying_push_count == 1


def test_same_ecosystem_scopes_must_project_the_identical_eligible_push_set() -> None:
    bundle = _valid_bundle()
    census = replace(
        bundle[3].plan_manifest.census,
        scope_rows=bundle[3].plan_manifest.census.scope_rows[:1],
        ordinary_rows=(EcosystemOrdinaryCensusV3("python", 1),),
        whole_underlying_push_count=2,
    )
    first = ArmScopeKey("arm-a", ScopeKey("family-a", "python"))
    second = ArmScopeKey("arm-b", ScopeKey("family-b", "python"))

    with pytest.raises(ValueError, match="eligible ordinary push set"):
        _derive(
            census,
            (first, second),
            (_identity(first, "a", "push-a"), _identity(second, "b", "push-b")),
            (_digest("push-a"), _digest("push-b")),
        )


def test_underlying_ordinary_push_cannot_project_into_another_ecosystem() -> None:
    bundle = _valid_bundle()
    census = replace(
        bundle[3].plan_manifest.census,
        ordinary_rows=(EcosystemOrdinaryCensusV3("javascript", 1), EcosystemOrdinaryCensusV3("python", 1)),
        whole_underlying_push_count=2,
    )
    javascript = ArmScopeKey("arm-a", ScopeKey("family-a", "javascript"))
    python = ArmScopeKey("arm-b", ScopeKey("family-b", "python"))

    with pytest.raises(ValueError, match="another ecosystem"):
        _derive(
            census,
            (javascript, python),
            (_identity(javascript, "js", "shared-push"), _identity(python, "py", "shared-push")),
            tuple(sorted((_digest("shared-push"), _digest("other-push")))),
        )


def test_scoped_and_whole_counts_must_match_the_reviewed_census() -> None:
    bundle = _valid_bundle()
    key = ArmScopeKey("arm-a", ScopeKey("family-a", "python"))
    census = replace(
        bundle[3].plan_manifest.census,
        scope_rows=bundle[3].plan_manifest.census.scope_rows[:1],
        ordinary_rows=(EcosystemOrdinaryCensusV3("python", 2),),
        whole_underlying_push_count=2,
    )
    identity = _identity(key, "a", "push-a")

    with pytest.raises(ValueError, match="ordinary census"):
        _derive(census, (key,), (identity,), (_digest("push-a"), _digest("push-b")))
    with pytest.raises(ValueError, match="whole-population census"):
        _derive(replace(census, ordinary_rows=(EcosystemOrdinaryCensusV3("python", 1),)), (key,), (identity,), (_digest("push-a"),))


def test_full_release_with_unreconciled_census_is_refused() -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case())

    with pytest.raises(ValueError, match="census"):
        _project(bundle)


def test_projection_contracts_are_non_authorizing_and_require_exact_collections() -> None:
    from openultrasast.core.evaluation_ordinary_projection import EvaluationOrdinaryProjectionV3

    projection = _project(_valid_bundle())
    assert not {"metrics", "gate", "decision", "authorization"} & EvaluationOrdinaryProjectionV3.__dataclass_fields__.keys()
    with pytest.raises(ValueError, match="exact tuple"):
        _derive(
            _valid_bundle()[3].plan_manifest.census,
            list(row.key for row in projection.scoped_projections),  # type: ignore[arg-type]
            (),
            (),
        )


def test_v2_whole_population_metric_contract_is_unchanged() -> None:
    from openultrasast.core.admission_metrics import AdmissionMetricEvidence

    assert "whole_population_case_count" in AdmissionMetricEvidence.__dataclass_fields__
    assert "whole_population_funnel" in AdmissionMetricEvidence.__dataclass_fields__
