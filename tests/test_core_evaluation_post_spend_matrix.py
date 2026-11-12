"""Adversarial post-spend, metric, combination, and replay matrix for V3."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
import test_core_evaluation_case_validation as case_fixtures
import test_core_evaluation_combination as combination_fixtures
import test_core_evaluation_metric_derivation as metric_fixtures
import test_core_evaluation_ordinary_projection as ordinary_fixtures
import test_core_evaluation_proof as proof_fixtures
import test_core_evaluation_replay as replay_fixtures
import test_core_evaluation_replay_validation as replay_validation_fixtures
import test_core_evaluation_report as report_fixtures
from detection_core_fixtures import InMemoryContentResolver
from test_core_evaluation_case_outcome import _case_record
from test_core_evaluation_plan import _digest

from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRelease, AdmissionCaseRole
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionError,
    derive_component_case_outcome_projection,
)
from openultrasast.core.evaluation_combination import CombinationValidationError, derive_combination_lineages_v3
from openultrasast.core.evaluation_measurement import ArmScopeKey, MetricId, ScopeKey
from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError, _scoped_result
from openultrasast.core.evaluation_ordinary_projection import (
    EvaluationOrdinaryProjectionError,
    WholePopulationProjectionV3,
)
from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3
from openultrasast.core.evaluation_release import EvaluationReleaseError
from openultrasast.core.evaluation_replay import EvaluationReplayError
from openultrasast.core.evaluation_replay_validation import (
    EvaluationReplayValidationError,
    validate_evaluation_replay_v3,
)
from openultrasast.core.evaluation_report import EvaluationReportError
from openultrasast.core.evidence import EvidenceBasis, NeutralOutcome


@dataclass
class _PostSpendDriver:
    insufficiencies: int = 0
    decisions: list[str] = field(default_factory=list)
    aggregate_authorities: int = 0
    fitted_eligibilities: int = 0
    events: list[tuple[str, str]] = field(default_factory=list)

    def snapshot(self) -> tuple[int, tuple[str, ...], int, int, tuple[tuple[str, str], ...]]:
        return (
            self.insufficiencies,
            tuple(self.decisions),
            self.aggregate_authorities,
            self.fitted_eligibilities,
            tuple(self.events),
        )

    def downstream_hooks(self, stage: str) -> None:
        self.insufficiencies += 1
        self.decisions.extend(("GO", "NO-GO"))
        self.aggregate_authorities += 1
        self.fitted_eligibilities += 1
        self.events.extend((stage, name) for name in ("insufficiency", "decision", "aggregate", "fitted"))

    def run(self, stage: str, operation: _Operation) -> object:
        result = operation(self)
        self.downstream_hooks(stage)
        return result


_Operation = Callable[[_PostSpendDriver], object]


@dataclass(frozen=True)
class _MutationCase:
    name: str
    owner: str
    operation: _Operation
    exception: type[BaseException]
    message: str


def _must_refuse(case: _MutationCase) -> None:
    driver = _PostSpendDriver()
    before = driver.snapshot()
    with pytest.raises(case.exception, match=re.escape(case.message)):
        driver.run(case.owner, case.operation)
    assert driver.snapshot() == before, f"{case.owner} refusal leaked post-spend authority"


def _unchecked(value: object, **changes: object) -> object:
    changed = object.__new__(type(value))
    for name, item in vars(value).items():
        object.__setattr__(changed, name, changes.get(name, item))
    return changed


def _v2_release(_driver: _PostSpendDriver) -> object:
    bundle = case_fixtures._bundle()
    return case_fixtures._validate(bundle, release=object.__new__(AdmissionCaseRelease))


def _case_swap(mutation: str) -> _Operation:
    def operation(_driver: _PostSpendDriver) -> object:
        bundle = case_fixtures._bundle()
        group = bundle[2][0]
        target_index = next(
            (index for index, case in enumerate(group.cases) if case.role is AdmissionCaseRole.VULNERABLE),
            0,
        )
        changed = case_fixtures._mutated_case(group.cases[target_index], mutation)
        assert changed is not None
        cases = group.cases[:target_index] + (changed,) + group.cases[target_index + 1 :]
        changed_group = _unchecked(group, cases=cases, cases_digest="")
        groups = tuple(changed_group if item.arm_id == group.arm_id else item for item in bundle[2])
        return case_fixtures._validate(bundle, groups=groups)

    return operation


def _projection_substitution(mutation: str) -> _Operation:
    def operation(_driver: _PostSpendDriver) -> object:
        bundle = case_fixtures._bundle(projection_mutation=mutation)
        return case_fixtures._validate(bundle)

    return operation


def _empty_outcome(_driver: _PostSpendDriver) -> object:
    return derive_component_case_outcome_projection(())


def _mixed_outcome(_driver: _PostSpendDriver) -> object:
    return derive_component_case_outcome_projection(
        (
            _case_record("matrix-violation", NeutralOutcome.VIOLATION),
            _case_record("matrix-satisfied", NeutralOutcome.SATISFIED),
        )
    )


def _combination_missing(_driver: _PostSpendDriver) -> object:
    bindings = combination_fixtures._valid_bindings()
    return derive_combination_lineages_v3(combination_fixtures._declaration(), bindings[1:])


def _combination_duplicate(_driver: _PostSpendDriver) -> object:
    bindings = combination_fixtures._valid_bindings()
    duplicate = tuple(
        sorted(
            bindings + (bindings[0],),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    return derive_combination_lineages_v3(combination_fixtures._declaration(), duplicate)


def _combination_contradiction(_driver: _PostSpendDriver) -> object:
    bindings = combination_fixtures._valid_bindings()
    combined = bindings[2]
    wrong = combination_fixtures._projection(
        combined.case_input_digest,
        NeutralOutcome.SATISFIED,
        sources=tuple(reversed(combined.outcome_projection.source_outcome_digests)),
        combined=True,
    )
    changed = replace(combined, outcome_projection=wrong, binding_digest="")
    return derive_combination_lineages_v3(combination_fixtures._declaration(), bindings[:2] + (changed,))


def _proof_transfer(_driver: _PostSpendDriver) -> object:
    case, binding, release, plan, context, authority, resolver = proof_fixtures._released_proof_case()
    case, binding = proof_fixtures._candidate_transfer_mutation("role", case, binding)
    return apply_released_case_proof_v3(
        case,
        binding,
        proof_fixtures._rerelease(release, binding),
        plan,
        context,
        authority,
        resolver,
    )


def _cross_ecosystem_projection(_driver: _PostSpendDriver) -> object:
    bundle = ordinary_fixtures._valid_bundle()
    census = replace(
        bundle[3].plan_manifest.census,
        ordinary_rows=(
            ordinary_fixtures.EcosystemOrdinaryCensusV3("javascript", 1),
            ordinary_fixtures.EcosystemOrdinaryCensusV3("python", 1),
        ),
        whole_underlying_push_count=2,
    )
    javascript = ArmScopeKey("arm-a", ScopeKey("family-a", "javascript"))
    python = ArmScopeKey("arm-b", ScopeKey("family-b", "python"))
    identities = (
        ordinary_fixtures._identity(javascript, "js", "shared-push"),
        ordinary_fixtures._identity(python, "py", "shared-push"),
    )
    return ordinary_fixtures._derive(census, (javascript, python), identities, (_digest("other-push"), _digest("shared-push")))


def _duplicate_whole_coverage(_driver: _PostSpendDriver) -> object:
    repeated = _digest("duplicate-whole-push")
    return WholePopulationProjectionV3((repeated, repeated), 2, "")


def _zero_denominator(_driver: _PostSpendDriver) -> object:
    partition = metric_fixtures._derived_inputs()[0]
    return _scoped_result(partition.key, MetricId.PRECISION, 0, 0)


def _mismatched_denominator(_driver: _PostSpendDriver) -> object:
    partition, projection, bindings, census, ordinary = metric_fixtures._derived_inputs()
    return metric_fixtures._derive(
        (partition,),
        (projection,),
        bindings,
        (replace(census, vulnerable_side_count=census.vulnerable_side_count + 1),),
        (ordinary,),
    )


def _missing_gate(_driver: _PostSpendDriver) -> object:
    reports, _ = report_fixtures._derive_reports(*report_fixtures._inputs())
    scoped = reports[0].scoped_results[0]
    return replace(scoped, quality_gate=object(), result_digest="")


def _incomplete_replay(index: int) -> _Operation:
    def operation(_driver: _PostSpendDriver) -> object:
        inputs = list(replay_fixtures._inputs())
        inputs[index] = inputs[index][:-1]
        return replay_fixtures._assemble(*inputs)

    return operation


def _missing_current_source(_driver: _PostSpendDriver) -> object:
    replay, context, custody, resolver = replay_validation_fixtures._case()
    artifact_id = replay.admission_manifest.observations[0].observation.artifact_id
    missing = InMemoryContentResolver({key: value for key, value in resolver.artifacts.items() if key != artifact_id})
    return validate_evaluation_replay_v3(replay, context, custody, missing)


def _stale_current_custody(_driver: _PostSpendDriver) -> object:
    replay, context, custody, resolver = replay_validation_fixtures._case()
    population = replay.plan_manifest.declaration.population_digest
    current = custody.current_log(population)
    custody.logs[population] = replace(current, log_digest=_digest("matrix-stale-current-custody"))
    return validate_evaluation_replay_v3(replay, context, custody, resolver)


_POST_SPEND_CASES = (
    _MutationCase("v2-release", "case-association", _v2_release, EvaluationReleaseError, "manifest and release must use exact V3 roots"),
    *(
        _MutationCase(f"case-{mutation}", "case-association", _case_swap(mutation), EvaluationReleaseError, message)
        for mutation, message in (
            ("arm", "arm case belongs to another arm"),
            ("scope", "arm cases must be unique and canonical"),
            ("role", "ordinary released case cannot carry a pair identity"),
            ("pair", "released pair must contain one vulnerable and one fixed case in the exact scope"),
            ("result", "released case differs from its exact sealed observation"),
            ("input", "released case result digest cannot be re-derived"),
        )
    ),
    _MutationCase(
        "empty-outcome",
        "case-outcome",
        _empty_outcome,
        CaseOutcomeProjectionError,
        "component evidence records must be a nonempty exact tuple",
    ),
    _MutationCase(
        "mixed-outcome",
        "case-outcome",
        _mixed_outcome,
        CaseOutcomeProjectionError,
        "component evidence records must carry the same neutral outcome",
    ),
    _MutationCase(
        "case-input-substitution",
        "case-association",
        _projection_substitution("case_input"),
        EvaluationReleaseError,
        "released component outcome projection differs from validated evidence",
    ),
    _MutationCase(
        "projection-substitution",
        "case-association",
        _projection_substitution("source"),
        EvaluationReleaseError,
        "released component outcome projection differs from validated evidence",
    ),
    _MutationCase(
        "missing-component",
        "combination",
        _combination_missing,
        CombinationValidationError,
        "combination bindings must cover every and only planned arm",
    ),
    _MutationCase(
        "duplicate-component",
        "combination",
        _combination_duplicate,
        CombinationValidationError,
        "combination arm-scope case inputs must be unique",
    ),
    _MutationCase(
        "contradictory-combination",
        "combination",
        _combination_contradiction,
        CombinationValidationError,
        "combined case projection differs from deterministic table replay",
    ),
    _MutationCase(
        "proof-transfer",
        "proof-continuity",
        _proof_transfer,
        EvaluationProofContinuityError,
        "released proof case differs from its canonical binding",
    ),
    _MutationCase(
        "cross-ecosystem-projection",
        "ordinary-projection",
        _cross_ecosystem_projection,
        EvaluationOrdinaryProjectionError,
        "an ordinary push cannot project into another ecosystem",
    ),
    _MutationCase(
        "duplicate-whole-coverage",
        "ordinary-projection",
        _duplicate_whole_coverage,
        EvaluationOrdinaryProjectionError,
        "whole underlying pushes must be unique and canonical",
    ),
    _MutationCase(
        "zero-denominator",
        "metric",
        _zero_denominator,
        EvaluationMetricDerivationError,
        "post-spend zero denominator for precision is invalid",
    ),
    _MutationCase(
        "mismatched-denominator",
        "metric",
        _mismatched_denominator,
        EvaluationMetricDerivationError,
        "released scoped metric denominators differ from the reviewed exact-scope census",
    ),
    _MutationCase("missing-gate", "report", _missing_gate, EvaluationReportError, "scope result requires the four exact mandatory gates"),
    _MutationCase(
        "incomplete-reports",
        "replay-assembly",
        _incomplete_replay(10),
        EvaluationReplayError,
        "case groups and reports must completely match every planned arm",
    ),
    _MutationCase(
        "incomplete-lineage",
        "replay-assembly",
        _incomplete_replay(11),
        EvaluationReplayError,
        "combination lineage does not replay from every required component",
    ),
    _MutationCase(
        "missing-current-source", "replay-current-source", _missing_current_source, canonical.ArtifactResolutionError, "artifact not found"
    ),
    _MutationCase(
        "stale-current-custody",
        "replay-current-custody",
        _stale_current_custody,
        EvaluationReplayValidationError,
        "authoritative V3 replay validation refused",
    ),
)


@pytest.mark.parametrize("case", _POST_SPEND_CASES, ids=lambda case: f"{case.owner}:{case.name}")
def test_each_post_spend_mutation_fails_at_its_owner_before_any_authority(case: _MutationCase) -> None:
    _must_refuse(case)


def test_refusal_harness_detects_post_spend_authority_that_runs_before_rejection() -> None:
    def leak_then_fail(driver: _PostSpendDriver) -> object:
        driver.downstream_hooks("metric")
        raise EvaluationMetricDerivationError("post-spend zero denominator for precision is invalid")

    leaking = _MutationCase(
        "negative-control",
        "metric",
        leak_then_fail,
        EvaluationMetricDerivationError,
        "post-spend zero denominator for precision is invalid",
    )
    with pytest.raises(AssertionError, match="leaked post-spend authority"):
        _must_refuse(leaking)


def test_absent_and_inconclusive_proof_never_upgrade_not_demonstrated_claims() -> None:
    case, binding, release, plan, context, authority, resolver = proof_fixtures._released_proof_case()
    absent = proof_fixtures._resign(replace(case, proof_attachments=()))
    absent_binding = proof_fixtures._rebind(binding, absent)
    absent_claims = apply_released_case_proof_v3(
        absent, absent_binding, proof_fixtures._rerelease(release, absent_binding), plan, context, authority, resolver
    )
    inconclusive, inconclusive_resolver = proof_fixtures._inconclusive(case, resolver)
    inconclusive_binding = proof_fixtures._rebind(binding, inconclusive)
    inconclusive_claims = apply_released_case_proof_v3(
        inconclusive,
        inconclusive_binding,
        proof_fixtures._rerelease(release, inconclusive_binding),
        plan,
        context,
        authority,
        inconclusive_resolver,
    )
    assert absent_claims == absent.claims and inconclusive_claims == inconclusive.claims
    assert all(claim.basis is not EvidenceBasis.EXECUTION_BACKED for claim in (*absent_claims, *inconclusive_claims))


def test_complete_replay_revalidates_sources_and_current_custody_exactly_without_hiding_an_arm() -> None:
    replay, context, custody, resolver = replay_validation_fixtures._case()
    reports = validate_evaluation_replay_v3(replay, context, custody, resolver)
    expected_arms = tuple(baseline.arm_id for baseline in replay.plan_manifest.baselines)
    assert reports == replay.reports and reports is not replay.reports
    assert tuple(report.baseline.arm_id for report in reports) == expected_arms
    assert tuple(group.arm_id for group in replay.cases_by_arm) == expected_arms
    assert all(report.scoped_results for report in reports)


def test_post_spend_instrument_reads_a_nonzero_fixture_before_reporting_results() -> None:
    fixture = Path(__file__).parent / "fixtures/detection_core/admission_v2/manifest.json"
    content = fixture.read_bytes()
    assert fixture.is_file() and len(content) > 0
    replay, context, custody, resolver = replay_validation_fixtures._case()
    first = replay.admission_manifest.observations[0].observation
    resolved = resolver.resolve(first)
    assert first.byte_length == len(resolved.content) > 0
    assert validate_evaluation_replay_v3(replay, context, custody, resolver) == replay.reports
