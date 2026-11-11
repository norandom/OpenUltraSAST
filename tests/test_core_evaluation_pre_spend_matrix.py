"""Adversarial pre-spend and compatibility matrix for evaluation V3."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path

import pytest
import test_core_evaluation_attempt as attempt_fixtures
import test_core_evaluation_authority as authority_fixtures
import test_core_evaluation_feasibility as feasibility_fixtures
import test_core_evaluation_observation as observation_fixtures
import test_core_evaluation_plan_review as plan_review_fixtures
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_report import _failed_quality_bundle, _score_bundle, _setup, _without_models
from test_core_admission_v2_compatibility import _manifest as _v2_manifest
from test_core_admission_v2_compatibility import _read_canonical, _read_nonzero
from test_core_evaluation_plan import _digest

from openultrasast.core import canonical, custody, evaluation_admission
from openultrasast.core.admission_report import (
    ADMISSION_REPLAY_SCHEMA,
    admission_replay_value,
    admission_report_value,
    validate_admission_replay,
)
from openultrasast.core.evaluation_admission import EvaluationAdmissionV3Error
from openultrasast.core.evaluation_attempt import (
    AttemptHistoryV3,
    EvaluationAttemptError,
    ObservationAccessPolicyV3,
    PreSpendDispositionV3,
    validate_evaluation_attempt_history,
)
from openultrasast.core.evaluation_authority import EvaluationAuthorityError
from openultrasast.core.evaluation_feasibility import derive_evaluation_feasibility
from openultrasast.core.evaluation_measurement import EvaluationMeasurementError, ScopeKey
from openultrasast.core.evaluation_observation import EvaluationObservationError, validate_evaluation_observations
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    EvaluationPlanError,
    EvaluationPlanManifestV3,
    validate_reviewed_evaluation_plan,
)
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_spend import (
    EvaluationPreparationV3,
    EvaluationSharedSpendError,
    prepare_evaluation_spend,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationVersionError,
    require_v3_child_schema,
)


@dataclass
class _SyntheticDriver:
    detector_executions: int = 0
    label_releases: int = 0
    results: int = 0
    quality_decisions: int = 0
    events: list[tuple[str, str]] = field(default_factory=list)

    def detector_hook(self, stage: str) -> None:
        self.detector_executions += 1
        self.events.append((stage, "detector"))

    def label_hook(self, stage: str) -> None:
        self.label_releases += 1
        self.events.append((stage, "labels"))

    def result_hook(self, stage: str, result: object) -> None:
        self.results += 1
        self.events.append((stage, f"result:{type(result).__name__}"))

    def quality_hook(self, stage: str) -> None:
        self.quality_decisions += 1
        self.events.append((stage, "quality"))

    def snapshot(self) -> tuple[int, int, int, int, tuple[tuple[str, str], ...]]:
        return (
            self.detector_executions,
            self.label_releases,
            self.results,
            self.quality_decisions,
            tuple(self.events),
        )

    def run(self, stage: str, operation: _Operation) -> object:
        result = operation(self)
        self.detector_hook(stage)
        self.label_hook(stage)
        self.result_hook(stage, result)
        self.quality_hook(stage)
        return result


_Operation = Callable[[_SyntheticDriver], object]


@dataclass(frozen=True)
class _MutationCase:
    name: str
    owner: str
    operation: _Operation
    exception: type[BaseException]
    message: str


def _must_refuse(case: _MutationCase) -> None:
    driver = _SyntheticDriver()
    before = driver.snapshot()
    with pytest.raises(case.exception, match=re.escape(case.message)):
        driver.run(case.owner, case.operation)
    assert driver.snapshot() == before, f"{case.owner} refusal leaked synthetic side effects"


def _v2_cases():
    return {
        "go": _score_bundle(_without_models(_setup())),
        "no_go": _failed_quality_bundle(),
        "zero_model": _score_bundle(_setup()),
    }


def _baseline_mutation(_driver: _SyntheticDriver) -> object:
    context_case, plan, _ = authority_fixtures._reviewed_plan()
    changed = replace(plan.baselines[0], baseline_digest=_digest("mutated-baseline"))
    return evaluation_admission.preflight_evaluation(
        replace(plan, baselines=(changed,) + plan.baselines[1:]),
        context_case.context,
        context_case.resolver,
    )


def _impossible_scope(_driver: _SyntheticDriver) -> object:
    context_case, plan, _ = authority_fixtures._reviewed_plan()
    configuration = plan.declaration.arm_configurations[0]
    impossible = replace(
        configuration,
        exact_scopes=(ScopeKey(configuration.exact_scopes[0].family_id, "unreviewed-ecosystem"),),
        configuration_identity_digest="",
    )
    changed = feasibility_fixtures._rebind_manifest(
        plan,
        configurations=(impossible,) + plan.declaration.arm_configurations[1:],
    )
    return derive_evaluation_feasibility(changed, context_case.context.admission_review_policy, context_case.resolver)


def _missing_observation_slot(_driver: _SyntheticDriver) -> object:
    declaration, _, sealed, resolver = observation_fixtures._bundle()
    return observation_fixtures._validate(declaration, sealed[:-1], resolver)


def _unreadable_observation(_driver: _SyntheticDriver) -> object:
    declaration, _, sealed, resolver = observation_fixtures._bundle()
    artifact_id = sealed[0].observation.artifact_id
    missing = InMemoryContentResolver({key: value for key, value in resolver.artifacts.items() if key != artifact_id})
    return observation_fixtures._validate(declaration, sealed, missing)


def _zero_observation(_driver: _SyntheticDriver) -> object:
    declaration, _, sealed, resolver = observation_fixtures._bundle()
    reference, zero = stored_artifact(b"", artifact_id="matrix-zero-observation")
    changed = replace(sealed[0], observation=reference, ref_digest="")
    combined = InMemoryContentResolver({**resolver.artifacts, **zero.artifacts})
    return observation_fixtures._validate(declaration, (changed,) + sealed[1:], combined)


def _self_reviewed_plan(_driver: _SyntheticDriver) -> object:
    census, manifest, policy, resolver = plan_review_fixtures._case()
    review = replace(
        manifest.review,
        producer_identity=manifest.review.reviewer_identity,
        attestation_digest="0" * 64,
    )
    return validate_reviewed_evaluation_plan(census, replace(manifest, review=review), policy, resolver)


def _forked_attempt_history(_driver: _SyntheticDriver) -> object:
    manifest, policy, history, events, resolver = attempt_fixtures._history_case()
    root = events[0]
    sibling = attempt_fixtures._event(
        root.attempt_identity,
        PreSpendDispositionV3.SEALED,
        root.access_policy,
        root.public_status_projection,
        root.event_digest,
        root.review.conflict_disclosure,
        root.review.reviewer_identity,
        producer=_digest("matrix-fork-producer"),
    )
    sibling_ref, content = attempt_fixtures._reference(sibling, "matrix-fork-attempt")
    changed = AttemptHistoryV3(history.population_digest, history.events + (sibling_ref,), sibling.event_digest, "")
    changed_resolver = InMemoryContentResolver({**resolver.artifacts, "matrix-fork-attempt": content})
    return validate_evaluation_attempt_history(manifest, changed, policy, changed_resolver)


def _changed_attempt_identity(_driver: _SyntheticDriver) -> object:
    case = attempt_fixtures._history_case((PreSpendDispositionV3.SEALED,))
    event = case[3][0]
    identity = replace(
        event.attempt_identity,
        execution_identities=event.attempt_identity.execution_identities[:-1] + ("changed-execution",),
        retry_identity_digest="",
    )
    return attempt_fixtures._validate(attempt_fixtures._replace_event(case, 0, attempt_identity=identity))


def _raw_access_attempt(_driver: _SyntheticDriver) -> object:
    case = attempt_fixtures._history_case((PreSpendDispositionV3.SEALED,))
    access = replace(case[3][0].access_policy, raw_observation_access_allowed=True, policy_digest="")
    assert isinstance(access, ObservationAccessPolicyV3)
    return attempt_fixtures._validate(attempt_fixtures._replace_event(case, 0, access_policy=access))


def _stale_custody_authority(_driver: _SyntheticDriver) -> object:
    case = authority_fixtures._authority_case()
    context_case, manifest, feasibility, readiness, _, resolver = case
    population = manifest.plan_manifest.declaration.population_digest
    current = context_case.port.current_log(population)
    request = custody.PopulationUseRequest(
        population,
        "unrelated-arm",
        custody.LineagePurpose.PROMOTION,
        False,
        _digest("unrelated-artifact"),
        current.log_digest,
    )
    context_case.port.append(request, current.custodian_identity)
    return evaluation_admission.authorize_evaluation(
        manifest,
        feasibility,
        readiness,
        context_case.context,
        context_case.port,
        resolver,
    )


def _subset_spend(_driver: _SyntheticDriver) -> object:
    case = authority_fixtures._authority_case()
    context_case, manifest = case[:2]
    authority = authority_fixtures._authorize(case)
    preparation = prepare_evaluation_spend(manifest, authority, context_case.context, context_case.port)
    return EvaluationPreparationV3(authority, preparation.label_release_request, authority.baseline_digests[:-1], "")


def _v2_as_v3(_driver: _SyntheticDriver) -> object:
    return evaluation_admission.decode_evaluation_v3(
        ADMISSION_REPLAY_SCHEMA,
        _v2_cases()["go"].replay,
        EvaluationReplayV3,
    )


def _unknown_schema(_driver: _SyntheticDriver) -> object:
    return evaluation_admission.decode_evaluation_v3(
        "openultrasast.unknown.v9",
        _v2_cases()["go"].replay,
        EvaluationReplayV3,
    )


def _mixed_schema(_driver: _SyntheticDriver) -> object:
    return require_v3_child_schema(ADMISSION_REPLAY_SCHEMA, field="mixed child")


def _subclass_root(_driver: _SyntheticDriver) -> object:
    class DerivedPlan(EvaluationPlanManifestV3):
        pass

    derived = object.__new__(DerivedPlan)
    return evaluation_admission.decode_evaluation_v3(
        EVALUATION_ADMISSION_V3_SCHEMA,
        derived,
        EvaluationPlanManifestV3,
    )


_VERSION_CASES = (
    _MutationCase(
        "v2-as-v3",
        "version",
        _v2_as_v3,
        EvaluationAdmissionV3Error,
        "V2 evidence cannot be converted",
    ),
    _MutationCase(
        "unknown-schema",
        "version",
        _unknown_schema,
        EvaluationAdmissionV3Error,
        "unknown evaluation schema",
    ),
    _MutationCase(
        "mixed-schema",
        "version",
        _mixed_schema,
        EvaluationVersionError,
        "mixed or incompatible evaluation schema",
    ),
    _MutationCase(
        "subclass-root",
        "version",
        _subclass_root,
        EvaluationAdmissionV3Error,
        "must use exact type EvaluationPlanManifestV3",
    ),
)


_PRE_SPEND_CASES = (
    _MutationCase(
        "baseline",
        "plan",
        _baseline_mutation,
        EvaluationPlanError,
        "baseline_digest does not match",
    ),
    _MutationCase(
        "impossible-scope",
        "feasibility",
        _impossible_scope,
        EvaluationMeasurementError,
        "denominator policies must occur once",
    ),
    _MutationCase(
        "missing-slot",
        "observation",
        _missing_observation_slot,
        EvaluationObservationError,
        "sealed observations must equal",
    ),
    _MutationCase(
        "unreadable-observation",
        "observation",
        _unreadable_observation,
        canonical.ArtifactResolutionError,
        "artifact not found",
    ),
    _MutationCase(
        "zero-observation",
        "observation",
        _zero_observation,
        EvaluationObservationError,
        "resolved observation bytes must be nonzero",
    ),
    _MutationCase(
        "self-review",
        "plan",
        _self_reviewed_plan,
        EvaluationPlanError,
        "producer and reviewer must be independent",
    ),
    _MutationCase(
        "forked-history",
        "attempt",
        _forked_attempt_history,
        EvaluationAttemptError,
        "history is forked",
    ),
    _MutationCase(
        "identity-change",
        "attempt",
        _changed_attempt_identity,
        EvaluationAttemptError,
        "changed retry identity",
    ),
    _MutationCase(
        "raw-access",
        "attempt",
        _raw_access_attempt,
        EvaluationAttemptError,
        "raw or diagnostic access",
    ),
    _MutationCase(
        "stale-custody",
        "authority",
        _stale_custody_authority,
        EvaluationAuthorityError,
        "custody head is stale",
    ),
    _MutationCase(
        "subset-spend",
        "spend",
        _subset_spend,
        EvaluationSharedSpendError,
        "planned baseline set must equal",
    ),
)


def test_v2_bytes_digests_decisions_and_replay_remain_frozen() -> None:
    manifest = _v2_manifest()
    rows = manifest["cases"]
    assert isinstance(rows, list)
    cases = _v2_cases()
    for row in rows:
        scored = cases[row["name"]]
        report = canonical.canonical_bytes(admission_report_value(scored.report))
        replay = canonical.canonical_bytes(admission_replay_value(scored.replay))
        assert report == _read_canonical(row["report_file"])
        assert replay == _read_canonical(row["replay_file"])
        assert sha256(report).hexdigest() == row["report_sha256"]
        assert sha256(replay).hexdigest() == row["replay_sha256"]
        assert scored.report.decision.value == row["decision"]
        assert validate_admission_replay(scored.replay, scored.setup.context, scored.setup.custody, scored.setup.resolver) == scored.report


@pytest.mark.parametrize("case", _VERSION_CASES, ids=lambda case: case.name)
def test_v2_unknown_mixed_and_subclass_roots_fail_at_the_version_boundary(case: _MutationCase) -> None:
    _must_refuse(case)


@pytest.mark.parametrize(
    "case",
    _PRE_SPEND_CASES,
    ids=lambda case: case.name,
)
def test_each_pre_spend_mutation_fails_before_execution_label_release_or_result(case: _MutationCase) -> None:
    _must_refuse(case)


def test_refusal_harness_detects_a_hook_that_runs_before_owner_rejection() -> None:
    def leak_then_fail(driver: _SyntheticDriver) -> object:
        driver.detector_hook("plan")
        raise EvaluationPlanError("baseline_digest does not match canonical content")

    leaking = _MutationCase(
        "negative-control",
        "plan",
        leak_then_fail,
        EvaluationPlanError,
        "baseline_digest does not match",
    )
    with pytest.raises(AssertionError, match="leaked synthetic side effects"):
        _must_refuse(leaking)


def test_insufficiency_is_non_authorizing_and_leaves_custody_available() -> None:
    context_case, plan, _ = authority_fixtures._reviewed_plan()
    zero_rows = tuple(
        replace(
            row,
            pair_count=0,
            vulnerable_side_count=0,
            fixed_side_count=0,
            semantic_site_capacity=0,
            model_call_capacity=0,
        )
        for row in plan.census.scope_rows
    )
    zero_ordinary = tuple(EcosystemOrdinaryCensusV3(row.ecosystem, 0) for row in plan.census.ordinary_rows)
    changed = replace(plan.census, scope_rows=zero_rows, ordinary_rows=zero_ordinary)
    insufficient_plan = feasibility_fixtures._rebind_census(plan, changed)
    population = insufficient_plan.declaration.population_digest
    before = context_case.port.current_log(population)

    result = derive_evaluation_feasibility(
        insufficient_plan,
        context_case.context.admission_review_policy,
        context_case.resolver,
    )

    assert not result.may_spend
    assert not hasattr(result, "decision")
    assert not hasattr(result, "authorize")
    assert context_case.port.current_log(population) == before
    assert before.status is custody.PopulationStatus.AVAILABLE


def test_measurement_instruments_prove_nonzero_reads_and_fail_loudly_when_unreadable() -> None:
    fixture = Path(__file__).parent / "fixtures/detection_core/admission_v2/manifest.json"
    content = fixture.read_bytes()
    assert fixture.is_file() and len(content) > 0
    assert _read_nonzero("manifest.json") == content
    with pytest.raises(AssertionError, match="missing"):
        _read_nonzero("does-not-exist.json")

    declaration, observations, sealed, resolver = observation_fixtures._bundle()
    for reference in sealed:
        resolved = resolver.artifacts[reference.observation.artifact_id]
        assert reference.observation.byte_length == len(resolved.content) > 0
    assert (
        validate_evaluation_observations(
            declaration,
            sealed,
            resolver,
            trusted_store_identities=("trusted-store",),
            maximum_bytes=4096,
        )
        == observations
    )
    _must_refuse(
        _MutationCase(
            "unreadable-instrument",
            "observation",
            _unreadable_observation,
            canonical.ArtifactResolutionError,
            "artifact not found",
        )
    )
