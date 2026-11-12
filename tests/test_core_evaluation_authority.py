"""Complete reviewed authority derivation for evaluation admission V3."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver
from test_core_admission_context import _case as _context_case
from test_core_evaluation_attempt import _event, _projection, _reference
from test_core_evaluation_feasibility import _feasible_manifest
from test_core_evaluation_observation import _observation, _seal
from test_core_evaluation_plan import _digest
from test_core_evaluation_plan_review import _attestation

from openultrasast.core import canonical
from openultrasast.core.custody import LineagePurpose, PopulationStatus, PopulationUseRequest
from openultrasast.core.evaluation_attempt import (
    AttemptHistoryV3,
    ObservationAccessPolicyV3,
    PreSpendDispositionV3,
    PublicStatusFieldV3,
    derive_attempt_identity,
)
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionAuthorityV3,
    EvaluationAdmissionManifestV3,
    EvaluationAuthorityError,
    authorize_evaluation_admission,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_feasibility import derive_evaluation_feasibility
from openultrasast.core.evaluation_plan import (
    EvaluationPlanManifestV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
)
from openultrasast.core.evaluation_version import NonAuthorizingV3


def _reviewed_plan():
    context_case = _context_case()
    template, _, _ = _feasible_manifest()
    inputs = tuple(sorted({slot.input_identity_digest for slot in template.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=context_case.manifest.identity.population_digest,
        freeze_digest=template.declaration.freeze_digest,
        input_set_digest=template.declaration.input_set_digest,
        arm_configurations=template.declaration.arm_configurations,
        input_identity_digests=inputs,
    )
    reviewer = context_case.context.admission_review_policy.reviewed_reviewer_digests[0]
    disclosure = context_case.manifest.review.conflict_disclosure
    producer = _digest("v3-authority-plan-producer")
    provisional = _attestation("0" * 64, producer, reviewer, disclosure)
    census_draft = replace(
        template.census,
        population_digest=declaration.population_digest,
        payload_digest="0" * 64,
        review=provisional,
        census_digest="0" * 64,
    )
    census_payload = derive_evaluation_census_payload_digest(census_draft)
    census = replace(census_draft, payload_digest=census_payload, review=_attestation(census_payload, producer, reviewer, disclosure))
    census = replace(census, census_digest=derive_evaluation_census_digest(census))
    readiness = tuple(context_case.readiness)
    custody_head = context_case.port.current_log(declaration.population_digest)
    manifest_draft = EvaluationPlanManifestV3(
        declaration,
        derive_evaluation_baselines(declaration),
        census,
        tuple(sorted(item.result_digest for item in readiness)),
        custody_head.log_digest,
        "0" * 64,
        provisional,
        "0" * 64,
    )
    payload = derive_evaluation_plan_manifest_payload_digest(manifest_draft)
    manifest = replace(manifest_draft, payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    manifest = replace(manifest, manifest_digest=derive_evaluation_plan_manifest_digest(manifest))
    return context_case, manifest, readiness


def _authority_case(*, attempt_count: int = 2):
    assert attempt_count > 0
    context_case, plan, readiness = _reviewed_plan()
    policy = context_case.context.admission_review_policy
    feasibility = derive_evaluation_feasibility(plan, policy, context_case.resolver)
    configurations = {row.arm_id: row for row in plan.declaration.arm_configurations}
    observations = []
    sealed = []
    artifacts = dict(context_case.resolver.artifacts)
    for index, slot in enumerate(plan.declaration.expected_observation_slots):
        observation = _observation(slot, configurations[slot.arm_id], case_number=index if index % 2 else None)
        reference, resolved = _seal(observation, f"authority-observation-{index}")
        observations.append(observation)
        sealed.append(reference)
        artifacts[reference.observation.artifact_id] = resolved

    projection, projection_resolver = _projection(artifact_id="authority-status")
    artifacts.update(projection_resolver.artifacts)
    identity = derive_attempt_identity(plan)
    access = ObservationAccessPolicyV3(tuple(PublicStatusFieldV3), False, False, "")
    predecessor = None
    event_refs = []
    for index in range(attempt_count):
        event = _event(
            identity,
            PreSpendDispositionV3.SEALED,
            access,
            projection,
            predecessor,
            plan.review.conflict_disclosure,
            policy.reviewed_reviewer_digests[0],
            producer=_digest(f"authority-attempt-producer-{index}"),
        )
        event_ref, resolved = _reference(event, f"authority-attempt-{index}")
        event_refs.append(event_ref)
        artifacts[event_ref.event.artifact_id] = resolved
        predecessor = event.event_digest
    history = AttemptHistoryV3(plan.declaration.population_digest, tuple(event_refs), predecessor, "")
    review_producer = _digest("admission-authority-producer")
    provisional_review = _attestation(
        "0" * 64,
        review_producer,
        policy.reviewed_reviewer_digests[0],
        plan.review.conflict_disclosure,
    )
    draft = EvaluationAdmissionManifestV3(
        plan,
        feasibility.feasibility_digest,
        tuple(sealed),
        tuple(sorted(item.result_digest for item in readiness)),
        context_case.port.current_log(plan.declaration.population_digest).log_digest,
        history,
        "0" * 64,
        provisional_review,
        "0" * 64,
    )
    payload = derive_evaluation_admission_manifest_payload_digest(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(payload, review_producer, policy.reviewed_reviewer_digests[0], plan.review.conflict_disclosure),
    )
    manifest = replace(reviewed, manifest_digest=derive_evaluation_admission_manifest_digest(reviewed))
    resolver = InMemoryContentResolver(artifacts)
    return context_case, manifest, feasibility, readiness, tuple(observations), resolver


def _authorize(case):
    context_case, manifest, feasibility, readiness, _, resolver = case
    return authorize_evaluation_admission(
        manifest,
        feasibility,
        readiness,
        context_case.context,
        context_case.port,
        resolver,
    )


def _resign(manifest: EvaluationAdmissionManifestV3, **changes) -> EvaluationAdmissionManifestV3:
    draft = replace(
        manifest,
        **changes,
        payload_digest="0" * 64,
        review=replace(manifest.review, subject_digest="0" * 64, attestation_digest="0" * 64),
        manifest_digest="0" * 64,
    )
    payload = derive_evaluation_admission_manifest_payload_digest(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(
            payload,
            manifest.review.producer_identity,
            manifest.review.reviewer_identity,
            manifest.review.conflict_disclosure,
        ),
    )
    return replace(reviewed, manifest_digest=derive_evaluation_admission_manifest_digest(reviewed))


def test_complete_reviewed_graph_derives_one_exact_authority() -> None:
    case = _authority_case()
    authority = _authorize(case)
    context_case, manifest, feasibility, readiness, observations, _ = case
    assert authority.admission_manifest_digest == manifest.manifest_digest
    assert authority.plan_manifest_digest == manifest.plan_manifest.manifest_digest
    assert authority.baseline_digests == tuple(item.baseline_digest for item in manifest.plan_manifest.baselines)
    assert authority.feasibility_digest == feasibility.feasibility_digest
    assert authority.validation_context_digest == context_case.context.context_digest
    assert authority.custody_log_digest == context_case.port.current_log(manifest.plan_manifest.declaration.population_digest).log_digest
    assert authority.attempt_history_head_digest == manifest.attempt_history.head_event_digest
    assert authority.admission_review_digest == manifest.review.attestation_digest
    assert authority.authority_digest
    assert len(observations) == len(manifest.observations)
    assert tuple(sorted(item.result_digest for item in readiness)) == manifest.readiness_digests


def test_authority_contracts_are_exact_v3_and_pre_consumer_non_authorizing() -> None:
    manifest_fields = {item.name for item in fields(EvaluationAdmissionManifestV3)}
    authority_fields = {item.name for item in fields(EvaluationAdmissionAuthorityV3)}
    assert manifest_fields == {
        "plan_manifest",
        "feasibility_digest",
        "observations",
        "readiness_digests",
        "custody_log_digest",
        "attempt_history",
        "payload_digest",
        "review",
        "manifest_digest",
    }
    assert authority_fields == {
        "admission_manifest_digest",
        "plan_manifest_digest",
        "baseline_digests",
        "feasibility_digest",
        "observation_set_digest",
        "readiness_set_digest",
        "validation_context_digest",
        "custody_log_digest",
        "attempt_history_head_digest",
        "admission_review_digest",
        "authority_digest",
    }
    assert issubclass(EvaluationAdmissionManifestV3, NonAuthorizingV3)
    assert issubclass(EvaluationAdmissionAuthorityV3, NonAuthorizingV3)
    assert not hasattr(_authorize(_authority_case()), "authorize_consumer")


@pytest.mark.parametrize("part", ("plan", "feasibility", "observation", "attempt", "readiness"))
def test_substituted_or_incomplete_reviewed_sources_fail_before_authority(part: str) -> None:
    case = _authority_case()
    context_case, manifest, feasibility, readiness, observations, resolver = case
    if part == "plan":
        changed_plan = replace(manifest.plan_manifest, manifest_digest=_digest("other-plan"))
        manifest = _resign(manifest, plan_manifest=changed_plan)
    elif part == "feasibility":
        manifest = _resign(manifest, feasibility_digest=_digest("other-feasibility"))
    elif part == "observation":
        manifest = _resign(manifest, observations=manifest.observations[:-1])
    elif part == "attempt":
        history = replace(manifest.attempt_history, head_event_digest=manifest.attempt_history.events[0].event_digest, history_digest="")
        manifest = _resign(manifest, attempt_history=history)
    else:
        readiness = readiness[:-1]
    changed = context_case, manifest, feasibility, readiness, observations, resolver
    with pytest.raises((EvaluationAuthorityError, ValueError)):
        _authorize(changed)


def test_changed_observation_bytes_are_rechecked_at_authority_time() -> None:
    case = _authority_case()
    context_case, manifest, feasibility, readiness, observations, resolver = case
    first = manifest.observations[0].observation
    resolved = resolver.artifacts[first.artifact_id]
    changed_resolver = InMemoryContentResolver({**resolver.artifacts, first.artifact_id: replace(resolved, content=resolved.content[:-1])})
    with pytest.raises(canonical.ArtifactValidationError):
        _authorize((context_case, manifest, feasibility, readiness, observations, changed_resolver))


def test_admission_review_must_be_independent_subject_bound_and_resolvable() -> None:
    case = _authority_case()
    context_case, manifest, feasibility, readiness, observations, resolver = case
    self_review = replace(
        manifest.review,
        producer_identity=manifest.review.reviewer_identity,
        attestation_digest="0" * 64,
    )
    with pytest.raises(EvaluationAuthorityError, match="independent"):
        _authorize((context_case, replace(manifest, review=self_review), feasibility, readiness, observations, resolver))
    missing = InMemoryContentResolver(
        {key: value for key, value in resolver.artifacts.items() if key != manifest.review.conflict_disclosure.artifact_id}
    )
    with pytest.raises(canonical.ArtifactResolutionError):
        _authorize((context_case, manifest, feasibility, readiness, observations, missing))


def test_current_context_and_available_custody_head_are_revalidated() -> None:
    case = _authority_case()
    context_case, manifest, feasibility, readiness, observations, resolver = case
    changed_context = replace(context_case.context, context_digest=_digest("other-context"))
    with pytest.raises(EvaluationAuthorityError, match="context"):
        authorize_evaluation_admission(
            manifest,
            feasibility,
            readiness,
            changed_context,
            context_case.port,
            resolver,
        )

    population = manifest.plan_manifest.declaration.population_digest
    current = context_case.port.current_log(population)
    request = PopulationUseRequest(
        population,
        "unrelated-arm",
        LineagePurpose.PROMOTION,
        False,
        _digest("unrelated-artifact"),
        current.log_digest,
    )
    context_case.port.append(request, current.custodian_identity)
    assert context_case.port.current_log(population).status is PopulationStatus.AVAILABLE
    with pytest.raises(EvaluationAuthorityError, match="custody|stale"):
        _authorize(case)


def test_spent_or_availability_restored_custody_never_produces_authority() -> None:
    case = _authority_case()
    context_case, manifest, _, _, _, _ = case
    population = manifest.plan_manifest.declaration.population_digest
    current = context_case.port.current_log(population)
    request = PopulationUseRequest(
        population,
        "planned-evaluation",
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        manifest.manifest_digest,
        current.log_digest,
    )
    context_case.port.append(request, current.custodian_identity)
    assert context_case.port.current_log(population).status is PopulationStatus.SPENT
    with pytest.raises(EvaluationAuthorityError, match="available|custody|stale"):
        _authorize(case)
