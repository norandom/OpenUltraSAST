"""Task 11.1 confidentiality validation suite: partitions, labels, diagnostics, retirement.

Adversarial suites over the committed confidentiality machinery: license
partitions (7.6), label-blind manifests (5.4), sealed pre-spend diagnostics and
reviewed development opening (5.2/5.6/10.3), and pre/post-freeze contamination
routing (3.5/3.6). Every refusal interpreted here is preceded by a nonzero
readability proof of the fixture (instrument rule).
"""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import case_for  # noqa: E402
from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_artifact_repository import _authority, _repo  # noqa: E402
from test_valid_benchmark_artifact_repository import _digest as _store_digest  # noqa: E402
from test_valid_benchmark_governance_validation import FREEZE, POPULATION, _active_chain  # noqa: E402
from test_valid_benchmark_isolated_executor import _authorities  # noqa: E402
from test_valid_benchmark_label_blind_manifest import _attestation, _policy, _sources  # noqa: E402
from test_valid_benchmark_observation_checkpoint import _frozen  # noqa: E402
from test_valid_benchmark_ordinary_draw import (  # noqa: E402
    LEAN_NAMES,
    OrdinaryFixtureHistory,
    _contamination,
    _draw,
    _lean_batches,
    _lean_state,
)
from test_valid_benchmark_population_freeze import _positives, _selection  # noqa: E402
from test_valid_benchmark_population_materials import _digest, _freeze, _inputs, _Validator  # noqa: E402

from benchmarks.valid import artifact_repository as repository  # noqa: E402
from benchmarks.valid import (  # noqa: E402
    lifecycle,
    reservation,
    sealed_diagnostics,  # noqa: E402
)
from benchmarks.valid import population_label_blind as label_blind
from benchmarks.valid import population_materials as materials  # noqa: E402
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    ContaminationTiming,
    OrdinaryExclusionReason,
    OrdinarySelectionError,
    ordinary_selection_bytes,
    reviewed_contamination,
)
from benchmarks.valid.ordinary_changes import post_freeze_contamination_retirement  # noqa: E402
from benchmarks.valid.ordinary_draw import OrdinaryDrawError, OrdinaryDrawReason  # noqa: E402
from benchmarks.valid.population_material_contract import PERMISSIVE_PUBLIC_LICENSES, _manifest_value  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import ArtifactKind  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

CONTAMINATION_POLICY = _digest("governance-contamination-review")
ACCESS_POLICY = _store_digest("read-policy")


def _loads(content: bytes) -> dict[str, object]:
    """Hostile-decode-disciplined loads for asserting on encoded artifact bytes."""

    def reject(value: str) -> object:
        raise ValueError(f"non-finite constant in encoded artifact: {value}")

    def finite(value: str) -> float:
        result = float(value)
        if result != result or result in (float("inf"), float("-inf")):
            raise ValueError("non-finite float in encoded artifact")
        return result

    try:
        decoded = json.loads(content, parse_constant=reject, parse_float=finite)
    except RecursionError as error:
        raise ValueError("encoded artifact nests too deeply") from error
    if not isinstance(decoded, dict):
        raise ValueError("encoded artifact is not an object")
    return decoded


# --------------------------------------------------- license partition (7.6)


def _changes() -> tuple[str, ...]:
    return tuple(_digest(f"governance-change-{index}") for index in range(3))


def _partitioned() -> tuple[materials.PopulationMaterialPartitionV1, tuple[bytes, ...], tuple[materials.PopulationMaterialInputV1, ...]]:
    changes = _changes()
    freeze = _freeze(changes)
    inputs = _inputs(changes)
    partition = materials.build_population_material_partition(
        freeze,
        inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    artifacts = materials.material_artifact_bytes(partition)
    assert all(artifacts)
    return partition, artifacts, inputs


def test_nonpermissive_and_uncertain_material_stay_behind_opaque_references() -> None:
    partition, artifacts, inputs = _partitioned()
    manifest = partition.manifest

    assert {item.license_expression for item in manifest.public_sources} == {"Apache-2.0"}
    assert len(manifest.private_refs) == 2
    public_bytes = materials.public_manifest_bytes(partition)
    for item in inputs:
        if item.license_class is not materials.LicenseClass.PERMISSIVE:
            assert item.source_content not in public_bytes
        assert item.label_content not in public_bytes
        assert item.review_judgment_content not in public_bytes
    for reference in manifest.public_sources:
        source = materials.resolve_public_source(partition, reference)
        assert source
        assert bytes_digest(source) == reference.source_digest
    covered = {item.change_digest for item in manifest.private_refs} | {item.change_digest for item in manifest.public_sources}
    assert covered == set(manifest.positive_change_digests)


def test_permissive_material_without_distribution_approval_remains_private() -> None:
    changes = tuple(_digest(f"unapproved-{index}") for index in range(3))
    freeze = _freeze(changes)
    inputs = tuple(
        materials.PopulationMaterialInputV1(
            change,
            materials.LicenseClass.PERMISSIVE if index < 2 else materials.LicenseClass.NON_PERMISSIVE,
            "Apache-2.0" if index < 2 else "BUSL-1.1",
            f"safe source {index}\n".encode(),
            f"private-label-{index}".encode(),
            f"review-judgment-{index}".encode(),
            True,
        )
        for index, change in enumerate(changes)
    )
    unapproved = (replace(inputs[0], public_distribution_approved=False), *inputs[1:])

    partition = materials.build_population_material_partition(
        freeze,
        unapproved,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    assert all(materials.material_artifact_bytes(partition))

    assert partition.manifest.public_count == 1
    assert partition.manifest.private_count == 2


@pytest.mark.parametrize(
    "license_class",
    (materials.LicenseClass.NON_PERMISSIVE, materials.LicenseClass.UNCERTAIN),
)
def test_non_permissive_class_with_an_allowlisted_expression_is_never_public(license_class) -> None:
    assert "MIT" in PERMISSIVE_PUBLIC_LICENSES
    changes = tuple(_digest(f"class-only-mismatch-{license_class.value}-{index}") for index in range(3))
    freeze = _freeze(changes)
    inputs = tuple(
        materials.PopulationMaterialInputV1(
            change,
            license_class if index == 0 else materials.LicenseClass.PERMISSIVE,
            "MIT",
            f"source {index}\n".encode(),
            f"private-label-{index}".encode(),
            f"review-judgment-{index}".encode(),
            True,
        )
        for index, change in enumerate(changes)
    )
    guarded = inputs[0]
    assert guarded.source_content and guarded.public_distribution_approved
    assert guarded.license_expression == inputs[1].license_expression

    partition = materials.build_population_material_partition(
        freeze,
        inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    manifest = partition.manifest

    assert manifest.public_count == 2
    assert manifest.private_count == 1
    (opaque,) = manifest.private_refs
    assert (opaque.change_digest, opaque.license_class) == (guarded.change_digest, license_class)
    assert guarded.source_content not in materials.public_manifest_bytes(partition)
    assert all(guarded.source_content not in record.source_content for record in partition.public_source_objects)
    forged = replace(
        manifest.public_sources[0],
        change_digest=guarded.change_digest,
        source_digest=opaque.source_digest,
        byte_length=opaque.byte_length,
    )
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.public_source_object_bytes(partition, forged)


def test_forged_public_reference_for_private_change_is_refused() -> None:
    partition, artifacts, inputs = _partitioned()
    private_reference = partition.manifest.private_refs[0]
    private_record = next(item for item in partition.private_records if item.change_digest == private_reference.change_digest)
    assert private_record.source_content
    permissive = partition.manifest.public_sources[0]
    forged_record = replace(
        permissive,
        change_digest=private_reference.change_digest,
        source_digest=private_reference.source_digest,
        byte_length=private_reference.byte_length,
    )
    forged_manifest = replace(
        partition.manifest,
        public_sources=tuple(sorted((forged_record, *partition.manifest.public_sources[1:]))),
        private_refs=partition.manifest.private_refs[1:],
        manifest_digest="",
    )
    forged_manifest = replace(
        forged_manifest,
        manifest_digest=canonical.content_digest(_manifest_value(forged_manifest, include_digest=False)),
    )
    forged = replace(partition, manifest=forged_manifest, public_source_objects=())

    with pytest.raises(materials.PopulationMaterialError):
        materials.public_manifest_bytes(forged)


def test_private_and_sealed_resolution_requires_the_custodian_boundary() -> None:
    partition, artifacts, inputs = _partitioned()
    reference = partition.manifest.private_refs[0]
    matching_label = next(item for item in partition.sealed_label_records if item.change_digest == reference.change_digest)
    custodian = materials.material_access_authority(
        partition,
        materials.MaterialActorRole.CUSTODIAN,
        (
            materials.MaterialPermission.PRIVATE_SOURCE,
            materials.MaterialPermission.SEALED_LABELS,
        ),
        ACCESS_POLICY,
        expected_access_policy_digest=ACCESS_POLICY,
    )

    resolved = materials.resolve_private_material(partition, reference, custodian, expected_access_policy_digest=ACCESS_POLICY)
    labels = materials.resolve_sealed_labels(partition, custodian, expected_access_policy_digest=ACCESS_POLICY)

    assert resolved
    assert matching_label.label_content not in resolved
    assert base64.b64encode(matching_label.label_content) in labels
    assert base64.b64encode(matching_label.judgment_content) in labels
    with pytest.raises(materials.PopulationMaterialError, match="non-custodian"):
        materials.material_access_authority(
            partition,
            materials.MaterialActorRole.OPERATOR,
            (materials.MaterialPermission.PRIVATE_SOURCE,),
            ACCESS_POLICY,
            expected_access_policy_digest=ACCESS_POLICY,
        )
    sealed_only = materials.material_access_authority(
        partition,
        materials.MaterialActorRole.CUSTODIAN,
        (materials.MaterialPermission.SEALED_LABELS,),
        ACCESS_POLICY,
        expected_access_policy_digest=ACCESS_POLICY,
    )
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.resolve_private_material(partition, reference, sealed_only, expected_access_policy_digest=ACCESS_POLICY)
    with pytest.raises(materials.PopulationMaterialError, match="policy mismatch"):
        materials.material_access_authority(
            partition,
            materials.MaterialActorRole.CUSTODIAN,
            (materials.MaterialPermission.SEALED_LABELS,),
            _digest("other-policy"),
            expected_access_policy_digest=ACCESS_POLICY,
        )


def test_operator_summary_carries_only_closed_codes_digests_and_counts() -> None:
    partition, artifacts, inputs = _partitioned()

    summary = materials.operator_material_summary(partition)
    decoded = _loads(summary)

    for item in inputs:
        assert item.label_content not in summary
        assert item.review_judgment_content not in summary
        assert item.source_content not in summary
    assert tuple(decoded["reason_codes"]) == ("private_material_opaque", "labels_custodian_sealed")
    assert decoded["public_count"] == partition.manifest.public_count
    assert set(decoded) == {
        "schema_version",
        "status",
        "population_digest",
        "freeze_digest",
        "manifest_digest",
        "private_object_digest",
        "sealed_label_digest",
        "public_count",
        "private_count",
        "reason_codes",
    }


# --------------------------------------------- label-blind manifest (5.4/10.3)


def test_manifest_review_requires_independence_disclosure_and_exact_subject() -> None:
    freeze, selection, partition = _sources()
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    assert draft.input_digests
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="governance-manifest-conflicts")
    review = _attestation(draft.draft_digest, disclosure)
    policy = _policy(review.reviewer_identity)

    accepted = label_blind.review_label_blind_population_manifest(draft, review, policy, resolver)

    assert label_blind.label_blind_population_manifest_bytes(accepted)
    self_reviewed = replace(review, producer_identity=review.reviewer_identity, attestation_digest="0" * 64)
    self_reviewed = replace(self_reviewed, attestation_digest=derive_independence_attestation_digest(self_reviewed))
    with pytest.raises(label_blind.LabelBlindManifestError, match="independent"):
        label_blind.review_label_blind_population_manifest(draft, self_reviewed, policy, resolver)
    stale = _attestation(_digest("another-draft"), disclosure)
    with pytest.raises(label_blind.LabelBlindManifestError, match="stale"):
        label_blind.review_label_blind_population_manifest(draft, stale, policy, resolver)
    forbidden_policy = _policy(review.reviewer_identity, ((review.producer_identity, review.reviewer_identity),))
    with pytest.raises(label_blind.LabelBlindManifestError, match="forbidden"):
        label_blind.review_label_blind_population_manifest(draft, review, forbidden_policy, resolver)


def test_manifest_bytes_hold_no_label_bearing_field_or_private_payload() -> None:
    freeze, selection, partition = _sources()
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="governance-manifest-conflicts")
    review = _attestation(draft.draft_digest, disclosure)
    manifest = label_blind.review_label_blind_population_manifest(draft, review, _policy(review.reviewer_identity), resolver)
    content = label_blind.label_blind_population_manifest_bytes(manifest)
    assert content
    decoded = _loads(content)

    for record in partition.sealed_label_records:
        assert record.label_content not in content
        assert record.judgment_content not in content
    for record in partition.private_records:
        assert record.source_content not in content
    assert partition.manifest.private_object_digest not in content.decode()
    assert set(decoded) == {
        "schema_version",
        "population_digest",
        "freeze_digest",
        "reservation_census_digest",
        "review_set_digest",
        "ordinary_selection_digest",
        "public_material_manifest_digest",
        "material_artifact_set_digest",
        "scope_census",
        "input_digests",
        "positive_count",
        "input_count",
        "input_set_digest",
        "draft_digest",
        "review_digest",
        "manifest_digest",
    }


# ------------------------------------- sealed diagnostics and development (5.2/5.6)


def _custodian() -> repository.ArtifactReadAuthority:
    return _authority(
        repository.ArtifactActorRole.CUSTODIAN,
        (
            repository.ArtifactReadPermission.CUSTODIAN_SEALED,
            repository.ArtifactReadPermission.PRIVATE,
        ),
    )


def _diagnostic_policy() -> ReviewIndependencePolicy:
    reviewer = _digest("governance-diagnostic-reviewer")
    policy_digest = derive_review_independence_policy_digest((reviewer,), (), ("trusted-store",), 4096)
    return ReviewIndependencePolicy((reviewer,), (), ("trusted-store",), 4096, policy_digest)


def _development_review(subject_digest: str, policy: ReviewIndependencePolicy):
    disclosure, review_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id=f"governance-access-{subject_digest[:12]}")
    producer = _digest("governance-requester")
    reviewer = policy.reviewed_reviewer_digests[0]
    draft = IndependenceAttestation(subject_digest, producer, reviewer, disclosure, "0" * 64)
    return replace(draft, attestation_digest=derive_independence_attestation_digest(draft)), review_resolver


def _development_request(bundle, predecessor, checkpoint, selection, resolver, manifest):
    policy = _diagnostic_policy()
    subject = sealed_diagnostics.build_development_access_subject(
        bundle.population_digest,
        bundle.freeze_digest,
        predecessor,
        checkpoint,
        bundle=bundle,
        selection=selection,
        resolver=resolver,
        manifest=manifest,
        artifact_access_policy_digest=ACCESS_POLICY,
        lifecycle_review_policy_digest=policy.policy_digest,
    )
    review, review_resolver = _development_review(subject.subject_digest, policy)
    request = sealed_diagnostics.build_development_access_request(subject, review, policy, review_resolver)
    return request, review_resolver


def _diagnostic_resolver(selection=None) -> reservation.RepositoryIdentityResolver:
    selection = _authorities()[2] if selection is None else selection
    networks = {push.network_identity_digest: reservation.build_network_identity(push.canonical_repository) for push in selection.pushes}
    return reservation.RepositoryIdentityResolver(tuple(networks.values()))


def test_pre_spend_projection_is_closed_and_instrumented_before_interpretation() -> None:
    bundle, client, _, frozen = _frozen()
    assert bundle.case_inputs

    projection = sealed_diagnostics.project_pre_spend_diagnostics(
        frozen,
        _repo(client),
        _custodian(),
        ACCESS_POLICY,
    )

    assert projection.status is sealed_diagnostics.DiagnosticStatus.COMPLETE
    assert projection.input_count == len(bundle.case_inputs) > 0
    assert projection.observation_count > 0
    content = sealed_diagnostics.pre_spend_diagnostic_bytes(projection)
    assert content
    for forbidden in (b"finding", b"path", b"exception", b"password", b"label", b"repository"):
        assert forbidden not in content.lower()


def test_self_reviewed_development_access_returns_no_raw_observation() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active_chain(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _diagnostic_resolver(selection)
    policy = _diagnostic_policy()
    subject = sealed_diagnostics.build_development_access_subject(
        bundle.population_digest,
        bundle.freeze_digest,
        predecessor,
        frozen,
        bundle=bundle,
        selection=selection,
        resolver=resolver,
        manifest=manifest,
        artifact_access_policy_digest=ACCESS_POLICY,
        lifecycle_review_policy_digest=policy.policy_digest,
    )
    review, review_resolver = _development_review(subject.subject_digest, policy)
    self_reviewed = replace(review, producer_identity=review.reviewer_identity, attestation_digest="0" * 64)
    self_reviewed = replace(self_reviewed, attestation_digest=derive_independence_attestation_digest(self_reviewed))
    put_before = len(client.put_calls)

    with pytest.raises(sealed_diagnostics.SealedDiagnosticError) as captured:
        sealed_diagnostics.build_development_access_request(subject, self_reviewed, policy, review_resolver)

    assert captured.value.reason is sealed_diagnostics.DiagnosticAccessReason.REVIEW_REQUIRED
    assert len(client.put_calls) == put_before
    lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


def test_development_opening_is_terminal_and_never_rewrites_prior_evidence() -> None:
    bundle, client, _, frozen = _frozen()
    lifecycle_authority, predecessor = _active_chain(bundle.population_digest, bundle.freeze_digest)
    manifest, _, selection = _authorities()
    resolver = _diagnostic_resolver(selection)
    request, review_resolver = _development_request(bundle, predecessor, frozen, selection, resolver, manifest)
    observation_before = (
        _repo(client)
        .get(
            frozen.reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=_custodian(),
            expected_access_policy_digest=ACCESS_POLICY,
        )
        .content
    )
    store_before = dict(client.objects)
    prior_events = lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest).event_digests

    opened = sealed_diagnostics.open_observation_for_development(
        request,
        repository=_repo(client),
        artifact_authority=_custodian(),
        lifecycle_authority=lifecycle_authority,
        reservation_authority=reservation.ReservationAuthority(resolver),
        resolver=resolver,
        selection=selection,
        manifest=manifest,
        review_resolver=review_resolver,
    )

    assert opened.artifact.reference == frozen.reference
    assert opened.artifact.content == observation_before
    assert opened.artifact.content
    assert opened.lifecycle_projection.state is lifecycle.PopulationLifecycleState.DEVELOPMENT_OPENED
    assert not opened.lifecycle_projection.admission_eligible
    assert opened.lifecycle_projection.event_digests[: len(prior_events)] == prior_events
    for key, content in store_before.items():
        assert client.objects[key] == content
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        lifecycle_authority.require_admission_eligible(bundle.population_digest, bundle.freeze_digest)


# ------------------------------------------- pre/post-freeze contamination (3.5/3.6)


def test_pre_freeze_contamination_excludes_the_change_with_reason() -> None:
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)
    assert batches

    draw = _draw(batches, resolved, history, reviews=(_contamination("py-00", str(case_for("py-00")["parent"])),))

    assert draw.pushes
    assert draw.exclusions
    assert all(item.reason is OrdinaryExclusionReason.REVIEWED_SECURITY_DEFECT for item in draw.exclusions)
    assert all(item.contamination_review_digest for item in draw.exclusions)
    assert all(count >= 20 for count in dict(draw.per_positive_counts).values())


def test_post_freeze_contamination_is_refused_by_the_draw_instead_of_excluding() -> None:
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)
    assert batches
    clean = _draw(batches, resolved, history)
    assert clean.pushes

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(
            batches,
            resolved,
            history,
            reviews=(_contamination("py-00", str(case_for("py-00")["parent"]), ContaminationTiming.POST_FREEZE),),
        )

    assert error.value.reason is OrdinaryDrawReason.POST_FREEZE_CONTAMINATION


def _post_freeze_review(push, timing: ContaminationTiming) -> object:
    return reviewed_contamination(
        network_identity_digest=push.network_identity_digest,
        tip_revision=push.tip_revision,
        timing=timing,
        evidence_digest=_digest("governance-contamination-evidence"),
        producer_identity="contamination-producer@example.invalid",
        reviewer_identity="contamination-reviewer@example.invalid",
        conflict_disclosed=True,
        policy_digest=CONTAMINATION_POLICY,
    )


def test_retirement_event_binds_exact_selection_and_preserves_prior_evidence() -> None:
    authority, head = _active_chain(POPULATION, FREEZE)
    projection = authority.require_admission_eligible(POPULATION, FREEZE)
    selection = _selection(_positives())
    push = selection.pushes[0]
    before = ordinary_selection_bytes(selection)
    assert before

    event_content = post_freeze_contamination_retirement(selection, _post_freeze_review(push, ContaminationTiming.POST_FREEZE), projection)

    assert ordinary_selection_bytes(selection) == before
    with pytest.raises(OrdinarySelectionError, match="post-freeze contamination review"):
        post_freeze_contamination_retirement(selection, _post_freeze_review(push, ContaminationTiming.PRE_FREEZE), projection)
    hostile = _post_freeze_review(replace(push, tip_revision="e" * 40), ContaminationTiming.POST_FREEZE)
    with pytest.raises(OrdinarySelectionError, match="one selected push"):
        post_freeze_contamination_retirement(selection, hostile, projection)

    event = lifecycle.decode_lifecycle_event(event_content)
    retired = authority.append(event_content)

    assert retired.state is lifecycle.PopulationLifecycleState.RETIRED
    assert not retired.admission_eligible
    assert retired.event_digests[: len(projection.event_digests)] == projection.event_digests
    assert event.population_digest == POPULATION
    assert event.freeze_digest == FREEZE
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        authority.require_admission_eligible(POPULATION, FREEZE)
    with pytest.raises(lifecycle.LifecycleConflict, match="terminal"):
        authority.append(
            lifecycle.reviewed_retirement_event(
                predecessor_digest=retired.head_event_digest,
                population_digest=POPULATION,
                freeze_digest=FREEZE,
                evidence_digest=_digest("governance-second-retirement"),
                reason_code="contaminated_negative",
                producer_identity="retirement-producer",
                reviewer_identity="retirement-reviewer",
                conflict_disclosed=True,
                policy_digest=_digest("lifecycle-policy"),
            )
        )
