"""Reviewed label-blind replacement population manifest tests."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import InMemoryContentResolver, stored_artifact  # noqa: E402
from test_core_evaluation_plan import _configuration  # noqa: E402
from test_valid_benchmark_population_freeze import (  # noqa: E402
    _freeze as _reviewed_freeze,
)
from test_valid_benchmark_population_freeze import (
    _positives,
    _selection,
)
from test_valid_benchmark_population_materials import _digest, _Validator  # noqa: E402

from benchmarks.valid import population_label_blind as label_blind  # noqa: E402
from benchmarks.valid import population_materials as materials  # noqa: E402
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1  # noqa: E402
from benchmarks.valid.population_freeze_contract import PopulationFreezeV3  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.evaluation_plan import (  # noqa: E402
    create_evaluation_plan_declaration,
    derive_evaluation_input_set_digest,
)
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)


def _policy(
    reviewer: str,
    forbidden: tuple[tuple[str, str], ...] = (),
    *,
    stores: tuple[str, ...] = ("trusted-store",),
    maximum_bytes: int = 4096,
) -> ReviewIndependencePolicy:
    digest = derive_review_independence_policy_digest((reviewer,), forbidden, stores, maximum_bytes)
    return ReviewIndependencePolicy((reviewer,), forbidden, stores, maximum_bytes, digest)


def _attestation(
    subject: str,
    disclosure: canonical.ContentRef,
    *,
    producer: str | None = None,
    reviewer: str | None = None,
) -> IndependenceAttestation:
    draft = IndependenceAttestation(
        subject,
        producer or _digest("manifest-producer"),
        reviewer or _digest("manifest-reviewer"),
        disclosure,
        "0" * 64,
    )
    return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))


@lru_cache(maxsize=1)
def _sources() -> tuple[
    PopulationFreezeV3,
    OrdinarySelectionV1,
    materials.PopulationMaterialPartitionV1,
]:
    positives = _positives()
    selection = _selection(positives)
    freeze = _reviewed_freeze(positives)
    material_inputs = tuple(
        materials.PopulationMaterialInputV1(
            change,
            materials.LicenseClass.PERMISSIVE,
            "Apache-2.0",
            f"public source {index}".encode(),
            f"sealed label {index}".encode(),
            f"sealed review {index}".encode(),
            True,
        )
        for index, change in enumerate(freeze.positive_change_digests)
    )
    partition = materials.build_population_material_partition(
        freeze,
        material_inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    return freeze, selection, partition


def _reviewed() -> tuple[
    PopulationFreezeV3,
    OrdinarySelectionV1,
    materials.PopulationMaterialPartitionV1,
    ReviewIndependencePolicy,
    InMemoryContentResolver,
    IndependenceAttestation,
    label_blind.LabelBlindPopulationManifestV3,
]:
    freeze, selection, partition = _sources()
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="label-blind-conflicts")
    review = _attestation(draft.draft_digest, disclosure)
    policy = _policy(review.reviewer_identity)
    manifest = label_blind.review_label_blind_population_manifest(draft, review, policy, resolver)
    return freeze, selection, partition, policy, resolver, review, manifest


def _validate(
    case: tuple[
        PopulationFreezeV3,
        OrdinarySelectionV1,
        materials.PopulationMaterialPartitionV1,
        ReviewIndependencePolicy,
        InMemoryContentResolver,
        IndependenceAttestation,
        label_blind.LabelBlindPopulationManifestV3,
    ],
) -> bytes:
    freeze, selection, partition, policy, resolver, review, manifest = case
    return label_blind.validate_label_blind_population_manifest(manifest, freeze, partition, selection, review, policy, resolver)


def test_reviewed_manifest_replays_core_v3_input_identity_and_exact_census() -> None:
    case = _reviewed()
    content = _validate(case)
    manifest = case[-1]
    decoded = json.loads(content)

    assert decoded["input_digests"] == list(manifest.input_digests)
    assert decoded["input_count"] == len(manifest.input_digests)
    assert manifest.input_set_digest == derive_evaluation_input_set_digest(manifest.input_digests)
    declaration = create_evaluation_plan_declaration(
        population_digest=manifest.population_digest,
        freeze_digest=manifest.freeze_digest,
        input_set_digest=manifest.input_set_digest,
        arm_configurations=(_configuration("compatibility-arm"),),
        input_identity_digests=manifest.input_digests,
    )
    assert declaration.input_set_digest == manifest.input_set_digest
    assert decoded["scope_census"]
    assert decoded["review_digest"] == case[-2].attestation_digest


def test_inputs_are_frozen_positives_plus_unique_underlying_pushes_once() -> None:
    freeze, selection, *_ = _reviewed()
    manifest = _reviewed()[-1]
    expected = tuple(sorted((*freeze.positive_change_digests, *(push.push_digest for push in selection.pushes))))

    assert manifest.input_digests == expected
    assert manifest.input_count == freeze.positive_count + len(selection.pushes)
    assert len(manifest.input_digests) < len(selection.assignments) + freeze.positive_count


def test_manifest_contains_only_census_and_digest_metadata() -> None:
    _, _, partition, _, _, review, manifest = _reviewed()
    content = label_blind.label_blind_population_manifest_bytes(manifest)
    decoded = json.loads(content)

    for forbidden in (b"sealed label", b"sealed review", b"public source", b"content_base64", b"/home/", b"password="):
        assert forbidden not in content
    assert partition.manifest.private_object_digest.encode() not in content
    assert partition.manifest.sealed_label_digest.encode() not in content
    assert review.producer_identity.encode() not in content
    assert review.reviewer_identity.encode() not in content
    assert set(decoded) == {
        "draft_digest",
        "freeze_digest",
        "input_count",
        "input_digests",
        "input_set_digest",
        "manifest_digest",
        "material_artifact_set_digest",
        "ordinary_selection_digest",
        "population_digest",
        "positive_count",
        "public_material_manifest_digest",
        "reservation_census_digest",
        "review_digest",
        "review_set_digest",
        "schema_version",
        "scope_census",
    }


@pytest.mark.parametrize("mutation", ("extra", "missing", "digest", "positives", "malformed"))
def test_changed_or_malformed_ordinary_selection_is_refused(mutation: str) -> None:
    freeze, selection, partition = _sources()
    changed = selection
    if mutation == "extra":
        extra = replace(selection.pushes[-1], push_digest=_digest("arbitrary-extra-push"))
        changed = replace(selection, pushes=tuple(sorted((*selection.pushes, extra))))
    elif mutation == "missing":
        changed = replace(selection, pushes=selection.pushes[:-1])
    elif mutation == "digest":
        changed = replace(selection, selection_digest=_digest("wrong-selection"))
    elif mutation == "positives":
        changed = replace(selection, positive_change_digests=selection.positive_change_digests[:-1])
    else:
        changed_push = replace(selection.pushes[0], change_byte_length=0)
        changed = replace(selection, pushes=(changed_push, *selection.pushes[1:]))

    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.build_label_blind_population_draft(freeze, partition, changed)


def test_review_requires_exact_core_independence_authority() -> None:
    freeze, selection, partition = _sources()
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="review-policy-cases")
    producer = _digest("manifest-producer")
    reviewer = _digest("manifest-reviewer")
    accepted = _attestation(draft.draft_digest, disclosure, producer=producer, reviewer=reviewer)

    cases = (
        (_attestation(draft.draft_digest, disclosure, reviewer=_digest("unregistered")), _policy(reviewer), resolver),
        (accepted, _policy(reviewer, ((producer, reviewer),)), resolver),
        (accepted, replace(_policy(reviewer), policy_digest=_digest("wrong-policy")), resolver),
        (_attestation(_digest("wrong-subject"), disclosure, producer=producer, reviewer=reviewer), _policy(reviewer), resolver),
        (replace(accepted, attestation_digest=_digest("wrong-attestation")), _policy(reviewer), resolver),
        (_attestation(draft.draft_digest, disclosure, producer=reviewer, reviewer=reviewer), _policy(reviewer), resolver),
    )
    for review, policy, selected_resolver in cases:
        with pytest.raises(label_blind.LabelBlindManifestError):
            label_blind.review_label_blind_population_manifest(draft, review, policy, selected_resolver)


@pytest.mark.parametrize("failure", ("missing", "wrong_store", "oversized", "empty"))
def test_conflict_disclosure_must_resolve_nonempty_under_policy(failure: str) -> None:
    freeze, selection, partition = _sources()
    draft = label_blind.build_label_blind_population_draft(freeze, partition, selection)
    content = b'{"conflicts":[]}' if failure != "empty" else b""
    store = "wrong-store" if failure == "wrong_store" else "trusted-store"
    disclosure, resolver = stored_artifact(content, artifact_id=f"disclosure-{failure}", store_identity=store)
    if failure == "missing":
        resolver = InMemoryContentResolver({})
    review = _attestation(draft.draft_digest, disclosure)
    maximum = max(1, disclosure.byte_length - 1) if failure == "oversized" else 4096

    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.review_label_blind_population_manifest(
            draft, review, _policy(review.reviewer_identity, maximum_bytes=maximum), resolver
        )


def test_stale_population_material_scope_and_review_are_refused() -> None:
    freeze, selection, partition, policy, resolver, review, manifest = _reviewed()
    changed_freeze = replace(freeze, population_digest=_digest("changed-population"))
    changed_partition = replace(partition, manifest=replace(partition.manifest, manifest_digest=_digest("changed-material")))

    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.validate_label_blind_population_manifest(manifest, changed_freeze, partition, selection, review, policy, resolver)
    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.validate_label_blind_population_manifest(manifest, freeze, changed_partition, selection, review, policy, resolver)
    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.validate_label_blind_population_manifest(
            replace(manifest, scope_census=()), freeze, partition, selection, review, policy, resolver
        )
    with pytest.raises(label_blind.LabelBlindManifestError):
        label_blind.validate_label_blind_population_manifest(
            replace(manifest, input_set_digest=_digest("wrong-input-set")),
            freeze,
            partition,
            selection,
            review,
            policy,
            resolver,
        )


def test_same_identity_different_bytes_conflicts() -> None:
    case = _reviewed()
    content = _validate(case)
    freeze, selection, partition, policy, resolver, review, manifest = case

    assert (
        label_blind.accept_label_blind_population_manifest(
            manifest, freeze, partition, selection, review, policy, resolver, existing_content=content
        )
        == content
    )
    with pytest.raises(label_blind.LabelBlindManifestConflict):
        label_blind.accept_label_blind_population_manifest(
            manifest, freeze, partition, selection, review, policy, resolver, existing_content=content + b"\n"
        )
