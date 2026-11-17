"""Build and validate independently reviewed label-blind population manifests."""

from __future__ import annotations

import re
from dataclasses import replace

from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1, ordinary_selection_bytes
from benchmarks.valid.population_freeze_contract import PopulationFreezeV3, population_freeze_bytes
from benchmarks.valid.population_label_blind_contract import (
    LabelBlindManifestConflict,
    LabelBlindManifestError,
    LabelBlindPopulationDraftV3,
    LabelBlindPopulationManifestV3,
    _draft_value,
    _manifest_value,
    label_blind_population_draft_bytes,
    label_blind_population_manifest_bytes,
)
from benchmarks.valid.population_material_contract import PopulationMaterialPartitionV1
from benchmarks.valid.population_materials import material_artifact_bytes, public_manifest_bytes
from openultrasast.core import canonical
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

_DIGEST = re.compile(r"[0-9a-f]{64}")


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LabelBlindManifestError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _validated_inputs(selection: OrdinarySelectionV1, freeze: PopulationFreezeV3) -> tuple[str, ...]:
    if type(selection) is not OrdinarySelectionV1:
        raise LabelBlindManifestError("input authority must use exact OrdinarySelectionV1")
    try:
        content = ordinary_selection_bytes(selection)
    except (TypeError, ValueError) as error:
        raise LabelBlindManifestError("ordinary selection authority is invalid") from error
    if not content:
        raise LabelBlindManifestError("ordinary selection authority is unreadable or empty")
    if selection.selection_digest != freeze.ordinary_selection_digest:
        raise LabelBlindManifestError("ordinary selection does not match the frozen authority")
    if selection.positive_change_digests != freeze.positive_change_digests:
        raise LabelBlindManifestError("ordinary selection does not bind the exact frozen positives")
    identities = (*freeze.positive_change_digests, *(push.push_digest for push in selection.pushes))
    if len(set(identities)) != len(identities):
        raise LabelBlindManifestError("positive and ordinary input identities must be unique")
    return tuple(sorted(identities))


def _validated_sources(
    freeze: PopulationFreezeV3,
    partition: PopulationMaterialPartitionV1,
) -> tuple[str, str]:
    if type(freeze) is not PopulationFreezeV3 or type(partition) is not PopulationMaterialPartitionV1:
        raise LabelBlindManifestError("label-blind manifest requires exact replacement V3 authorities")
    try:
        freeze_content = population_freeze_bytes(freeze)
        manifest_content = public_manifest_bytes(partition)
        artifacts = material_artifact_bytes(partition)
    except (TypeError, ValueError) as error:
        raise LabelBlindManifestError("label-blind source authority is invalid") from error
    if not freeze_content or not manifest_content or any(not item for item in artifacts):
        raise LabelBlindManifestError("label-blind source authority is unreadable or empty")
    manifest = partition.manifest
    if (manifest.population_digest, manifest.freeze_digest) != (freeze.population_digest, freeze.freeze_digest):
        raise LabelBlindManifestError("material partition does not bind the exact replacement freeze")
    artifact_set = canonical.content_digest({"artifact_digests": tuple(canonical.bytes_digest(item) for item in artifacts)})
    return manifest.manifest_digest, artifact_set


def build_label_blind_population_draft(
    freeze: PopulationFreezeV3,
    partition: PopulationMaterialPartitionV1,
    ordinary_selection: OrdinarySelectionV1,
) -> LabelBlindPopulationDraftV3:
    """Derive label-blind census metadata from exact frozen authorities."""
    public_manifest_digest, artifact_set_digest = _validated_sources(freeze, partition)
    inputs = _validated_inputs(ordinary_selection, freeze)
    if not freeze.scope_census:
        raise LabelBlindManifestError("label-blind population requires exact scope counts")
    draft = LabelBlindPopulationDraftV3(
        freeze.population_digest,
        freeze.freeze_digest,
        freeze.reservation_census_digest,
        freeze.review_set_digest,
        freeze.ordinary_selection_digest,
        public_manifest_digest,
        artifact_set_digest,
        freeze.scope_census,
        inputs,
        freeze.positive_count,
        len(inputs),
        derive_evaluation_input_set_digest(inputs),
        "",
    )
    result = replace(draft, draft_digest=canonical.content_digest(_draft_value(draft, include_digest=False)))
    label_blind_population_draft_bytes(result)
    return result


def _validated_policy(policy: ReviewIndependencePolicy) -> ReviewIndependencePolicy:
    if type(policy) is not ReviewIndependencePolicy:
        raise LabelBlindManifestError("review policy must use exact ReviewIndependencePolicy")
    try:
        policy.__post_init__()
        expected = derive_review_independence_policy_digest(
            policy.reviewed_reviewer_digests,
            policy.forbidden_identity_pairs,
            policy.trusted_store_identities,
            policy.maximum_evidence_bytes,
        )
    except (FactPackValidationError, TypeError, ValueError) as error:
        raise LabelBlindManifestError("review independence policy is invalid") from error
    if policy.policy_digest != expected:
        raise LabelBlindManifestError("review independence policy digest cannot be re-derived")
    return policy


def _validated_review(
    draft: LabelBlindPopulationDraftV3,
    review: IndependenceAttestation,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> str:
    label_blind_population_draft_bytes(draft)
    policy = _validated_policy(policy)
    if type(review) is not IndependenceAttestation or type(review.conflict_disclosure) is not canonical.ContentRef:
        raise LabelBlindManifestError("review must use exact detection-core independence contracts")
    try:
        review.__post_init__()
        review.conflict_disclosure.__post_init__()
    except (FactPackValidationError, TypeError, ValueError) as error:
        raise LabelBlindManifestError("review attestation is invalid") from error
    if review.subject_digest != draft.draft_digest:
        raise LabelBlindManifestError("label-blind manifest review is stale")
    if review.producer_identity == review.reviewer_identity:
        raise LabelBlindManifestError("label-blind manifest review must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise LabelBlindManifestError("manifest reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise LabelBlindManifestError("manifest producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise LabelBlindManifestError("review attestation digest cannot be re-derived")
    try:
        disclosure = canonical.resolve_content(
            review.conflict_disclosure,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (AttributeError, TypeError, ValueError, LookupError) as error:
        raise LabelBlindManifestError("review conflict disclosure cannot be resolved") from error
    if not disclosure:
        raise LabelBlindManifestError("review conflict disclosure must be nonempty")
    return review.attestation_digest


def _reviewed_manifest(draft: LabelBlindPopulationDraftV3, review_digest: str) -> LabelBlindPopulationManifestV3:
    manifest = LabelBlindPopulationManifestV3(
        draft.population_digest,
        draft.freeze_digest,
        draft.reservation_census_digest,
        draft.review_set_digest,
        draft.ordinary_selection_digest,
        draft.public_material_manifest_digest,
        draft.material_artifact_set_digest,
        draft.scope_census,
        draft.input_digests,
        draft.positive_count,
        draft.input_count,
        draft.input_set_digest,
        draft.draft_digest,
        review_digest,
        "",
    )
    result = replace(manifest, manifest_digest=canonical.content_digest(_manifest_value(manifest, include_digest=False)))
    label_blind_population_manifest_bytes(result)
    return result


def review_label_blind_population_manifest(
    draft: LabelBlindPopulationDraftV3,
    review: IndependenceAttestation,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> LabelBlindPopulationManifestV3:
    """Accept an externally supplied core review of one exact draft."""
    return _reviewed_manifest(draft, _validated_review(draft, review, policy, resolver))


def validate_label_blind_population_manifest(
    manifest: LabelBlindPopulationManifestV3,
    freeze: PopulationFreezeV3,
    partition: PopulationMaterialPartitionV1,
    ordinary_selection: OrdinarySelectionV1,
    review: IndependenceAttestation,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> bytes:
    """Rebuild all label-blind authorities before accepting manifest bytes."""
    draft = build_label_blind_population_draft(freeze, partition, ordinary_selection)
    expected = review_label_blind_population_manifest(draft, review, policy, resolver)
    if manifest != expected:
        raise LabelBlindManifestError("reviewed label-blind manifest does not replay from exact authorities")
    return label_blind_population_manifest_bytes(manifest)


def accept_label_blind_population_manifest(
    manifest: LabelBlindPopulationManifestV3,
    freeze: PopulationFreezeV3,
    partition: PopulationMaterialPartitionV1,
    ordinary_selection: OrdinarySelectionV1,
    review: IndependenceAttestation,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
    *,
    existing_content: bytes | None = None,
) -> bytes:
    content = validate_label_blind_population_manifest(manifest, freeze, partition, ordinary_selection, review, policy, resolver)
    if existing_content is not None and existing_content != content:
        raise LabelBlindManifestConflict("same label-blind manifest identity resolves to different bytes")
    return content


__all__ = [
    "IndependenceAttestation",
    "LabelBlindManifestConflict",
    "LabelBlindManifestError",
    "LabelBlindPopulationDraftV3",
    "LabelBlindPopulationManifestV3",
    "ReviewIndependencePolicy",
    "accept_label_blind_population_manifest",
    "build_label_blind_population_draft",
    "label_blind_population_manifest_bytes",
    "review_label_blind_population_manifest",
    "validate_label_blind_population_manifest",
]
