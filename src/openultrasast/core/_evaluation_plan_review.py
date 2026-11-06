"""Validation helpers for reviewed V3 plan census and manifest values."""

from __future__ import annotations

import re

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import ScopeKey
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    EvaluationPlanDeclarationV3,
    EvaluationPlanError,
    EvaluationPlanManifestV3,
    ExactScopeCensusV3,
    PopulationCensusV3,
    validate_evaluation_baselines,
)
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_CENSUS_PAYLOAD_SCHEMA = "openultrasast.detection-core.evaluation-census-payload.v3"
_CENSUS_SCHEMA = "openultrasast.detection-core.evaluation-census.v3"
_MANIFEST_PAYLOAD_SCHEMA = "openultrasast.detection-core.evaluation-plan-manifest-payload.v3"
_MANIFEST_SCHEMA = "openultrasast.detection-core.evaluation-plan-manifest.v3"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationPlanError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        qualifier = "positive" if positive else "non-negative"
        raise EvaluationPlanError(f"{field} must be a {qualifier} integer")
    return value


def _attestation_value(review: IndependenceAttestation) -> canonical.JsonValue:
    reference = review.conflict_disclosure
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": {
            "artifact_id": reference.artifact_id,
            "content_digest": reference.content_digest,
            "media_type": reference.media_type,
            "byte_length": reference.byte_length,
            "retention_policy_digest": reference.retention_policy_digest,
            "storage_receipt_digest": reference.storage_receipt_digest,
        },
        "attestation_digest": review.attestation_digest,
    }


def _scope_value(scope: ScopeKey) -> canonical.JsonValue:
    return {"family_id": scope.family_id, "ecosystem": scope.ecosystem}


def _scope_row_value(row: ExactScopeCensusV3) -> canonical.JsonValue:
    return {
        "scope": _scope_value(row.scope),
        "pair_count": row.pair_count,
        "vulnerable_side_count": row.vulnerable_side_count,
        "fixed_side_count": row.fixed_side_count,
        "semantic_site_capacity": row.semantic_site_capacity,
        "model_call_capacity": row.model_call_capacity,
    }


def _census_payload_value(census: PopulationCensusV3) -> canonical.JsonValue:
    return {
        "schema_version": _CENSUS_PAYLOAD_SCHEMA,
        "population_digest": census.population_digest,
        "scope_rows": tuple(_scope_row_value(row) for row in census.scope_rows),
        "ordinary_rows": tuple(
            {"ecosystem": row.ecosystem, "ordinary_push_count": row.ordinary_push_count} for row in census.ordinary_rows
        ),
        "whole_underlying_push_count": census.whole_underlying_push_count,
        "labels_exposed": census.labels_exposed,
    }


def _manifest_payload_value(manifest: EvaluationPlanManifestV3) -> canonical.JsonValue:
    return {
        "schema_version": _MANIFEST_PAYLOAD_SCHEMA,
        "plan_declaration_digest": manifest.declaration.declaration_digest,
        "baseline_digests": tuple(row.baseline_digest for row in manifest.baselines),
        "census_digest": manifest.census.census_digest,
        "readiness_digests": manifest.readiness_digests,
        "custody_log_digest": manifest.custody_log_digest,
    }


def validate_exact_scope_census_shape(row: ExactScopeCensusV3) -> None:
    if type(row.scope) is not ScopeKey:
        raise EvaluationPlanError("census scope must use exact ScopeKey")
    row.scope.__post_init__()
    for field in (
        "pair_count",
        "vulnerable_side_count",
        "fixed_side_count",
        "semantic_site_capacity",
        "model_call_capacity",
    ):
        _count(getattr(row, field), field)
    if row.pair_count > min(row.vulnerable_side_count, row.fixed_side_count):
        raise EvaluationPlanError("census pair count exceeds vulnerable or fixed side capacity")


def validate_ordinary_census_shape(row: EcosystemOrdinaryCensusV3) -> None:
    if type(row.ecosystem) is not str or not row.ecosystem:
        raise EvaluationPlanError("ordinary census ecosystem must be nonempty exact text")
    _count(row.ordinary_push_count, "ordinary push count")


def _validate_review_shape(review: object) -> IndependenceAttestation:
    if type(review) is not IndependenceAttestation:
        raise EvaluationPlanError("review must use exact IndependenceAttestation")
    if type(review.conflict_disclosure) is not canonical.ContentRef:
        raise EvaluationPlanError("review conflict disclosure must use exact ContentRef")
    try:
        review.__post_init__()
        review.conflict_disclosure.__post_init__()
    except (FactPackValidationError, ValueError) as exc:
        raise EvaluationPlanError(f"review attestation is invalid: {exc}") from exc
    return review


def _validate_scope_rows(rows: object) -> tuple[ExactScopeCensusV3, ...]:
    if type(rows) is not tuple or not rows:
        raise EvaluationPlanError("scope census rows must be a nonempty tuple")
    if any(type(row) is not ExactScopeCensusV3 for row in rows):
        raise EvaluationPlanError("scope census rows must use exact values")
    for scope_row in rows:
        validate_exact_scope_census_shape(scope_row)
    scopes = tuple(scope_row.scope for scope_row in rows)
    if scopes != tuple(sorted(scopes)) or len(set(scopes)) != len(scopes):
        raise EvaluationPlanError("scope census rows must be unique and canonical")
    return rows


def _validate_ordinary_rows(rows: object) -> tuple[EcosystemOrdinaryCensusV3, ...]:
    if type(rows) is not tuple or not rows:
        raise EvaluationPlanError("ordinary census rows must be a nonempty tuple")
    if any(type(row) is not EcosystemOrdinaryCensusV3 for row in rows):
        raise EvaluationPlanError("ordinary census rows must use exact values")
    for ordinary_row in rows:
        validate_ordinary_census_shape(ordinary_row)
    ecosystems = tuple(ordinary_row.ecosystem for ordinary_row in rows)
    if ecosystems != tuple(sorted(ecosystems)) or len(set(ecosystems)) != len(ecosystems):
        raise EvaluationPlanError("ordinary census ecosystems must be unique and canonical")
    return rows


def validate_population_census_shape(census: PopulationCensusV3) -> None:
    _digest(census.population_digest, "census population digest")
    _validate_scope_rows(census.scope_rows)
    ordinary_rows = _validate_ordinary_rows(census.ordinary_rows)
    whole_count = _count(census.whole_underlying_push_count, "whole underlying push count", positive=True)
    if sum(row.ordinary_push_count for row in ordinary_rows) > whole_count:
        raise EvaluationPlanError("ordinary push capacity exceeds whole-population capacity")
    if type(census.labels_exposed) is not bool:
        raise EvaluationPlanError("labels_exposed must be exact boolean")
    _digest(census.payload_digest, "census payload digest")
    _validate_review_shape(census.review)
    _digest(census.census_digest, "census digest")


def validate_plan_manifest_shape(manifest: EvaluationPlanManifestV3) -> None:
    if type(manifest.declaration) is not EvaluationPlanDeclarationV3:
        raise EvaluationPlanError("manifest declaration must use exact EvaluationPlanDeclarationV3")
    manifest.declaration.__post_init__()
    validate_evaluation_baselines(manifest.declaration, manifest.baselines)
    if type(manifest.census) is not PopulationCensusV3:
        raise EvaluationPlanError("manifest census must use exact PopulationCensusV3")
    validate_population_census_shape(manifest.census)
    if type(manifest.readiness_digests) is not tuple or not manifest.readiness_digests:
        raise EvaluationPlanError("readiness digests must be a nonempty tuple")
    for item in manifest.readiness_digests:
        _digest(item, "readiness digest")
    if manifest.readiness_digests != tuple(sorted(set(manifest.readiness_digests))):
        raise EvaluationPlanError("readiness digests must be unique and canonical")
    _digest(manifest.custody_log_digest, "custody log digest")
    _digest(manifest.payload_digest, "manifest payload digest")
    _validate_review_shape(manifest.review)
    _digest(manifest.manifest_digest, "manifest digest")


def census_payload_digest(census: PopulationCensusV3) -> str:
    validate_population_census_shape(census)
    return canonical.content_digest(_census_payload_value(census))


def census_digest(census: PopulationCensusV3) -> str:
    validate_population_census_shape(census)
    return canonical.content_digest(
        {
            "schema_version": _CENSUS_SCHEMA,
            "payload_digest": census.payload_digest,
            "review": _attestation_value(census.review),
        }
    )


def manifest_payload_digest(manifest: EvaluationPlanManifestV3) -> str:
    validate_plan_manifest_shape(manifest)
    return canonical.content_digest(_manifest_payload_value(manifest))


def manifest_digest(manifest: EvaluationPlanManifestV3) -> str:
    validate_plan_manifest_shape(manifest)
    return canonical.content_digest(
        {
            "schema_version": _MANIFEST_SCHEMA,
            "payload_digest": manifest.payload_digest,
            "review": _attestation_value(manifest.review),
        }
    )


def _validate_policy(policy: object) -> ReviewIndependencePolicy:
    if type(policy) is not ReviewIndependencePolicy:
        raise EvaluationPlanError("review policy must use exact ReviewIndependencePolicy")
    try:
        policy.__post_init__()
    except FactPackValidationError as exc:
        raise EvaluationPlanError(f"review policy is invalid: {exc}") from exc
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise EvaluationPlanError("review policy digest cannot be re-derived")
    return policy


def _validate_review(
    review: IndependenceAttestation,
    subject_digest: str,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    _validate_review_shape(review)
    if review.subject_digest != subject_digest:
        raise EvaluationPlanError("review subject does not match reviewed payload")
    if review.producer_identity == review.reviewer_identity:
        raise EvaluationPlanError("review producer and reviewer must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise EvaluationPlanError("reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise EvaluationPlanError("review producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise EvaluationPlanError("review attestation digest cannot be re-derived")
    try:
        content = canonical.resolve_content(
            review.conflict_disclosure,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except (AttributeError, TypeError) as exc:
        raise EvaluationPlanError("review resolver returned a malformed result") from exc
    if not content:
        raise EvaluationPlanError("review conflict disclosure must be nonempty")


def _planned_scopes(manifest: EvaluationPlanManifestV3) -> tuple[ScopeKey, ...]:
    return tuple(sorted({scope for config in manifest.declaration.arm_configurations for scope in config.exact_scopes}))


def _validate_census_plan_binding(census: PopulationCensusV3, manifest: EvaluationPlanManifestV3) -> None:
    if manifest.census != census:
        raise EvaluationPlanError("manifest census does not match the reviewed census")
    if census.population_digest != manifest.declaration.population_digest:
        raise EvaluationPlanError("census population does not match the plan declaration")
    planned_scopes = _planned_scopes(manifest)
    if tuple(row.scope for row in census.scope_rows) != planned_scopes:
        raise EvaluationPlanError("census scopes do not match every planned exact scope")
    planned_ecosystems = tuple(sorted({scope.ecosystem for scope in planned_scopes}))
    if tuple(row.ecosystem for row in census.ordinary_rows) != planned_ecosystems:
        raise EvaluationPlanError("ordinary census ecosystems do not match the plan")


def validate_reviewed_plan(
    census: PopulationCensusV3,
    manifest: EvaluationPlanManifestV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    if type(census) is not PopulationCensusV3 or type(manifest) is not EvaluationPlanManifestV3:
        raise EvaluationPlanError("reviewed census and manifest must use exact V3 types")
    validate_population_census_shape(census)
    validate_plan_manifest_shape(manifest)
    policy = _validate_policy(policy)
    if census.labels_exposed:
        raise EvaluationPlanError("reviewed census must keep labels sealed")
    expected_payload = census_payload_digest(census)
    if census.payload_digest != expected_payload:
        raise EvaluationPlanError("census payload digest cannot be re-derived")
    _validate_review(census.review, expected_payload, policy, resolver)
    if census.census_digest != census_digest(census):
        raise EvaluationPlanError("census digest cannot be re-derived")
    _validate_census_plan_binding(census, manifest)
    expected_manifest_payload = manifest_payload_digest(manifest)
    if manifest.payload_digest != expected_manifest_payload:
        raise EvaluationPlanError("manifest payload digest cannot be re-derived")
    _validate_review(manifest.review, expected_manifest_payload, policy, resolver)
    if manifest.manifest_digest != manifest_digest(manifest):
        raise EvaluationPlanError("manifest digest cannot be re-derived")


__all__ = [
    "census_digest",
    "census_payload_digest",
    "manifest_digest",
    "manifest_payload_digest",
    "validate_exact_scope_census_shape",
    "validate_ordinary_census_shape",
    "validate_plan_manifest_shape",
    "validate_population_census_shape",
    "validate_reviewed_plan",
]
