"""Reviewed label-blind census and admission-manifest contracts."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._admission_review_shape import closed_graph_problem
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    MetricId,
    ScopeKey,
    Statistic,
    derive_baseline_identity_digest,
)

CENSUS_PAYLOAD_SCHEMA = "openultrasast.detection-core.population-census-payload.v2"
CENSUS_SCHEMA = "openultrasast.detection-core.population-census.v2"
MANIFEST_PAYLOAD_SCHEMA = "openultrasast.detection-core.admission-manifest-payload.v2"
MANIFEST_SCHEMA = "openultrasast.detection-core.admission-manifest.v2"
THRESHOLD_SET_SCHEMA = "openultrasast.detection-core.threshold-set.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class AdmissionReviewError(ValueError):
    """A census or manifest review contract is invalid."""


@dataclass(frozen=True)
class ScopeCensus:
    scope: ScopeKey
    total_cases: int
    pair_count: int
    vulnerable_side_count: int
    fixed_side_count: int
    ordinary_case_count: int
    semantic_site_capacity: int
    model_call_capacity: int


@dataclass(frozen=True)
class PopulationCensus:
    population_digest: str
    rows: tuple[ScopeCensus, ...]
    case_labels_exposed: bool
    census_payload_digest: str
    review: IndependenceAttestation
    census_digest: str


@dataclass(frozen=True)
class AdmissionThreshold:
    metric_id: MetricId
    statistic: Statistic
    comparator: Comparator
    target: float


@dataclass(frozen=True)
class AdmissionManifestV2:
    manifest_payload_digest: str
    review: IndependenceAttestation
    label_isolated: bool
    labels_opened: bool
    identity: BaselineIdentity
    census: PopulationCensus
    readiness_digests: tuple[str, ...]
    custody_log_digest: str
    denominator_policy_digest: str
    thresholds: tuple[AdmissionThreshold, ...]
    threshold_set_digest: str
    threshold_lineage_manifest_digest: str
    validation_context_digest: str
    manifest_digest: str


_GRAPH_DATACLASS_TYPES: tuple[type[object], ...] = (
    ScopeCensus,
    PopulationCensus,
    AdmissionThreshold,
    AdmissionManifestV2,
    ScopeKey,
    BaselineIdentity,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    canonical.ContentRef,
)
_GRAPH_ENUM_TYPES: tuple[type[object], ...] = (MetricId, Statistic, Comparator)


def _closed_graph(value: object, field: str) -> None:
    problem = closed_graph_problem(
        value,
        dataclass_types=_GRAPH_DATACLASS_TYPES,
        enum_types=_GRAPH_ENUM_TYPES,
        path=field,
    )
    if problem is not None:
        raise AdmissionReviewError(f"closed payload graph violation: {problem}")


def derive_census_payload_digest(census: PopulationCensus) -> str:
    _closed_graph(census, "census")
    _validate_census_shape(census)
    return canonical.content_digest(_census_payload_value(census))


def derive_census_digest(census: PopulationCensus) -> str:
    _closed_graph(census, "census")
    _validate_census_shape(census)
    return canonical.content_digest(
        {
            "schema_version": CENSUS_SCHEMA,
            "census_payload_digest": census.census_payload_digest,
            "review": _attestation_value(census.review),
        }
    )


def derive_manifest_payload_digest(manifest: AdmissionManifestV2) -> str:
    _closed_graph(manifest, "manifest")
    _validate_manifest_shape(manifest)
    return canonical.content_digest(_manifest_payload_value(manifest))


def derive_manifest_digest(manifest: AdmissionManifestV2) -> str:
    _closed_graph(manifest, "manifest")
    _validate_manifest_shape(manifest)
    return canonical.content_digest(
        {
            "schema_version": MANIFEST_SCHEMA,
            "manifest_payload_digest": manifest.manifest_payload_digest,
            "review": _attestation_value(manifest.review),
        }
    )


def derive_threshold_set_digest(thresholds: tuple[AdmissionThreshold, ...]) -> str:
    _closed_graph(thresholds, "thresholds")
    _validate_thresholds(thresholds)
    return canonical.content_digest(
        {"schema_version": THRESHOLD_SET_SCHEMA, "thresholds": tuple(_threshold_value(item) for item in thresholds)}
    )


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionReviewError(f"{field} must be a full lowercase SHA-256 digest")


def _count(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdmissionReviewError(f"{field} must be a non-negative integer")


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _attestation_value(attestation: IndependenceAttestation) -> canonical.JsonValue:
    return {
        "subject_digest": attestation.subject_digest,
        "producer_identity": attestation.producer_identity,
        "reviewer_identity": attestation.reviewer_identity,
        "conflict_disclosure": _content_ref_value(attestation.conflict_disclosure),
        "attestation_digest": attestation.attestation_digest,
    }


def _scope_value(scope: ScopeKey) -> canonical.JsonValue:
    return {"family_id": scope.family_id, "ecosystem": scope.ecosystem}


def _row_value(row: ScopeCensus) -> canonical.JsonValue:
    return {
        "scope": _scope_value(row.scope),
        "total_cases": row.total_cases,
        "pair_count": row.pair_count,
        "vulnerable_side_count": row.vulnerable_side_count,
        "fixed_side_count": row.fixed_side_count,
        "ordinary_case_count": row.ordinary_case_count,
        "semantic_site_capacity": row.semantic_site_capacity,
        "model_call_capacity": row.model_call_capacity,
    }


def _census_payload_value(census: PopulationCensus) -> canonical.JsonValue:
    return {
        "schema_version": CENSUS_PAYLOAD_SCHEMA,
        "population_digest": census.population_digest,
        "rows": tuple(_row_value(row) for row in census.rows),
        "case_labels_exposed": census.case_labels_exposed,
    }


def _threshold_value(threshold: AdmissionThreshold) -> canonical.JsonValue:
    return {
        "metric_id": threshold.metric_id.value,
        "statistic": threshold.statistic.value,
        "comparator": threshold.comparator.value,
        "target": threshold.target,
    }


def _manifest_payload_value(manifest: AdmissionManifestV2) -> canonical.JsonValue:
    return {
        "schema_version": MANIFEST_PAYLOAD_SCHEMA,
        "label_isolated": manifest.label_isolated,
        "labels_opened": manifest.labels_opened,
        "baseline_identity_digest": derive_baseline_identity_digest(manifest.identity),
        "census_digest": manifest.census.census_digest,
        "readiness_digests": manifest.readiness_digests,
        "custody_log_digest": manifest.custody_log_digest,
        "denominator_policy_digest": manifest.denominator_policy_digest,
        "thresholds": tuple(_threshold_value(item) for item in manifest.thresholds),
        "threshold_set_digest": manifest.threshold_set_digest,
        "threshold_lineage_manifest_digest": manifest.threshold_lineage_manifest_digest,
        "validation_context_digest": manifest.validation_context_digest,
    }


def _validate_row(row: ScopeCensus) -> None:
    row.scope.__post_init__()
    for field in (
        "total_cases",
        "pair_count",
        "vulnerable_side_count",
        "fixed_side_count",
        "ordinary_case_count",
        "semantic_site_capacity",
        "model_call_capacity",
    ):
        _count(getattr(row, field), field)
    if row.total_cases != row.vulnerable_side_count + row.fixed_side_count + row.ordinary_case_count:
        raise AdmissionReviewError("census total does not reconcile with aggregate roles")
    if row.pair_count > min(row.vulnerable_side_count, row.fixed_side_count):
        raise AdmissionReviewError("census pair count exceeds side capacity")


def _validate_census_shape(census: PopulationCensus) -> None:
    _digest(census.population_digest, "census population digest")
    if not census.rows:
        raise AdmissionReviewError("census rows must be a nonempty tuple")
    for row in census.rows:
        _validate_row(row)
    scopes = tuple(row.scope for row in census.rows)
    if scopes != tuple(sorted(scopes)) or len(set(scopes)) != len(scopes):
        raise AdmissionReviewError("census scopes must be unique and canonically ordered")
    if not isinstance(census.case_labels_exposed, bool):
        raise AdmissionReviewError("case_labels_exposed must be boolean")
    for value, field in (
        (census.census_payload_digest, "census payload digest"),
        (census.census_digest, "census digest"),
    ):
        _digest(value, field)


def _validate_thresholds(thresholds: tuple[AdmissionThreshold, ...]) -> None:
    if not thresholds:
        raise AdmissionReviewError("thresholds must be a nonempty tuple")
    for threshold in thresholds:
        if not isinstance(threshold.metric_id, MetricId) or not isinstance(threshold.statistic, Statistic):
            raise AdmissionReviewError("threshold metric and statistic must use closed enums")
        if not isinstance(threshold.comparator, Comparator):
            raise AdmissionReviewError("threshold comparator must use the closed enum")
        if isinstance(threshold.target, bool) or not isinstance(threshold.target, float) or not math.isfinite(threshold.target):
            raise AdmissionReviewError("threshold target must be a finite float")
    values = tuple((item.metric_id.value, item.statistic.value) for item in thresholds)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise AdmissionReviewError("thresholds must be unique and canonically ordered")


def _validate_manifest_shape(manifest: AdmissionManifestV2) -> None:
    _validate_census_shape(manifest.census)
    derive_baseline_identity_digest(manifest.identity)
    if not isinstance(manifest.label_isolated, bool) or not isinstance(manifest.labels_opened, bool):
        raise AdmissionReviewError("manifest label flags must be boolean")
    if not manifest.readiness_digests:
        raise AdmissionReviewError("readiness digests must be a nonempty tuple")
    for item in manifest.readiness_digests:
        _digest(item, "readiness digest")
    if manifest.readiness_digests != tuple(sorted(manifest.readiness_digests)):
        raise AdmissionReviewError("readiness digests must use canonical order")
    if len(set(manifest.readiness_digests)) != len(manifest.readiness_digests):
        raise AdmissionReviewError("readiness digests contain duplicates")
    for value, field in (
        (manifest.manifest_payload_digest, "manifest payload digest"),
        (manifest.custody_log_digest, "custody log digest"),
        (manifest.denominator_policy_digest, "denominator policy digest"),
        (manifest.threshold_set_digest, "threshold set digest"),
        (manifest.threshold_lineage_manifest_digest, "threshold lineage manifest digest"),
        (manifest.validation_context_digest, "validation context digest"),
        (manifest.manifest_digest, "manifest digest"),
    ):
        _digest(value, field)
    _validate_thresholds(manifest.thresholds)


def _validate_policy(policy: ReviewIndependencePolicy) -> None:
    try:
        policy.__post_init__()
    except FactPackValidationError as exc:
        raise AdmissionReviewError(f"review policy is invalid: {exc}") from exc
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise AdmissionReviewError("review policy digest cannot be re-derived")


def _validate_review(
    review: IndependenceAttestation,
    subject: str,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    try:
        review.__post_init__()
        review.conflict_disclosure.__post_init__()
    except (FactPackValidationError, ValueError) as exc:
        raise AdmissionReviewError(f"review attestation is invalid: {exc}") from exc
    if review.subject_digest != subject:
        raise AdmissionReviewError("review subject does not match payload digest")
    if review.producer_identity == review.reviewer_identity:
        raise AdmissionReviewError("review producer and reviewer must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise AdmissionReviewError("reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise AdmissionReviewError("review producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise AdmissionReviewError("review attestation digest cannot be re-derived")
    content = canonical.resolve_content(
        review.conflict_disclosure,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_evidence_bytes,
    )
    if not content:
        raise AdmissionReviewError("review conflict disclosure must be nonempty")


def _validate_census(
    census: PopulationCensus,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    _validate_census_shape(census)
    if census.case_labels_exposed:
        raise AdmissionReviewError("census must not expose case labels")
    expected_census_payload = derive_census_payload_digest(census)
    if census.census_payload_digest != expected_census_payload:
        raise AdmissionReviewError("census payload digest cannot be re-derived")
    _validate_review(census.review, expected_census_payload, policy, resolver)
    if census.census_digest != derive_census_digest(census):
        raise AdmissionReviewError("census digest cannot be re-derived")


def _validate_manifest(
    manifest: AdmissionManifestV2,
    census: PopulationCensus,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    _validate_manifest_shape(manifest)
    if not manifest.label_isolated or manifest.labels_opened:
        raise AdmissionReviewError("manifest must remain label isolated and unopened")
    if manifest.census != census:
        raise AdmissionReviewError("manifest census does not match reviewed census")
    if manifest.identity.population_digest != census.population_digest:
        raise AdmissionReviewError("manifest population does not match reviewed census")
    if manifest.denominator_policy_digest != manifest.identity.denominator_policy_digest:
        raise AdmissionReviewError("manifest denominator does not match baseline identity")
    expected_thresholds = derive_threshold_set_digest(manifest.thresholds)
    if manifest.threshold_set_digest != expected_thresholds:
        raise AdmissionReviewError("threshold set digest cannot be re-derived")
    if manifest.identity.threshold_set_digest != expected_thresholds:
        raise AdmissionReviewError("manifest thresholds do not match baseline identity")
    expected_manifest_payload = derive_manifest_payload_digest(manifest)
    if manifest.manifest_payload_digest != expected_manifest_payload:
        raise AdmissionReviewError("manifest payload digest cannot be re-derived")
    _validate_review(manifest.review, expected_manifest_payload, policy, resolver)
    if manifest.manifest_digest != derive_manifest_digest(manifest):
        raise AdmissionReviewError("manifest digest cannot be re-derived")


def validate_reviewed_admission_payloads(
    census: PopulationCensus,
    manifest: AdmissionManifestV2,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    _closed_graph(census, "census")
    _closed_graph(manifest, "manifest")
    _closed_graph(policy, "review policy")
    _validate_policy(policy)
    _validate_census(census, policy, resolver)
    _validate_manifest(manifest, census, policy, resolver)


__all__ = [
    "AdmissionManifestV2",
    "AdmissionReviewError",
    "AdmissionThreshold",
    "PopulationCensus",
    "ScopeCensus",
    "derive_census_digest",
    "derive_census_payload_digest",
    "derive_manifest_digest",
    "derive_manifest_payload_digest",
    "derive_threshold_set_digest",
    "validate_reviewed_admission_payloads",
]
