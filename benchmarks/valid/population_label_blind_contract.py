"""Canonical contracts for the reviewed label-blind population manifest."""

from __future__ import annotations

import re
from dataclasses import dataclass

from benchmarks.valid.population_freeze_contract import PopulationScopeCountV1
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest

LABEL_BLIND_DRAFT_SCHEMA = "openultrasast.valid-detection-benchmark.label-blind-population-draft.v3"
LABEL_BLIND_MANIFEST_SCHEMA = "openultrasast.valid-detection-benchmark.label-blind-population-manifest.v3"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class LabelBlindManifestError(ValueError):
    """A label-blind manifest or its review violates the canonical contract."""


class LabelBlindManifestConflict(LabelBlindManifestError):
    """One accepted manifest identity resolves to different bytes."""


@dataclass(frozen=True)
class LabelBlindPopulationDraftV3:
    population_digest: str
    freeze_digest: str
    reservation_census_digest: str
    review_set_digest: str
    ordinary_selection_digest: str
    public_material_manifest_digest: str
    material_artifact_set_digest: str
    scope_census: tuple[PopulationScopeCountV1, ...]
    input_digests: tuple[str, ...]
    positive_count: int
    input_count: int
    input_set_digest: str
    draft_digest: str


@dataclass(frozen=True)
class LabelBlindPopulationManifestV3:
    population_digest: str
    freeze_digest: str
    reservation_census_digest: str
    review_set_digest: str
    ordinary_selection_digest: str
    public_material_manifest_digest: str
    material_artifact_set_digest: str
    scope_census: tuple[PopulationScopeCountV1, ...]
    input_digests: tuple[str, ...]
    positive_count: int
    input_count: int
    input_set_digest: str
    draft_digest: str
    review_digest: str
    manifest_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LabelBlindManifestError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum:
        qualifier = "positive" if positive else "nonnegative"
        raise LabelBlindManifestError(f"{field} must be a {qualifier} integer")
    return value


def _scope_value(row: PopulationScopeCountV1) -> dict[str, JsonValue]:
    if type(row) is not PopulationScopeCountV1:
        raise LabelBlindManifestError("scope census must contain exact PopulationScopeCountV1 rows")
    return {
        "vulnerability_family": row.vulnerability_family,
        "ecosystem": row.ecosystem.value,
        "count": _count(row.count, "scope count", positive=True),
    }


def _validate_draft_shape(draft: LabelBlindPopulationDraftV3) -> None:
    if type(draft) is not LabelBlindPopulationDraftV3:
        raise LabelBlindManifestError("label-blind draft must use the exact V3 contract")
    if draft.scope_census != tuple(sorted(set(draft.scope_census))) or not draft.scope_census:
        raise LabelBlindManifestError("scope census must be nonempty and canonical")
    if draft.input_digests != tuple(sorted(set(draft.input_digests))) or not draft.input_digests:
        raise LabelBlindManifestError("input identities must be nonempty and canonical")
    for item in draft.input_digests:
        _digest(item, "input identity")
    positive_count = _count(draft.positive_count, "positive count", positive=True)
    input_count = _count(draft.input_count, "input count", positive=True)
    if input_count != len(draft.input_digests) or positive_count > input_count:
        raise LabelBlindManifestError("manifest counts do not match exact input identities")
    if any(row.count > positive_count for row in draft.scope_census):
        raise LabelBlindManifestError("scope census count exceeds the positive population")
    if draft.input_set_digest != derive_evaluation_input_set_digest(draft.input_digests):
        raise LabelBlindManifestError("input-set digest does not match canonical input identities")


def _draft_value(draft: LabelBlindPopulationDraftV3, *, include_digest: bool) -> dict[str, JsonValue]:
    _validate_draft_shape(draft)
    value: dict[str, JsonValue] = {
        "schema_version": LABEL_BLIND_DRAFT_SCHEMA,
        "population_digest": _digest(draft.population_digest, "population"),
        "freeze_digest": _digest(draft.freeze_digest, "freeze"),
        "reservation_census_digest": _digest(draft.reservation_census_digest, "reservation census"),
        "review_set_digest": _digest(draft.review_set_digest, "review set"),
        "ordinary_selection_digest": _digest(draft.ordinary_selection_digest, "ordinary selection"),
        "public_material_manifest_digest": _digest(draft.public_material_manifest_digest, "public material manifest"),
        "material_artifact_set_digest": _digest(draft.material_artifact_set_digest, "material artifact set"),
        "scope_census": tuple(_scope_value(row) for row in draft.scope_census),
        "input_digests": draft.input_digests,
        "positive_count": draft.positive_count,
        "input_count": draft.input_count,
        "input_set_digest": _digest(draft.input_set_digest, "input set"),
    }
    if include_digest:
        value["draft_digest"] = _digest(draft.draft_digest, "label-blind draft")
    return value


def label_blind_population_draft_bytes(draft: LabelBlindPopulationDraftV3) -> bytes:
    value = _draft_value(draft, include_digest=False)
    if content_digest(value) != draft.draft_digest:
        raise LabelBlindManifestError("label-blind draft digest does not match")
    return canonical_bytes(_draft_value(draft, include_digest=True))


def _manifest_draft(manifest: LabelBlindPopulationManifestV3) -> LabelBlindPopulationDraftV3:
    return LabelBlindPopulationDraftV3(
        manifest.population_digest,
        manifest.freeze_digest,
        manifest.reservation_census_digest,
        manifest.review_set_digest,
        manifest.ordinary_selection_digest,
        manifest.public_material_manifest_digest,
        manifest.material_artifact_set_digest,
        manifest.scope_census,
        manifest.input_digests,
        manifest.positive_count,
        manifest.input_count,
        manifest.input_set_digest,
        manifest.draft_digest,
    )


def _manifest_value(manifest: LabelBlindPopulationManifestV3, *, include_digest: bool) -> dict[str, JsonValue]:
    if type(manifest) is not LabelBlindPopulationManifestV3:
        raise LabelBlindManifestError("label-blind manifest must use the exact V3 contract")
    draft = _manifest_draft(manifest)
    label_blind_population_draft_bytes(draft)
    value = _draft_value(draft, include_digest=True)
    value["schema_version"] = LABEL_BLIND_MANIFEST_SCHEMA
    value["review_digest"] = _digest(manifest.review_digest, "label-blind manifest review")
    if include_digest:
        value["manifest_digest"] = _digest(manifest.manifest_digest, "label-blind manifest")
    return value


def label_blind_population_manifest_bytes(manifest: LabelBlindPopulationManifestV3) -> bytes:
    value = _manifest_value(manifest, include_digest=False)
    if content_digest(value) != manifest.manifest_digest:
        raise LabelBlindManifestError("label-blind manifest digest does not match")
    return canonical_bytes(_manifest_value(manifest, include_digest=True))


__all__ = [
    "LabelBlindManifestConflict",
    "LabelBlindManifestError",
    "LabelBlindPopulationDraftV3",
    "LabelBlindPopulationManifestV3",
    "label_blind_population_draft_bytes",
    "label_blind_population_manifest_bytes",
]
