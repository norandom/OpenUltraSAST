"""Canonical contracts for replacement population classification and freeze."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

POPULATION_FREEZE_SCHEMA = "openultrasast.valid-detection-benchmark.population-freeze.v3"
POPULATION_IDENTITY_SCHEMA = "openultrasast.valid-detection-benchmark.population-identity.v3"
MINIMUM_ADMISSION_POSITIVES = 40
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")


class PopulationFreezeError(ValueError):
    """Population inputs or freeze identity are invalid."""


class PopulationFreezeConflict(PopulationFreezeError):
    """One freeze identity was presented with different canonical bytes."""


class PopulationClass(StrEnum):
    DEVELOPMENT_PILOT = "development_pilot"
    INSUFFICIENT = "insufficient"
    ADMISSION = "admission"


class PopulationClassificationReason(StrEnum):
    BELOW_MINIMUM_POSITIVES = "below_minimum_positives"
    MISSING_ECOSYSTEM = "missing_ecosystem"
    MISSING_SECOND_FAMILY = "missing_second_family"
    SCOPE_MINIMUM_UNMET = "scope_minimum_unmet"


@dataclass(frozen=True, order=True)
class ScopeMinimumV1:
    vulnerability_family: str
    ecosystem: CanonicalEcosystem
    minimum_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "vulnerability_family", _family(self.vulnerability_family))
        object.__setattr__(self, "ecosystem", _ecosystem(self.ecosystem))
        if isinstance(self.minimum_count, bool) or not isinstance(self.minimum_count, int) or self.minimum_count <= 0:
            raise PopulationFreezeError("scope minimum must be a positive integer")


@dataclass(frozen=True, order=True)
class PopulationScopeCountV1:
    vulnerability_family: str
    ecosystem: CanonicalEcosystem
    count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "vulnerability_family", _family(self.vulnerability_family))
        object.__setattr__(self, "ecosystem", _ecosystem(self.ecosystem))
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count <= 0:
            raise PopulationFreezeError("population scope count must be positive")


@dataclass(frozen=True)
class PopulationFreezeV3:
    population_class: PopulationClass
    classification_reasons: tuple[PopulationClassificationReason, ...]
    positive_count: int
    ecosystems: tuple[CanonicalEcosystem, ...]
    families: tuple[str, ...]
    scope_census: tuple[PopulationScopeCountV1, ...]
    scope_minimums: tuple[ScopeMinimumV1, ...]
    positive_change_digests: tuple[str, ...]
    positive_selection_digest: str
    ecosystem_review_digests: tuple[str, ...]
    ground_truth_review_digests: tuple[str, ...]
    review_set_digest: str
    ordinary_selection_digest: str
    reservation_census_digest: str
    exclusion_counts: tuple[tuple[str, int], ...]
    source_provenance_digest: str
    ecosystem_policy_digest: str
    ground_truth_policy_digest: str
    freeze_policy_digest: str
    population_digest: str
    freeze_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PopulationFreezeError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _family(value: object) -> str:
    if not isinstance(value, str) or _FAMILY.fullmatch(value) is None:
        raise PopulationFreezeError("vulnerability family must be a canonical evidence label")
    return value


def _ecosystem(value: object) -> CanonicalEcosystem:
    if isinstance(value, CanonicalEcosystem):
        return value
    if not isinstance(value, str):
        raise PopulationFreezeError("canonical ecosystem is unsupported")
    try:
        return CanonicalEcosystem(value)
    except (TypeError, ValueError) as error:
        raise PopulationFreezeError("canonical ecosystem is unsupported") from error


def _scope_value(scope: PopulationScopeCountV1 | ScopeMinimumV1) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "vulnerability_family": _family(scope.vulnerability_family),
        "ecosystem": _ecosystem(scope.ecosystem).value,
    }
    if isinstance(scope, PopulationScopeCountV1):
        value["count"] = scope.count
    else:
        value["minimum_count"] = scope.minimum_count
    return value


def _exclusions(values: tuple[tuple[str, int], ...]) -> None:
    if values != tuple(sorted(set(values))):
        raise PopulationFreezeError("population exclusion counts are not canonical")
    for reason, count in values:
        if not isinstance(reason, str) or not _FAMILY.fullmatch(reason):
            raise PopulationFreezeError("population exclusion reason is not canonical")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise PopulationFreezeError("population exclusion count is invalid")


def _canonical_digests(values: tuple[str, ...], field: str) -> None:
    if values != tuple(sorted(set(values))):
        raise PopulationFreezeError(f"{field} identities are not canonical")
    for value in values:
        _digest(value, field)


def _population_value(freeze: PopulationFreezeV3) -> dict[str, JsonValue]:
    return {
        "schema_version": POPULATION_IDENTITY_SCHEMA,
        "positive_change_digests": freeze.positive_change_digests,
        "positive_selection_digest": freeze.positive_selection_digest,
        "ecosystem_review_digests": freeze.ecosystem_review_digests,
        "ground_truth_review_digests": freeze.ground_truth_review_digests,
        "review_set_digest": freeze.review_set_digest,
        "ordinary_selection_digest": freeze.ordinary_selection_digest,
        "reservation_census_digest": freeze.reservation_census_digest,
        "exclusion_counts": freeze.exclusion_counts,
        "source_provenance_digest": freeze.source_provenance_digest,
        "ecosystem_policy_digest": freeze.ecosystem_policy_digest,
        "ground_truth_policy_digest": freeze.ground_truth_policy_digest,
        "freeze_policy_digest": freeze.freeze_policy_digest,
    }


def _freeze_value(freeze: PopulationFreezeV3, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": POPULATION_FREEZE_SCHEMA,
        "population_class": PopulationClass(freeze.population_class).value,
        "classification_reasons": tuple(PopulationClassificationReason(item).value for item in freeze.classification_reasons),
        "positive_count": freeze.positive_count,
        "ecosystems": tuple(_ecosystem(item).value for item in freeze.ecosystems),
        "families": freeze.families,
        "scope_census": tuple(_scope_value(item) for item in freeze.scope_census),
        "scope_minimums": tuple(_scope_value(item) for item in freeze.scope_minimums),
        **_population_value(freeze),
        "population_digest": freeze.population_digest,
    }
    if include_digest:
        value["freeze_digest"] = freeze.freeze_digest
    return value


def _validate_collections(freeze: PopulationFreezeV3) -> None:
    if isinstance(freeze.positive_count, bool) or freeze.positive_count != len(freeze.positive_change_digests):
        raise PopulationFreezeError("population positive count does not match identities")
    _canonical_digests(freeze.positive_change_digests, "positive change")
    _canonical_digests(freeze.ecosystem_review_digests, "ecosystem review")
    _canonical_digests(freeze.ground_truth_review_digests, "ground-truth review")
    if freeze.ecosystems != tuple(sorted(set(freeze.ecosystems), key=lambda item: item.value)):
        raise PopulationFreezeError("population ecosystems are not canonical")
    if freeze.families != tuple(sorted(set(freeze.families))) or any(_family(item) != item for item in freeze.families):
        raise PopulationFreezeError("population families are not canonical")
    if freeze.scope_census != tuple(sorted(set(freeze.scope_census))):
        raise PopulationFreezeError("population scope census is not canonical")
    if freeze.scope_minimums != tuple(sorted(set(freeze.scope_minimums))):
        raise PopulationFreezeError("population scope minimums are not canonical")
    minimum_keys = {(item.vulnerability_family, item.ecosystem) for item in freeze.scope_minimums}
    if len(minimum_keys) != len(freeze.scope_minimums):
        raise PopulationFreezeError("population scope has conflicting minimums")
    _exclusions(freeze.exclusion_counts)
    if len({reason for reason, _ in freeze.exclusion_counts}) != len(freeze.exclusion_counts):
        raise PopulationFreezeError("population exclusion reason has conflicting counts")
    reasons = tuple(sorted(set(freeze.classification_reasons), key=lambda item: item.value))
    if freeze.classification_reasons != reasons:
        raise PopulationFreezeError("population classification reasons are not canonical")


def _validate_scope_shape(freeze: PopulationFreezeV3) -> None:
    scoped_ecosystems = tuple(sorted({item.ecosystem for item in freeze.scope_census}, key=lambda item: item.value))
    scoped_families = tuple(sorted({item.vulnerability_family for item in freeze.scope_census}))
    if (freeze.ecosystems, freeze.families) != (scoped_ecosystems, scoped_families):
        raise PopulationFreezeError("population ecosystem or family census does not match exact scopes")
    if any(item.count > freeze.positive_count for item in freeze.scope_census):
        raise PopulationFreezeError("population scope count exceeds whole positive count")
    if len(freeze.ecosystem_review_digests) != freeze.positive_count or len(freeze.ground_truth_review_digests) != freeze.positive_count:
        raise PopulationFreezeError("population review sets do not cover every positive")


def _validate_identity_bindings(freeze: PopulationFreezeV3) -> None:
    expected_positive = content_digest(
        {
            "accepted_changes": freeze.positive_change_digests,
            "scope_census": tuple((item.vulnerability_family, item.ecosystem.value, item.count) for item in freeze.scope_census),
        }
    )
    expected_reviews = content_digest(
        {
            "ecosystem_reviews": freeze.ecosystem_review_digests,
            "ground_truth_reviews": freeze.ground_truth_review_digests,
        }
    )
    if freeze.positive_selection_digest != expected_positive or freeze.review_set_digest != expected_reviews:
        raise PopulationFreezeError("population selection or review-set identity does not match")


def _expected_classification(
    freeze: PopulationFreezeV3,
) -> tuple[PopulationClass, tuple[PopulationClassificationReason, ...]]:
    reasons: set[PopulationClassificationReason] = set()
    if freeze.positive_count < MINIMUM_ADMISSION_POSITIVES:
        reasons.add(PopulationClassificationReason.BELOW_MINIMUM_POSITIVES)
    if set(freeze.ecosystems) != {CanonicalEcosystem.PYTHON, CanonicalEcosystem.JAVASCRIPT}:
        reasons.add(PopulationClassificationReason.MISSING_ECOSYSTEM)
    if len(freeze.families) < 2:
        reasons.add(PopulationClassificationReason.MISSING_SECOND_FAMILY)
    counts = {(item.vulnerability_family, item.ecosystem): item.count for item in freeze.scope_census}
    if any(counts.get((item.vulnerability_family, item.ecosystem), 0) < item.minimum_count for item in freeze.scope_minimums):
        reasons.add(PopulationClassificationReason.SCOPE_MINIMUM_UNMET)
    ordered = tuple(sorted(reasons, key=lambda item: item.value))
    expected_class = PopulationClass.ADMISSION
    if ordered == (PopulationClassificationReason.BELOW_MINIMUM_POSITIVES,):
        expected_class = PopulationClass.DEVELOPMENT_PILOT
    elif ordered:
        expected_class = PopulationClass.INSUFFICIENT
    return expected_class, ordered


def _validate_derived(freeze: PopulationFreezeV3) -> None:
    _validate_scope_shape(freeze)
    _validate_identity_bindings(freeze)
    expected_class, ordered = _expected_classification(freeze)
    if (freeze.population_class, freeze.classification_reasons) != (expected_class, ordered):
        raise PopulationFreezeError("population classification does not match its exact census")


def population_freeze_bytes(freeze: PopulationFreezeV3) -> bytes:
    """Validate and encode a canonical replacement freeze."""
    _validate_collections(freeze)
    _validate_derived(freeze)
    for value, field in (
        (freeze.positive_selection_digest, "positive selection"),
        (freeze.review_set_digest, "review set"),
        (freeze.ordinary_selection_digest, "ordinary selection"),
        (freeze.reservation_census_digest, "reservation census"),
        (freeze.source_provenance_digest, "source provenance"),
        (freeze.ecosystem_policy_digest, "ecosystem policy"),
        (freeze.ground_truth_policy_digest, "ground-truth policy"),
        (freeze.freeze_policy_digest, "freeze policy"),
        (freeze.population_digest, "population"),
        (freeze.freeze_digest, "freeze"),
    ):
        _digest(value, field)
    if freeze.population_digest != content_digest(_population_value(freeze)):
        raise PopulationFreezeError("population digest does not match exact selections and authorities")
    if freeze.freeze_digest != content_digest(_freeze_value(freeze, include_digest=False)):
        raise PopulationFreezeError("freeze digest does not match canonical freeze")
    return canonical_bytes(_freeze_value(freeze, include_digest=True))


def accept_population_freeze(freeze: PopulationFreezeV3, *, existing_content: bytes | None = None) -> bytes:
    content = population_freeze_bytes(freeze)
    if existing_content is not None and existing_content != content:
        raise PopulationFreezeConflict("same freeze identity resolves to different bytes")
    return content


__all__ = [
    "PopulationClass",
    "PopulationClassificationReason",
    "PopulationFreezeConflict",
    "PopulationFreezeError",
    "PopulationFreezeV3",
    "PopulationScopeCountV1",
    "ScopeMinimumV1",
    "accept_population_freeze",
    "population_freeze_bytes",
]
