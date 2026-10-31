"""Exact structural fact-match evidence and matcher-lineage validation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from openultrasast.core import canonical
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyError,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationUseReceipt,
    validate_population_custody_log,
)
from openultrasast.core.factpack import (
    FactPack,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirementKind,
    derive_fact_pack_content_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.lineage import LineageExpectation, LineageManifest, LineageValidationError, validate_lineage
from openultrasast.core.semantics import RelationStatus, SourceLocation

STRUCTURAL_OBSERVATION_SCHEMA = "openultrasast.detection-core.structural-observation.v2"
FACT_MATCH_SCHEMA = "openultrasast.detection-core.fact-match.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class FactMatchValidationError(ValueError):
    """A fact match identity, artifact, or lineage join cannot be reproduced."""


def _require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise FactMatchValidationError(f"{field} must be nonempty text")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FactMatchValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _freeze_json(value: canonical.JsonValue) -> canonical.JsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _location_value(location: SourceLocation) -> Mapping[str, canonical.JsonValue]:
    return {"path": location.path, "line": location.line, "column": location.column, "symbol": location.symbol}


def _reference_value(reference: canonical.ContentRef) -> Mapping[str, canonical.JsonValue]:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


@dataclass(frozen=True)
class StructuralObservation:
    requirement_id: str
    location: SourceLocation
    observed: canonical.JsonValue
    evidence: canonical.ContentRef

    def __post_init__(self) -> None:
        _require_text(self.requirement_id, "requirement_id")
        if not isinstance(self.location, SourceLocation):
            raise FactMatchValidationError("observation location must be a SourceLocation")
        self.location.__post_init__()
        frozen = _freeze_json(self.observed)
        canonical.canonical_bytes(frozen)
        object.__setattr__(self, "observed", frozen)
        if not isinstance(self.evidence, canonical.ContentRef):
            raise FactMatchValidationError("observation evidence must be a ContentRef")


def _observation_payload(observation: StructuralObservation) -> Mapping[str, canonical.JsonValue]:
    return {
        "schema_version": STRUCTURAL_OBSERVATION_SCHEMA,
        "requirement_id": observation.requirement_id,
        "location": _location_value(observation.location),
        "observed": observation.observed,
    }


def structural_observation_bytes(observation: StructuralObservation) -> bytes:
    """Canonical bytes that an observation ContentRef must resolve."""
    if not isinstance(observation, StructuralObservation):
        raise TypeError("observation must be a StructuralObservation")
    return canonical.canonical_record_bytes(
        _observation_payload(observation),
        known_schema_versions=(STRUCTURAL_OBSERVATION_SCHEMA,),
    )


def _match_observation_value(observation: StructuralObservation) -> Mapping[str, canonical.JsonValue]:
    return {
        "requirement_id": observation.requirement_id,
        "location": _location_value(observation.location),
        "observed": observation.observed,
        "evidence": _reference_value(observation.evidence),
    }


@dataclass(frozen=True)
class FactMatchEvidence:
    pack_digest: str
    fact_id: str
    product_location: SourceLocation
    observations: tuple[StructuralObservation, ...]
    matcher_revision: str
    matcher_behavior_digest: str
    matcher_lineage_manifest_digest: str
    match_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.pack_digest, "pack_digest")
        _require_text(self.fact_id, "fact_id")
        if not isinstance(self.product_location, SourceLocation):
            raise FactMatchValidationError("product_location must be a SourceLocation")
        self.product_location.__post_init__()
        if not isinstance(self.observations, tuple) or not all(isinstance(item, StructuralObservation) for item in self.observations):
            raise FactMatchValidationError("observations must be a tuple of StructuralObservation values")
        _require_text(self.matcher_revision, "matcher_revision")
        _require_digest(self.matcher_behavior_digest, "matcher_behavior_digest")
        _require_digest(self.matcher_lineage_manifest_digest, "matcher_lineage_manifest_digest")
        _require_digest(self.match_digest, "match_digest")


def _match_value(match: FactMatchEvidence) -> Mapping[str, canonical.JsonValue]:
    return {
        "schema_version": FACT_MATCH_SCHEMA,
        "pack_digest": match.pack_digest,
        "fact_id": match.fact_id,
        "product_location": _location_value(match.product_location),
        "observations": tuple(_match_observation_value(item) for item in match.observations),
        "matcher_revision": match.matcher_revision,
        "matcher_behavior_digest": match.matcher_behavior_digest,
        "matcher_lineage_manifest_digest": match.matcher_lineage_manifest_digest,
    }


def derive_fact_match_digest(match: FactMatchEvidence) -> str:
    if not isinstance(match, FactMatchEvidence):
        raise TypeError("match must be FactMatchEvidence")
    return canonical.content_digest(_match_value(match))


@dataclass(frozen=True)
class FactMatchDecision:
    status: RelationStatus
    reasons: tuple[str, ...]
    effect_eligible: bool
    lineage_decision_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, RelationStatus):
            raise FactMatchValidationError("status must be a RelationStatus")
        if not isinstance(self.reasons, tuple) or not all(isinstance(item, str) and item for item in self.reasons):
            raise FactMatchValidationError("reasons must be a tuple of nonempty text")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise FactMatchValidationError("reasons must be sorted and unique")
        if not isinstance(self.effect_eligible, bool):
            raise FactMatchValidationError("effect_eligible must be boolean")
        if self.effect_eligible is not (self.status is RelationStatus.COMPLETE):
            raise FactMatchValidationError("only COMPLETE decisions may be effect eligible")
        _require_digest(self.lineage_decision_digest, "lineage_decision_digest")


def _fact_for(pack: FactPack, fact_id: str) -> SemanticFact:
    matches = tuple(fact for fact in pack.facts if fact.fact_id == fact_id)
    if len(matches) != 1:
        raise FactMatchValidationError("fact identity is missing or ambiguous in pack")
    return matches[0]


def _validate_named_inputs(
    pack: FactPack,
    fact_id: str,
    match: FactMatchEvidence,
    review_policy: ReviewIndependencePolicy,
) -> SemanticFact:
    if pack.normalized_content_digest != derive_fact_pack_content_digest(pack):
        raise FactMatchValidationError("pack digest cannot be re-derived")
    if match.pack_digest != pack.normalized_content_digest:
        raise FactMatchValidationError("match pack digest does not name supplied pack")
    if match.fact_id != fact_id:
        raise FactMatchValidationError("match fact identity does not name requested fact")
    fact = _fact_for(pack, fact_id)
    if match.match_digest != derive_fact_match_digest(match):
        raise FactMatchValidationError("match digest cannot be re-derived")
    expected_policy = derive_review_independence_policy_digest(
        review_policy.reviewed_reviewer_digests,
        review_policy.forbidden_identity_pairs,
        review_policy.trusted_store_identities,
        review_policy.maximum_evidence_bytes,
    )
    if review_policy.policy_digest != expected_policy or pack.review_policy_digest != expected_policy:
        raise FactMatchValidationError("review policy identity cannot be re-derived from named inputs")
    return fact


def _resolve_observations(
    match: FactMatchEvidence,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    for observation in match.observations:
        observation.__post_init__()
        observation.evidence.__post_init__()
        try:
            resolved = canonical.resolve_content(
                observation.evidence,
                resolver,
                trusted_store_identities=review_policy.trusted_store_identities,
                maximum_bytes=review_policy.maximum_evidence_bytes,
            )
        except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError) as exc:
            raise FactMatchValidationError(f"observation artifact cannot be validated: {exc}") from exc
        if resolved != structural_observation_bytes(observation):
            raise FactMatchValidationError("resolved bytes do not equal canonical observation payload")


def _conflicting(items: tuple[StructuralObservation, ...]) -> bool:
    values = {
        canonical.content_digest(
            {
                "location": _location_value(item.location),
                "observed": item.observed,
                "evidence": _reference_value(item.evidence),
            }
        )
        for item in items
    }
    return len(values) > 1


def _unresolved_reasons(fact: SemanticFact, match: FactMatchEvidence) -> list[str]:
    expected_ids = {item.requirement_id for item in fact.structural_requirements}
    grouped: dict[str, list[StructuralObservation]] = {}
    reasons: list[str] = []
    for observation in match.observations:
        grouped.setdefault(observation.requirement_id, []).append(observation)
        if observation.requirement_id not in expected_ids:
            reasons.append(f"fabricated_observation:{observation.requirement_id}")
        if observation.location != match.product_location:
            reasons.append(f"ambiguous_product_location:{observation.requirement_id}")
    for requirement_id, items in grouped.items():
        if len(items) > 1:
            reasons.extend(("ambiguous_match", f"duplicate_observation:{requirement_id}"))
            if _conflicting(tuple(items)):
                reasons.append(f"conflicting_observation:{requirement_id}")
    return reasons


def _incomplete_reasons(fact: SemanticFact, match: FactMatchEvidence) -> list[str]:
    indexed = {item.requirement_id: item for item in match.observations}
    reasons: list[str] = []
    present_kinds: set[StructuralRequirementKind] = set()
    for requirement in fact.structural_requirements:
        observation = indexed.get(requirement.requirement_id)
        if observation is None:
            reasons.append(f"missing_observation:{requirement.requirement_id}")
            continue
        present_kinds.add(requirement.kind)
        if canonical.canonical_bytes(observation.observed) != canonical.canonical_bytes(requirement.expected):
            reasons.append(f"predicate_mismatch:{requirement.requirement_id}")
    if present_kinds == {StructuralRequirementKind.QUALIFIED_NAME}:
        reasons.append("name_only_match")
    return reasons


def _lineage_for(match: FactMatchEvidence, lineages: Sequence[LineageManifest]) -> LineageManifest:
    if not isinstance(lineages, Sequence) or not all(isinstance(item, LineageManifest) for item in lineages):
        raise FactMatchValidationError("lineages must be a sequence of LineageManifest values")
    matches = tuple(item for item in lineages if item.manifest_digest == match.matcher_lineage_manifest_digest)
    if len(matches) != 1:
        raise FactMatchValidationError("matcher lineage manifest is missing or ambiguous")
    return matches[0]


def _authoritative_matching_receipts(
    lineage: LineageManifest,
    match: FactMatchEvidence,
    protected_population_digest: str,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> tuple[PopulationUseReceipt, ...]:
    populations = {protected_population_digest, *(use.source_population_digest for use in lineage.uses)}
    relevant: list[PopulationUseReceipt] = []
    for population_digest in sorted(populations):
        log = custody.current_log(population_digest)
        validate_population_custody_log(log, custody_policy, current=custody)
        for receipt in log.receipts:
            request = receipt.request
            if (
                request.arm_id == lineage.arm_id
                and request.purpose is LineagePurpose.MATCHING_BEHAVIOR
                and request.influenced_artifact_digest == match.matcher_behavior_digest
            ):
                relevant.append(receipt)
    return tuple(relevant)


def _omitted_matching_reasons(
    lineage: LineageManifest,
    current_receipts: tuple[PopulationUseReceipt, ...],
    protected_population_digest: str,
) -> tuple[str, ...]:
    declared = {use.population_use_receipt_digest for use in lineage.uses}
    reasons: list[str] = []
    for receipt in current_receipts:
        if receipt.receipt_digest in declared:
            continue
        reasons.append(f"omitted_current_matching_use:{receipt.receipt_digest}")
        if receipt.request.labels_accessed:
            reasons.append(f"label_access_forbidden:{receipt.population_digest}")
            if receipt.population_digest == protected_population_digest:
                reasons.append(f"protected_population_labels:{receipt.population_digest}")
    return tuple(sorted(set(reasons)))


def _validate_matcher_lineage(
    match: FactMatchEvidence,
    protected_population_digest: str,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> tuple[tuple[str, ...], str]:
    lineage = _lineage_for(match, lineages)
    expectation = LineageExpectation(LineagePurpose.MATCHING_BEHAVIOR, match.matcher_behavior_digest, 1, 1)
    try:
        decision = validate_lineage(
            lineage,
            match.matcher_behavior_digest,
            (expectation,),
            protected_population_digest,
            True,
            custody,
            custody_policy,
        )
        current_receipts = _authoritative_matching_receipts(
            lineage,
            match,
            protected_population_digest,
            custody,
            custody_policy,
        )
    except (LineageValidationError, PopulationCustodyError, canonical.DigestFormatError) as exc:
        raise FactMatchValidationError(f"matcher lineage contract is invalid: {exc}") from exc
    omitted = _omitted_matching_reasons(lineage, current_receipts, protected_population_digest)
    return tuple(sorted(set((*decision.reasons, *omitted)))), decision.decision_digest


def _decision(
    unresolved: Sequence[str],
    incomplete: Sequence[str],
    lineage_digest: str,
) -> FactMatchDecision:
    if unresolved:
        status = RelationStatus.UNRESOLVED
        reasons = tuple(sorted(set(unresolved)))
    elif incomplete:
        status = RelationStatus.INCOMPLETE
        reasons = tuple(sorted(set(incomplete)))
    else:
        status = RelationStatus.COMPLETE
        reasons = ()
    return FactMatchDecision(status, reasons, status is RelationStatus.COMPLETE, lineage_digest)


def validate_fact_match(
    pack: FactPack,
    fact_id: str,
    match: FactMatchEvidence,
    protected_population_digest: str,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> FactMatchDecision:
    """Resolve one complete fact match and make downstream effect eligibility explicit."""
    if not isinstance(pack, FactPack) or not isinstance(match, FactMatchEvidence):
        raise FactMatchValidationError("pack and match must use v2 contract types")
    if not isinstance(review_policy, ReviewIndependencePolicy):
        raise FactMatchValidationError("review_policy must use the v2 contract type")
    match.__post_init__()
    review_policy.__post_init__()
    fact = _validate_named_inputs(pack, fact_id, match, review_policy)
    _resolve_observations(match, review_policy, resolver)
    unresolved = _unresolved_reasons(fact, match)
    incomplete = _incomplete_reasons(fact, match)
    lineage_reasons, lineage_digest = _validate_matcher_lineage(
        match,
        protected_population_digest,
        lineages,
        custody,
        custody_policy,
    )
    return _decision((*unresolved, *lineage_reasons), incomplete, lineage_digest)


__all__ = [
    "FACT_MATCH_SCHEMA",
    "STRUCTURAL_OBSERVATION_SCHEMA",
    "FactMatchDecision",
    "FactMatchEvidence",
    "FactMatchValidationError",
    "StructuralObservation",
    "derive_fact_match_digest",
    "structural_observation_bytes",
    "validate_fact_match",
]
