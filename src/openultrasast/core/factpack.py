"""Pure versioned semantic fact-pack admission contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from openultrasast.core import _factpack_digest as digest_projection
from openultrasast.core import canonical
from openultrasast.core._legacy_factpack import FactPackError, admit_fact_pack, admit_pack_file, load_pack_file, verify_fact_pack
from openultrasast.core.custody import LineagePurpose, PopulationCustodyPolicy, PopulationCustodyPort
from openultrasast.core.family import FamilyContract, family_contract_digest, validate_contract
from openultrasast.core.lineage import LineageExpectation, LineageManifest, validate_lineage
from openultrasast.core.semantics import RelationKind

FACT_PACK_SCHEMA = "openultrasast.detection-core.fact-pack.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class FactPackValidationError(ValueError):
    """A v2 fact pack cannot be reproduced under the supplied trust context."""


class KnowledgeEvidenceKind(Enum):
    SOURCE_CODE = "source_code"
    OFFICIAL_DOCUMENTATION = "official_documentation"
    INDEPENDENT_BEHAVIOR = "independent_behavior"


class StructuralRequirementKind(Enum):
    QUALIFIED_NAME = "qualified_name"
    AST_SHAPE = "ast_shape"
    RECEIVER_TYPE = "receiver_type"
    CALL_TARGET = "call_target"
    ARGUMENT_SHAPE = "argument_shape"
    CONFIGURATION = "configuration"


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise FactPackValidationError(f"{field} must be nonempty text")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FactPackValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _unique(values: tuple[str, ...], field: str) -> None:
    if len(set(values)) != len(values):
        raise FactPackValidationError(f"duplicate {field}")


def _digest_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise FactPackValidationError(f"{field} must be a nonempty tuple")
    for value in values:
        _digest(value, field)
    if len(set(values)) != len(values):
        raise FactPackValidationError(f"duplicate {field}")


def _forbidden_pairs(values: object) -> None:
    if not isinstance(values, tuple):
        raise FactPackValidationError("forbidden identity pairs must be a tuple")
    for pair in values:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise FactPackValidationError("forbidden identity pairs must contain pairs")
        _digest(pair[0], "forbidden producer")
        _digest(pair[1], "forbidden reviewer")
    if len(set(values)) != len(values):
        raise FactPackValidationError("duplicate forbidden identity pair")


def _text_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise FactPackValidationError(f"{field} must be a nonempty tuple")
    for value in values:
        _text(value, field)
    if len(set(values)) != len(values):
        raise FactPackValidationError(f"duplicate {field}")


def _freeze_json(value: canonical.JsonValue) -> canonical.JsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True)
class IndependenceAttestation:
    subject_digest: str
    producer_identity: str
    reviewer_identity: str
    conflict_disclosure: canonical.ContentRef
    attestation_digest: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.subject_digest, "attestation subject"),
            (self.producer_identity, "attestation producer"),
            (self.reviewer_identity, "attestation reviewer"),
            (self.attestation_digest, "attestation digest"),
        ):
            _digest(value, field)
        if not isinstance(self.conflict_disclosure, canonical.ContentRef):
            raise FactPackValidationError("conflict disclosure must be a ContentRef")


@dataclass(frozen=True)
class ReviewIndependencePolicy:
    reviewed_reviewer_digests: tuple[str, ...]
    forbidden_identity_pairs: tuple[tuple[str, str], ...]
    trusted_store_identities: tuple[str, ...]
    maximum_evidence_bytes: int
    policy_digest: str

    def __post_init__(self) -> None:
        _digest_tuple(self.reviewed_reviewer_digests, "reviewed reviewer")
        _forbidden_pairs(self.forbidden_identity_pairs)
        _text_tuple(self.trusted_store_identities, "trusted store identity")
        if isinstance(self.maximum_evidence_bytes, bool) or not isinstance(self.maximum_evidence_bytes, int):
            raise FactPackValidationError("maximum evidence bytes must be a positive integer")
        if self.maximum_evidence_bytes <= 0:
            raise FactPackValidationError("maximum evidence bytes must be a positive integer")
        _digest(self.policy_digest, "review policy digest")


@dataclass(frozen=True)
class KnowledgeEvidence:
    kind: KnowledgeEvidenceKind
    content: canonical.ContentRef
    producer_identity: str
    reviewer_identity: str
    independence: IndependenceAttestation
    lineage_manifest_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, KnowledgeEvidenceKind):
            raise FactPackValidationError("knowledge evidence kind is unknown")
        if not isinstance(self.content, canonical.ContentRef):
            raise FactPackValidationError("knowledge evidence content must be a ContentRef")
        _digest(self.producer_identity, "evidence producer")
        _digest(self.reviewer_identity, "evidence reviewer")
        if not isinstance(self.independence, IndependenceAttestation):
            raise FactPackValidationError("evidence independence must be an attestation")
        _digest(self.lineage_manifest_digest, "evidence lineage manifest")


@dataclass(frozen=True)
class StructuralRequirement:
    requirement_id: str
    kind: StructuralRequirementKind
    field: str
    expected: canonical.JsonValue

    def __post_init__(self) -> None:
        _text(self.requirement_id, "requirement_id")
        if not isinstance(self.kind, StructuralRequirementKind):
            raise FactPackValidationError("structural requirement kind is unknown")
        _text(self.field, "structural requirement field")
        frozen = _freeze_json(self.expected)
        canonical.canonical_bytes(frozen)
        object.__setattr__(self, "expected", frozen)


@dataclass(frozen=True)
class RelationEffect:
    kind: RelationKind
    role: str
    source_role: str
    target_role: str
    conditions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RelationKind):
            raise FactPackValidationError("relation effect kind is unknown")
        for value, field in (
            (self.role, "effect role"),
            (self.source_role, "effect source role"),
            (self.target_role, "effect target role"),
        ):
            _text(value, field)
        if not isinstance(self.conditions, tuple):
            raise FactPackValidationError("effect conditions must be a tuple")
        for condition in self.conditions:
            _text(condition, "effect condition")
        _unique(self.conditions, "effect condition")


@dataclass(frozen=True)
class SemanticFact:
    fact_id: str
    role: str
    structural_requirements: tuple[StructuralRequirement, ...]
    relation_effects: tuple[RelationEffect, ...]

    def __post_init__(self) -> None:
        _text(self.fact_id, "fact_id")
        _text(self.role, "fact role")
        if not isinstance(self.structural_requirements, tuple) or not self.structural_requirements:
            raise FactPackValidationError("a fact requires a tuple of structural requirements")
        if not all(isinstance(item, StructuralRequirement) for item in self.structural_requirements):
            raise FactPackValidationError("structural requirements have the wrong type")
        if not isinstance(self.relation_effects, tuple) or not self.relation_effects:
            raise FactPackValidationError("a fact requires a tuple of relation effects")
        if not all(isinstance(item, RelationEffect) for item in self.relation_effects):
            raise FactPackValidationError("relation effects have the wrong type")
        _unique(tuple(item.requirement_id for item in self.structural_requirements), "requirement_id")


@dataclass(frozen=True)
class FactPack:
    schema_version: str
    family_contract_digest: str
    family_id: str
    ecosystem: str
    language: str
    facts: tuple[SemanticFact, ...]
    normalized_content_digest: str
    review_identity: str
    review_evidence: tuple[KnowledgeEvidence, ...]
    review_evidence_digest: str
    review_policy_digest: str

    def __post_init__(self) -> None:
        _text(self.schema_version, "schema_version")
        _digest(self.family_contract_digest, "family contract digest")
        for value, field in ((self.family_id, "family_id"), (self.ecosystem, "ecosystem"), (self.language, "language")):
            _text(value, field)
        if not isinstance(self.facts, tuple) or not all(isinstance(item, SemanticFact) for item in self.facts):
            raise FactPackValidationError("facts must be a tuple of SemanticFact values")
        for value, field in (
            (self.normalized_content_digest, "normalized content digest"),
            (self.review_identity, "review identity"),
            (self.review_evidence_digest, "review evidence digest"),
            (self.review_policy_digest, "review policy digest"),
        ):
            _digest(value, field)
        if not isinstance(self.review_evidence, tuple) or not all(isinstance(item, KnowledgeEvidence) for item in self.review_evidence):
            raise FactPackValidationError("review evidence must be a tuple of KnowledgeEvidence values")


def derive_independence_attestation_digest(attestation: IndependenceAttestation) -> str:
    return digest_projection.attestation_digest(attestation)


def derive_review_independence_policy_digest(
    reviewed_reviewer_digests: tuple[str, ...],
    forbidden_identity_pairs: tuple[tuple[str, str], ...],
    trusted_store_identities: tuple[str, ...],
    maximum_evidence_bytes: int,
) -> str:
    return digest_projection.review_policy_digest(
        reviewed_reviewer_digests,
        forbidden_identity_pairs,
        trusted_store_identities,
        maximum_evidence_bytes,
    )


def derive_fact_pack_content_digest(pack: FactPack) -> str:
    return digest_projection.pack_content_digest(pack)


def derive_review_evidence_digest(review_evidence: tuple[KnowledgeEvidence, ...]) -> str:
    return digest_projection.evidence_digest(review_evidence)


def _revalidate_shapes(pack: FactPack, policy: ReviewIndependencePolicy) -> None:
    pack.__post_init__()
    policy.__post_init__()
    for fact in pack.facts:
        fact.__post_init__()
        for requirement in fact.structural_requirements:
            requirement.__post_init__()
        for effect in fact.relation_effects:
            effect.__post_init__()
    for evidence in pack.review_evidence:
        evidence.__post_init__()
        evidence.independence.__post_init__()
        evidence.content.__post_init__()
        evidence.independence.conflict_disclosure.__post_init__()


def _validate_scope(pack: FactPack, contract: FamilyContract) -> None:
    validate_contract(contract)
    if pack.schema_version != FACT_PACK_SCHEMA:
        raise FactPackValidationError("unknown fact-pack schema")
    if pack.family_id != contract.family_id:
        raise FactPackValidationError("fact-pack family does not match contract")
    if pack.family_contract_digest != family_contract_digest(contract):
        raise FactPackValidationError("family contract digest does not match contract")
    if pack.ecosystem not in contract.ecosystems:
        raise FactPackValidationError("fact-pack ecosystem is outside contract scope")
    if not pack.facts:
        raise FactPackValidationError("fact pack must contain facts")
    _unique(tuple(fact.fact_id for fact in pack.facts), "fact identity")


def _validate_roles(pack: FactPack, contract: FamilyContract) -> None:
    roles = {role.role: role for role in contract.roles}
    for fact in pack.facts:
        if fact.role not in roles:
            raise FactPackValidationError(f"fact uses undeclared role: {fact.role}")
        for effect in fact.relation_effects:
            if any(role not in roles for role in (effect.role, effect.source_role, effect.target_role)):
                raise FactPackValidationError("relation effect uses an undeclared role")
            if effect.kind not in roles[effect.role].allowed_relation_kinds:
                raise FactPackValidationError("relation kind is not allowed for its effect role")


def _validate_policy(pack: FactPack, policy: ReviewIndependencePolicy) -> None:
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise FactPackValidationError("review policy digest cannot be re-derived")
    if pack.review_policy_digest != policy.policy_digest:
        raise FactPackValidationError("pack review policy digest does not match supplied policy")


def _resolve_evidence(
    evidence: KnowledgeEvidence,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    attestation = evidence.independence
    if attestation.subject_digest != evidence.content.content_digest:
        raise FactPackValidationError("attestation subject does not match evidence content digest")
    if attestation.producer_identity != evidence.producer_identity:
        raise FactPackValidationError("attestation producer does not match evidence producer")
    if attestation.reviewer_identity != evidence.reviewer_identity:
        raise FactPackValidationError("attestation reviewer does not match evidence reviewer")
    if attestation.attestation_digest != derive_independence_attestation_digest(attestation):
        raise FactPackValidationError("attestation digest cannot be re-derived")
    if evidence.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise FactPackValidationError("evidence reviewer is not trusted")
    if (evidence.producer_identity, evidence.reviewer_identity) in policy.forbidden_identity_pairs:
        raise FactPackValidationError("evidence producer/reviewer pair is forbidden")
    if evidence.kind is KnowledgeEvidenceKind.INDEPENDENT_BEHAVIOR and evidence.producer_identity == evidence.reviewer_identity:
        raise FactPackValidationError("behavioral evidence producer and reviewer must be independent")
    for reference in (evidence.content, attestation.conflict_disclosure):
        content = canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
        if not content:
            raise FactPackValidationError("review evidence and conflict disclosures must be nonempty")


def _lineage_for(evidence: KnowledgeEvidence, lineages: Sequence[LineageManifest]) -> LineageManifest:
    matches = tuple(item for item in lineages if item.manifest_digest == evidence.lineage_manifest_digest)
    if len(matches) != 1:
        raise FactPackValidationError("evidence lineage manifest is missing or ambiguous")
    return matches[0]


def _validate_evidence_lineage(
    pack: FactPack,
    evidence: KnowledgeEvidence,
    lineages: Sequence[LineageManifest],
    protected_population_digest: str | None,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> None:
    lineage = _lineage_for(evidence, lineages)
    if lineage.subject_digest != pack.normalized_content_digest and pack.normalized_content_digest != derive_fact_pack_content_digest(pack):
        raise FactPackValidationError("normalized content digest cannot be re-derived")
    expectations = (
        LineageExpectation(LineagePurpose.SEMANTIC_FACT, pack.normalized_content_digest, 1, 1),
        LineageExpectation(LineagePurpose.PROMOTION, pack.normalized_content_digest, 0, 1),
    )
    decision = validate_lineage(
        lineage,
        pack.normalized_content_digest,
        expectations,
        protected_population_digest,
        True,
        custody,
        custody_policy,
    )
    if not decision.allowed:
        raise FactPackValidationError("fact lineage refused: " + ",".join(decision.reasons))


def _validate_digests(pack: FactPack) -> None:
    if pack.normalized_content_digest != derive_fact_pack_content_digest(pack):
        raise FactPackValidationError("normalized content digest cannot be re-derived")
    if pack.review_evidence_digest != derive_review_evidence_digest(pack.review_evidence):
        raise FactPackValidationError("review evidence digest cannot be re-derived")


def validate_fact_pack(
    pack: FactPack,
    contract: FamilyContract,
    protected_population_digest: str | None,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    """Revalidate a closed v2 pack against exact scope, trust, artifacts, and lineage."""
    if not isinstance(pack, FactPack) or not isinstance(review_policy, ReviewIndependencePolicy):
        raise FactPackValidationError("pack and review policy must use v2 contract types")
    _revalidate_shapes(pack, review_policy)
    _validate_scope(pack, contract)
    _validate_roles(pack, contract)
    _validate_policy(pack, review_policy)
    if not pack.review_evidence:
        raise FactPackValidationError("fact pack requires review evidence")
    _unique(tuple(item.independence.attestation_digest for item in pack.review_evidence), "review attestation")
    for evidence in pack.review_evidence:
        _resolve_evidence(evidence, review_policy, resolver)
        _validate_evidence_lineage(
            pack,
            evidence,
            lineages,
            protected_population_digest,
            custody,
            custody_policy,
        )
    if pack.review_identity not in {item.reviewer_identity for item in pack.review_evidence}:
        raise FactPackValidationError("pack review identity is absent from review evidence")
    _validate_digests(pack)


__all__ = [
    "FACT_PACK_SCHEMA",
    "FactPack",
    "FactPackError",
    "FactPackValidationError",
    "IndependenceAttestation",
    "KnowledgeEvidence",
    "KnowledgeEvidenceKind",
    "RelationEffect",
    "ReviewIndependencePolicy",
    "SemanticFact",
    "StructuralRequirement",
    "StructuralRequirementKind",
    "admit_fact_pack",
    "admit_pack_file",
    "derive_fact_pack_content_digest",
    "derive_independence_attestation_digest",
    "derive_review_evidence_digest",
    "derive_review_independence_policy_digest",
    "load_pack_file",
    "validate_fact_pack",
    "verify_fact_pack",
]
