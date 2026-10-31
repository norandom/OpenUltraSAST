"""Materialize reviewed semantic-fact effects with exact match provenance."""

from __future__ import annotations

from collections.abc import Sequence

from openultrasast.core import canonical
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    validate_population_custody_log,
)
from openultrasast.core.factmatch import FactMatchEvidence, fact_match_bytes, validate_fact_match
from openultrasast.core.factpack import FactPack, RelationEffect, ReviewIndependencePolicy, SemanticFact, validate_fact_pack
from openultrasast.core.family import FamilyContract
from openultrasast.core.lineage import LineageManifest
from openultrasast.core.semantics import (
    EvidenceProvenance,
    ProvenanceKind,
    RelationStatus,
    SemanticNode,
    SemanticRelation,
    make_relation,
    resolve_relation_candidates,
)


class FactApplicationError(ValueError):
    """A reviewed fact effect cannot be reproduced from its named inputs."""


def _fact_for(pack: FactPack, fact_id: str) -> SemanticFact:
    matches = tuple(fact for fact in pack.facts if fact.fact_id == fact_id)
    if len(matches) != 1:
        raise FactApplicationError("fact identity is missing or ambiguous in pack")
    return matches[0]


def _resolve_match_reference(
    match: FactMatchEvidence,
    reference: canonical.ContentRef,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    try:
        content = canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError) as exc:
        raise FactApplicationError(f"match reference cannot be validated: {exc}") from exc
    if reference.content_digest != match.match_digest or content != fact_match_bytes(match):
        raise FactApplicationError("match reference does not resolve to canonical match bytes")


def _refuse_current_labelled_promotion(
    pack: FactPack,
    evaluation_population_digest: str,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> None:
    log = custody.current_log(evaluation_population_digest)
    validate_population_custody_log(log, custody_policy, current=custody)
    contaminated = any(
        receipt.request.purpose is LineagePurpose.PROMOTION
        and receipt.request.influenced_artifact_digest == pack.normalized_content_digest
        and receipt.request.labels_accessed
        for receipt in log.receipts
    )
    if contaminated:
        raise FactApplicationError(f"promotion lineage is contaminated: protected_population_labels:{evaluation_population_digest}")


def _node(match: FactMatchEvidence, role: str) -> SemanticNode:
    node_id = canonical.content_digest(
        {
            "match_digest": match.match_digest,
            "product_location": {
                "path": match.product_location.path,
                "line": match.product_location.line,
                "column": match.product_location.column,
                "symbol": match.product_location.symbol,
            },
            "role": role,
        }
    )
    return SemanticNode(node_id, role, match.product_location)


def _provenance(pack: FactPack, fact_id: str, match: FactMatchEvidence, reference: canonical.ContentRef) -> EvidenceProvenance:
    return EvidenceProvenance(
        ProvenanceKind.SEMANTIC_FACT,
        match.match_digest,
        pack.normalized_content_digest,
        fact_id,
        reference,
    )


def _relation(
    effect: RelationEffect,
    match: FactMatchEvidence,
    status: RelationStatus,
    reasons: tuple[str, ...],
    provenance: EvidenceProvenance,
) -> SemanticRelation:
    if status is RelationStatus.INCOMPLETE:
        reasons = tuple(sorted(set((*reasons, *(f"unmet_condition:{item}" for item in effect.conditions)))))
    return make_relation(
        kind=effect.kind,
        role=effect.role,
        source=_node(match, effect.source_role),
        target=_node(match, effect.target_role),
        location=match.product_location,
        status=status,
        conditions=effect.conditions,
        reasons=reasons,
        provenance=provenance,
    )


def _slot(relation: SemanticRelation) -> tuple[object, ...]:
    return relation.kind, relation.role, relation.source, relation.target, relation.location


def _duplicate_ambiguity(candidates: tuple[SemanticRelation, ...]) -> SemanticRelation:
    anchor = candidates[0]
    reasons = tuple(sorted({f"duplicate_declared_effect:{item.relation_id}" for item in candidates}))
    return make_relation(
        kind=anchor.kind,
        role=anchor.role,
        source=anchor.source,
        target=anchor.target,
        location=anchor.location,
        status=RelationStatus.UNRESOLVED,
        conditions=anchor.conditions,
        reasons=reasons,
        provenance=anchor.provenance,
    )


def _resolve_effects(relations: tuple[SemanticRelation, ...]) -> tuple[SemanticRelation, ...]:
    groups: dict[tuple[object, ...], list[SemanticRelation]] = {}
    for relation in relations:
        groups.setdefault(_slot(relation), []).append(relation)
    resolved: list[SemanticRelation] = []
    for candidates in groups.values():
        values = tuple(candidates)
        if len(values) == 1:
            resolved.append(values[0])
        elif len({item.relation_id for item in values}) != len(values):
            resolved.append(_duplicate_ambiguity(values))
        else:
            resolved.append(resolve_relation_candidates(values))
    return tuple(resolved)


def apply_fact(
    pack: FactPack,
    fact_id: str,
    match: FactMatchEvidence,
    match_reference: canonical.ContentRef,
    contract: FamilyContract,
    evaluation_population_digest: str,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[SemanticRelation, ...]:
    """Apply only declared effects after replaying pack, match, and lineage trust."""
    validate_fact_pack(
        pack,
        contract,
        evaluation_population_digest,
        lineages,
        custody,
        custody_policy,
        review_policy,
        resolver,
    )
    _refuse_current_labelled_promotion(pack, evaluation_population_digest, custody, custody_policy)
    fact = _fact_for(pack, fact_id)
    decision = validate_fact_match(
        pack,
        fact_id,
        match,
        evaluation_population_digest,
        lineages,
        custody,
        custody_policy,
        review_policy,
        resolver,
    )
    _resolve_match_reference(match, match_reference, review_policy, resolver)
    origin = _provenance(pack, fact_id, match, match_reference)
    relations = tuple(_relation(effect, match, decision.status, decision.reasons, origin) for effect in fact.relation_effects)
    return _resolve_effects(relations)


__all__ = ["FactApplicationError", "apply_fact"]
