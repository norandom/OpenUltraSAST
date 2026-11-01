"""Authority-bearing application of reviewed Express structural facts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from openultrasast.core import canonical
from openultrasast.core.factapply import apply_fact
from openultrasast.core.factmatch import (
    FactMatchDecision,
    FactMatchEvidence,
    StructuralObservation,
    derive_fact_match_digest,
    validate_fact_match,
)
from openultrasast.core.factpack import FactPack, SemanticFact, StructuralRequirement, StructuralRequirementKind
from openultrasast.core.semantics import SemanticRelation, SourceLocation
from openultrasast.mapping.entry_fact_structure import (
    CandidateStructure,
    EntryStructureError,
    ResolvedHandler,
    analyze_candidate,
    candidates,
    read_source_structure,
)
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter


class EntryFactMatcherError(ValueError):
    """Reviewed structural evidence could not be safely produced."""


@dataclass(frozen=True)
class _JoinedResolver:
    primary: canonical.ContentResolver
    fallback: canonical.ContentResolver

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        try:
            return self.primary.resolve(reference)
        except canonical.ArtifactResolutionError:
            return self.fallback.resolve(reference)


@dataclass(frozen=True)
class EntryFactMatchResult:
    """Persisted match, lexical evidence, and exact core application result."""

    pack: FactPack
    match: FactMatchEvidence
    match_reference: canonical.ContentRef
    decision: FactMatchDecision
    relations: tuple[SemanticRelation, ...]
    resolver: canonical.ContentResolver
    resolved_handlers: tuple[ResolvedHandler, ...]
    structural_reasons: tuple[str, ...]


def _selected(pack: FactPack, fact_id: str) -> SemanticFact:
    facts = tuple(fact for fact in pack.facts if fact.fact_id == fact_id)
    if len(facts) != 1:
        raise EntryFactMatcherError("reviewed fact is missing or ambiguous")
    return facts[0]


def _pack(authority: EntryFactAuthorityContext, language: str, fact_id: str) -> tuple[FactPack, SemanticFact]:
    if not isinstance(authority, EntryFactAuthorityContext):
        raise TypeError("authority must be EntryFactAuthorityContext")
    packs = tuple(pack for pack in authority.bundle.packs if pack.language == language)
    if len(packs) != 1:
        raise EntryFactMatcherError("reviewed language pack is missing or ambiguous")
    return packs[0], _selected(packs[0], fact_id)


def _qualified_target(fact: SemanticFact) -> str:
    targets = tuple(
        item.expected
        for item in fact.structural_requirements
        if item.kind is StructuralRequirementKind.QUALIFIED_NAME and isinstance(item.expected, str)
    )
    if len(targets) != 1:
        raise EntryFactMatcherError("reviewed fact lacks one textual qualified target")
    return targets[0]


def _observed(requirement: StructuralRequirement, structure: CandidateStructure) -> tuple[canonical.JsonValue, ...]:
    if requirement.kind is StructuralRequirementKind.QUALIFIED_NAME:
        return (structure.candidate.target,)
    if requirement.kind is StructuralRequirementKind.AST_SHAPE:
        return (structure.candidate.shape,)
    if requirement.kind is StructuralRequirementKind.RECEIVER_TYPE:
        return structure.receiver_types
    if requirement.kind is StructuralRequirementKind.ARGUMENT_SHAPE and requirement.field == "arguments":
        return structure.argument_shapes
    if requirement.kind is StructuralRequirementKind.ARGUMENT_SHAPE and requirement.field == "binding":
        return structure.binding_shapes
    return ()


def _location(path: str, structure: CandidateStructure) -> SourceLocation:
    node = structure.candidate.node
    symbol = structure.candidate.target
    if len(structure.resolved_handlers) == 1:
        symbol = f"{symbol}->{structure.resolved_handlers[0].identity}"
    return SourceLocation(path, node.start_point.row + 1, node.start_point.column, symbol)


def _persist_observations(
    fact: SemanticFact,
    structure: CandidateStructure,
    location: SourceLocation,
    writer: FactMatchArtifactWriter,
) -> tuple[StructuralObservation, ...]:
    values: list[StructuralObservation] = []
    pending = canonical.ContentRef("pending", "0" * 64, "application/json", 0, "0" * 64, "0" * 64)
    for requirement in fact.structural_requirements:
        for observed in _observed(requirement, structure):
            provisional = StructuralObservation(requirement.requirement_id, location, observed, pending)
            values.append(replace(provisional, evidence=writer.persist_observation(provisional)))
    return tuple(values)


def _match(
    pack: FactPack,
    fact: SemanticFact,
    location: SourceLocation,
    observations: tuple[StructuralObservation, ...],
    authority: EntryFactAuthorityContext,
) -> FactMatchEvidence:
    bundle = authority.bundle
    provisional = FactMatchEvidence(
        pack.normalized_content_digest,
        fact.fact_id,
        location,
        observations,
        bundle.matcher_revision,
        bundle.matcher_behavior_digest,
        bundle.matcher_lineage_manifest_digest,
        "0" * 64,
    )
    return replace(provisional, match_digest=derive_fact_match_digest(provisional))


def _apply(
    pack: FactPack,
    fact: SemanticFact,
    match: FactMatchEvidence,
    structure: CandidateStructure,
    authority: EntryFactAuthorityContext,
    writer: FactMatchArtifactWriter,
    evaluation_population_digest: str,
) -> EntryFactMatchResult:
    reference = writer.persist_match(match)
    resolver = _JoinedResolver(writer.resolver, authority.resolver)
    bundle = authority.bundle
    core_tail = (
        evaluation_population_digest,
        bundle.lineages,
        authority.custody,
        bundle.custody_policy,
        bundle.review_policy,
        resolver,
    )
    decision = validate_fact_match(pack, fact.fact_id, match, *core_tail)
    relations = apply_fact(pack, fact.fact_id, match, reference, bundle.contract, *core_tail)
    return EntryFactMatchResult(
        pack,
        match,
        reference,
        decision,
        relations,
        resolver,
        structure.resolved_handlers,
        structure.reasons,
    )


def match_entry_fact(
    *,
    repository_root: Path,
    relative_path: str,
    language: str,
    fact_id: str,
    authority: EntryFactAuthorityContext,
    writer: FactMatchArtifactWriter,
    evaluation_population_digest: str,
) -> tuple[EntryFactMatchResult, ...]:
    """Resolve lexical structure, persist it, and apply one reviewed fact."""
    try:
        source = read_source_structure(repository_root, relative_path, language)
    except EntryStructureError as exc:
        raise EntryFactMatcherError(str(exc)) from exc
    pack, fact = _pack(authority, language, fact_id)
    results: list[EntryFactMatchResult] = []
    for candidate in candidates(source, _qualified_target(fact)):
        structure = analyze_candidate(source, candidate)
        location = _location(source.path, structure)
        observations = _persist_observations(fact, structure, location, writer)
        match = _match(pack, fact, location, observations, authority)
        results.append(_apply(pack, fact, match, structure, authority, writer, evaluation_population_digest))
    return tuple(results)


__all__ = ["EntryFactMatchResult", "EntryFactMatcherError", "ResolvedHandler", "match_entry_fact"]
