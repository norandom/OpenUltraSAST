"""Closed object-graph whitelist for evidence validation contexts."""

from __future__ import annotations

from types import MappingProxyType

from openultrasast.core._closed_graph import closed_graph_problem
from openultrasast.core.canonical import ContentRef
from openultrasast.core.custody import LineagePurpose, PopulationCustodyPolicy
from openultrasast.core.evidence import NeutralOutcome
from openultrasast.core.factpack import (
    FactPack,
    IndependenceAttestation,
    KnowledgeEvidence,
    KnowledgeEvidenceKind,
    RelationEffect,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
)
from openultrasast.core.family import (
    DecisionRule,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RelationOriginPolicy,
    ResidualQuestion,
    RoleSpec,
)
from openultrasast.core.family_catalog import FamilyCatalog, FamilyCatalogEntry
from openultrasast.core.lineage import LineageManifest, LineageUse
from openultrasast.core.model import ModelProgramDeclaration
from openultrasast.core.provenance import ProvenanceTrustPolicy
from openultrasast.core.semantics import FieldKind, RelationKind, RelationStatus

_DATACLASSES: tuple[type[object], ...] = (
    FamilyCatalog,
    FamilyCatalogEntry,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RoleSpec,
    DecisionRule,
    ResidualQuestion,
    FactPack,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    KnowledgeEvidence,
    StructuralRequirement,
    RelationEffect,
    SemanticFact,
    ContentRef,
    ModelProgramDeclaration,
    LineageManifest,
    LineageUse,
    ProvenanceTrustPolicy,
    PopulationCustodyPolicy,
)
_ENUMS: tuple[type[object], ...] = (
    NeutralOutcome,
    RelationOriginPolicy,
    FieldKind,
    RelationKind,
    RelationStatus,
    KnowledgeEvidenceKind,
    StructuralRequirementKind,
    LineagePurpose,
)
_MAPPINGS: tuple[type[object], ...] = (type(MappingProxyType({})),)


def evidence_context_problem(value: object, context_type: type[object]) -> str | None:
    return closed_graph_problem(
        value,
        dataclass_types=(context_type, *_DATACLASSES),
        enum_types=_ENUMS,
        mapping_types=_MAPPINGS,
        path="evidence validation context",
    )


__all__ = ["evidence_context_problem"]
