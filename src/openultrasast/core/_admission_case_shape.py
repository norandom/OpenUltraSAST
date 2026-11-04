"""Closed object-graph whitelist for immutable admission cases."""

from __future__ import annotations

from openultrasast.core._closed_graph import closed_graph_problem
from openultrasast.core._model_result import ModelResult, ModelStatus, PreservedModelResponse
from openultrasast.core.budget import BudgetDerivation, ChangeComplexity, ReferenceHardware, ReferenceWorkload
from openultrasast.core.canonical import ContentRef
from openultrasast.core.coverage import CoverageFunnel, InputManifest, InputReadReceipt, ReasonCount, RelationStatusCount
from openultrasast.core.custody import LineagePurpose
from openultrasast.core.evidence import (
    AnalyzedScope,
    Decision,
    EvidenceBasis,
    EvidencePacket,
    EvidenceRecord,
    NeutralOutcome,
    SourceRegion,
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
from openultrasast.core.lineage import LineageManifest, LineageUse
from openultrasast.core.measurement import ScopeKey
from openultrasast.core.model import CompletenessItem, ModelProgramDeclaration, ModelRequest
from openultrasast.core.proof import (
    ControlBinding,
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofVerificationReceipt,
)
from openultrasast.core.provenance import (
    DecisionProvenance,
    ModelCallIdentity,
    NamedInput,
    NamedInputs,
    ProvenanceInputRole,
    ProvenanceStamp,
)
from openultrasast.core.semantics import (
    EvidenceProvenance,
    FieldKind,
    FieldValue,
    Observation,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticNode,
    SemanticRelation,
    SourceLocation,
)
from openultrasast.core.validation import EvidenceValidationInput
from openultrasast.core.verdict import BoundedSatisfaction, BoundedSilence, DefectClaim

_DATACLASSES: tuple[type[object], ...] = (
    ScopeKey,
    EvidenceValidationInput,
    EvidenceRecord,
    EvidencePacket,
    Decision,
    AnalyzedScope,
    SourceRegion,
    SourceLocation,
    SemanticNode,
    EvidenceProvenance,
    FieldValue,
    SemanticRelation,
    Observation,
    ProvenanceStamp,
    DecisionProvenance,
    ModelCallIdentity,
    NamedInput,
    NamedInputs,
    ContentRef,
    ModelRequest,
    ModelProgramDeclaration,
    CompletenessItem,
    ModelResult,
    PreservedModelResponse,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RoleSpec,
    DecisionRule,
    ResidualQuestion,
    LineageManifest,
    LineageUse,
    DefectClaim,
    BoundedSatisfaction,
    BoundedSilence,
    ProofAttachment,
    DifferentialProofRecord,
    ProofProducerIdentity,
    ProofSideResult,
    ControlBinding,
    ProofVerificationReceipt,
    CoverageFunnel,
    RelationStatusCount,
    ReasonCount,
    InputManifest,
    InputReadReceipt,
    ChangeComplexity,
    BudgetDerivation,
    ReferenceWorkload,
    ReferenceHardware,
)

_ENUMS: tuple[type[object], ...] = (
    NeutralOutcome,
    EvidenceBasis,
    FieldKind,
    RelationKind,
    RelationStatus,
    ProvenanceKind,
    RelationOriginPolicy,
    ProvenanceInputRole,
    LineagePurpose,
    ModelStatus,
    ProofOutcome,
)


def admission_case_problem(value: object, case_type: type[object], role_type: type[object]) -> str | None:
    return closed_graph_problem(
        value,
        dataclass_types=(case_type, *_DATACLASSES),
        enum_types=(role_type, *_ENUMS),
        path="admission case result",
    )
