"""V3-local closed graph whitelists for fitted-component authorization."""

from __future__ import annotations

from types import MappingProxyType

from openultrasast.core._closed_graph import closed_graph_problem
from openultrasast.core.admission_fitted import FittedComponentEvidence
from openultrasast.core.canonical import ContentRef
from openultrasast.core.coverage import CoverageFunnel, ReasonCount, RelationStatusCount
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
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.lineage import LineageManifest, LineageUse
from openultrasast.core.measurement import BaselineIdentity, IntervalMethod, MetricId, MetricResult, ScopeKey
from openultrasast.core.measurement_record import (
    BasisCount,
    MeasurementRecordV2,
    OutcomeCount,
    ReadinessReference,
    RepositoryHoldoutReport,
)
from openultrasast.core.probes import (
    ProbeEvaluationInput,
    ProbeObservation,
    ReversedPairProbe,
    SemanticEquivalenceReview,
)
from openultrasast.core.provenance import DecisionProvenance, ModelCallIdentity, ProvenanceStamp
from openultrasast.core.readiness import ReadinessEvidenceUse, ReadinessStage, StageResult
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

_MAPPINGS: tuple[type[object], ...] = (type(MappingProxyType({})),)
_PROBE_DATACLASSES: tuple[type[object], ...] = (
    ProbeEvaluationInput,
    ReversedPairProbe,
    ProbeObservation,
    SemanticEquivalenceReview,
    IndependenceAttestation,
    ContentRef,
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
)
_PROBE_ENUMS: tuple[type[object], ...] = (
    NeutralOutcome,
    EvidenceBasis,
    FieldKind,
    RelationKind,
    RelationStatus,
    ProvenanceKind,
)
_HOLDOUT_DATACLASSES: tuple[type[object], ...] = (
    RepositoryHoldoutReport,
    ContentRef,
    MeasurementRecordV2,
    BaselineIdentity,
    ScopeKey,
    MetricResult,
    CoverageFunnel,
    RelationStatusCount,
    ReasonCount,
    OutcomeCount,
    BasisCount,
    ReadinessReference,
)
_HOLDOUT_ENUMS: tuple[type[object], ...] = (
    ReadinessEvidenceUse,
    NeutralOutcome,
    EvidenceBasis,
    MetricId,
    IntervalMethod,
    RelationStatus,
    ReadinessStage,
    StageResult,
)


def fitted_evidence_problem(value: object) -> str | None:
    """Return the first non-closed node in fitted evidence."""
    return closed_graph_problem(
        value,
        dataclass_types=(FittedComponentEvidence, ContentRef),
        enum_types=(),
        path="fitted evidence",
    )


def probe_input_problem(value: object, index: int) -> str | None:
    """Return the first non-closed node in one full probe graph."""
    return closed_graph_problem(
        value,
        dataclass_types=_PROBE_DATACLASSES,
        enum_types=_PROBE_ENUMS,
        mapping_types=_MAPPINGS,
        path=f"probe inputs[{index}]",
    )


def fitting_lineage_problem(value: object) -> str | None:
    """Return the first non-closed node in fitting lineage."""
    return closed_graph_problem(
        value,
        dataclass_types=(LineageManifest, LineageUse),
        enum_types=(LineagePurpose,),
        path="fitting lineage",
    )


def repository_holdout_problem(value: object) -> str | None:
    """Return the first non-closed node in a holdout measurement graph."""
    return closed_graph_problem(
        value,
        dataclass_types=_HOLDOUT_DATACLASSES,
        enum_types=_HOLDOUT_ENUMS,
        path="repository holdout",
    )


__all__ = [
    "fitted_evidence_problem",
    "fitting_lineage_problem",
    "probe_input_problem",
    "repository_holdout_problem",
]
