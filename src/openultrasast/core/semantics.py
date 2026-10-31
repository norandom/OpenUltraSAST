"""Family-neutral semantic evidence contracts for detection core v2."""

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from openultrasast.core.canonical import ContentRef, JsonValue, content_digest, require_unique_identities

SEMANTIC_RELATION_SCHEMA = "openultrasast.detection-core.semantic-relation.v2"
OBSERVATION_SCHEMA = "openultrasast.detection-core.observation.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class SemanticContractError(ValueError):
    pass


class FieldKind(Enum):
    TEXT = "text"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    TEXT_TUPLE = "text_tuple"
    SOURCE_LOCATION = "source_location"


class RelationKind(Enum):
    REGISTRATION = "registration"
    INVOCATION = "invocation"
    CALL = "call"
    RETURN = "return"
    VALUE_TRANSFORMATION = "value_transformation"
    OPERATION_EFFECT = "operation_effect"
    CONSTRAINT_EFFECT = "constraint_effect"


class RelationStatus(Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNRESOLVED = "unresolved"


class ProvenanceKind(Enum):
    PRODUCT_CODE = "product_code"
    SEMANTIC_FACT = "semantic_fact"


def _require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise SemanticContractError(f"{field} must be nonempty text")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise SemanticContractError(f"{field} must be a full lowercase SHA-256 digest")


def _require_enum(value: object, enum_type: type[Enum], field: str) -> None:
    if not isinstance(value, enum_type):
        raise SemanticContractError(f"{field} must be a {enum_type.__name__}")


def _require_text_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not all(isinstance(value, str) and value for value in values):
        raise SemanticContractError(f"{field} must be a tuple of nonempty text")
    try:
        require_unique_identities(values, kind=field)
    except ValueError as exc:
        raise SemanticContractError(str(exc)) from exc


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line: int
    column: int | None
    symbol: str | None

    def __post_init__(self) -> None:
        _require_text(self.path, "path")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise SemanticContractError("line must be a positive integer")
        if self.column is not None and (isinstance(self.column, bool) or not isinstance(self.column, int) or self.column < 0):
            raise SemanticContractError("column must be a non-negative integer or None")
        if self.symbol is not None:
            _require_text(self.symbol, "symbol")


@dataclass(frozen=True)
class SemanticNode:
    node_id: str
    role: str
    location: SourceLocation

    def __post_init__(self) -> None:
        _require_text(self.node_id, "node_id")
        _require_text(self.role, "role")
        if not isinstance(self.location, SourceLocation):
            raise SemanticContractError("location must be a SourceLocation")


def _location_value(location: SourceLocation) -> Mapping[str, JsonValue]:
    return {"path": location.path, "line": location.line, "column": location.column, "symbol": location.symbol}


def _node_value(node: SemanticNode) -> Mapping[str, JsonValue]:
    return {"node_id": node.node_id, "role": node.role, "location": _location_value(node.location)}


def _content_ref_value(reference: ContentRef) -> Mapping[str, JsonValue]:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


@dataclass(frozen=True)
class EvidenceProvenance:
    kind: ProvenanceKind
    source_content_digest: str
    semantic_pack_digest: str | None
    semantic_fact_id: str | None
    fact_match: ContentRef | None

    def __post_init__(self) -> None:
        _require_enum(self.kind, ProvenanceKind, "kind")
        _require_digest(self.source_content_digest, "source_content_digest")
        if self.kind is ProvenanceKind.PRODUCT_CODE:
            if any(value is not None for value in (self.semantic_pack_digest, self.semantic_fact_id, self.fact_match)):
                raise SemanticContractError("product-code provenance forbids semantic fact fields")
            return
        if self.semantic_pack_digest is None:
            raise SemanticContractError("semantic_pack_digest is required")
        _require_digest(self.semantic_pack_digest, "semantic_pack_digest")
        if self.semantic_fact_id is None:
            raise SemanticContractError("semantic_fact_id is required")
        _require_text(self.semantic_fact_id, "semantic_fact_id")
        if not isinstance(self.fact_match, ContentRef):
            raise SemanticContractError("fact_match is required and must be a ContentRef")


def _provenance_value(provenance: EvidenceProvenance) -> Mapping[str, JsonValue]:
    fact_match: JsonValue = None if provenance.fact_match is None else _content_ref_value(provenance.fact_match)
    return {
        "kind": provenance.kind.value,
        "source_content_digest": provenance.source_content_digest,
        "semantic_pack_digest": provenance.semantic_pack_digest,
        "semantic_fact_id": provenance.semantic_fact_id,
        "fact_match": fact_match,
    }


def _source_location_field(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"path", "line", "column", "symbol"}:
        return False
    path, line, column, symbol = value["path"], value["line"], value["column"], value["symbol"]
    return (
        isinstance(path, str)
        and bool(path)
        and isinstance(line, int)
        and not isinstance(line, bool)
        and line >= 1
        and (column is None or (isinstance(column, int) and not isinstance(column, bool) and column >= 0))
        and (symbol is None or (isinstance(symbol, str) and bool(symbol)))
    )


def _valid_field_value(kind: FieldKind, value: object) -> bool:
    if kind is FieldKind.TEXT:
        return isinstance(value, str)
    if kind is FieldKind.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is FieldKind.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if kind is FieldKind.BOOLEAN:
        return isinstance(value, bool)
    if kind is FieldKind.TEXT_TUPLE:
        return isinstance(value, tuple) and all(isinstance(item, str) for item in value)
    return _source_location_field(value)


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True)
class FieldValue:
    name: str
    kind: FieldKind
    value: JsonValue

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_enum(self.kind, FieldKind, "kind")
        frozen = _freeze_json(self.value)
        if not _valid_field_value(self.kind, frozen):
            raise SemanticContractError(f"value does not match FieldKind.{self.kind.name}")
        object.__setattr__(self, "value", frozen)


def _field_value(field: FieldValue) -> Mapping[str, JsonValue]:
    return {"name": field.name, "kind": field.kind.value, "value": field.value}


def _relation_payload(relation: "SemanticRelation") -> Mapping[str, JsonValue]:
    return {
        "schema_version": SEMANTIC_RELATION_SCHEMA,
        "kind": relation.kind.value,
        "role": relation.role,
        "source": _node_value(relation.source),
        "target": _node_value(relation.target),
        "location": _location_value(relation.location),
        "status": relation.status.value,
        "conditions": relation.conditions,
        "reasons": relation.reasons,
        "provenance": _provenance_value(relation.provenance),
    }


@dataclass(frozen=True)
class SemanticRelation:
    relation_id: str
    kind: RelationKind
    role: str
    source: SemanticNode
    target: SemanticNode
    location: SourceLocation
    status: RelationStatus
    conditions: tuple[str, ...]
    reasons: tuple[str, ...]
    provenance: EvidenceProvenance

    def __post_init__(self) -> None:
        _validate_relation_fields(self, allow_empty_id=True)
        expected = content_digest(_relation_payload(self))
        if not self.relation_id:
            object.__setattr__(self, "relation_id", expected)
        elif self.relation_id != expected:
            raise SemanticContractError("relation_id does not match canonical relation fields")


def _validate_relation_fields(relation: SemanticRelation, *, allow_empty_id: bool = False) -> None:
    if relation.relation_id or not allow_empty_id:
        _require_digest(relation.relation_id, "relation_id")
    _require_enum(relation.kind, RelationKind, "kind")
    _require_text(relation.role, "role")
    if not isinstance(relation.source, SemanticNode) or not isinstance(relation.target, SemanticNode):
        raise SemanticContractError("source and target must be SemanticNode values")
    if not isinstance(relation.location, SourceLocation):
        raise SemanticContractError("location must be a SourceLocation")
    _require_enum(relation.status, RelationStatus, "status")
    _require_text_tuple(relation.conditions, "condition")
    _require_text_tuple(relation.reasons, "reason")
    if relation.status is RelationStatus.COMPLETE and relation.reasons:
        raise SemanticContractError("complete relation must not carry incompleteness reasons")
    if relation.status is not RelationStatus.COMPLETE and not relation.reasons:
        raise SemanticContractError("incomplete or unresolved relation requires a reason")
    if not isinstance(relation.provenance, EvidenceProvenance):
        raise SemanticContractError("provenance must be EvidenceProvenance")


def make_relation(
    *,
    kind: RelationKind,
    role: str,
    source: SemanticNode,
    target: SemanticNode,
    location: SourceLocation,
    status: RelationStatus,
    conditions: tuple[str, ...],
    reasons: tuple[str, ...],
    provenance: EvidenceProvenance,
) -> SemanticRelation:
    return SemanticRelation("", kind, role, source, target, location, status, conditions, reasons, provenance)


def relation_from_conditions(
    *,
    kind: RelationKind,
    role: str,
    source: SemanticNode,
    target: SemanticNode,
    location: SourceLocation,
    declared_conditions: tuple[str, ...],
    unmet_conditions: tuple[str, ...],
    provenance: EvidenceProvenance,
) -> SemanticRelation:
    _require_text_tuple(declared_conditions, "declared condition")
    _require_text_tuple(unmet_conditions, "unmet condition")
    if not set(unmet_conditions).issubset(declared_conditions):
        raise SemanticContractError("unmet conditions must be declared")
    status = RelationStatus.INCOMPLETE if unmet_conditions else RelationStatus.COMPLETE
    reasons = tuple(f"unmet_condition:{condition}" for condition in unmet_conditions)
    return make_relation(
        kind=kind,
        role=role,
        source=source,
        target=target,
        location=location,
        status=status,
        conditions=declared_conditions,
        reasons=reasons,
        provenance=provenance,
    )


def _same_slot(candidate: SemanticRelation, first: SemanticRelation) -> bool:
    return all(getattr(candidate, field) == getattr(first, field) for field in ("kind", "role", "source", "target", "location"))


def _candidate_provenance_reason(candidate: SemanticRelation) -> str:
    provenance = candidate.provenance
    match = "-" if provenance.fact_match is None else provenance.fact_match.content_digest
    return ":".join(
        (
            "conflicting_candidate_provenance",
            content_digest(_provenance_value(provenance)),
            provenance.kind.value,
            provenance.semantic_pack_digest or "-",
            provenance.semantic_fact_id or "-",
            match,
        )
    )


def resolve_relation_candidates(candidates: Sequence[SemanticRelation]) -> SemanticRelation:
    if not candidates:
        raise SemanticContractError("at least one relation candidate is required")
    if not all(isinstance(candidate, SemanticRelation) for candidate in candidates):
        raise SemanticContractError("every candidate must be a SemanticRelation")
    first = candidates[0]
    if not all(_same_slot(candidate, first) for candidate in candidates):
        raise SemanticContractError("relation candidates must describe the same semantic slot")
    try:
        require_unique_identities(tuple(candidate.relation_id for candidate in candidates), kind="candidate")
    except ValueError as exc:
        raise SemanticContractError(str(exc)) from exc
    complete = [candidate for candidate in candidates if candidate.status is RelationStatus.COMPLETE]
    if len(complete) == 1:
        return complete[0]
    if len(candidates) == 1:
        return first
    ordered = sorted(candidates, key=lambda candidate: candidate.relation_id)
    anchor = ordered[0]
    conditions = tuple(sorted({condition for candidate in ordered for condition in candidate.conditions}))
    reasons = (
        tuple(f"conflicting_complete_candidate:{candidate.relation_id}" for candidate in ordered)
        + tuple(sorted({_candidate_provenance_reason(candidate) for candidate in ordered}))
        + (f"ambiguity_provenance_anchor:{anchor.relation_id}",)
    )
    return make_relation(
        kind=anchor.kind,
        role=anchor.role,
        source=anchor.source,
        target=anchor.target,
        location=anchor.location,
        status=RelationStatus.UNRESOLVED,
        conditions=conditions,
        reasons=reasons,
        provenance=anchor.provenance,
    )


def _observation_payload(observation: "Observation") -> Mapping[str, JsonValue]:
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "role": observation.role,
        "location": _location_value(observation.location),
        "fields": tuple(_field_value(field) for field in observation.fields),
        "status": observation.status.value,
        "provenance": _provenance_value(observation.provenance),
    }


@dataclass(frozen=True)
class Observation:
    observation_id: str
    role: str
    location: SourceLocation
    fields: tuple[FieldValue, ...]
    status: RelationStatus
    provenance: EvidenceProvenance

    def __post_init__(self) -> None:
        if self.observation_id:
            _require_digest(self.observation_id, "observation_id")
        _require_text(self.role, "role")
        if not isinstance(self.location, SourceLocation):
            raise SemanticContractError("location must be a SourceLocation")
        if not isinstance(self.fields, tuple) or not all(isinstance(field, FieldValue) for field in self.fields):
            raise SemanticContractError("fields must be a tuple of FieldValue values")
        try:
            require_unique_identities(tuple(field.name for field in self.fields), kind="field")
        except ValueError as exc:
            raise SemanticContractError(str(exc)) from exc
        _require_enum(self.status, RelationStatus, "status")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise SemanticContractError("provenance must be EvidenceProvenance")
        expected = content_digest(_observation_payload(self))
        if not self.observation_id:
            object.__setattr__(self, "observation_id", expected)
        elif self.observation_id != expected:
            raise SemanticContractError("observation_id does not match canonical observation fields")


def make_observation(
    *,
    role: str,
    location: SourceLocation,
    fields: tuple[FieldValue, ...],
    status: RelationStatus,
    provenance: EvidenceProvenance,
) -> Observation:
    return Observation("", role, location, fields, status, provenance)
