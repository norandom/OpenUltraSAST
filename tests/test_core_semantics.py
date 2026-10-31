"""Family-neutral semantic evidence contracts (Req 1.2, 4.1-4.3, 5.2)."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import FrozenInstanceError, replace
from enum import Enum
from typing import cast

import pytest
from detection_core_fixtures import stored_artifact

import openultrasast.core.canonical as canonical
import openultrasast.core.semantics as semantics


def _location(line: int = 7) -> semantics.SourceLocation:
    return semantics.SourceLocation(path="src/app.py", line=line, column=3, symbol="handle")


def _node(node_id: str, role: str) -> semantics.SemanticNode:
    return semantics.SemanticNode(node_id=node_id, role=role, location=_location())


def _product_provenance() -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(
        kind=semantics.ProvenanceKind.PRODUCT_CODE,
        source_content_digest="1" * 64,
        semantic_pack_digest=None,
        semantic_fact_id=None,
        fact_match=None,
    )


def _fact_provenance() -> semantics.EvidenceProvenance:
    reference, _ = stored_artifact(b'{"matched":true}')
    return semantics.EvidenceProvenance(
        kind=semantics.ProvenanceKind.SEMANTIC_FACT,
        source_content_digest="2" * 64,
        semantic_pack_digest="3" * 64,
        semantic_fact_id="express.route.registration",
        fact_match=reference,
    )


def _named_fact_provenance(pack: str, fact: str) -> semantics.EvidenceProvenance:
    reference, _ = stored_artifact(fact.encode())
    return semantics.EvidenceProvenance(
        kind=semantics.ProvenanceKind.SEMANTIC_FACT,
        source_content_digest="4" * 64,
        semantic_pack_digest=pack,
        semantic_fact_id=fact,
        fact_match=reference,
    )


def _relation(
    *,
    kind_name: str = "CALL",
    status_name: str = "COMPLETE",
    target_id: str = "target",
    conditions: tuple[str, ...] = (),
    reasons: tuple[str, ...] = (),
    provenance: semantics.EvidenceProvenance | None = None,
) -> semantics.SemanticRelation:
    return semantics.make_relation(
        kind=getattr(semantics.RelationKind, kind_name),
        role="framework_transition",
        source=_node("source", "caller"),
        target=_node(target_id, "callee"),
        location=_location(),
        status=getattr(semantics.RelationStatus, status_name),
        conditions=conditions,
        reasons=reasons,
        provenance=_product_provenance() if provenance is None else provenance,
    )


@pytest.mark.parametrize(
    "kind_name",
    [
        "REGISTRATION",
        "INVOCATION",
        "CALL",
        "RETURN",
        "VALUE_TRANSFORMATION",
        "OPERATION_EFFECT",
        "CONSTRAINT_EFFECT",
    ],
)
def test_every_relation_kind_has_a_canonical_identity(kind_name: str) -> None:
    relation = _relation(kind_name=kind_name)
    same = _relation(kind_name=kind_name)

    assert relation.kind.value == kind_name.lower()
    assert relation.relation_id == same.relation_id
    assert len(relation.relation_id) == 64
    assert relation.role == "framework_transition"
    assert relation.location == _location()
    assert relation.provenance == _product_provenance()


@pytest.mark.parametrize(
    ("status_name", "reasons"),
    [
        ("COMPLETE", ()),
        ("INCOMPLETE", ("unmet_condition:authenticated",)),
        ("UNRESOLVED", ("ambiguous_framework_match",)),
    ],
)
def test_relation_status_is_independent_and_canonical(status_name: str, reasons: tuple[str, ...]) -> None:
    relation = _relation(status_name=status_name, reasons=reasons)

    assert relation.status.value == status_name.lower()
    assert relation.reasons == reasons
    assert relation.relation_id == _relation(status_name=status_name, reasons=reasons).relation_id


def test_relation_identity_preserves_condition_order_and_rejects_tampering() -> None:
    left = _relation(conditions=("registered", "authenticated"))
    right = _relation(conditions=("authenticated", "registered"))

    assert left.relation_id != right.relation_id
    with pytest.raises(semantics.SemanticContractError, match="relation_id"):
        replace(left, relation_id="0" * 64)


def test_unmet_declared_conditions_make_relation_incomplete() -> None:
    relation = semantics.relation_from_conditions(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role="authorization_constraint",
        source=_node("request", "request"),
        target=_node("resource", "resource"),
        location=_location(),
        declared_conditions=("authenticated", "owns_resource"),
        unmet_conditions=("owns_resource",),
        provenance=_product_provenance(),
    )

    assert relation.status is semantics.RelationStatus.INCOMPLETE
    assert relation.conditions == ("authenticated", "owns_resource")
    assert relation.reasons == ("unmet_condition:owns_resource",)


def test_conflicting_complete_candidates_produce_stable_explicit_ambiguity() -> None:
    first = _relation(conditions=("framework:v1",))
    second = _relation(conditions=("framework:v2",))

    forward = semantics.resolve_relation_candidates((first, second))
    reverse = semantics.resolve_relation_candidates((second, first))

    assert forward.status is semantics.RelationStatus.UNRESOLVED
    assert forward.relation_id == reverse.relation_id
    assert forward.conditions == ("framework:v1", "framework:v2")
    for identity in (first.relation_id, second.relation_id):
        assert f"conflicting_complete_candidate:{identity}" in forward.reasons
    assert any(reason.startswith("ambiguity_provenance_anchor:") for reason in forward.reasons)
    assert forward not in (first, second)


def test_distinct_reviewed_fact_candidates_produce_order_independent_ambiguity() -> None:
    first_provenance = _named_fact_provenance("5" * 64, "express.route.v1")
    second_provenance = _named_fact_provenance("6" * 64, "express.route.v2")
    first = _relation(conditions=("framework:v1",), provenance=first_provenance)
    second = _relation(conditions=("framework:v2",), provenance=second_provenance)

    forward = semantics.resolve_relation_candidates((first, second))
    reverse = semantics.resolve_relation_candidates((second, first))

    assert forward.status is semantics.RelationStatus.UNRESOLVED
    assert forward.relation_id == reverse.relation_id
    assert forward.provenance == reverse.provenance
    assert any(reason.startswith("ambiguity_provenance_anchor:") for reason in forward.reasons)
    for candidate in (first, second):
        assert f"conflicting_complete_candidate:{candidate.relation_id}" in forward.reasons
        provenance = candidate.provenance
        assert provenance.semantic_pack_digest is not None
        assert provenance.semantic_fact_id is not None
        assert provenance.fact_match is not None
        assert any(
            provenance.semantic_pack_digest in reason
            and provenance.semantic_fact_id in reason
            and provenance.fact_match.content_digest in reason
            for reason in forward.reasons
        )


def test_candidate_resolution_returns_the_only_complete_candidate() -> None:
    complete = _relation()
    incomplete = _relation(status_name="INCOMPLETE", reasons=("missing_fact",))

    assert semantics.resolve_relation_candidates((incomplete, complete)) is complete


def test_candidate_resolution_refuses_unrelated_relation_slots() -> None:
    with pytest.raises(semantics.SemanticContractError, match="same semantic slot"):
        semantics.resolve_relation_candidates((_relation(), _relation(target_id="other")))


def test_product_provenance_forbids_semantic_fact_fields() -> None:
    reference, _ = stored_artifact(b"match")
    with pytest.raises(semantics.SemanticContractError, match="forbids semantic fact"):
        semantics.EvidenceProvenance(
            kind=semantics.ProvenanceKind.PRODUCT_CODE,
            source_content_digest="1" * 64,
            semantic_pack_digest="2" * 64,
            semantic_fact_id="fact",
            fact_match=reference,
        )


@pytest.mark.parametrize("missing", ["semantic_pack_digest", "semantic_fact_id", "fact_match"])
def test_semantic_fact_provenance_requires_all_fact_identity_fields(missing: str) -> None:
    reference, _ = stored_artifact(b"match")
    values: dict[str, object] = {
        "semantic_pack_digest": "2" * 64,
        "semantic_fact_id": "fact",
        "fact_match": reference,
    }
    values[missing] = None

    with pytest.raises(semantics.SemanticContractError, match=missing):
        semantics.EvidenceProvenance(
            kind=semantics.ProvenanceKind.SEMANTIC_FACT,
            source_content_digest="1" * 64,
            semantic_pack_digest=cast(str | None, values["semantic_pack_digest"]),
            semantic_fact_id=cast(str | None, values["semantic_fact_id"]),
            fact_match=cast(canonical.ContentRef | None, values["fact_match"]),
        )


def test_semantic_fact_identity_changes_relation_identity() -> None:
    product = _relation()
    fact = semantics.make_relation(
        kind=product.kind,
        role=product.role,
        source=product.source,
        target=product.target,
        location=product.location,
        status=product.status,
        conditions=product.conditions,
        reasons=product.reasons,
        provenance=_fact_provenance(),
    )

    assert fact.relation_id != product.relation_id


@pytest.mark.parametrize(
    ("kind_name", "value"),
    [
        ("TEXT", "query"),
        ("INTEGER", 7),
        ("NUMBER", 2.5),
        ("BOOLEAN", True),
        ("TEXT_TUPLE", ("read", "write")),
        ("SOURCE_LOCATION", {"path": "src/app.py", "line": 7, "column": 3, "symbol": "handle"}),
    ],
)
def test_observation_fields_have_closed_typed_values(kind_name: str, value: object) -> None:
    field = semantics.FieldValue(name="observed", kind=getattr(semantics.FieldKind, kind_name), value=cast(canonical.JsonValue, value))
    observation = semantics.make_observation(
        role="operation",
        location=_location(),
        fields=(field,),
        status=semantics.RelationStatus.COMPLETE,
        provenance=_product_provenance(),
    )

    assert observation.fields == (field,)
    assert (
        observation.observation_id
        == semantics.make_observation(
            role="operation",
            location=_location(),
            fields=(field,),
            status=semantics.RelationStatus.COMPLETE,
            provenance=_product_provenance(),
        ).observation_id
    )


def test_field_value_defensively_freezes_caller_mapping() -> None:
    caller_value: dict[str, canonical.JsonValue] = {
        "path": "src/original.py",
        "line": 3,
        "column": None,
        "symbol": "original",
    }
    field = semantics.FieldValue("location", semantics.FieldKind.SOURCE_LOCATION, caller_value)
    observation = semantics.make_observation(
        role="operation",
        location=_location(),
        fields=(field,),
        status=semantics.RelationStatus.COMPLETE,
        provenance=_product_provenance(),
    )

    caller_value["path"] = "src/mutated.py"
    exposed = cast(MutableMapping[str, canonical.JsonValue], field.value)
    with pytest.raises(TypeError):
        exposed["path"] = "src/also-mutated.py"

    frozen_value = cast(Mapping[str, canonical.JsonValue], field.value)
    assert frozen_value["path"] == "src/original.py"
    assert (
        observation.observation_id
        == semantics.make_observation(
            role="operation",
            location=_location(),
            fields=(field,),
            status=semantics.RelationStatus.COMPLETE,
            provenance=_product_provenance(),
        ).observation_id
    )


def test_observation_preserves_field_order_and_all_statuses() -> None:
    first = semantics.FieldValue("first", semantics.FieldKind.TEXT, "one")
    second = semantics.FieldValue("second", semantics.FieldKind.INTEGER, 2)
    identities = []
    for status in semantics.RelationStatus:
        observation = semantics.make_observation(
            role="operation",
            location=_location(),
            fields=(first, second),
            status=status,
            provenance=_product_provenance(),
        )
        reversed_fields = semantics.make_observation(
            role="operation",
            location=_location(),
            fields=(second, first),
            status=status,
            provenance=_product_provenance(),
        )
        assert observation.observation_id != reversed_fields.observation_id
        identities.append(observation.observation_id)
    assert len(set(identities)) == 3


def test_observation_refuses_duplicate_field_names() -> None:
    duplicate = semantics.FieldValue("same", semantics.FieldKind.TEXT, "value")
    with pytest.raises(semantics.SemanticContractError, match="duplicate field"):
        semantics.make_observation(
            role="operation",
            location=_location(),
            fields=(duplicate, duplicate),
            status=semantics.RelationStatus.COMPLETE,
            provenance=_product_provenance(),
        )


@pytest.mark.parametrize(
    ("kind_name", "value"),
    [
        ("TEXT", 1),
        ("INTEGER", True),
        ("NUMBER", float("nan")),
        ("BOOLEAN", "true"),
        ("TEXT_TUPLE", ("valid", 2)),
        ("SOURCE_LOCATION", {"path": "src/app.py"}),
    ],
)
def test_field_kind_refuses_wrong_runtime_shape(kind_name: str, value: object) -> None:
    with pytest.raises(semantics.SemanticContractError, match="value"):
        semantics.FieldValue("observed", getattr(semantics.FieldKind, kind_name), cast(canonical.JsonValue, value))


@pytest.mark.parametrize(
    ("path", "line", "column", "symbol"),
    [("", 1, None, None), ("src/app.py", 0, None, None), ("src/app.py", 1, -1, None), ("src/app.py", 1, None, "")],
)
def test_source_location_refuses_invalid_runtime_values(path: str, line: int, column: int | None, symbol: str | None) -> None:
    with pytest.raises(semantics.SemanticContractError):
        semantics.SourceLocation(path=path, line=line, column=column, symbol=symbol)


def test_unknown_enum_values_are_refused_at_runtime() -> None:
    class Unknown(Enum):
        VALUE = "call"

    with pytest.raises(semantics.SemanticContractError, match="RelationKind"):
        semantics.make_relation(
            kind=cast(semantics.RelationKind, Unknown.VALUE),
            role="role",
            source=_node("source", "source"),
            target=_node("target", "target"),
            location=_location(),
            status=semantics.RelationStatus.COMPLETE,
            conditions=(),
            reasons=(),
            provenance=_product_provenance(),
        )


def test_semantic_contracts_are_frozen() -> None:
    relation = _relation()
    with pytest.raises(FrozenInstanceError):
        relation.__setattr__("role", "mutated")
