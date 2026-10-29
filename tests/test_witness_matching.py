"""Witness kind, scope and resource matching (task 10.2, Reqs 2.1, 2.2, 2.5-2.7, 11.1)."""

from openultrasast.semantic.obligations.abstract_domain import (
    UNKNOWN_RESOURCE,
    EvidenceRelation,
    ResourceRef,
    parse_resource,
)
from openultrasast.semantic.obligations.facts import OperationFact
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.witness import match_witness

PATH = "src/C.java"


def _witness(
    *,
    resource: ResourceRef | None = None,
    kind: str = "path_guard",
    scope: str = "statement",
    function: str = "handle",
    line: int | None = 3,
) -> Discharge:
    return Discharge(
        path=PATH,
        line=line,
        function=function,
        kind=kind,
        fact_id="java:authorize",
        provenance="call",
        scope=scope,
        resource=resource,
    )


def _operation(*, resource: str | None = "book", requires: tuple[str, ...] = ("path_guard",)) -> Operation:
    return Operation(
        path=PATH,
        line=4,
        function="handle",
        kind="protected_read",
        fact_id="java:protected-read",
        resource=resource,
        requires=requires,
    )


def _fact(*, request_global_kinds: tuple[str, ...] = ("path_guard",)) -> OperationFact:
    return OperationFact(
        id="protected-read",
        kind="protected_read",
        language="java",
        calls=("read",),
        resource_arg=1,
        requires=("path_guard",),
        sensitivity="confidential",
        request_global_kinds=request_global_kinds,
    )


def test_same_resource_exact_match_is_must() -> None:
    match = match_witness(_witness(resource=parse_resource("book")), _operation(resource="book"), _fact())
    assert match.resource_relation is EvidenceRelation.MUST
    assert match.relation is EvidenceRelation.MUST
    assert match.authority_relation is EvidenceRelation.UNKNOWN


def test_definite_resource_mismatch_is_no() -> None:
    match = match_witness(_witness(resource=parse_resource("volume")), _operation(resource="book"), _fact())
    assert match.resource_relation is EvidenceRelation.NO
    assert match.relation is EvidenceRelation.NO


def test_alias_overlap_is_may() -> None:
    alias_set = ResourceRef(kind="aliases", values=("book", "volume"))
    match = match_witness(_witness(resource=alias_set), _operation(resource="book"), _fact())
    assert match.resource_relation is EvidenceRelation.MAY
    assert match.relation is EvidenceRelation.MAY


def test_request_global_witness_with_declared_kind_is_must() -> None:
    match = match_witness(
        _witness(resource=ResourceRef(kind="request_global", values=())),
        _operation(),
        _fact(request_global_kinds=("path_guard",)),
    )
    assert match.resource_relation is EvidenceRelation.MUST
    assert match.relation is EvidenceRelation.MUST


def test_request_global_witness_without_declaration_is_unknown_never_no() -> None:
    match = match_witness(
        _witness(resource=ResourceRef(kind="request_global", values=())),
        _operation(),
        _fact(request_global_kinds=()),
    )
    assert match.resource_relation is EvidenceRelation.UNKNOWN
    assert match.relation is EvidenceRelation.UNKNOWN
    without_fact = match_witness(_witness(resource=ResourceRef(kind="request_global", values=())), _operation(), None)
    assert without_fact.resource_relation is EvidenceRelation.UNKNOWN


def test_unknown_witness_resource_is_unknown() -> None:
    match = match_witness(_witness(resource=UNKNOWN_RESOURCE), _operation(resource="book"), _fact())
    assert match.resource_relation is EvidenceRelation.UNKNOWN
    assert match.relation is EvidenceRelation.UNKNOWN


def test_unknown_operation_resource_is_unknown() -> None:
    match = match_witness(_witness(resource=parse_resource("book")), _operation(resource=None), _fact())
    assert match.resource_relation is EvidenceRelation.UNKNOWN


def test_kind_not_required_is_no() -> None:
    match = match_witness(_witness(kind="ownership_check"), _operation(requires=("path_guard",)), _fact())
    assert match.relation is EvidenceRelation.NO


def test_scoped_witness_on_other_function_is_no() -> None:
    match = match_witness(_witness(scope="router", function="other", line=None), _operation(), _fact())
    assert match.relation is EvidenceRelation.NO


def test_evidence_carries_fact_ids_and_resource_tokens() -> None:
    match = match_witness(_witness(resource=parse_resource("book")), _operation(resource="book"), _fact())
    assert "witness:java:authorize" in match.evidence
    assert "operation:java:protected-read" in match.evidence
    assert "resource:book" in match.evidence


def test_matching_is_deterministic() -> None:
    witness = _witness(resource=parse_resource("book"))
    operation = _operation(resource="book")
    assert match_witness(witness, operation, _fact()) == match_witness(witness, operation, _fact())
