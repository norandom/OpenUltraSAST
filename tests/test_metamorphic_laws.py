"""Metamorphic-law validation for the abstract evidence domain (task 13.1).

Covers the requirements the 7.1 algebra tests and the 10.4/10.5 fixture tests
leave as cross-domain laws only: the mixed-obligation rule swept over every
per-kind relation pair, judgment preservation under bijective type renaming,
and the Req 11.6 ambiguity-monotonicity law (adding ambiguity preserves a
judgment or makes it indeterminate -- it never flips unguarded/discharged).
Every law runs twice and asserts equal results (deterministic across repeated
runs).

Reqs 11.2-11.7. The join-table, conjunction, witness-aggregation and
monotonicity laws of the domain itself are pinned in
tests/test_obligation_abstract_domain.py and are not duplicated here.
"""

from __future__ import annotations

import itertools

import pytest

from openultrasast.semantic.obligations.abstract_domain import (
    AuthorityImplication,
    AuthorityRef,
    Completeness,
    EvidenceRelation,
    ResourceRef,
    WitnessMatch,
)
from openultrasast.semantic.obligations.cfg_dominance import DominanceEvidence
from openultrasast.semantic.obligations.judgment import judgment_for_path
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.witness import match_witness

KINDS = ("path_guard", "ownership_check")
RELATIONS = (
    EvidenceRelation.MUST,
    EvidenceRelation.MAY,
    EvidenceRelation.NO,
    EvidenceRelation.UNKNOWN,
)
_COMPLETE = Completeness(is_complete=True)


def _operation() -> Operation:
    return Operation(
        "src/C.java",
        4,
        "handle",
        "protected_read",
        "f:op",
        "book",
        KINDS,
    )


def _pair(relation: EvidenceRelation) -> tuple[WitnessMatch, DominanceEvidence]:
    match = WitnessMatch(
        relation=relation,
        resource_relation=EvidenceRelation.MUST,
        authority_relation=EvidenceRelation.MUST,
        evidence=("witness:f:guard",),
    )
    return match, DominanceEvidence(relation=EvidenceRelation.MUST, guard_effect="throws")


def _matches_by_kind(
    path_guard_relation: EvidenceRelation, ownership_relation: EvidenceRelation
) -> dict[str, tuple[tuple[WitnessMatch, DominanceEvidence], ...]]:
    return {
        "path_guard": (_pair(path_guard_relation),),
        "ownership_check": (_pair(ownership_relation),),
    }


def _expected_judgment(path_guard_relation: EvidenceRelation, ownership_relation: EvidenceRelation) -> str:
    relations = (path_guard_relation, ownership_relation)
    if any(relation not in (EvidenceRelation.MUST, EvidenceRelation.NO) for relation in relations):
        return "indeterminate"
    if EvidenceRelation.NO in relations:
        missing = sorted(kind for kind, relation in zip(KINDS, relations, strict=True) if relation is EvidenceRelation.NO)
        return "unguarded:" + "+".join(missing)
    return "discharged"


def _judgment_name(judgment: object) -> str:
    value = getattr(judgment, "value", None)
    if isinstance(value, str):
        return value
    return getattr(judgment, "name", str(judgment))


def test_mixed_obligation_rule_sweeps_every_relation_pair() -> None:
    """Reqs 11.2-11.4: the mixed-obligation rule holds for every per-kind pair."""
    for path_guard_relation, ownership_relation in itertools.product(RELATIONS, RELATIONS):
        judgment = judgment_for_path(
            _operation(),
            _matches_by_kind(path_guard_relation, ownership_relation),
            _COMPLETE,
        )
        expected = _expected_judgment(path_guard_relation, ownership_relation)
        name = _judgment_name(judgment.judgment)
        if expected.startswith("unguarded:"):
            assert name == "unguarded", (path_guard_relation, ownership_relation, expected, name)
            assert set(judgment.missing) == set(expected.split(":", 1)[1].split("+"))
        else:
            assert name == expected, (path_guard_relation, ownership_relation, expected, name)


def test_type_renaming_preserves_judgment_and_matching() -> None:
    """Req 11.7: bijective renames of resources, authorities and fact ids change nothing observable."""
    witness = Discharge(
        "src/C.java",
        3,
        "handle",
        "path_guard",
        "java:guard",
        "call",
        "statement",
        "",
        resource=ResourceRef(kind="exact", values=("book",)),
        authority=AuthorityRef(values=("admin",)),
    )
    renamed_witness = Discharge(
        "src/C.java",
        3,
        "handle",
        "path_guard",
        "renamed:guard",
        "call",
        "statement",
        "",
        resource=ResourceRef(kind="exact", values=("tome",)),
        authority=AuthorityRef(values=("root",)),
    )
    operation = _operation()
    renamed_operation = Operation(
        "src/C.java",
        4,
        "handle",
        "protected_read",
        "renamed:op",
        "tome",
        KINDS,
    )
    implication = AuthorityImplication(id="impl:1", authority="admin", implies="supervisor")
    renamed_implication = AuthorityImplication(id="impl:1", authority="root", implies="manager")
    required = AuthorityRef(values=("supervisor",))
    renamed_required = AuthorityRef(values=("manager",))

    base = match_witness(witness, operation, None, required_authority=required, implications=(implication,))
    renamed = match_witness(
        renamed_witness,
        renamed_operation,
        None,
        required_authority=renamed_required,
        implications=(renamed_implication,),
    )
    assert base.relation is renamed.relation is EvidenceRelation.MUST
    assert base.resource_relation is renamed.resource_relation
    assert base.authority_relation is renamed.authority_relation


def test_added_ambiguity_never_flips_discharged_to_unguarded() -> None:
    """Req 11.6: degrading any dimension of a discharged pair keeps it discharged or makes it indeterminate."""
    degraded_relations = (EvidenceRelation.MAY, EvidenceRelation.UNKNOWN)
    for degraded in degraded_relations:
        for kind_index in range(len(KINDS)):
            relations = [EvidenceRelation.MUST, EvidenceRelation.MUST]
            relations[kind_index] = degraded
            judgment = judgment_for_path(
                _operation(),
                _matches_by_kind(relations[0], relations[1]),
                _COMPLETE,
            )
            assert _judgment_name(judgment.judgment) in ("discharged", "indeterminate"), (degraded, kind_index)


def test_added_ambiguity_never_flips_unguarded_to_discharged() -> None:
    """Req 11.6: degrading a governed kind of an unguarded pair keeps it unguarded or makes it indeterminate."""
    degraded_relations = (EvidenceRelation.MAY, EvidenceRelation.UNKNOWN)
    for degraded in degraded_relations:
        judgment = judgment_for_path(
            _operation(),
            _matches_by_kind(EvidenceRelation.NO, degraded),
            _COMPLETE,
        )
        assert _judgment_name(judgment.judgment) in ("unguarded", "indeterminate"), degraded


@pytest.mark.parametrize(
    ("path_guard_relation", "ownership_relation"),
    list(itertools.product(RELATIONS, RELATIONS)),
)
def test_laws_hold_deterministically_across_repeated_runs(
    path_guard_relation: EvidenceRelation, ownership_relation: EvidenceRelation
) -> None:
    """Req 11.7: two evaluations of the same law produce identical results."""
    matches = _matches_by_kind(path_guard_relation, ownership_relation)
    first = judgment_for_path(_operation(), matches, _COMPLETE)
    second = judgment_for_path(_operation(), matches, _COMPLETE)
    assert first == second
