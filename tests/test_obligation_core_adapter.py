"""Authorization traces cross into detection-core v2 only through the adapter."""

from __future__ import annotations

import inspect
from dataclasses import replace

from test_core_evidence import _scope, _stamp
from test_core_reference_families import _contract, _load

from openultrasast.core import evidence, family, semantics
from openultrasast.semantic.obligations import trace as trace_module
from openultrasast.semantic.obligations.abstract_domain import (
    AuthorityRef,
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    ResourceRef,
    WitnessMatch,
)
from openultrasast.semantic.obligations.core_adapter import to_evidence_record


def _trace() -> trace_module.Trace:
    state = trace_module.AbstractTraceState(
        path_judgment=PathJudgment(
            judgment=PairJudgment.UNGUARDED,
            missing=("identity_constraint",),
            completeness=Completeness(is_complete=True, reasons=()),
            matches=(WitnessMatch(EvidenceRelation.MUST, EvidenceRelation.MUST, EvidenceRelation.NO, ("fact:f",)),),
        ),
        resource=ResourceRef(kind="exact", values=("credentials",)),
        authority=AuthorityRef(values=("admin",), is_unknown=False),
        resource_relation=EvidenceRelation.MUST,
        authority_relation=EvidenceRelation.MUST,
    )
    guard = trace_module.Guard("permission_check", "path", 2, "fact:f", "f1", "all_paths", "branches")
    return trace_module.Trace(
        entry_kind="route",
        boundary="request",
        access="public",
        parameters=("request",),
        hops=(trace_module.Hop("handler", 2, (guard,), ()),),
        operation_kind="protected_read",
        fact_id="obligation:protected_read:src/app.py:3",
        operation_line=3,
        arguments=(),
        guards_after=(),
        requires=("identity_constraint",),
        dominating=(),
        missing="identity_constraint",
        abstract_state=state,
    )


def _adapt(trace: trace_module.Trace) -> evidence.EvidenceRecord:
    contract = _contract(_load("obligation_family.json"))
    stamp = replace(_stamp(), family_contract_digest=family.family_contract_digest(contract))
    return to_evidence_record(
        trace,
        contract=contract,
        ecosystem="reference-obligation",
        scope=_scope(),
        provenance=stamp,
    )


def test_direct_complete_authorization_trace_maps_to_v2_violation() -> None:
    trace = replace(_trace(), hops=(), operation_line=3)

    record = _adapt(trace)

    assert record.decision.outcome is evidence.NeutralOutcome.VIOLATION
    assert record.decision.family_code == "constraint_exposed"
    assert tuple(item.role for item in record.packet.transitions) == ("operation", "constraint")
    assert all(item.status is semantics.RelationStatus.COMPLETE for item in record.packet.transitions)


def test_missing_per_hop_completeness_stays_incomplete_and_indeterminate() -> None:
    trace = replace(_trace(), operation_line=3)

    record = _adapt(trace)

    constraint = next(item for item in record.packet.transitions if item.role == "constraint")
    assert constraint.status is semantics.RelationStatus.INCOMPLETE
    assert record.decision.outcome is evidence.NeutralOutcome.INDETERMINATE
    assert record.decision.family_code == "constraint_unknown"
    assert "missing_constraint_relation" in record.packet.completeness_reasons


def test_complete_discharged_trace_maps_to_v2_satisfaction() -> None:
    trace = replace(_trace(), hops=(), operation_line=3)
    assert trace.abstract_state is not None
    state = replace(
        trace.abstract_state,
        path_judgment=replace(trace.abstract_state.path_judgment, judgment=PairJudgment.DISCHARGED, missing=()),
    )

    record = _adapt(replace(trace, abstract_state=state))

    assert record.decision.outcome is evidence.NeutralOutcome.SATISFIED
    assert record.decision.family_code == "constraint_enforced"


def test_unknown_resource_degrades_complete_legacy_judgment_to_indeterminate() -> None:
    trace = replace(_trace(), hops=(), operation_line=3)
    assert trace.abstract_state is not None
    state = replace(trace.abstract_state, resource=ResourceRef(kind="unknown"))

    record = _adapt(replace(trace, abstract_state=state))

    assert record.decision.outcome is evidence.NeutralOutcome.INDETERMINATE
    assert record.packet.transitions[1].status is semantics.RelationStatus.INCOMPLETE


def test_unset_abstract_state_never_lifts_legacy_trace_to_a_clean_result() -> None:
    record = _adapt(replace(_trace(), hops=(), operation_line=3, abstract_state=None))

    assert record.decision.outcome is evidence.NeutralOutcome.INDETERMINATE
    assert record.packet.transitions[1].status is semantics.RelationStatus.INCOMPLETE


def test_authorization_trace_domain_has_no_core_import_or_conversion_method() -> None:
    source = inspect.getsource(trace_module)

    assert "openultrasast.core" not in source
    assert not hasattr(trace_module.Trace, "to_core_record")
