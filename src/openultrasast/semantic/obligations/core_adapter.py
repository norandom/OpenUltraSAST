"""Conservative authorization adapters for detection-core migration boundaries."""

from __future__ import annotations

from collections.abc import Mapping

from openultrasast.core import evidence, family, semantics
from openultrasast.core import provenance as core_provenance
from openultrasast.core.trace import Guard as LegacyGuard
from openultrasast.core.trace import Hop as LegacyHop
from openultrasast.core.trace import TraceRecord
from openultrasast.core.trace import Witness as LegacyWitness
from openultrasast.core.verdict import Judgment

from .abstract_domain import EvidenceRelation, PairJudgment
from .trace import Trace

_MISSING_CONSTRAINT = "missing_constraint_relation"
_AMBIGUOUS_CONSTRAINT = "ambiguous_constraint_relation"


def _location(trace: Trace, scope: evidence.AnalyzedScope) -> semantics.SourceLocation:
    matches = tuple(region for region in scope.regions if region.start_line <= trace.operation_line <= region.end_line)
    if len(matches) != 1:
        raise ValueError("trace operation must resolve to exactly one analyzed source region")
    return semantics.SourceLocation(matches[0].path, trace.operation_line, 0, trace.operation_kind)


def _product(stamp: core_provenance.ProvenanceStamp) -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(
        semantics.ProvenanceKind.PRODUCT_CODE,
        stamp.change_input_digest,
        None,
        None,
        None,
    )


def _constraint_state(trace: Trace) -> tuple[semantics.RelationStatus, str, str, evidence.NeutralOutcome]:
    state = trace.abstract_state
    if state is None or trace.hops:
        return semantics.RelationStatus.INCOMPLETE, "unknown", _MISSING_CONSTRAINT, evidence.NeutralOutcome.INDETERMINATE
    complete = state.path_judgment.completeness.is_complete
    known_values = state.resource.kind != "unknown" and not state.authority.is_unknown
    known_relations = state.resource_relation in (EvidenceRelation.MUST, EvidenceRelation.NO) and state.authority_relation in (
        EvidenceRelation.MUST,
        EvidenceRelation.NO,
    )
    if not (complete and known_values and known_relations):
        return semantics.RelationStatus.INCOMPLETE, "unknown", _MISSING_CONSTRAINT, evidence.NeutralOutcome.INDETERMINATE
    judgment = state.path_judgment.judgment
    if judgment is PairJudgment.UNGUARDED:
        return semantics.RelationStatus.COMPLETE, "unconstrained", "", evidence.NeutralOutcome.VIOLATION
    if judgment is PairJudgment.DISCHARGED:
        return semantics.RelationStatus.COMPLETE, "guarded", "", evidence.NeutralOutcome.SATISFIED
    return semantics.RelationStatus.UNRESOLVED, "unknown", _AMBIGUOUS_CONSTRAINT, evidence.NeutralOutcome.INDETERMINATE


def _decision_rule(contract: family.FamilyContract, outcome: evidence.NeutralOutcome) -> family.DecisionRule:
    matches = tuple(rule for rule in contract.decisions if rule.outcome is outcome)
    if len(matches) != 1:
        raise ValueError("authorization contract must declare exactly one rule for each neutral outcome")
    return matches[0]


def _relations(
    trace: Trace,
    location: semantics.SourceLocation,
    product: semantics.EvidenceProvenance,
) -> tuple[tuple[semantics.SemanticRelation, ...], str, evidence.NeutralOutcome]:
    entry = semantics.SemanticNode("entry", "entry", location)
    operation = semantics.SemanticNode("operation", "operation", location)
    operation_relation = semantics.make_relation(
        kind=semantics.RelationKind.OPERATION_EFFECT,
        role="operation",
        source=entry,
        target=operation,
        location=location,
        status=semantics.RelationStatus.COMPLETE,
        conditions=(),
        reasons=(),
        provenance=product,
    )
    status, target_name, reason, outcome = _constraint_state(trace)
    constraint_relation = semantics.make_relation(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role="constraint",
        source=operation,
        target=semantics.SemanticNode(target_name, "constraint", location),
        location=location,
        status=status,
        conditions=tuple(dict.fromkeys(trace.requires)),
        reasons=() if not reason else (reason,),
        provenance=product,
    )
    return (operation_relation, constraint_relation), reason, outcome


def _packet(
    trace: Trace,
    contract: family.FamilyContract,
    ecosystem: str,
    scope: evidence.AnalyzedScope,
    stamp: core_provenance.ProvenanceStamp,
) -> tuple[evidence.EvidencePacket, evidence.NeutralOutcome]:
    location = _location(trace, scope)
    product = _product(stamp)
    transitions, reason, outcome = _relations(trace, location, product)
    fields = (
        semantics.FieldValue("operation", semantics.FieldKind.TEXT, trace.operation_kind),
        semantics.FieldValue("boundary", semantics.FieldKind.TEXT, trace.boundary),
    )
    observation = semantics.make_observation(
        role="security_object",
        location=location,
        fields=fields,
        status=semantics.RelationStatus.COMPLETE,
        provenance=product,
    )
    completeness = () if not reason else (reason,)
    return (
        evidence.EvidencePacket(
            evidence.EVIDENCE_PACKET_SCHEMA,
            contract.family_id,
            family.family_contract_digest(contract),
            family.derive_security_object_id(contract.security_object, fields),
            ecosystem,
            scope,
            transitions,
            (observation,),
            fields,
            completeness,
            stamp,
        ),
        outcome,
    )


def to_evidence_record(
    trace: Trace,
    *,
    contract: family.FamilyContract,
    ecosystem: str,
    scope: evidence.AnalyzedScope,
    provenance: core_provenance.ProvenanceStamp,
) -> evidence.EvidenceRecord:
    """Map one parked authorization trace without promoting missing hop knowledge."""
    if type(trace) is not Trace:
        raise TypeError("authorization adapter requires an exact Trace")
    family.validate_contract(contract)
    packet, outcome = _packet(trace, contract, ecosystem, scope, provenance)
    completeness = packet.completeness_reasons
    rule = _decision_rule(contract, outcome)
    decision = evidence.Decision(
        rule.family_code,
        outcome,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        completeness,
        evidence.derive_packet_digest(packet),
        _deterministic_provenance(),
    )
    record = evidence.EvidenceRecord(packet, decision, "")
    family.validate_record(contract, record)
    return record


def _deterministic_provenance() -> core_provenance.DecisionProvenance:
    return core_provenance.DecisionProvenance(None, None, None, None, None, None)


def to_legacy_trace_record(
    trace: Trace,
    *,
    entry: str,
    digests: Mapping[str, str],
    complete: bool = False,
) -> TraceRecord:
    """Preserve the frozen v1 conversion while its writers remain parked."""
    state = trace.abstract_state
    if state is None:
        judgment = Judgment.INDETERMINATE
        reasons: tuple[str, ...] = ("abstract_state_unset",)
        witnesses: tuple[LegacyWitness, ...] = ()
        resource = authority = "unknown"
    else:
        judgment = Judgment(state.path_judgment.judgment.value)
        completeness = state.path_judgment.completeness
        reasons = tuple(completeness.reasons) or (("incomplete",) if not completeness.is_complete else ())
        witnesses = tuple(
            LegacyWitness(kind="witness", provenance=item, relation=match.relation.value)
            for match in state.path_judgment.matches
            for item in match.evidence
        )
        resource = ",".join(state.resource.values) or "unknown"
        authority = ",".join(state.authority.values) or "unknown"
    hops = tuple(LegacyHop(function=item.function, call_line=item.call_line, complete=complete) for item in trace.hops)
    hop_guards = tuple(guard for hop in trace.hops for guard in hop.guards_before_call)
    guards = tuple(LegacyGuard(kind=item.kind, effect=item.effect) for item in (*hop_guards, *trace.guards_after))
    return TraceRecord(
        entry=entry,
        hops=hops,
        operation_kind=trace.operation_kind,
        resource=resource,
        authority=authority,
        witnesses=witnesses,
        guards=guards,
        completeness_reasons=reasons,
        judgment=judgment,
        digests=dict(digests),
    )


__all__ = ["to_evidence_record", "to_legacy_trace_record"]
