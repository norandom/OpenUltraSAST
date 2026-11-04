"""Bounded defect, satisfaction, and silence derivation."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from openultrasast.core import canonical, provenance
from openultrasast.core.evidence import (
    EVIDENCE_PACKET_SCHEMA,
    AnalyzedScope,
    Decision,
    EvidenceBasis,
    EvidencePacket,
    EvidenceRecord,
    NeutralOutcome,
    SourceRegion,
    derive_packet_digest,
)
from openultrasast.core.family import (
    DecisionRule,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RelationOriginPolicy,
    ResidualQuestion,
    RoleSpec,
    derive_security_object_id,
    family_contract_digest,
)
from openultrasast.core.semantics import (
    EvidenceProvenance,
    FieldKind,
    FieldValue,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticNode,
    SemanticRelation,
    SourceLocation,
    make_relation,
)
from openultrasast.core.verdict import DefectClaim, VerdictContractError, derive_verdict_outputs


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _contract(*, extra_question: bool = False) -> FamilyContract:
    questions = [ResidualQuestion("flow_decision", ("flow",), ("bad", "good", "unknown"))]
    if extra_question:
        questions.append(ResidualQuestion("missing_guard", ("guard",), ("bad", "good", "unknown")))
    return FamilyContract(
        "reference-flow",
        "1",
        EVIDENCE_PACKET_SCHEMA,
        ("python",),
        ObjectSpec("operation", (FieldSpec("name", FieldKind.TEXT, True),), ("name",)),
        (
            RoleSpec("flow", (), (RelationKind.CALL,), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("guard", (), (RelationKind.CONSTRAINT_EFFECT,), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
        ),
        (
            DecisionRule("bad", NeutralOutcome.VIOLATION, ("flow",), (RelationStatus.COMPLETE,)),
            DecisionRule("good", NeutralOutcome.SATISFIED, ("flow",), (RelationStatus.COMPLETE,)),
            DecisionRule(
                "unknown",
                NeutralOutcome.INDETERMINATE,
                ("flow",),
                (RelationStatus.INCOMPLETE, RelationStatus.UNRESOLVED),
            ),
        ),
        tuple(questions),
        ("missing_flow",),
    )


def _stamp(contract: FamilyContract) -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        _digest("analyzer"),
        family_contract_digest(contract),
        _digest("facts"),
        _digest("acquisition"),
        _digest("configuration"),
        _digest("population"),
        _digest("change"),
    )


def _relation(status: RelationStatus, *, line: int = 12) -> SemanticRelation:
    source = SourceLocation("src/app.py", 10, 2, "source")
    target = SourceLocation("src/app.py", 11, 2, "target")
    return make_relation(
        kind=RelationKind.CALL,
        role="flow",
        source=SemanticNode("source", "source", source),
        target=SemanticNode("target", "target", target),
        location=SourceLocation("src/app.py", line, 4, "call"),
        status=status,
        conditions=(),
        reasons=() if status is RelationStatus.COMPLETE else ("missing_flow",),
        provenance=EvidenceProvenance(ProvenanceKind.PRODUCT_CODE, _digest("source"), None, None, None),
    )


def _record(contract: FamilyContract, code: str, status: RelationStatus, *, line: int = 12) -> EvidenceRecord:
    relation = _relation(status, line=line)
    fields = (FieldValue("name", FieldKind.TEXT, "read"),)
    scope = AnalyzedScope("base", "head", _digest("change"), (SourceRegion("src/app.py", 1, 20),))
    reasons = () if status is RelationStatus.COMPLETE else ("missing_flow",)
    packet = EvidencePacket(
        EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        family_contract_digest(contract),
        derive_security_object_id(contract.security_object, fields),
        "python",
        scope,
        (relation,),
        (),
        fields,
        reasons,
        _stamp(contract),
    )
    outcomes = {"bad": NeutralOutcome.VIOLATION, "good": NeutralOutcome.SATISFIED, "unknown": NeutralOutcome.INDETERMINATE}
    decision = Decision(
        code,
        outcomes[code],
        EvidenceBasis.DETERMINISTIC,
        scope,
        reasons,
        derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return EvidenceRecord(packet, decision, "")


def test_complete_violation_derives_exact_change_tied_claim() -> None:
    contract = _contract()
    record = _record(contract, "bad", RelationStatus.COMPLETE)
    result = derive_verdict_outputs((record,), contract, _digest("coverage"))
    assert result.satisfactions == () and result.silence == ()
    assert len(result.defects) == 1
    claim = result.defects[0]
    assert claim.record is record
    assert claim.basis is record.decision.basis
    assert claim.location == record.packet.transitions[0].location
    assert claim.change_anchor == record.packet.scope.regions[0]


def test_complete_satisfaction_carries_question_and_exact_scope() -> None:
    contract = _contract()
    record = _record(contract, "good", RelationStatus.COMPLETE)
    result = derive_verdict_outputs((record,), contract, _digest("coverage"))
    assert result.defects == () and result.silence == ()
    assert result.satisfactions[0].question_ids == ("flow_decision",)
    assert result.satisfactions[0].records == (record,)
    assert result.satisfactions[0].scope is record.decision.bounded_scope


def test_satisfaction_requires_support_inside_its_exact_bounded_scope() -> None:
    contract = _contract()
    record = _record(contract, "good", RelationStatus.COMPLETE)
    narrow = AnalyzedScope("base", "head", _digest("change"), (SourceRegion("src/app.py", 1, 5),))
    changed = replace(record, decision=replace(record.decision, bounded_scope=narrow), record_id="")
    result = derive_verdict_outputs((changed,), contract, _digest("coverage"))
    assert result.satisfactions == ()
    assert result.silence[0].reasons == ("evidence_outside_bounded_scope:flow",)
    assert result.silence[0].evidence_record_digests == (changed.record_id,)


def test_indeterminate_record_preserves_reasons_identity_and_coverage() -> None:
    contract = _contract()
    record = _record(contract, "unknown", RelationStatus.INCOMPLETE)
    coverage = _digest("coverage")
    result = derive_verdict_outputs((record,), contract, coverage)
    assert result.defects == () and result.satisfactions == ()
    silence = result.silence[0]
    assert silence.question_ids == ("flow_decision",)
    assert silence.reasons == ("missing_flow",)
    assert silence.evidence_record_digests == (record.record_id,)
    assert silence.coverage_digest == coverage


def test_mixed_complete_and_incomplete_paths_keep_claim_and_silence() -> None:
    contract = _contract()
    complete = _record(contract, "bad", RelationStatus.COMPLETE)
    incomplete = _record(contract, "unknown", RelationStatus.INCOMPLETE)
    result = derive_verdict_outputs((incomplete, complete), contract, _digest("coverage"))
    assert tuple(item.record.record_id for item in result.defects) == (complete.record_id,)
    assert result.satisfactions == ()
    assert result.silence[0].evidence_record_digests == (incomplete.record_id,)


def test_unanswered_question_is_bounded_silence_not_repository_clean() -> None:
    contract = _contract(extra_question=True)
    record = _record(contract, "good", RelationStatus.COMPLETE)
    result = derive_verdict_outputs((record,), contract, _digest("coverage"))
    assert result.satisfactions[0].question_ids == ("flow_decision",)
    silence = next(item for item in result.silence if item.question_ids == ("missing_guard",))
    assert silence.reasons == ("missing_required_role:guard",)
    assert silence.evidence_record_digests == (record.record_id,)


def test_claim_location_outside_change_scope_is_refused() -> None:
    contract = _contract()
    record = _record(contract, "bad", RelationStatus.COMPLETE, line=99)
    with pytest.raises(VerdictContractError, match="scope"):
        derive_verdict_outputs((record,), contract, _digest("coverage"))


def test_claim_contract_refuses_redirected_location_and_anchor() -> None:
    contract = _contract()
    record = _record(contract, "bad", RelationStatus.COMPLETE)
    with pytest.raises(VerdictContractError, match="evidence location"):
        DefectClaim(record, record.decision.basis, SourceLocation("src/app.py", 15, 0, "redirected"), record.packet.scope.regions[0])
    with pytest.raises(VerdictContractError, match="bounded decision scope"):
        DefectClaim(record, record.decision.basis, record.packet.transitions[0].location, SourceRegion("src/app.py", 2, 20))


def test_invalid_coverage_identity_and_forged_record_are_refused() -> None:
    contract = _contract()
    record = _record(contract, "bad", RelationStatus.COMPLETE)
    with pytest.raises(VerdictContractError, match="coverage"):
        derive_verdict_outputs((record,), contract, "not-a-digest")
    forged = copy.copy(record)
    object.__setattr__(forged, "record_id", _digest("forged"))
    with pytest.raises(VerdictContractError, match="record"):
        derive_verdict_outputs((forged,), contract, _digest("coverage"))
