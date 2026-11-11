"""Fail-closed per-case outcome projection contracts for evaluation V3."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from itertools import permutations

import pytest
from test_core_evidence import _record

from openultrasast.core import canonical
from openultrasast.core.evidence import Decision, EvidencePacket, EvidenceRecord, NeutralOutcome, derive_packet_digest, derive_record_id


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _case_record(label: str, outcome: NeutralOutcome, *, change: str = "change-a") -> EvidenceRecord:
    reasons = ("ambiguous",) if outcome is NeutralOutcome.INDETERMINATE else ()
    base = _record(outcome=outcome, reasons=reasons)
    provenance = replace(base.packet.provenance, change_input_digest=_digest(change))
    packet = replace(base.packet, security_object_id=f"resource:{label}", provenance=provenance)
    return _record(packet=packet, outcome=outcome, reasons=reasons)


def _rehash_record(record: EvidenceRecord) -> None:
    object.__setattr__(record.decision, "packet_digest", derive_packet_digest(record.packet))
    object.__setattr__(record, "record_id", derive_record_id(record.packet, record.decision))


def _projection_operations() -> tuple[Callable[[tuple[EvidenceRecord, ...]], object], ...]:
    from openultrasast.core.evaluation_case_outcome import derive_case_input_digest, derive_component_case_outcome_projection

    return (derive_case_input_digest, derive_component_case_outcome_projection)


def test_component_projection_derives_canonical_case_input_sources_and_outcome() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionPolicyV3,
        derive_case_input_digest,
        derive_component_case_outcome_projection,
    )

    first = _case_record("first", NeutralOutcome.VIOLATION, change="change-b")
    second = _case_record("second", NeutralOutcome.VIOLATION, change="change-a")
    forward = derive_component_case_outcome_projection((first, second))
    reverse = derive_component_case_outcome_projection((second, first))

    assert forward == reverse
    assert forward.case_input_digest == derive_case_input_digest((first, second))
    assert forward.source_outcome_digests == tuple(sorted((first.record_id, second.record_id)))
    assert forward.policy is CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE
    assert forward.normalized_outcome is NeutralOutcome.VIOLATION
    assert len(forward.projection_digest) == 64


def test_component_projection_refuses_empty_duplicate_and_mixed_record_sets() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionError,
        derive_component_case_outcome_projection,
    )

    violation = _case_record("violation", NeutralOutcome.VIOLATION)
    satisfied = _case_record("satisfied", NeutralOutcome.SATISFIED)
    indeterminate = _case_record("indeterminate", NeutralOutcome.INDETERMINATE)

    with pytest.raises(CaseOutcomeProjectionError, match="nonempty"):
        derive_component_case_outcome_projection(())
    with pytest.raises(CaseOutcomeProjectionError, match="unique"):
        derive_component_case_outcome_projection((violation, violation))
    for selected in permutations((violation, satisfied, indeterminate), 2):
        with pytest.raises(CaseOutcomeProjectionError, match="same neutral outcome"):
            derive_component_case_outcome_projection(selected)


def test_projection_contract_refuses_noncanonical_sources_wrong_types_and_tampering() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionError,
        CaseOutcomeProjectionPolicyV3,
        CaseOutcomeProjectionV3,
        derive_component_case_outcome_projection,
    )

    first = _case_record("first", NeutralOutcome.SATISFIED, change="change-b")
    second = _case_record("second", NeutralOutcome.SATISFIED, change="change-a")
    projection = derive_component_case_outcome_projection((first, second))

    mutations = (
        {"case_input_digest": _digest("wrong")},
        {"policy": "unanimous_evidence"},
        {"source_outcome_digests": tuple(reversed(projection.source_outcome_digests))},
        {"source_outcome_digests": (projection.source_outcome_digests[0],) * 2, "projection_digest": ""},
        {"normalized_outcome": "satisfied"},
        {"projection_digest": _digest("tampered")},
    )
    for mutation in mutations:
        with pytest.raises(CaseOutcomeProjectionError):
            replace(projection, **mutation)

    combined = CaseOutcomeProjectionV3(
        projection.case_input_digest,
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        (projection.projection_digest, projection.projection_digest),
        projection.normalized_outcome,
        "",
    )
    assert combined.projection_digest != projection.projection_digest


def test_component_projection_refuses_record_subclasses_and_source_changes() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionError,
        derive_component_case_outcome_projection,
    )

    record = _case_record("base", NeutralOutcome.SATISFIED)

    class DerivedRecord(EvidenceRecord):
        pass

    derived = DerivedRecord(record.packet, record.decision, record.record_id)
    with pytest.raises(CaseOutcomeProjectionError, match="exact EvidenceRecord"):
        derive_component_case_outcome_projection((derived,))

    tampered = _case_record("tampered", NeutralOutcome.SATISFIED)
    object.__setattr__(tampered, "record_id", _digest("wrong"))
    with pytest.raises(CaseOutcomeProjectionError, match="revalidated"):
        derive_component_case_outcome_projection((tampered,))

    changed = _case_record("base", NeutralOutcome.SATISFIED, change="change-b")
    assert (
        derive_component_case_outcome_projection((record,)).case_input_digest
        != derive_component_case_outcome_projection((changed,)).case_input_digest
    )


def test_case_input_derivation_refuses_self_consistent_invalid_nested_change_identity() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionError,
        derive_case_input_digest,
        derive_component_case_outcome_projection,
    )

    record = _case_record("nested", NeutralOutcome.SATISFIED)
    object.__setattr__(record.packet.provenance, "change_input_digest", "caller-selected-text")
    object.__setattr__(record.decision, "packet_digest", derive_packet_digest(record.packet))
    object.__setattr__(record, "record_id", derive_record_id(record.packet, record.decision))

    for operation in (derive_case_input_digest, derive_component_case_outcome_projection):
        with pytest.raises(CaseOutcomeProjectionError, match="change input digest"):
            operation((record,))


def test_case_input_derivation_wraps_plainly_wrong_nested_provenance_type() -> None:
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionError,
        derive_case_input_digest,
        derive_component_case_outcome_projection,
    )

    record = _case_record("wrong-provenance", NeutralOutcome.SATISFIED)
    object.__setattr__(record.packet, "provenance", object())

    for operation in (derive_case_input_digest, derive_component_case_outcome_projection):
        with pytest.raises(CaseOutcomeProjectionError, match="exact ProvenanceStamp"):
            operation((record,))


def test_case_input_derivation_wraps_plainly_wrong_nested_packet_type() -> None:
    from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionError

    record = _case_record("wrong-packet", NeutralOutcome.SATISFIED)
    object.__setattr__(record, "packet", object())

    for operation in _projection_operations():
        with pytest.raises(CaseOutcomeProjectionError, match="exact EvidencePacket"):
            operation((record,))


@pytest.mark.parametrize("nested_kind", ("packet", "decision"))
def test_case_input_derivation_refuses_nested_aggregate_subclasses(nested_kind: str) -> None:
    from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionError

    record = _case_record(f"subclass-{nested_kind}", NeutralOutcome.SATISFIED)
    if nested_kind == "packet":

        class DerivedPacket(EvidencePacket):
            pass

        packet = DerivedPacket(**vars(record.packet))
        object.__setattr__(record, "packet", packet)
        _rehash_record(record)
    else:

        class DerivedDecision(Decision):
            pass

        decision = DerivedDecision(**vars(record.decision))
        object.__setattr__(record, "decision", decision)
        object.__setattr__(record, "record_id", derive_record_id(record.packet, decision))

    expected_type = "EvidencePacket" if nested_kind == "packet" else "Decision"
    for operation in _projection_operations():
        with pytest.raises(CaseOutcomeProjectionError, match=f"exact {expected_type}"):
            operation((record,))


@pytest.mark.parametrize("nested_kind", ("packet", "decision"))
def test_case_input_derivation_revalidates_self_consistently_rehashed_aggregates(nested_kind: str) -> None:
    from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionError

    record = _case_record(f"invalid-{nested_kind}", NeutralOutcome.SATISFIED)
    if nested_kind == "packet":
        object.__setattr__(record.packet, "family_id", "")
        _rehash_record(record)
    else:
        object.__setattr__(record.decision, "family_code", "")
        object.__setattr__(record, "record_id", derive_record_id(record.packet, record.decision))

    for operation in _projection_operations():
        with pytest.raises(CaseOutcomeProjectionError, match="cannot be revalidated"):
            operation((record,))
