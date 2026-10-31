"""Measured workload budgets and affected-scope enforcement."""

from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import budget as budget_v2
from openultrasast.core import canonical, evidence, provenance, semantics


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _measurement(changed_bytes: int) -> tuple[canonical.ContentRef, InMemoryContentResolver]:
    content = canonical.canonical_bytes({"schema_version": budget_v2.CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": changed_bytes})
    return stored_artifact(content, artifact_id=f"changed-bytes-{changed_bytes}")


def _complexity(
    *,
    workload_class: str = "small",
    changed_regions: int = 2,
    transition_count: int = 4,
    changed_bytes: int = 120,
) -> tuple[budget_v2.ChangeComplexity, InMemoryContentResolver]:
    reference, resolver = _measurement(changed_bytes)
    return (
        budget_v2.ChangeComplexity(
            change_id=_digest("change-1"),
            workload_class=workload_class,
            changed_regions=changed_regions,
            transition_count=transition_count,
            changed_bytes=changed_bytes,
            measurement=reference,
        ),
        resolver,
    )


def _reference_workload() -> budget_v2.ReferenceWorkload:
    artifact, _ = stored_artifact(b"samples", artifact_id="sample-artifact")
    value = budget_v2.ReferenceWorkload(
        name="small-reference",
        description="small change workload",
        changed_region_range=(1, 3),
        transition_count_range=(0, 10),
        changed_bytes_range=(1, 500),
        sample_artifact=artifact,
        record_digest="",
    )
    return replace(value, record_digest=budget_v2.derive_reference_workload_digest(value))


def _hardware() -> budget_v2.ReferenceHardware:
    value = budget_v2.ReferenceHardware(
        cpu_model="Example CPU",
        logical_cpu_count=8,
        memory_bytes=16_000_000_000,
        operating_system="linux",
        runtime_version="python-3.11",
        record_digest="",
    )
    return replace(value, record_digest=budget_v2.derive_reference_hardware_digest(value))


def _samples() -> tuple[budget_v2.MeasuredSample, ...]:
    values: list[budget_v2.MeasuredSample] = []
    for elapsed in (80, 100, 120, 140, 160):
        complexity, _ = _complexity(changed_bytes=100 + elapsed)
        values.append(budget_v2.MeasuredSample(complexity, elapsed))
    return tuple(values)


def _derivation() -> budget_v2.BudgetDerivation:
    return budget_v2.derive_budget(
        _samples(),
        workload_class="small",
        percentile=0.8,
        reference_workload=_reference_workload(),
        reference_hardware=_hardware(),
    )


def _scope(*regions: evidence.SourceRegion) -> evidence.AnalyzedScope:
    selected = regions or (evidence.SourceRegion("src/app.py", 1, 30),)
    return evidence.AnalyzedScope("base", "head", _digest("change"), selected)


def _provenance() -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(semantics.ProvenanceKind.PRODUCT_CODE, _digest("source"), None, None, None)


def _packet(
    *,
    line: int = 10,
    scope: evidence.AnalyzedScope | None = None,
    observation_fields: tuple[semantics.FieldValue, ...] = (),
    family_fields: tuple[semantics.FieldValue, ...] = (),
) -> evidence.EvidencePacket:
    location = semantics.SourceLocation("src/app.py", line, 0, "handle")
    relation = semantics.make_relation(
        kind=semantics.RelationKind.CALL,
        role="operation",
        source=semantics.SemanticNode("source", "source", location),
        target=semantics.SemanticNode("target", "target", location),
        location=location,
        status=semantics.RelationStatus.COMPLETE,
        conditions=(),
        reasons=(),
        provenance=_provenance(),
    )
    stamp = provenance.ProvenanceStamp(*(_digest(name) for name in ("a", "f", "s", "q", "c", "p", "i")))
    observations: tuple[semantics.Observation, ...] = ()
    if observation_fields:
        observations = (
            semantics.make_observation(
                role="operation",
                location=location,
                fields=observation_fields,
                status=semantics.RelationStatus.COMPLETE,
                provenance=_provenance(),
            ),
        )
    return evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        "reference-family",
        stamp.family_contract_digest,
        "object-1",
        "python",
        _scope() if scope is None else scope,
        (relation,),
        observations,
        family_fields,
        (),
        stamp,
    )


def test_budget_v2_test_instrument_is_nonzero() -> None:
    assert __file__
    assert len(Path(__file__).read_bytes()) > 0


def test_derivation_is_deterministic_and_discloses_measurement_context() -> None:
    first = _derivation()
    second = budget_v2.derive_budget(
        tuple(reversed(_samples())),
        workload_class="small",
        percentile=0.8,
        reference_workload=_reference_workload(),
        reference_hardware=_hardware(),
    )
    assert first == second
    assert first.sample_count == 5
    assert first.percentile == 0.8
    assert first.budget_ms == 144
    assert len(first.derivation_digest) == 64


def test_v2_design_signature_accepts_positional_derivation_context() -> None:
    derived = budget_v2.derive_budget(_samples(), "small", 0.8, _reference_workload(), _hardware())
    assert isinstance(derived, budget_v2.BudgetDerivation)
    assert derived.budget_ms == 144


@pytest.mark.parametrize(
    ("samples", "workload_class", "percentile"),
    [
        ((), "small", 0.8),
        (_samples(), "", 0.8),
        (_samples(), "small", 0.0),
        (_samples(), "small", 1.1),
        (_samples(), "small", math.nan),
    ],
)
def test_derivation_refuses_missing_or_nonfinite_inputs(
    samples: tuple[budget_v2.MeasuredSample, ...], workload_class: str, percentile: float
) -> None:
    with pytest.raises((TypeError, ValueError)):
        budget_v2.derive_budget(
            samples,
            workload_class=workload_class,
            percentile=percentile,
            reference_workload=_reference_workload(),
            reference_hardware=_hardware(),
        )


def test_derivation_refuses_mixed_classes_and_incompatible_complexity() -> None:
    wrong_class, _ = _complexity(workload_class="large")
    too_large, _ = _complexity(changed_bytes=501)
    for candidate in (wrong_class, too_large):
        with pytest.raises(ValueError):
            budget_v2.derive_budget(
                (budget_v2.MeasuredSample(candidate, 100),),
                workload_class="small",
                percentile=0.8,
                reference_workload=_reference_workload(),
                reference_hardware=_hardware(),
            )


def test_derivation_revalidates_tampered_sample_complexity() -> None:
    complexity, _ = _complexity()
    sample = budget_v2.MeasuredSample(complexity, 100)
    object.__setattr__(complexity, "changed_bytes", math.nan)
    with pytest.raises(ValueError):
        budget_v2.derive_budget(
            (sample,),
            workload_class="small",
            percentile=0.8,
            reference_workload=_reference_workload(),
            reference_hardware=_hardware(),
        )


def test_reference_workload_identity_covers_complete_sample_reference() -> None:
    first = _reference_workload()
    other_reference, _ = stored_artifact(b"samples", artifact_id="other-sample-artifact")
    second = replace(first, sample_artifact=other_reference, record_digest="")
    assert first.record_digest != second.record_digest


@pytest.mark.parametrize("elapsed", [0, -1, math.inf, math.nan])
def test_measured_sample_refuses_nonpositive_or_nonfinite_reply_time(elapsed: float) -> None:
    complexity, _ = _complexity()
    with pytest.raises((TypeError, ValueError)):
        budget_v2.MeasuredSample(complexity, elapsed)  # type: ignore[arg-type]


def test_budget_gate_resolves_exact_changed_byte_measurement() -> None:
    complexity, resolver = _complexity(changed_bytes=120)
    budget_v2.check_budget(complexity, 100, _derivation(), resolver)


def test_budget_gate_refuses_unreadable_zero_or_substituted_measurement() -> None:
    complexity, resolver = _complexity(changed_bytes=120)
    missing = InMemoryContentResolver({})
    zero_reference, zero_resolver = _measurement(0)
    with pytest.raises(ValueError):
        replace(complexity, changed_bytes=0, measurement=zero_reference)
    substituted = replace(complexity, changed_bytes=121)
    assert zero_resolver.resolve(zero_reference).content
    for change, selected in ((complexity, missing), (substituted, resolver)):
        with pytest.raises((canonical.ArtifactResolutionError, canonical.ArtifactValidationError, ValueError)):
            budget_v2.check_budget(change, 100, _derivation(), selected)


def test_budget_gate_names_change_elapsed_class_and_derivation() -> None:
    complexity, resolver = _complexity()
    derivation = _derivation()
    with pytest.raises(budget_v2.BudgetGateFailure) as caught:
        budget_v2.check_budget(complexity, derivation.budget_ms + 1, derivation, resolver)
    message = str(caught.value)
    assert complexity.change_id in message
    assert str(derivation.budget_ms + 1) in message
    assert derivation.workload_class in message
    assert derivation.derivation_digest in message


def test_budget_gate_refuses_tampered_derivation_and_incompatible_change() -> None:
    complexity, resolver = _complexity()
    derivation = _derivation()
    object.__setattr__(derivation, "sample_count", 99)
    with pytest.raises(ValueError):
        budget_v2.check_budget(complexity, 100, derivation, resolver)
    incompatible, incompatible_resolver = _complexity(changed_regions=4)
    with pytest.raises(ValueError):
        budget_v2.check_budget(incompatible, 100, _derivation(), incompatible_resolver)


def test_scope_accepts_contained_regions_and_semantic_anchors() -> None:
    allowed = _scope(evidence.SourceRegion("src/app.py", 1, 30), evidence.SourceRegion("src/other.py", 1, 5))
    packet = _packet(scope=_scope(evidence.SourceRegion("src/app.py", 5, 20)))
    evidence.validate_scope(packet, allowed)


def test_scope_refuses_revision_change_or_region_escape() -> None:
    allowed = _scope(evidence.SourceRegion("src/app.py", 1, 30))
    wrong_change = evidence.AnalyzedScope("base", "head", _digest("different"), allowed.regions)
    escaped = _packet(scope=_scope(evidence.SourceRegion("src/app.py", 1, 31)))
    for packet, boundary in ((_packet(), wrong_change), (escaped, allowed)):
        with pytest.raises(evidence.ScopeValidationError):
            evidence.validate_scope(packet, boundary)


def test_scope_refuses_relation_anchor_outside_declared_packet_region() -> None:
    packet = _packet(line=25, scope=_scope(evidence.SourceRegion("src/app.py", 1, 20)))
    with pytest.raises(evidence.ScopeValidationError):
        evidence.validate_scope(packet, _scope())


def _location_field(name: str, *, line: int) -> semantics.FieldValue:
    return semantics.FieldValue(
        name,
        semantics.FieldKind.SOURCE_LOCATION,
        {"path": "src/app.py", "line": line, "column": 0, "symbol": "handle"},
    )


def test_scope_refuses_out_of_scope_observation_embedded_location() -> None:
    packet = _packet(observation_fields=(_location_field("related_site", line=31),))
    with pytest.raises(evidence.ScopeValidationError):
        evidence.validate_scope(packet, _scope())


def test_scope_refuses_out_of_scope_family_field_location() -> None:
    packet = _packet(
        scope=_scope(evidence.SourceRegion("src/app.py", 1, 20)),
        family_fields=(_location_field("claim_site", line=25),),
    )
    with pytest.raises(evidence.ScopeValidationError):
        evidence.validate_scope(packet, _scope())


def test_scope_revalidates_object_setattr_field_tampering() -> None:
    field = _location_field("claim_site", line=10)
    packet = _packet(family_fields=(field,))
    object.__setattr__(field, "value", {"path": "src/other.py", "line": 1, "column": 0, "symbol": None})
    with pytest.raises(evidence.ScopeValidationError):
        evidence.validate_scope(packet, _scope())


def test_source_location_field_mapping_is_deeply_immutable() -> None:
    field = _location_field("claim_site", line=10)
    with pytest.raises(TypeError):
        cast(dict[str, object], field.value)["line"] = 31


def test_scope_revalidates_post_construction_tampering() -> None:
    allowed = _scope()
    object.__setattr__(allowed.regions[0], "end_line", 0)
    with pytest.raises((evidence.EvidenceValidationError, evidence.ScopeValidationError)):
        evidence.validate_scope(_packet(), allowed)


def test_legacy_budget_api_remains_available() -> None:
    samples = ((budget_v2.Complexity(1, 1, 10), 1.0), (budget_v2.Complexity(2, 2, 20), 2.0))
    legacy = budget_v2.derive_budget(samples, workload_class="legacy", percentile=0.5, hardware="runner")
    assert isinstance(legacy, budget_v2.Budget)
    budget_v2.check_budget(change_id="change", seconds=1.0, budget=legacy)
