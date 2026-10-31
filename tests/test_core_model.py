"""Dependency-free, reproducible model handoff contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical, evidence, family, model, provenance, semantics


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _contract() -> family.FamilyContract:
    return family.FamilyContract(
        "reference-family",
        "1",
        evidence.EVIDENCE_PACKET_SCHEMA,
        ("python",),
        family.ObjectSpec(
            "resource",
            (family.FieldSpec("name", semantics.FieldKind.TEXT, True),),
            ("name",),
        ),
        (
            family.RoleSpec(
                "flow",
                (),
                (semantics.RelationKind.CALL,),
                family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
            ),
            family.RoleSpec(
                "security_object",
                (family.FieldSpec("kind", semantics.FieldKind.TEXT, True),),
                (),
                family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
            ),
        ),
        (
            family.DecisionRule(
                "unsafe",
                evidence.NeutralOutcome.VIOLATION,
                ("flow", "security_object"),
                (semantics.RelationStatus.COMPLETE,),
            ),
            family.DecisionRule(
                "safe",
                evidence.NeutralOutcome.SATISFIED,
                ("flow", "security_object"),
                (semantics.RelationStatus.COMPLETE,),
            ),
        ),
        (family.ResidualQuestion("classify", ("flow", "security_object"), ("unsafe", "safe")),),
        ("missing",),
    )


def _record(contract: family.FamilyContract) -> evidence.EvidenceRecord:
    location = semantics.SourceLocation("src/product.py", 7, 2, "handle")
    origin = semantics.EvidenceProvenance(semantics.ProvenanceKind.PRODUCT_CODE, _digest("source"), None, None, None)
    relation = semantics.make_relation(
        kind=semantics.RelationKind.CALL,
        role="flow",
        source=semantics.SemanticNode("source", "source", location),
        target=semantics.SemanticNode("target", "target", location),
        location=location,
        status=semantics.RelationStatus.COMPLETE,
        conditions=(),
        reasons=(),
        provenance=origin,
    )
    observation = semantics.make_observation(
        role="security_object",
        location=location,
        fields=(semantics.FieldValue("kind", semantics.FieldKind.TEXT, "resource"),),
        status=semantics.RelationStatus.COMPLETE,
        provenance=origin,
    )
    object_fields = (semantics.FieldValue("name", semantics.FieldKind.TEXT, "document"),)
    contract_digest = family.family_contract_digest(contract)
    scope = evidence.AnalyzedScope("base", "head", _digest("change"), (evidence.SourceRegion("src/product.py", 1, 20),))
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        contract_digest,
        family.derive_security_object_id(contract.security_object, object_fields),
        "python",
        scope,
        (relation,),
        (observation,),
        object_fields,
        (),
        provenance.ProvenanceStamp(
            _digest("analyzer"),
            contract_digest,
            _digest("facts"),
            _digest("acquisition"),
            _digest("configuration"),
            _digest("population"),
            _digest("change-input"),
        ),
    )
    decision = evidence.Decision(
        "unsafe",
        evidence.NeutralOutcome.VIOLATION,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        (),
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, decision, "")


@dataclass(frozen=True)
class HandoffCase:
    contract: family.FamilyContract
    record: evidence.EvidenceRecord
    request: model.ModelRequest
    response: model.PreservedModelResponse
    result: model.ModelResult
    resolver: InMemoryContentResolver


def _case(*, artifact_response: bool = False, failed: bool = False) -> HandoffCase:
    contract = _contract()
    record = _record(contract)
    question = contract.residual_questions[0]
    completeness = model.completeness_snapshot(record, contract)
    bundle = model.derive_model_input_bundle_digest(record, contract, question, completeness)
    lineage_digest = provenance.derive_lineage_manifest_digest("model-arm", bundle, ())
    lineage = provenance.LineageManifest("model-arm", bundle, (), lineage_digest)
    program = model.make_model_program_declaration(
        family_contract_digest=family.family_contract_digest(contract),
        provider="provider",
        model_name="model-v1",
        program_digest=_digest("program"),
        prompt_digest=_digest("prompt"),
        example_set_digest=_digest("examples"),
        fitted_component_digest=_digest("fitted"),
        configuration_digest=_digest("model-configuration"),
        adapter_revision="adapter-v1",
        decision_mapping_digest=_digest("mapping"),
        input_bundle_digest=bundle,
        lineage_manifest_digest=lineage.manifest_digest,
    )
    request = model.make_model_request(
        record=record,
        contract=contract,
        residual_question_id=question.question_id,
        program=program,
        lineage=lineage,
        custody_policy_digest=_digest("custody-policy"),
        proposal_program_digests=(_digest("proposer"),),
        trusted_response_store_identities=("trusted-store",),
        maximum_response_bytes=256,
    )
    raw_response = b'{"decision":"unsafe"}'
    reference, resolver = stored_artifact(raw_response, artifact_id="model-response")
    response = model.make_preserved_model_response(
        normalized_fields=(semantics.FieldValue("decision", semantics.FieldKind.TEXT, "unsafe"),),
        inline_redacted_text=None if artifact_response else "[redacted] unsafe",
        artifact=reference if artifact_response else None,
        redaction_policy_digest=_digest("redaction-policy"),
    )
    result = model.make_model_result(
        request=request,
        status=model.ModelStatus.FAILED if failed else model.ModelStatus.SUCCEEDED,
        response=response,
        family_decision=None if failed else "unsafe",
        failure_reason="provider_timeout" if failed else None,
    )
    return HandoffCase(contract, record, request, response, result, resolver)


@pytest.mark.parametrize("artifact_response", [False, True])
def test_success_request_and_result_round_trip_canonically(artifact_response: bool) -> None:
    case = _case(artifact_response=artifact_response)
    request_bytes = model.model_request_bytes(case.request)
    result_bytes = model.model_result_bytes(case.result)

    assert len(request_bytes) > 0 and len(result_bytes) > 0
    assert json.dumps(json.loads(request_bytes), sort_keys=True, separators=(",", ":")).encode() == request_bytes
    assert json.dumps(json.loads(result_bytes), sort_keys=True, separators=(",", ":")).encode() == result_bytes
    model.validate_model_result(case.request, case.result, case.resolver)


def test_failed_result_preserves_bounded_response_and_named_failure() -> None:
    case = _case(failed=True)

    model.validate_model_result(case.request, case.result, case.resolver)

    assert case.result.response == case.response
    assert case.result.failure_reason == "provider_timeout"
    assert case.result.family_decision is None


def test_request_contains_exact_record_contract_question_and_completeness() -> None:
    case = _case()

    assert case.request.record is case.record
    assert case.request.contract is case.contract
    assert case.request.residual_question == case.contract.residual_questions[0]
    assert case.request.packet_digest == evidence.derive_packet_digest(case.record.packet)
    assert case.request.completeness == (
        model.CompletenessItem("flow", semantics.RelationStatus.COMPLETE, ()),
        model.CompletenessItem("security_object", semantics.RelationStatus.COMPLETE, ()),
    )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("packet_digest", _digest("other-packet"), "packet"),
        ("family_contract_digest", _digest("other-contract"), "family contract"),
        ("residual_question_id", "other-question", "residual"),
        ("completeness_digest", _digest("other-completeness"), "completeness"),
    ],
)
def test_request_refuses_substituted_redundant_identity(field: str, replacement: str, message: str) -> None:
    case = _case()
    object.__setattr__(case.request, field, replacement)

    with pytest.raises(model.ModelContractError, match=message):
        model.model_request_bytes(case.request)


def test_request_refuses_substituted_record_program_and_mapping() -> None:
    case = _case()
    other_record = _record(case.contract)
    object.__setattr__(other_record.packet, "security_object_id", "substituted")
    object.__setattr__(case.request, "record", other_record)

    with pytest.raises(model.ModelContractError):
        model.model_request_bytes(case.request)

    case = _case()
    object.__setattr__(case.request.program, "program_digest", _digest("substituted-program"))
    with pytest.raises(model.ModelContractError, match="declaration"):
        model.model_request_bytes(case.request)

    case = _case()
    object.__setattr__(case.request.program, "decision_mapping_digest", _digest("substituted-mapping"))
    with pytest.raises(model.ModelContractError, match="declaration"):
        model.model_request_bytes(case.request)


def test_request_and_result_refuse_substituted_record_identity() -> None:
    case = _case()
    object.__setattr__(case.request.record, "record_id", _digest("substituted-record-identity"))

    with pytest.raises(model.ModelContractError, match="record identity"):
        model.model_request_bytes(case.request)
    with pytest.raises(model.ModelContractError, match="record identity"):
        model.validate_model_result(case.request, case.result, case.resolver)


def test_result_refuses_substituted_request_packet_program_mapping_and_response() -> None:
    mutations = (
        ("request_digest", _digest("other-request"), "request"),
        ("packet_digest", _digest("other-packet"), "packet"),
        ("decision_mapping_digest", _digest("other-mapping"), "mapping"),
    )
    for field, replacement, message in mutations:
        case = _case()
        object.__setattr__(case.result, field, replacement)
        with pytest.raises(model.ModelContractError, match=message):
            model.validate_model_result(case.request, case.result, case.resolver)

    case = _case()
    object.__setattr__(case.result.identity, "program_digest", _digest("other-program"))
    with pytest.raises(model.ModelContractError, match="program"):
        model.validate_model_result(case.request, case.result, case.resolver)

    case = _case()
    object.__setattr__(case.result.response, "inline_redacted_text", "substituted response")
    with pytest.raises(model.ModelContractError, match="response"):
        model.validate_model_result(case.request, case.result, case.resolver)


def test_artifact_response_requires_trusted_resolved_bytes() -> None:
    case = _case(artifact_response=True)
    model.validate_model_result(case.request, case.result, case.resolver)

    with pytest.raises(model.ModelContractError, match="response artifact"):
        model.validate_model_result(case.request, case.result, InMemoryContentResolver({}))


def test_inline_response_must_be_bounded_and_exactly_one_preservation_form() -> None:
    case = _case()
    object.__setattr__(case.request, "maximum_response_bytes", 4)
    with pytest.raises(model.ModelContractError, match="maximum"):
        model.validate_model_result(case.request, case.result, case.resolver)

    with pytest.raises(model.ModelContractError, match="exactly one"):
        model.make_preserved_model_response(
            normalized_fields=case.response.normalized_fields,
            inline_redacted_text="inline",
            artifact=stored_artifact(b"artifact")[0],
            redaction_policy_digest=_digest("redaction-policy"),
        )


def test_failure_without_received_response_is_preserved() -> None:
    case = _case()
    result = model.make_model_result(
        request=case.request,
        status=model.ModelStatus.FAILED,
        response=None,
        family_decision=None,
        failure_reason="no_response",
    )

    model.validate_model_result(case.request, result, case.resolver)
    assert result.response is None


def test_core_model_contract_has_no_runtime_dependency_imports() -> None:
    with open(model.__file__, encoding="utf-8") as source_file:
        source = source_file.read()

    assert "import dspy" not in source
    assert "litellm" not in source
    assert "openai" not in source
