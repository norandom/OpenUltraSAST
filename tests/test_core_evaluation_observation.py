"""Exact nonzero sealed-observation validation for evaluation admission V3."""

from __future__ import annotations

import json
from dataclasses import fields, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_evaluation_plan import _declaration, _digest

from openultrasast.core import canonical
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionV3
from openultrasast.core.evaluation_measurement import CaseOutcomeProjectionPolicyV3
from openultrasast.core.evaluation_observation import (
    ArmObservationSetV3,
    EvaluationObservationError,
    ObservationCaseRefV3,
    SealedObservationRefV3,
    decode_arm_observation_set,
    encode_arm_observation_set,
    validate_evaluation_observations,
)
from openultrasast.core.evaluation_version import NonAuthorizingV3
from openultrasast.core.evidence import NeutralOutcome


def _projection(
    case_number: int | str,
    policy: CaseOutcomeProjectionPolicyV3 = CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
) -> CaseOutcomeProjectionV3:
    case_input = _digest(f"case-input-{case_number}")
    return CaseOutcomeProjectionV3(
        case_input,
        policy,
        (_digest(f"record-{case_number}"),),
        NeutralOutcome.SATISFIED,
        "",
    )


def _observation(slot, configuration, *, case_number: int | None = None) -> ArmObservationSetV3:
    cases = ()
    if case_number is not None:
        projection = _projection(case_number, configuration.case_outcome_policy)
        cases = (
            ObservationCaseRefV3(
                _digest(f"case-{case_number}"),
                projection.case_input_digest,
                _digest(f"push-{case_number}"),
                _digest(f"result-{case_number}"),
                projection,
                _digest(f"proof-{case_number}"),
            ),
        )
    return ArmObservationSetV3(
        slot.slot_digest,
        slot.arm_id,
        slot.input_identity_digest,
        slot.execution_identity,
        configuration.registered_budget_digest,
        configuration.configuration_identity_digest,
        _digest(f"read-{slot.slot_digest}"),
        _digest(f"stages-{slot.slot_digest}"),
        cases,
        "",
    )


def _seal(observation: ArmObservationSetV3, artifact_id: str) -> tuple[SealedObservationRefV3, canonical.ResolvedContent]:
    reference, resolver = stored_artifact(encode_arm_observation_set(observation), artifact_id=artifact_id)
    sealed = SealedObservationRefV3(
        observation.slot_digest,
        observation.arm_id,
        observation.input_identity_digest,
        observation.execution_identity,
        observation.registered_budget_digest,
        observation.configuration_digest,
        reference,
        observation.observation_digest,
        observation.input_read_evidence_digest,
        "",
    )
    return sealed, resolver.artifacts[artifact_id]


def _bundle():
    declaration = _declaration()
    configurations = {row.arm_id: row for row in declaration.arm_configurations}
    sealed = []
    artifacts = {}
    observations = []
    for index, slot in enumerate(declaration.expected_observation_slots):
        observation = _observation(slot, configurations[slot.arm_id], case_number=index if index % 2 else None)
        reference, resolved = _seal(observation, f"observation-{index}")
        observations.append(observation)
        sealed.append(reference)
        artifacts[reference.observation.artifact_id] = resolved
    return declaration, tuple(observations), tuple(sealed), InMemoryContentResolver(artifacts)


def _validate(declaration, sealed, resolver):
    return validate_evaluation_observations(
        declaration,
        sealed,
        resolver,
        trusted_store_identities=("trusted-store",),
        maximum_bytes=4096,
    )


def test_complete_canonical_slot_set_resolves_nonzero_observations() -> None:
    declaration, observations, sealed, resolver = _bundle()
    assert _validate(declaration, sealed, resolver) == observations
    assert all(reference.observation.byte_length > 0 for reference in sealed)
    assert all(observation.input_read_evidence_digest != "0" * 64 for observation in observations)
    assert all(observation.stage_execution_evidence_digest != "0" * 64 for observation in observations)


@pytest.mark.parametrize(
    ("arm_id", "substituted_policy"),
    (
        ("arm-a", CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE),
        ("arm-combined", CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE),
    ),
)
def test_observation_case_policy_must_equal_planned_arm_policy(
    arm_id: str,
    substituted_policy: CaseOutcomeProjectionPolicyV3,
) -> None:
    declaration, observations, sealed, resolver = _bundle()
    index = next(index for index, item in enumerate(observations) if item.arm_id == arm_id and item.cases)
    original = observations[index]
    original_case = original.cases[0]
    sources = original_case.outcome_projection.source_outcome_digests
    if substituted_policy is CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE:
        sources = tuple(dict.fromkeys(sources))
    projection = CaseOutcomeProjectionV3(
        original_case.case_input_digest,
        substituted_policy,
        sources,
        original_case.outcome_projection.normalized_outcome,
        "",
    )
    changed_case = replace(original_case, outcome_projection=projection)
    changed_observation = replace(original, cases=(changed_case,), observation_digest="")
    changed_ref, changed_content = _seal(changed_observation, f"wrong-policy-{arm_id}")
    changed_sealed = sealed[:index] + (changed_ref,) + sealed[index + 1 :]
    changed_resolver = InMemoryContentResolver({**resolver.artifacts, changed_ref.observation.artifact_id: changed_content})

    with pytest.raises(EvaluationObservationError, match="policy"):
        _validate(declaration, changed_sealed, changed_resolver)


def test_observation_contracts_are_exact_v3_non_authorizing_and_label_blind() -> None:
    case_fields = {item.name for item in fields(ObservationCaseRefV3)}
    observation_fields = {item.name for item in fields(ArmObservationSetV3)}
    sealed_fields = {item.name for item in fields(SealedObservationRefV3)}
    assert case_fields == {
        "case_id_digest",
        "case_input_digest",
        "underlying_push_digest",
        "result_digest",
        "outcome_projection",
        "proof_candidate_digest",
    }
    assert observation_fields == {
        "slot_digest",
        "arm_id",
        "input_identity_digest",
        "execution_identity",
        "registered_budget_digest",
        "configuration_digest",
        "input_read_evidence_digest",
        "stage_execution_evidence_digest",
        "cases",
        "observation_digest",
    }
    assert sealed_fields == {
        "slot_digest",
        "arm_id",
        "input_identity_digest",
        "execution_identity",
        "registered_budget_digest",
        "configuration_digest",
        "observation",
        "observation_digest",
        "read_receipt_digest",
        "ref_digest",
    }
    for value_type in (ObservationCaseRefV3, ArmObservationSetV3, SealedObservationRefV3):
        assert issubclass(value_type, NonAuthorizingV3)
        assert not {"label", "labels", "role", "ground_truth", "authorize"} & {item.name for item in fields(value_type)}


def test_canonical_round_trip_preserves_clean_and_proof_candidate_observations() -> None:
    _, observations, _, _ = _bundle()
    for observation in observations:
        encoded = encode_arm_observation_set(observation)
        assert encoded
        assert decode_arm_observation_set(encoded) == observation
        assert json.dumps(json.loads(encoded), sort_keys=True, separators=(",", ":")).encode() == encoded
        assert not hasattr(observation, "authorize")
        assert all(not hasattr(case, "demonstrated") for case in observation.cases)


def test_observation_case_projection_is_exact_and_nested_decoder_is_closed() -> None:
    _, observations, _, _ = _bundle()
    observation = next(item for item in observations if item.cases)
    case = observation.cases[0]
    with pytest.raises(EvaluationObservationError, match="input identity"):
        replace(case, case_input_digest=_digest("unrelated-case-input"))

    document = json.loads(encode_arm_observation_set(observation))
    document["cases"][0]["outcome_projection"]["unexpected"] = "field"
    changed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(EvaluationObservationError, match="malformed|field"):
        decode_arm_observation_set(changed)

    document = json.loads(encode_arm_observation_set(observation))
    document["cases"][0]["outcome_projection"]["projection_digest"] = _digest("tampered-projection")
    changed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(EvaluationObservationError, match="malformed|canonical"):
        decode_arm_observation_set(changed)


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "extra", "reordered"))
def test_slot_set_must_equal_the_canonical_plan_product(mutation: str) -> None:
    declaration, _, sealed, resolver = _bundle()
    if mutation == "missing":
        changed = sealed[:-1]
    elif mutation == "duplicate":
        changed = sealed + (sealed[-1],)
    elif mutation == "extra":
        changed = sealed + (replace(sealed[-1], slot_digest=_digest("unplanned-slot"), ref_digest=""),)
    else:
        changed = tuple(reversed(sealed))
    with pytest.raises(EvaluationObservationError):
        _validate(declaration, changed, resolver)


@pytest.mark.parametrize(
    "field,value",
    (
        ("slot_digest", _digest("other-slot")),
        ("arm_id", "other-arm"),
        ("input_identity_digest", _digest("other-input")),
        ("execution_identity", "other-execution"),
        ("registered_budget_digest", _digest("other-budget")),
        ("configuration_digest", _digest("other-configuration")),
        ("read_receipt_digest", _digest("other-read")),
    ),
)
def test_sealed_header_identity_mutation_is_refused(field: str, value: str) -> None:
    declaration, _, sealed, resolver = _bundle()
    changed = (replace(sealed[0], **{field: value, "ref_digest": ""}),) + sealed[1:]
    with pytest.raises(EvaluationObservationError):
        _validate(declaration, changed, resolver)


@pytest.mark.parametrize(
    "field,value",
    (
        ("slot_digest", _digest("other-slot")),
        ("arm_id", "other-arm"),
        ("input_identity_digest", _digest("other-input")),
        ("execution_identity", "other-execution"),
        ("registered_budget_digest", _digest("other-budget")),
        ("configuration_digest", _digest("other-configuration")),
        ("input_read_evidence_digest", _digest("other-read")),
    ),
)
def test_resolved_observation_identity_mutation_is_refused(field: str, value: str) -> None:
    declaration, observations, sealed, resolver = _bundle()
    changed_observation = replace(observations[0], **{field: value, "observation_digest": ""})
    changed_ref, changed_content = _seal(changed_observation, "changed-observation")
    header = replace(
        sealed[0],
        observation=changed_ref.observation,
        observation_digest=changed_ref.observation_digest,
        ref_digest="",
    )
    changed_resolver = InMemoryContentResolver({**resolver.artifacts, "changed-observation": changed_content})
    with pytest.raises(EvaluationObservationError):
        _validate(declaration, (header,) + sealed[1:], changed_resolver)


def test_cross_slot_content_swap_is_refused() -> None:
    declaration, _, sealed, resolver = _bundle()
    changed = replace(
        sealed[0],
        observation=sealed[1].observation,
        observation_digest=sealed[1].observation_digest,
        read_receipt_digest=sealed[1].read_receipt_digest,
        ref_digest="",
    )
    with pytest.raises(EvaluationObservationError):
        _validate(declaration, (changed,) + sealed[1:], resolver)


def test_unreadable_truncated_and_zero_byte_content_are_refused_before_parsing() -> None:
    declaration, _, sealed, resolver = _bundle()
    first = sealed[0]
    missing = InMemoryContentResolver({key: value for key, value in resolver.artifacts.items() if key != first.observation.artifact_id})
    with pytest.raises(canonical.ArtifactResolutionError):
        _validate(declaration, sealed, missing)

    resolved = resolver.artifacts[first.observation.artifact_id]
    truncated = replace(resolved, content=resolved.content[:-1])
    with pytest.raises(canonical.ArtifactValidationError):
        _validate(declaration, sealed, InMemoryContentResolver({**resolver.artifacts, first.observation.artifact_id: truncated}))

    zero_reference, zero_resolver = stored_artifact(b"", artifact_id="zero-observation")
    zero_header = replace(first, observation=zero_reference, ref_digest="")
    with pytest.raises(EvaluationObservationError, match="nonzero"):
        _validate(
            declaration,
            (zero_header,) + sealed[1:],
            InMemoryContentResolver({**resolver.artifacts, **zero_resolver.artifacts}),
        )


def test_noncanonical_changed_or_malformed_content_is_refused() -> None:
    declaration, observations, sealed, resolver = _bundle()
    pretty = json.dumps(json.loads(encode_arm_observation_set(observations[0])), indent=2).encode()
    pretty_ref, pretty_resolver = stored_artifact(pretty, artifact_id="pretty-observation")
    changed = replace(sealed[0], observation=pretty_ref, ref_digest="")
    with pytest.raises(EvaluationObservationError, match="canonical"):
        _validate(declaration, (changed,) + sealed[1:], InMemoryContentResolver({**resolver.artifacts, **pretty_resolver.artifacts}))

    class MalformedResolver:
        def resolve(self, reference):
            return object()

    with pytest.raises(EvaluationObservationError, match="malformed"):
        _validate(declaration, sealed, MalformedResolver())


def test_digest_case_order_duplicate_cases_and_zero_evidence_are_refused() -> None:
    declaration, observations, _, _ = _bundle()
    slot = declaration.expected_observation_slots[0]
    configuration = declaration.arm_configurations[0]
    first_projection = _projection("a")
    second_projection = _projection("b")
    first = ObservationCaseRefV3(
        _digest("case-a"), first_projection.case_input_digest, _digest("push-a"), _digest("result-a"), first_projection, None
    )
    second = ObservationCaseRefV3(
        _digest("case-b"),
        second_projection.case_input_digest,
        _digest("push-b"),
        _digest("result-b"),
        second_projection,
        _digest("proof-b"),
    )
    base = observations[0]
    with pytest.raises(EvaluationObservationError, match="canonical"):
        replace(base, cases=(second, first), observation_digest="")
    with pytest.raises(EvaluationObservationError, match="unique"):
        replace(base, cases=(first, first), observation_digest="")
    with pytest.raises(EvaluationObservationError, match="nonzero"):
        replace(base, input_read_evidence_digest="0" * 64, observation_digest="")
    with pytest.raises(EvaluationObservationError, match="nonzero"):
        replace(base, stage_execution_evidence_digest="0" * 64, observation_digest="")

    class CaseSubclass(ObservationCaseRefV3):
        pass

    with pytest.raises((EvaluationObservationError, TypeError, ValueError)):
        ArmObservationSetV3(
            slot.slot_digest,
            slot.arm_id,
            slot.input_identity_digest,
            slot.execution_identity,
            configuration.registered_budget_digest,
            configuration.configuration_identity_digest,
            _digest("read"),
            _digest("stages"),
            (
                CaseSubclass(
                    first.case_id_digest,
                    first.case_input_digest,
                    first.underlying_push_digest,
                    first.result_digest,
                    first.outcome_projection,
                    None,
                ),
            ),
            "",
        )


@pytest.mark.parametrize(
    "content",
    (
        b"{",
        b"[]",
        b'{"schema_version":"unknown"}',
        b'{"schema_version":"openultrasast.detection-core.evaluation-observation.v3","schema_version":"duplicate"}',
    ),
)
def test_decoder_refuses_malformed_unknown_or_duplicate_field_documents(content: bytes) -> None:
    with pytest.raises(EvaluationObservationError):
        decode_arm_observation_set(content)
