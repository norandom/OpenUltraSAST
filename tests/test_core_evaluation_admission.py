"""Integrated public facade for evaluation-admission V3."""

from __future__ import annotations

import pytest
from test_core_evaluation_authority import _authority_case
from test_core_evaluation_replay import _assemble, _inputs
from test_core_evaluation_replay_validation import _bundle_case
from test_core_evaluation_spend import _append_without_precheck

from openultrasast.core import __all__ as core_exports
from openultrasast.core import admission
from openultrasast.core.evaluation_version import EVALUATION_ADMISSION_V3_SCHEMA


def _raw_copy(value, *, mutation: str | None = None, **changes):
    copied = object.__new__(type(value))
    values = {**vars(value), **changes}
    missing = next(iter(vars(value)))
    for name, item in values.items():
        if mutation != "missing" or name != missing:
            object.__setattr__(copied, name, item)
    if mutation == "extra":
        object.__setattr__(copied, "undeclared_phase_field", "forbidden")
    return copied


def test_public_surface_adds_only_the_separate_v3_facade() -> None:
    from openultrasast.core import evaluation_admission

    assert "evaluation_admission" in core_exports
    assert "EVALUATION_ADMISSION_V3_SCHEMA" not in admission.__all__
    assert not set(evaluation_admission.__all__) & {"authorize_admission", "score_admission"}


def test_facade_preflight_authorization_and_shared_spend_form_exact_phase_chain() -> None:
    from openultrasast.core import evaluation_admission

    case = _authority_case()
    context_case, manifest, expected_feasibility, readiness, _, resolver = case
    feasibility = evaluation_admission.preflight_evaluation(
        manifest.plan_manifest,
        context_case.context,
        resolver,
    )
    assert feasibility == expected_feasibility

    preparation = evaluation_admission.authorize_evaluation(
        manifest,
        feasibility,
        readiness,
        context_case.context,
        context_case.port,
        resolver,
    )
    receipt = _append_without_precheck(case, preparation)
    binding = evaluation_admission.validate_shared_spend(
        manifest,
        preparation,
        receipt,
        context_case.context,
        context_case.port,
    )

    assert preparation.authority.feasibility_digest == feasibility.feasibility_digest
    assert binding.preparation_digest == preparation.preparation_digest
    assert binding.receipt_digest == receipt.receipt_digest


def test_facade_scores_and_independently_validates_one_complete_replay() -> None:
    from openultrasast.core import evaluation_admission

    bundle = _bundle_case()
    canonical_inputs = _inputs(bundle=bundle, canonical_sources=True)
    expected = _assemble(*canonical_inputs)
    context_case = bundle[5][0]
    source = canonical_inputs[9]
    aggregate = canonical_inputs[14]
    assert aggregate is not None

    replay = evaluation_admission.score_and_replay(
        bundle[3],
        canonical_inputs[1],
        bundle[7],
        bundle[8],
        canonical_inputs[6],
        bundle[1],
        bundle[2],
        source.readiness,
        context_case.context,
        context_case.port,
        bundle[4],
        aggregate_weights=aggregate.weights,
    )

    assert replay == expected
    assert (
        evaluation_admission.validate_evaluation_replay(
            replay,
            context_case.context,
            context_case.port,
            bundle[4],
        )
        == replay.reports
    )


def test_strict_root_decoder_accepts_only_the_named_exact_v3_contract() -> None:
    from openultrasast.core import evaluation_admission
    from openultrasast.core.admission_report import AdmissionReplay
    from openultrasast.core.evaluation_replay import EvaluationReplayV3

    replay = _assemble(*_inputs(bundle=_bundle_case(), canonical_sources=True))
    assert (
        evaluation_admission.decode_evaluation_v3(
            EVALUATION_ADMISSION_V3_SCHEMA,
            replay,
            EvaluationReplayV3,
        )
        is replay
    )

    with pytest.raises(Exception, match="V2|convert|schema"):
        evaluation_admission.decode_evaluation_v3(
            "openultrasast.detection-core.admission-replay.v2",
            object.__new__(AdmissionReplay),
            EvaluationReplayV3,
        )
    with pytest.raises(Exception, match="unknown|schema"):
        evaluation_admission.decode_evaluation_v3("openultrasast.unknown.v9", replay, EvaluationReplayV3)
    with pytest.raises(Exception, match="exact|EvaluationReplayV3"):
        evaluation_admission.decode_evaluation_v3(
            EVALUATION_ADMISSION_V3_SCHEMA,
            replay.report_source,
            EvaluationReplayV3,
        )


def test_wrong_phase_and_mixed_roots_fail_at_the_facade_boundary() -> None:
    from openultrasast.core import evaluation_admission
    from openultrasast.core.admission_review import AdmissionManifestV2
    from openultrasast.core.evaluation_replay import EvaluationReplayV3

    case = _authority_case()
    context_case, manifest, feasibility, readiness, _, resolver = case
    with pytest.raises(Exception, match="plan|exact|V3"):
        evaluation_admission.preflight_evaluation(
            object.__new__(AdmissionManifestV2),
            context_case.context,
            resolver,
        )
    with pytest.raises(Exception, match="feasibility|exact|phase"):
        evaluation_admission.authorize_evaluation(
            manifest,
            object(),
            readiness,
            context_case.context,
            context_case.port,
            resolver,
        )

    replay = _assemble(*_inputs(bundle=_bundle_case(), canonical_sources=True))

    class ReplaySubclass(EvaluationReplayV3):
        """Wrong exact root used only by this boundary regression."""

    substituted = object.__new__(ReplaySubclass)
    for field, value in replay.__dict__.items():
        object.__setattr__(substituted, field, value)
    with pytest.raises(Exception, match="exact|replay|V3"):
        evaluation_admission.validate_evaluation_replay(
            substituted,
            _bundle_case()[5][0].context,
            _bundle_case()[5][0].port,
            _bundle_case()[4],
        )


@pytest.mark.parametrize("mutation", ("extra", "missing"))
@pytest.mark.parametrize("root_index", (0, 1, 2, 4, 6, 7, 15))
def test_every_public_phase_root_requires_exact_declared_instance_fields(root_index: int, mutation: str) -> None:
    from openultrasast.core import evaluation_admission

    inputs = _inputs(bundle=_bundle_case(), canonical_sources=True)
    replay = _assemble(*inputs)
    roots = (*inputs, replay)
    original = roots[root_index]
    changed = _raw_copy(original, mutation=mutation)

    with pytest.raises(Exception, match="declared fields|missing|exact|refused"):
        evaluation_admission.decode_evaluation_v3(
            EVALUATION_ADMISSION_V3_SCHEMA,
            changed,
            type(original),
        )


@pytest.mark.parametrize("mutation", ("extra", "missing"))
@pytest.mark.parametrize("target", ("receipt", "request"))
def test_shared_spend_closes_receipt_and_nested_request_before_validation(target: str, mutation: str) -> None:
    from openultrasast.core import evaluation_admission

    case = _authority_case()
    context_case, manifest, feasibility, readiness, _, resolver = case
    preparation = evaluation_admission.authorize_evaluation(
        manifest, feasibility, readiness, context_case.context, context_case.port, resolver
    )
    receipt = _append_without_precheck(case, preparation)
    if target == "request":
        receipt = _raw_copy(receipt, request=_raw_copy(receipt.request, mutation=mutation))
    else:
        receipt = _raw_copy(receipt, mutation=mutation)

    with pytest.raises(Exception, match="declared fields|missing|receipt|request|closed"):
        evaluation_admission.validate_shared_spend(manifest, preparation, receipt, context_case.context, context_case.port)


def _score_with(bundle, canonical_inputs, *, groups=None, readiness=None, weights=None):
    from openultrasast.core import evaluation_admission

    context_case = bundle[5][0]
    return evaluation_admission.score_and_replay(
        bundle[3],
        canonical_inputs[1],
        bundle[7],
        bundle[8],
        canonical_inputs[6],
        bundle[1],
        canonical_inputs[8] if groups is None else groups,
        canonical_inputs[9].readiness if readiness is None else readiness,
        context_case.context,
        context_case.port,
        bundle[4],
        aggregate_weights=canonical_inputs[14].weights if weights is None else weights,
    )


@pytest.mark.parametrize("mutation", ("extra", "missing"))
@pytest.mark.parametrize("target", ("case_group", "case_item", "readiness", "aggregate_weight"))
def test_scoring_closes_every_nonroot_phase_input_before_derivation(target: str, mutation: str) -> None:
    bundle = _bundle_case()
    inputs = _inputs(bundle=bundle, canonical_sources=True)
    groups = inputs[8]
    readiness = inputs[9].readiness
    aggregate = inputs[14]
    assert aggregate is not None
    weights = aggregate.weights
    if target == "case_group":
        groups = (_raw_copy(groups[0], mutation=mutation),) + groups[1:]
    elif target == "case_item":
        changed_case = _raw_copy(groups[0].cases[0], mutation=mutation)
        groups = (_raw_copy(groups[0], cases=(changed_case,) + groups[0].cases[1:]),) + groups[1:]
    elif target == "readiness":
        readiness = (_raw_copy(readiness[0], mutation=mutation),) + readiness[1:]
    else:
        weights = (_raw_copy(weights[0], mutation=mutation),) + weights[1:]

    with pytest.raises(Exception, match="declared fields|missing|readiness|case|weight|closed"):
        _score_with(bundle, inputs, groups=groups, readiness=readiness, weights=weights)


def test_facade_exposes_no_benchmark_execution_storage_or_presentation_ownership() -> None:
    from openultrasast.core import evaluation_admission

    forbidden = {
        "execute_detector",
        "run_benchmark",
        "store_observation",
        "reserve_population",
        "notify_operator",
        "render_report",
    }
    assert forbidden.isdisjoint(evaluation_admission.__all__)
    assert all("benchmark" not in name and "presentation" not in name for name in evaluation_admission.__all__)
