"""Atomic all-arm shared-spend binding for evaluation admission V3."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest
from test_core_evaluation_authority import _authority_case, _authorize
from test_core_evaluation_plan import _digest

from openultrasast.core import custody
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3
from openultrasast.core.evaluation_spend import (
    EvaluationPreparationV3,
    EvaluationSharedSpendError,
    EvaluationSpendBindingV3,
    bind_evaluation_spend,
    derive_evaluation_preparation_digest,
    prepare_evaluation_spend,
    validate_evaluation_preparation,
)
from openultrasast.core.evaluation_version import NonAuthorizingV3


def _prepare(case):
    context_case, manifest, _, _, _, _ = case
    authority = _authorize(case)
    preparation = prepare_evaluation_spend(
        manifest,
        authority,
        context_case.context,
        context_case.port,
    )
    return authority, preparation


def _spend(case, preparation: EvaluationPreparationV3):
    context_case = case[0]
    validate_evaluation_preparation(
        case[1],
        preparation,
        context_case.context,
        context_case.port,
    )
    return _append_without_precheck(case, preparation)


def _append_without_precheck(case, preparation: EvaluationPreparationV3):
    context_case = case[0]
    request = preparation.label_release_request
    current = context_case.port.current_log(request.population_digest)
    receipt = custody.record_population_use(
        request,
        current,
        current.custodian_identity,
        context_case.context.evidence.custody_policy,
    )
    context_case.port.logs[current.population_digest] = custody.append_population_use(
        current,
        receipt,
        context_case.context.evidence.custody_policy,
    )
    return receipt


def _bind(case, preparation, receipt):
    context_case = case[0]
    return bind_evaluation_spend(
        case[1],
        preparation,
        receipt,
        context_case.context,
        context_case.port,
    )


def test_preparation_is_pure_and_binds_plan_authority_all_baselines_and_head() -> None:
    case = _authority_case()
    context_case, manifest, _, _, _, _ = case
    population = manifest.plan_manifest.declaration.population_digest
    before = context_case.port.current_log(population)

    authority, preparation = _prepare(case)

    assert context_case.port.current_log(population) == before
    assert preparation.authority == authority
    assert preparation.planned_baseline_digests == authority.baseline_digests
    assert preparation.label_release_request == custody.PopulationUseRequest(
        population,
        manifest.plan_manifest.manifest_digest,
        custody.LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        authority.authority_digest,
        before.log_digest,
    )
    assert preparation.preparation_digest == derive_evaluation_preparation_digest(preparation)


def test_shared_spend_contracts_are_exact_v3_non_consumer_authorities() -> None:
    assert {item.name for item in fields(EvaluationPreparationV3)} == {
        "authority",
        "label_release_request",
        "planned_baseline_digests",
        "preparation_digest",
    }
    assert {item.name for item in fields(EvaluationSpendBindingV3)} == {
        "preparation_digest",
        "receipt_digest",
        "planned_baseline_digests",
        "binding_digest",
    }
    assert issubclass(EvaluationPreparationV3, NonAuthorizingV3)
    assert issubclass(EvaluationSpendBindingV3, NonAuthorizingV3)
    assert not hasattr(EvaluationSpendBindingV3, "authorize_consumer")


def test_exact_external_available_to_spent_successor_yields_all_arm_binding() -> None:
    case = _authority_case()
    authority, preparation = _prepare(case)
    receipt = _spend(case, preparation)

    binding = _bind(case, preparation, receipt)

    assert binding.preparation_digest == preparation.preparation_digest
    assert binding.receipt_digest == receipt.receipt_digest
    assert binding.planned_baseline_digests == authority.baseline_digests
    assert binding.binding_digest
    assert receipt.prior_status is custody.PopulationStatus.AVAILABLE
    assert receipt.status is custody.PopulationStatus.SPENT


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("population_digest", _digest("other-population")),
        ("arm_id", _digest("other-plan")),
        ("purpose", custody.LineagePurpose.PROMOTION),
        ("labels_accessed", False),
        ("influenced_artifact_digest", _digest("other-authority")),
        ("expected_log_digest", _digest("other-head")),
    ),
)
def test_every_release_request_identity_mutation_is_refused(field: str, value: object) -> None:
    case = _authority_case()
    authority, preparation = _prepare(case)
    request = replace(preparation.label_release_request, **{field: value})
    if field == "population_digest":
        changed = EvaluationPreparationV3(authority, request, authority.baseline_digests, "")
        with pytest.raises(EvaluationSharedSpendError, match="population"):
            validate_evaluation_preparation(
                case[1],
                changed,
                case[0].context,
                case[0].port,
            )
        receipt = _spend(case, preparation)
        with pytest.raises(EvaluationSharedSpendError):
            _bind(case, changed, receipt)
        return
    with pytest.raises(EvaluationSharedSpendError):
        EvaluationPreparationV3(authority, request, authority.baseline_digests, "")


@pytest.mark.parametrize("mutation", ("subset", "extra", "reordered"))
def test_partial_extra_or_reordered_planned_baselines_are_not_constructible(mutation: str) -> None:
    case = _authority_case()
    authority, preparation = _prepare(case)
    baselines = authority.baseline_digests
    if mutation == "subset":
        changed = baselines[:-1]
    elif mutation == "extra":
        changed = (*baselines, _digest("extra-baseline"))
    else:
        changed = tuple(reversed(baselines))
    with pytest.raises(EvaluationSharedSpendError, match="baseline"):
        EvaluationPreparationV3(authority, preparation.label_release_request, changed, "")


def test_substituted_authority_cannot_create_a_canonical_preparation() -> None:
    case = _authority_case()
    context_case, manifest, _, _, _, _ = case
    authority = _authorize(case)
    changed = replace(
        authority,
        feasibility_digest=_digest("other-feasibility"),
        authority_digest="",
    )
    with pytest.raises(EvaluationSharedSpendError, match="authority"):
        prepare_evaluation_spend(manifest, changed, context_case.context, context_case.port)


@pytest.mark.parametrize("mutation", ("subset", "extra", "reordered"))
def test_self_consistent_mutated_authority_cannot_pass_either_spend_boundary(mutation: str) -> None:
    case = _authority_case()
    authority, preparation = _prepare(case)
    assert len(authority.baseline_digests) == 3
    if mutation == "subset":
        changed_baselines = authority.baseline_digests[:-1]
    elif mutation == "extra":
        changed_baselines = (*authority.baseline_digests, _digest("extra-authority-baseline"))
    else:
        changed_baselines = tuple(reversed(authority.baseline_digests))
    changed_authority = replace(
        authority,
        baseline_digests=changed_baselines,
        authority_digest="",
    )
    changed_request = replace(
        preparation.label_release_request,
        influenced_artifact_digest=changed_authority.authority_digest,
    )
    changed_preparation = EvaluationPreparationV3(
        changed_authority,
        changed_request,
        changed_authority.baseline_digests,
        "",
    )
    with pytest.raises(EvaluationSharedSpendError, match="baseline|authority|manifest"):
        validate_evaluation_preparation(
            case[1],
            changed_preparation,
            case[0].context,
            case[0].port,
        )
    receipt = _append_without_precheck(case, changed_preparation)

    with pytest.raises(EvaluationSharedSpendError, match="baseline|authority|manifest"):
        _bind(case, changed_preparation, receipt)


def test_missing_or_mismatched_receipt_never_yields_a_binding() -> None:
    case = _authority_case()
    _, preparation = _prepare(case)
    with pytest.raises(EvaluationSharedSpendError, match="missing"):
        _bind(case, preparation, None)

    current = case[0].port.current_log(preparation.label_release_request.population_digest)
    wrong_request = replace(
        preparation.label_release_request,
        influenced_artifact_digest=_digest("wrong-authority"),
    )
    wrong = custody.record_population_use(
        wrong_request,
        current,
        current.custodian_identity,
        case[0].context.evidence.custody_policy,
    )
    case[0].port.logs[current.population_digest] = custody.append_population_use(
        current,
        wrong,
        case[0].context.evidence.custody_policy,
    )
    with pytest.raises(EvaluationSharedSpendError, match="preparation"):
        _bind(case, preparation, wrong)


def test_non_successor_and_availability_restoration_are_refused() -> None:
    case = _authority_case()
    _, preparation = _prepare(case)
    receipt = _spend(case, preparation)
    with pytest.raises(EvaluationSharedSpendError, match="successor"):
        _bind(case, preparation, replace(receipt, sequence=receipt.sequence + 1))
    with pytest.raises(EvaluationSharedSpendError, match="available to spent"):
        _bind(case, preparation, replace(receipt, status=custody.PopulationStatus.AVAILABLE))


def test_later_current_head_change_invalidates_the_once_winning_receipt() -> None:
    case = _authority_case()
    _, preparation = _prepare(case)
    winner = _spend(case, preparation)
    context_case = case[0]
    population = preparation.label_release_request.population_digest
    current = context_case.port.current_log(population)
    later_request = custody.PopulationUseRequest(
        population,
        "post-spend-audit",
        custody.LineagePurpose.PROMOTION,
        False,
        _digest("post-spend-artifact"),
        current.log_digest,
    )
    later = custody.record_population_use(
        later_request,
        current,
        current.custodian_identity,
        context_case.context.evidence.custody_policy,
    )
    context_case.port.logs[population] = custody.append_population_use(
        current,
        later,
        context_case.context.evidence.custody_policy,
    )
    with pytest.raises(EvaluationSharedSpendError, match="successor"):
        _bind(case, preparation, winner)


@pytest.mark.parametrize("mutation", ("broken_chain", "restored_available"))
def test_broken_or_availability_restored_current_log_is_refused(mutation: str) -> None:
    case = _authority_case()
    _, preparation = _prepare(case)
    receipt = _spend(case, preparation)
    context_case = case[0]
    population = preparation.label_release_request.population_digest
    current = context_case.port.current_log(population)
    if mutation == "broken_chain":
        broken_head = replace(current.receipts[-1], predecessor_digest=_digest("broken-predecessor"))
        changed = replace(current, receipts=(*current.receipts[:-1], broken_head))
    else:
        changed = replace(current, status=custody.PopulationStatus.AVAILABLE)
    context_case.port.logs[population] = changed
    with pytest.raises(EvaluationSharedSpendError):
        _bind(case, preparation, receipt)


def test_two_stale_preparations_allow_only_the_external_cas_winner() -> None:
    case = _authority_case()
    _, first = _prepare(case)
    _, second = _prepare(case)
    assert first == second
    winner = _spend(case, first)
    with pytest.raises(EvaluationSharedSpendError, match="stale|unavailable"):
        _spend(case, second)
    assert _bind(case, first, winner).planned_baseline_digests == first.planned_baseline_digests


def test_subclasses_and_forged_binding_digest_are_refused() -> None:
    case = _authority_case()
    _, preparation = _prepare(case)
    receipt = _spend(case, preparation)
    binding = _bind(case, preparation, receipt)
    with pytest.raises(EvaluationSharedSpendError, match="canonical"):
        replace(binding, binding_digest=_digest("forged-binding"))

    class DerivedAuthority(EvaluationAdmissionAuthorityV3):
        pass

    derived = object.__new__(DerivedAuthority)
    with pytest.raises((EvaluationSharedSpendError, TypeError, ValueError)):
        EvaluationPreparationV3(
            derived,
            preparation.label_release_request,
            preparation.planned_baseline_digests,
            "",
        )
