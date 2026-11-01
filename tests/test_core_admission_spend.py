"""Pre-label population spend protocol (Requirements 12.2 and 13.4)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_admission_context import AdmissionCase, _case, _resign_manifest

from openultrasast.core import canonical, custody, validation
from openultrasast.core.admission_context import make_admission_validation_context
from openultrasast.core.admission_review import AdmissionThreshold, derive_threshold_set_digest
from openultrasast.core.admission_spend import AdmissionAuthorization, AdmissionPreparation
from openultrasast.core.lineage import LineageManifest, LineageUse, derive_lineage_manifest_digest
from openultrasast.core.measurement import Comparator, MetricId, Statistic


def _feasible_case() -> AdmissionCase:
    case = _case()
    threshold = AdmissionThreshold(MetricId.VULNERABLE_RECALL, Statistic.COUNT, Comparator.AT_LEAST, 1.0)
    threshold_digest = derive_threshold_set_digest((threshold,))
    old_digest = case.manifest.threshold_lineage_manifest_digest
    old_lineage = next(item for item in case.context.evidence.lineages if item.manifest_digest == old_digest)
    population = old_lineage.uses[0].source_population_digest
    current = case.port.current_log(population)
    request = custody.PopulationUseRequest(
        population,
        case.manifest.identity.arm_id,
        custody.LineagePurpose.THRESHOLD,
        False,
        threshold_digest,
        current.log_digest,
    )
    receipt = case.port.append(request, current.custodian_identity)
    use = LineageUse(custody.LineagePurpose.THRESHOLD, population, False, threshold_digest, receipt.receipt_digest)
    lineage = LineageManifest(
        case.manifest.identity.arm_id,
        threshold_digest,
        (use,),
        derive_lineage_manifest_digest(case.manifest.identity.arm_id, threshold_digest, (use,)),
    )
    lineages = tuple(lineage if item.manifest_digest == old_digest else item for item in case.context.evidence.lineages)
    evidence = validation.make_evidence_validation_context(
        family_catalog=case.context.evidence.family_catalog,
        fact_packs=case.context.evidence.fact_packs,
        model_programs=case.context.evidence.model_programs,
        lineages=lineages,
        fact_review_policy=case.context.evidence.fact_review_policy,
        provenance_trust_policy=case.context.evidence.provenance_trust_policy,
        custody_policy=case.context.evidence.custody_policy,
    )
    context = make_admission_validation_context(
        evidence=evidence,
        admission_review_policy=case.context.admission_review_policy,
        proof_trust_policy=case.context.proof_trust_policy,
    )
    identity = replace(case.manifest.identity, threshold_set_digest=threshold_digest)
    manifest = _resign_manifest(
        replace(
            case.manifest,
            identity=identity,
            thresholds=(threshold,),
            threshold_set_digest=threshold_digest,
            threshold_lineage_manifest_digest=lineage.manifest_digest,
            validation_context_digest=context.context_digest,
        ),
        case.manifest.review.conflict_disclosure,
    )
    return replace(case, manifest=manifest, context=context)


def _prepare(case: AdmissionCase) -> AdmissionPreparation:
    from openultrasast.core.admission_spend import authorize_admission

    return authorize_admission(
        case.manifest,
        case.denominator,
        case.readiness,
        case.context,
        case.port,
        case.resolver,
    )


def _spend(case: AdmissionCase, preparation: AdmissionPreparation) -> custody.PopulationUseReceipt:
    current = case.port.current_log(preparation.label_release_request.population_digest)
    receipt = custody.record_population_use(
        preparation.label_release_request,
        current,
        current.custodian_identity,
        case.context.evidence.custody_policy,
    )
    case.port.logs[current.population_digest] = custody.append_population_use(
        current,
        receipt,
        case.context.evidence.custody_policy,
    )
    return receipt


def _validate_spend(
    case: AdmissionCase,
    preparation: AdmissionPreparation,
    receipt: custody.PopulationUseReceipt | None,
) -> AdmissionAuthorization:
    from openultrasast.core.admission_spend import validate_pre_label_spend

    return validate_pre_label_spend(
        case.manifest,
        case.denominator,
        case.readiness,
        case.context,
        preparation,
        receipt,
        case.port,
        case.resolver,
    )


def test_preparation_binds_exact_authorization_and_current_available_head_without_append() -> None:
    case = _feasible_case()
    population = case.manifest.identity.population_digest
    before = case.port.current_log(population)

    preparation = _prepare(case)

    request = preparation.label_release_request
    assert case.port.current_log(population) == before
    assert preparation.authorization.manifest_digest == case.manifest.manifest_digest
    assert preparation.authorization.validation_context_digest == case.context.context_digest
    assert preparation.authorization.readiness_digests == case.manifest.readiness_digests
    assert preparation.authorization.custody_log_digest == before.log_digest
    assert request == custody.PopulationUseRequest(
        population,
        case.manifest.identity.arm_id,
        custody.LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        preparation.authorization.authorization_digest,
        before.log_digest,
    )


def test_exact_current_chain_available_to_spent_successor_authorizes_scoring() -> None:
    case = _feasible_case()
    preparation = _prepare(case)
    receipt = _spend(case, preparation)
    spent_log = case.port.current_log(case.manifest.identity.population_digest)

    authorization = _validate_spend(case, preparation, receipt)

    assert authorization == preparation.authorization
    assert case.port.current_log(case.manifest.identity.population_digest) == spent_log
    assert receipt.prior_status is custody.PopulationStatus.AVAILABLE
    assert receipt.status is custody.PopulationStatus.SPENT


def test_substituted_authorization_or_release_request_is_refused() -> None:
    from openultrasast.core.admission_spend import AdmissionSpendError

    case = _feasible_case()
    preparation = _prepare(case)
    receipt = _spend(case, preparation)
    changed_authorization = replace(
        preparation.authorization,
        manifest_digest=canonical.content_digest("substituted-manifest"),
    )
    changed_request = replace(
        preparation.label_release_request,
        influenced_artifact_digest=canonical.content_digest("substituted-authorization"),
    )

    with pytest.raises(AdmissionSpendError, match="authorization digest"):
        _validate_spend(case, replace(preparation, authorization=changed_authorization), receipt)
    with pytest.raises(AdmissionSpendError, match="exact authorization"):
        _validate_spend(case, replace(preparation, label_release_request=changed_request), receipt)


@pytest.mark.parametrize("field", ("arm_id", "population_digest"))
def test_self_rehashed_request_cannot_replace_canonical_preparation(field: str) -> None:
    from openultrasast.core.admission_spend import (
        AdmissionSpendError,
        derive_admission_authorization_digest,
        derive_admission_preparation_digest,
    )

    case = _feasible_case()
    preparation = _prepare(case)
    if field == "arm_id":
        request = replace(preparation.label_release_request, arm_id="substituted-arm")
        changed = replace(preparation, label_release_request=request, preparation_digest="0" * 64)
    else:
        population = case.context.evidence.lineages[0].uses[0].source_population_digest
        wrong_log = case.port.current_log(population)
        authorization = replace(
            preparation.authorization,
            custody_log_digest=wrong_log.log_digest,
            authorization_digest="0" * 64,
        )
        authorization = replace(
            authorization,
            authorization_digest=derive_admission_authorization_digest(authorization),
        )
        request = replace(
            preparation.label_release_request,
            population_digest=population,
            influenced_artifact_digest=authorization.authorization_digest,
            expected_log_digest=wrong_log.log_digest,
        )
        changed = replace(
            preparation,
            authorization=authorization,
            label_release_request=request,
            preparation_digest="0" * 64,
        )
    changed = replace(changed, preparation_digest=derive_admission_preparation_digest(changed))
    receipt = _spend(case, changed)
    spent_log = case.port.current_log(changed.label_release_request.population_digest)

    with pytest.raises(AdmissionSpendError, match="canonical preparation"):
        _validate_spend(case, changed, receipt)
    assert case.port.current_log(changed.label_release_request.population_digest) == spent_log


def test_missing_receipt_is_refused_while_population_remains_available() -> None:
    from openultrasast.core.admission_spend import AdmissionSpendError

    case = _feasible_case()
    preparation = _prepare(case)

    with pytest.raises(AdmissionSpendError, match="missing"):
        _validate_spend(case, preparation, None)

    assert case.port.current_log(case.manifest.identity.population_digest).status is custody.PopulationStatus.AVAILABLE


def test_stale_or_mismatched_receipt_never_authorizes_scoring() -> None:
    from openultrasast.core.admission_spend import AdmissionSpendError

    case = _feasible_case()
    first = _prepare(case)
    other_request = replace(
        first.label_release_request,
        influenced_artifact_digest=canonical.content_digest("different-authorization"),
    )
    prior = case.port.current_log(case.manifest.identity.population_digest)
    other_receipt = custody.record_population_use(
        other_request,
        prior,
        prior.custodian_identity,
        case.context.evidence.custody_policy,
    )
    case.port.logs[prior.population_digest] = custody.append_population_use(
        prior,
        other_receipt,
        case.context.evidence.custody_policy,
    )

    with pytest.raises(AdmissionSpendError, match="match preparation"):
        _validate_spend(case, first, other_receipt)


def test_non_successor_and_availability_restoring_receipts_are_refused() -> None:
    from openultrasast.core.admission_spend import AdmissionSpendError

    case = _feasible_case()
    preparation = _prepare(case)
    receipt = _spend(case, preparation)
    non_successor = replace(receipt, sequence=receipt.sequence + 1)
    restoring = replace(receipt, status=custody.PopulationStatus.AVAILABLE)

    with pytest.raises(AdmissionSpendError, match="current-chain direct successor"):
        _validate_spend(case, preparation, non_successor)
    with pytest.raises(AdmissionSpendError, match="available to spent"):
        _validate_spend(case, preparation, restoring)


def test_preparation_is_stale_after_any_competing_current_head_change() -> None:
    from openultrasast.core.admission_spend import AdmissionSpendError

    case = _feasible_case()
    preparation = _prepare(case)
    winner = _spend(case, preparation)
    current = case.port.current_log(case.manifest.identity.population_digest)
    later_request = custody.PopulationUseRequest(
        current.population_digest,
        "other-arm",
        custody.LineagePurpose.PROMOTION,
        False,
        canonical.content_digest("later-artifact"),
        current.log_digest,
    )
    later = custody.record_population_use(
        later_request,
        current,
        current.custodian_identity,
        case.context.evidence.custody_policy,
    )
    case.port.logs[current.population_digest] = custody.append_population_use(
        current,
        later,
        case.context.evidence.custody_policy,
    )

    with pytest.raises(AdmissionSpendError, match="current-chain direct successor"):
        _validate_spend(case, preparation, winner)
