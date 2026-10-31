from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryPopulationCustody, custody_contract

from openultrasast.core import canonical, provenance


def _lineage(
    uses: tuple[provenance.LineageUse, ...],
    *,
    subject: str | None = None,
    arm_id: str = "arm",
) -> provenance.LineageManifest:
    subject_digest = subject or canonical.content_digest("subject")
    digest = provenance.derive_lineage_manifest_digest(arm_id, subject_digest, uses)
    return provenance.LineageManifest(arm_id, subject_digest, uses, digest)


def _use(
    purpose: provenance.LineagePurpose,
    artifact: str,
    *,
    labels: bool = False,
) -> tuple[provenance.LineageUse, InMemoryPopulationCustody, provenance.PopulationCustodyPolicy]:
    initial, policy, custodian = custody_contract()
    port = InMemoryPopulationCustody(initial, policy)
    request = provenance.PopulationUseRequest(
        initial.population_digest,
        "arm",
        purpose,
        labels,
        artifact,
        initial.log_digest,
    )
    receipt = port.append(request, custodian)
    return (
        provenance.LineageUse(purpose, initial.population_digest, labels, artifact, receipt.receipt_digest),
        port,
        policy,
    )


def _expectation(
    purpose: provenance.LineagePurpose,
    artifact: str,
    minimum: int = 1,
    maximum: int | None = 1,
) -> provenance.LineageExpectation:
    return provenance.LineageExpectation(purpose, artifact, minimum, maximum)


@pytest.mark.parametrize(
    "purpose",
    [
        provenance.LineagePurpose.PROMPT,
        provenance.LineagePurpose.EXAMPLE,
        provenance.LineagePurpose.THRESHOLD,
        provenance.LineagePurpose.FITTED_MODEL,
        provenance.LineagePurpose.SEMANTIC_FACT,
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        provenance.LineagePurpose.DECISION_MAPPING,
        provenance.LineagePurpose.PROMOTION,
    ],
)
def test_every_preparation_purpose_binds_exact_artifact_and_receipt(
    purpose: provenance.LineagePurpose,
) -> None:
    artifact = canonical.content_digest(purpose.value)
    use, port, policy = _use(purpose, artifact)
    manifest = _lineage((use,))

    decision = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (_expectation(purpose, artifact),),
        None,
        False,
        port,
        policy,
    )

    assert decision.allowed
    assert decision.reasons == ()
    assert decision.decision_digest == provenance.derive_lineage_decision_digest(decision)


def test_required_optional_and_maximum_use_counts_are_enforced() -> None:
    required = canonical.content_digest("required")
    optional = canonical.content_digest("optional")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, required)
    manifest = _lineage((use,))
    allowed = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (
            _expectation(provenance.LineagePurpose.PROMPT, required),
            _expectation(provenance.LineagePurpose.EXAMPLE, optional, 0, 1),
        ),
        None,
        False,
        port,
        policy,
    )
    assert allowed.allowed

    current = port.current_log(use.source_population_digest)
    second_receipt = port.append(
        provenance.PopulationUseRequest(
            use.source_population_digest,
            "arm",
            provenance.LineagePurpose.PROMPT,
            False,
            required,
            current.log_digest,
        ),
        current.custodian_identity,
    )
    second_use = provenance.LineageUse(
        provenance.LineagePurpose.PROMPT,
        use.source_population_digest,
        False,
        required,
        second_receipt.receipt_digest,
    )
    too_many_manifest = _lineage((use, second_use))
    too_many = provenance.validate_lineage(
        too_many_manifest,
        too_many_manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.PROMPT, required),),
        None,
        False,
        port,
        policy,
    )
    assert not too_many.allowed
    assert any(reason.startswith("too_many_uses:prompt") for reason in too_many.reasons)

    missing = provenance.validate_lineage(
        _lineage(()),
        manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.PROMPT, required),),
        None,
        False,
        port,
        policy,
    )
    assert not missing.allowed
    assert any(reason.startswith("missing_required_use:prompt") for reason in missing.reasons)


def test_duplicate_receipt_cannot_inflate_a_required_use_count() -> None:
    artifact = canonical.content_digest("prompt")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, artifact)
    manifest = _lineage((use, use))

    with pytest.raises(provenance.LineageValidationError, match="duplicate.*receipt"):
        provenance.validate_lineage(
            manifest,
            manifest.subject_digest,
            (_expectation(provenance.LineagePurpose.PROMPT, artifact, 2, 2),),
            None,
            False,
            port,
            policy,
        )


def test_matching_subject_cannot_mask_redirected_artifact_or_wrong_purpose() -> None:
    expected = canonical.content_digest("expected")
    redirected = canonical.content_digest("redirected")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, redirected)
    manifest = _lineage((use,))

    decision = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.PROMPT, expected),),
        None,
        False,
        port,
        policy,
    )
    assert not decision.allowed
    assert any(reason.startswith("unexpected_use:prompt") for reason in decision.reasons)
    assert any(reason.startswith("missing_required_use:prompt") for reason in decision.reasons)

    wrong_purpose = replace(use, purpose=provenance.LineagePurpose.EXAMPLE)
    wrong_manifest = _lineage((wrong_purpose,))
    with pytest.raises(provenance.LineageValidationError, match="does not match its current-chain receipt"):
        provenance.validate_lineage(
            wrong_manifest,
            wrong_manifest.subject_digest,
            (_expectation(provenance.LineagePurpose.PROMPT, redirected),),
            None,
            False,
            port,
            policy,
        )


def test_fact_ancestry_forbids_all_label_access_and_records_spent_population() -> None:
    artifact = canonical.content_digest("fact")
    use, port, policy = _use(provenance.LineagePurpose.SEMANTIC_FACT, artifact, labels=True)
    manifest = _lineage((use,))

    decision = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.SEMANTIC_FACT, artifact),),
        None,
        True,
        port,
        policy,
    )

    assert not decision.allowed
    assert decision.spent_population_digests == (use.source_population_digest,)
    assert decision.reasons == (f"label_access_forbidden:{use.source_population_digest}",)


def test_development_lineage_may_use_different_spent_population() -> None:
    artifact = canonical.content_digest("development-model")
    protected = canonical.content_digest("admission-population")
    use, port, policy = _use(provenance.LineagePurpose.FITTED_MODEL, artifact, labels=True)
    manifest = _lineage((use,))

    decision = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.FITTED_MODEL, artifact),),
        protected,
        False,
        port,
        policy,
    )

    assert decision.allowed
    assert decision.spent_population_digests == (use.source_population_digest,)


def test_protected_population_label_influence_is_refused() -> None:
    artifact = canonical.content_digest("threshold")
    use, port, policy = _use(provenance.LineagePurpose.THRESHOLD, artifact, labels=True)
    manifest = _lineage((use,))

    decision = provenance.validate_lineage(
        manifest,
        manifest.subject_digest,
        (_expectation(provenance.LineagePurpose.THRESHOLD, artifact),),
        use.source_population_digest,
        False,
        port,
        policy,
    )

    assert not decision.allowed
    assert decision.reasons == (f"protected_population_labels:{use.source_population_digest}",)


def test_incomplete_current_history_and_substituted_receipt_are_refused() -> None:
    artifact = canonical.content_digest("prompt")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, artifact)
    absent = replace(use, population_use_receipt_digest=canonical.content_digest("absent"))
    manifest = _lineage((absent,))

    with pytest.raises(provenance.LineageValidationError, match="absent from the current complete custody chain"):
        provenance.validate_lineage(
            manifest,
            manifest.subject_digest,
            (_expectation(provenance.LineagePurpose.PROMPT, artifact),),
            None,
            False,
            port,
            policy,
        )


def test_receipt_issued_to_another_arm_is_refused() -> None:
    artifact = canonical.content_digest("prompt")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, artifact)
    manifest = _lineage((use,), arm_id="different-arm")

    with pytest.raises(provenance.LineageValidationError, match="arm"):
        provenance.validate_lineage(
            manifest,
            manifest.subject_digest,
            (_expectation(provenance.LineagePurpose.PROMPT, artifact),),
            None,
            False,
            port,
            policy,
        )


def test_manifest_identity_subject_and_duplicate_expectation_tampering_is_refused() -> None:
    artifact = canonical.content_digest("prompt")
    use, port, policy = _use(provenance.LineagePurpose.PROMPT, artifact)
    manifest = _lineage((use,))
    expected = _expectation(provenance.LineagePurpose.PROMPT, artifact)

    with pytest.raises(provenance.LineageValidationError, match="manifest digest"):
        provenance.validate_lineage(
            replace(manifest, manifest_digest=canonical.content_digest("tampered")),
            manifest.subject_digest,
            (expected,),
            None,
            False,
            port,
            policy,
        )
    with pytest.raises(provenance.LineageValidationError, match="subject"):
        provenance.validate_lineage(
            manifest,
            canonical.content_digest("other-subject"),
            (expected,),
            None,
            False,
            port,
            policy,
        )
    with pytest.raises(provenance.LineageValidationError, match="duplicate"):
        provenance.validate_lineage(
            manifest,
            manifest.subject_digest,
            (expected, expected),
            None,
            False,
            port,
            policy,
        )


def test_lineage_models_validate_runtime_types_and_counts() -> None:
    digest = canonical.content_digest("value")
    with pytest.raises(ValueError, match="maximum_uses"):
        provenance.LineageExpectation(provenance.LineagePurpose.PROMPT, digest, 2, 1)
    with pytest.raises(TypeError, match="labels_accessed"):
        provenance.LineageUse(provenance.LineagePurpose.PROMPT, digest, 1, digest, digest)  # type: ignore[arg-type]
