"""Independently reviewed label-blind admission payload contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import cast

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical
from openultrasast.core.admission_review import (
    AdmissionManifestV2,
    AdmissionReviewError,
    AdmissionThreshold,
    PopulationCensus,
    ScopeCensus,
    derive_census_digest,
    derive_census_payload_digest,
    derive_manifest_digest,
    derive_manifest_payload_digest,
    derive_threshold_set_digest,
    validate_reviewed_admission_payloads,
)
from openultrasast.core.factpack import (
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    MetricId,
    ScopeKey,
    Statistic,
    derive_baseline_identity_digest,
)


def _policy(reviewer: str, forbidden: tuple[tuple[str, str], ...] = ()) -> ReviewIndependencePolicy:
    stores = ("trusted-store",)
    return ReviewIndependencePolicy(
        (reviewer,),
        forbidden,
        stores,
        4096,
        derive_review_independence_policy_digest((reviewer,), forbidden, stores, 4096),
    )


def _attestation(subject: str, producer: str, reviewer: str, disclosure: canonical.ContentRef) -> IndependenceAttestation:
    provisional = IndependenceAttestation(subject, producer, reviewer, disclosure, "0" * 64)
    return replace(provisional, attestation_digest=derive_independence_attestation_digest(provisional))


def _baseline(population: str, scope: ScopeKey) -> BaselineIdentity:
    digest = canonical.content_digest
    return BaselineIdentity(
        "arm-a",
        population,
        digest("freeze"),
        (scope,),
        (digest("contract"),),
        digest("catalog"),
        digest("fact-schema"),
        digest("fact-set"),
        digest("acquisition"),
        "analyzer-v2",
        digest("configuration"),
        (),
        None,
        digest("denominator"),
        digest("threshold-set"),
        digest("outcomes"),
    )


def _case() -> tuple[PopulationCensus, AdmissionManifestV2, ReviewIndependencePolicy, InMemoryContentResolver]:
    producer = canonical.content_digest("benchmark-producer")
    reviewer = canonical.content_digest("independent-reviewer")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="admission-conflicts")
    policy = _policy(reviewer)
    population = canonical.content_digest("untouched-population")
    scope = ScopeKey("reference-family", "python")
    row = ScopeCensus(scope, 8, 2, 2, 2, 4, 12, 3)
    provisional_review = _attestation("0" * 64, producer, reviewer, disclosure)
    provisional_census = PopulationCensus(population, (row,), False, "0" * 64, provisional_review, "0" * 64)
    census_payload = derive_census_payload_digest(provisional_census)
    census_review = _attestation(census_payload, producer, reviewer, disclosure)
    census = replace(provisional_census, census_payload_digest=census_payload, review=census_review)
    census = replace(census, census_digest=derive_census_digest(census))

    threshold = AdmissionThreshold(MetricId.VULNERABLE_RECALL, Statistic.WILSON_LOWER, Comparator.AT_LEAST, 0.5)
    thresholds = (threshold,)
    threshold_set = derive_threshold_set_digest(thresholds)
    identity = replace(_baseline(population, scope), threshold_set_digest=threshold_set)
    provisional_manifest = AdmissionManifestV2(
        "0" * 64,
        provisional_review,
        True,
        False,
        identity,
        census,
        (canonical.content_digest("readiness-development"),),
        canonical.content_digest("custody-head"),
        identity.denominator_policy_digest,
        thresholds,
        threshold_set,
        canonical.content_digest("threshold-lineage"),
        canonical.content_digest("validation-context"),
        "0" * 64,
    )
    payload = derive_manifest_payload_digest(provisional_manifest)
    review = _attestation(payload, producer, reviewer, disclosure)
    manifest = replace(provisional_manifest, manifest_payload_digest=payload, review=review)
    manifest = replace(manifest, manifest_digest=derive_manifest_digest(manifest))
    return census, manifest, policy, disclosure_resolver


def _validate(case: tuple[PopulationCensus, AdmissionManifestV2, ReviewIndependencePolicy, InMemoryContentResolver]) -> None:
    validate_reviewed_admission_payloads(*case)


def test_label_blind_census_and_manifest_validate_and_preserve_only_aggregates() -> None:
    case = _case()
    _validate(case)
    census, manifest, _, _ = case
    assert census.rows[0].total_cases == 8
    assert not hasattr(census, "case_ids")
    assert not hasattr(census, "labels")
    assert census.review.subject_digest == census.census_payload_digest
    assert manifest.review.subject_digest == manifest.manifest_payload_digest
    assert derive_baseline_identity_digest(manifest.identity)


def test_every_census_and_manifest_field_is_bound_to_its_own_review_subject() -> None:
    census, manifest, policy, resolver = _case()
    changed_row = replace(census.rows[0], semantic_site_capacity=13)
    changed_census = replace(census, rows=(changed_row,))
    with pytest.raises(AdmissionReviewError, match="census payload"):
        _validate((changed_census, manifest, policy, resolver))

    changed_manifest = replace(manifest, readiness_digests=(canonical.content_digest("other-readiness"),))
    with pytest.raises(AdmissionReviewError, match="manifest payload"):
        _validate((census, changed_manifest, policy, resolver))


def test_copied_attestation_cannot_review_another_payload() -> None:
    census, manifest, policy, resolver = _case()
    copied = replace(manifest, review=census.review)
    with pytest.raises(AdmissionReviewError, match="subject"):
        _validate((census, copied, policy, resolver))


@pytest.mark.parametrize("failure", ("self", "unknown", "forbidden", "digest"))
def test_independence_policy_rejects_invalid_reviews(failure: str) -> None:
    census, manifest, policy, resolver = _case()
    review = manifest.review
    if failure == "self":
        review = replace(review, producer_identity=review.reviewer_identity)
    elif failure == "unknown":
        review = replace(review, reviewer_identity=canonical.content_digest("unknown-reviewer"))
    elif failure == "forbidden":
        policy = _policy(review.reviewer_identity, ((review.producer_identity, review.reviewer_identity),))
    else:
        review = replace(review, attestation_digest=canonical.content_digest("forged-attestation"))
    changed = replace(manifest, review=review)
    with pytest.raises(AdmissionReviewError, match="review|attestation|independent|forbidden"):
        _validate((census, changed, policy, resolver))


def test_unreadable_or_empty_conflict_disclosure_is_refused() -> None:
    census, manifest, policy, resolver = _case()
    unreadable = InMemoryContentResolver({})
    with pytest.raises(canonical.ArtifactResolutionError):
        _validate((census, manifest, policy, unreadable))

    empty_ref, empty_resolver = stored_artifact(b"", artifact_id="empty-conflicts")
    review = _attestation(manifest.manifest_payload_digest, manifest.review.producer_identity, manifest.review.reviewer_identity, empty_ref)
    changed = replace(manifest, review=review)
    combined = InMemoryContentResolver({**resolver.artifacts, **empty_resolver.artifacts})
    with pytest.raises(AdmissionReviewError, match="nonempty"):
        _validate((census, changed, policy, combined))


@pytest.mark.parametrize("target", ("census", "manifest"))
def test_label_exposure_is_refused_before_manifest_validation(target: str) -> None:
    census, manifest, policy, resolver = _case()
    if target == "census":
        census = replace(census, case_labels_exposed=True)
    else:
        manifest = replace(manifest, labels_opened=True)
    with pytest.raises(AdmissionReviewError, match="label"):
        _validate((census, manifest, policy, resolver))


@dataclass(frozen=True)
class _CensusWithCases(PopulationCensus):
    case_ids: tuple[str, ...]


@dataclass(frozen=True)
class _ManifestWithLabels(AdmissionManifestV2):
    per_case_labels: tuple[str, ...]


class _HiddenTuple(tuple[object, ...]):
    def __new__(cls, values: tuple[object, ...], field: str, hidden: object) -> _HiddenTuple:
        instance = super().__new__(cls, values)
        setattr(instance, field, hidden)
        return instance


class _HiddenStr(str):
    hidden: str

    def __new__(cls, value: str) -> _HiddenStr:
        instance = super().__new__(cls, value)
        instance.hidden = "case-data"
        return instance


class _HiddenInt(int):
    hidden: str

    def __new__(cls, value: int) -> _HiddenInt:
        instance = super().__new__(cls, value)
        instance.hidden = "case-data"
        return instance


class _HiddenFloat(float):
    hidden: str

    def __new__(cls, value: float) -> _HiddenFloat:
        instance = super().__new__(cls, value)
        instance.hidden = "case-data"
        return instance


@pytest.mark.parametrize("target", ("census_subclass", "manifest_subclass", "census_injected", "manifest_injected"))
def test_payload_graph_refuses_subtypes_and_injected_fields(target: str) -> None:
    census, manifest, policy, resolver = _case()
    if target == "census_subclass":
        census = _CensusWithCases(
            census.population_digest,
            census.rows,
            census.case_labels_exposed,
            census.census_payload_digest,
            census.review,
            census.census_digest,
            (canonical.content_digest("case-identity"),),
        )
        manifest = replace(manifest, census=census)
    elif target == "manifest_subclass":
        manifest = _ManifestWithLabels(
            manifest.manifest_payload_digest,
            manifest.review,
            manifest.label_isolated,
            manifest.labels_opened,
            manifest.identity,
            manifest.census,
            manifest.readiness_digests,
            manifest.custody_log_digest,
            manifest.denominator_policy_digest,
            manifest.thresholds,
            manifest.threshold_set_digest,
            manifest.threshold_lineage_manifest_digest,
            manifest.validation_context_digest,
            manifest.manifest_digest,
            ("vulnerable",),
        )
    elif target == "census_injected":
        object.__setattr__(census, "case_ids", (canonical.content_digest("case-identity"),))
    else:
        object.__setattr__(manifest, "per_case_labels", ("vulnerable",))

    with pytest.raises(AdmissionReviewError, match="closed|exact|field|type"):
        _validate((census, manifest, policy, resolver))


@pytest.mark.parametrize("target", ("row", "scope", "threshold", "baseline", "review", "disclosure", "policy"))
def test_nested_payload_graph_refuses_undeclared_fields(target: str) -> None:
    census, manifest, policy, resolver = _case()
    values = {
        "row": census.rows[0],
        "scope": census.rows[0].scope,
        "threshold": manifest.thresholds[0],
        "baseline": manifest.identity,
        "review": manifest.review,
        "disclosure": manifest.review.conflict_disclosure,
        "policy": policy,
    }
    object.__setattr__(values[target], "undeclared", "not-canonical")

    with pytest.raises(AdmissionReviewError, match="closed|exact|field|type"):
        _validate((census, manifest, policy, resolver))


@pytest.mark.parametrize("target", ("rows", "readiness"))
def test_payload_graph_refuses_tuple_subclasses_with_hidden_case_data(target: str) -> None:
    census, manifest, policy, resolver = _case()
    if target == "rows":
        rows = _HiddenTuple(census.rows, "case_ids", (canonical.content_digest("hidden-case"),))
        census = replace(census, rows=cast(tuple[ScopeCensus, ...], rows))
        manifest = replace(manifest, census=census)
    else:
        readiness = _HiddenTuple(manifest.readiness_digests, "per_case_labels", ("vulnerable",))
        manifest = replace(manifest, readiness_digests=cast(tuple[str, ...], readiness))

    with pytest.raises(AdmissionReviewError, match="tuple|closed|exact"):
        _validate((census, manifest, policy, resolver))


@pytest.mark.parametrize(
    "target",
    ("thresholds", "scopes", "contracts", "models", "reviewers", "pairs", "pair", "stores"),
)
def test_all_nested_tuple_nodes_require_plain_tuples(target: str) -> None:
    census, manifest, policy, resolver = _case()

    def hidden(values: tuple[object, ...]) -> _HiddenTuple:
        return _HiddenTuple(values, "hidden", "case-data")

    if target == "thresholds":
        changed = cast(tuple[AdmissionThreshold, ...], hidden(manifest.thresholds))
        manifest = replace(manifest, thresholds=changed)
    elif target == "scopes":
        changed_scopes = cast(tuple[ScopeKey, ...], hidden(manifest.identity.claimed_scopes))
        identity = replace(manifest.identity, claimed_scopes=changed_scopes)
        manifest = replace(manifest, identity=identity)
    elif target == "contracts":
        changed_contracts = cast(tuple[str, ...], hidden(manifest.identity.family_contract_digests))
        identity = replace(manifest.identity, family_contract_digests=changed_contracts)
        manifest = replace(manifest, identity=identity)
    elif target == "models":
        changed_models = cast(tuple[str, ...], hidden(manifest.identity.model_program_digests))
        identity = replace(manifest.identity, model_program_digests=changed_models)
        manifest = replace(manifest, identity=identity)
    elif target == "reviewers":
        changed_reviewers = cast(tuple[str, ...], hidden(policy.reviewed_reviewer_digests))
        policy = replace(policy, reviewed_reviewer_digests=changed_reviewers)
    elif target == "pairs":
        changed_pairs = cast(tuple[tuple[str, str], ...], hidden(policy.forbidden_identity_pairs))
        policy = replace(policy, forbidden_identity_pairs=changed_pairs)
    elif target == "pair":
        other = _HiddenTuple(
            (canonical.content_digest("other-producer"), canonical.content_digest("other-reviewer")),
            "hidden",
            "case-data",
        )
        policy = _policy(manifest.review.reviewer_identity, (cast(tuple[str, str], other),))
    else:
        changed_stores = cast(tuple[str, ...], hidden(policy.trusted_store_identities))
        policy = replace(policy, trusted_store_identities=changed_stores)

    with pytest.raises(AdmissionReviewError, match="tuple|closed|exact"):
        _validate((census, manifest, policy, resolver))


def _payload_with_hidden_scalar(
    target: str,
    census: PopulationCensus,
    manifest: AdmissionManifestV2,
) -> tuple[PopulationCensus, AdmissionManifestV2]:
    if target == "census_digest":
        census = replace(census, population_digest=_HiddenStr(census.population_digest))
        identity = replace(manifest.identity, population_digest=census.population_digest)
        manifest = replace(manifest, census=census, identity=identity)
    elif target == "manifest_digest":
        manifest = replace(manifest, custody_log_digest=_HiddenStr(manifest.custody_log_digest))
    elif target == "scope_text":
        scope = replace(census.rows[0].scope, family_id=_HiddenStr(census.rows[0].scope.family_id))
        census = replace(census, rows=(replace(census.rows[0], scope=scope),))
        manifest = replace(manifest, census=census, identity=replace(manifest.identity, claimed_scopes=(scope,)))
    elif target == "baseline_text":
        manifest = replace(manifest, identity=replace(manifest.identity, arm_id=_HiddenStr(manifest.identity.arm_id)))
    elif target == "baseline_digest":
        identity = replace(manifest.identity, freeze_digest=_HiddenStr(manifest.identity.freeze_digest))
        manifest = replace(manifest, identity=identity)
    elif target == "count":
        row = replace(census.rows[0], total_cases=_HiddenInt(census.rows[0].total_cases))
        census = replace(census, rows=(row,))
        manifest = replace(manifest, census=census)
    elif target == "threshold_target":
        threshold = replace(manifest.thresholds[0], target=_HiddenFloat(manifest.thresholds[0].target))
        manifest = replace(manifest, thresholds=(threshold,))
    else:
        review = replace(manifest.review, producer_identity=_HiddenStr(manifest.review.producer_identity))
        manifest = replace(manifest, review=review)
    return census, manifest


def _reference_with_hidden_scalar(target: str, reference: canonical.ContentRef) -> canonical.ContentRef:
    if target == "ref_artifact":
        return replace(reference, artifact_id=_HiddenStr(reference.artifact_id))
    if target == "ref_digest":
        return replace(reference, content_digest=_HiddenStr(reference.content_digest))
    if target == "ref_media":
        return replace(reference, media_type=_HiddenStr(reference.media_type))
    if target == "ref_retention":
        return replace(reference, retention_policy_digest=_HiddenStr(reference.retention_policy_digest))
    if target == "ref_receipt":
        return replace(reference, storage_receipt_digest=_HiddenStr(reference.storage_receipt_digest))
    return replace(reference, byte_length=_HiddenInt(reference.byte_length))


@pytest.mark.parametrize(
    "target",
    (
        "census_digest",
        "manifest_digest",
        "scope_text",
        "baseline_text",
        "baseline_digest",
        "count",
        "threshold_target",
        "review_identity",
        "ref_artifact",
        "ref_digest",
        "ref_media",
        "ref_retention",
        "ref_receipt",
        "ref_length",
        "policy_identity",
        "policy_store",
        "policy_bytes",
    ),
)
def test_recursive_payload_graph_refuses_scalar_subclasses(target: str) -> None:
    census, manifest, policy, resolver = _case()
    if target.startswith("ref_"):
        changed_ref = _reference_with_hidden_scalar(target, manifest.review.conflict_disclosure)
        manifest = replace(manifest, review=replace(manifest.review, conflict_disclosure=changed_ref))
    elif target == "policy_identity":
        policy = replace(policy, reviewed_reviewer_digests=(_HiddenStr(policy.reviewed_reviewer_digests[0]),))
    elif target == "policy_store":
        policy = replace(policy, trusted_store_identities=(_HiddenStr(policy.trusted_store_identities[0]),))
    elif target == "policy_bytes":
        policy = replace(policy, maximum_evidence_bytes=_HiddenInt(policy.maximum_evidence_bytes))
    else:
        census, manifest = _payload_with_hidden_scalar(target, census, manifest)

    with pytest.raises(AdmissionReviewError, match="closed|exact|scalar|type"):
        _validate((census, manifest, policy, resolver))


def test_each_public_digest_entry_closes_its_complete_input_graph() -> None:
    census, manifest, _, _ = _case()
    hidden_census = replace(census, census_digest=_HiddenStr(census.census_digest))
    for derive_census in (derive_census_payload_digest, derive_census_digest):
        with pytest.raises(AdmissionReviewError, match="closed|type"):
            derive_census(hidden_census)

    hidden_manifest = replace(manifest, manifest_digest=_HiddenStr(manifest.manifest_digest))
    for derive_manifest in (derive_manifest_payload_digest, derive_manifest_digest):
        with pytest.raises(AdmissionReviewError, match="closed|type"):
            derive_manifest(hidden_manifest)

    hidden_threshold = replace(manifest.thresholds[0], target=_HiddenFloat(manifest.thresholds[0].target))
    with pytest.raises(AdmissionReviewError, match="closed|type"):
        derive_threshold_set_digest((hidden_threshold,))


@pytest.mark.parametrize(
    ("member", "hidden_field"),
    (
        pytest.param(MetricId.VULNERABLE_RECALL, "case_ids", id="metric-id"),
        pytest.param(Statistic.WILSON_LOWER, "per_case_labels", id="statistic"),
        pytest.param(Comparator.AT_LEAST, "case_ids", id="comparator"),
    ),
)
def test_payload_graph_refuses_mutated_exact_enum_members(member: object, hidden_field: str) -> None:
    _, manifest, _, _ = _case()
    original_state = dict(vars(member))
    try:
        object.__setattr__(member, hidden_field, ("hidden-case-data",))
        with pytest.raises(AdmissionReviewError, match="closed|enum|field|state"):
            derive_threshold_set_digest(manifest.thresholds)
    finally:
        current_state = vars(member)
        current_state.clear()
        current_state.update(original_state)
        assert vars(member) == original_state
