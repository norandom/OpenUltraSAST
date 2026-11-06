"""Reviewed label-blind census and plan-manifest contracts for V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_evaluation_plan import _declaration, _digest

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import ScopeKey
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    EvaluationPlanError,
    EvaluationPlanManifestV3,
    ExactScopeCensusV3,
    PopulationCensusV3,
    derive_evaluation_baselines,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
    validate_reviewed_evaluation_plan,
)
from openultrasast.core.factpack import (
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)


def _policy(
    reviewer: str,
    forbidden: tuple[tuple[str, str], ...] = (),
    *,
    stores: tuple[str, ...] = ("trusted-store",),
    maximum_bytes: int = 4096,
) -> ReviewIndependencePolicy:
    return ReviewIndependencePolicy(
        (reviewer,),
        forbidden,
        stores,
        maximum_bytes,
        derive_review_independence_policy_digest((reviewer,), forbidden, stores, maximum_bytes),
    )


def _attestation(
    subject: str,
    producer: str,
    reviewer: str,
    disclosure: canonical.ContentRef,
) -> IndependenceAttestation:
    draft = IndependenceAttestation(subject, producer, reviewer, disclosure, "0" * 64)
    return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))


def _case() -> tuple[
    PopulationCensusV3,
    EvaluationPlanManifestV3,
    ReviewIndependencePolicy,
    InMemoryContentResolver,
]:
    declaration = _declaration()
    producer = _digest("plan-producer")
    reviewer = _digest("independent-plan-reviewer")
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="v3-plan-conflicts")
    provisional_review = _attestation("0" * 64, producer, reviewer, disclosure)
    scope_rows = (ExactScopeCensusV3(ScopeKey("access_control", "python"), 4, 4, 4, 20, 6),)
    ordinary_rows = (EcosystemOrdinaryCensusV3("python", 12),)
    draft_census = PopulationCensusV3(
        declaration.population_digest,
        scope_rows,
        ordinary_rows,
        20,
        False,
        "0" * 64,
        provisional_review,
        "0" * 64,
    )
    census_payload = derive_evaluation_census_payload_digest(draft_census)
    census_review = _attestation(census_payload, producer, reviewer, disclosure)
    census = replace(draft_census, payload_digest=census_payload, review=census_review)
    census = replace(census, census_digest=derive_evaluation_census_digest(census))

    draft_manifest = EvaluationPlanManifestV3(
        declaration,
        derive_evaluation_baselines(declaration),
        census,
        tuple(sorted((_digest("readiness-a"), _digest("readiness-b")))),
        _digest("custody-head"),
        "0" * 64,
        provisional_review,
        "0" * 64,
    )
    payload = derive_evaluation_plan_manifest_payload_digest(draft_manifest)
    review = _attestation(payload, producer, reviewer, disclosure)
    manifest = replace(draft_manifest, payload_digest=payload, review=review)
    manifest = replace(manifest, manifest_digest=derive_evaluation_plan_manifest_digest(manifest))
    return census, manifest, _policy(reviewer), resolver


def _validate(
    case: tuple[
        PopulationCensusV3,
        EvaluationPlanManifestV3,
        ReviewIndependencePolicy,
        InMemoryContentResolver,
    ],
) -> None:
    validate_reviewed_evaluation_plan(*case)


def test_reviewed_multi_arm_manifest_validates_with_labels_sealed() -> None:
    case = _case()
    _validate(case)
    census, manifest, _, _ = case
    assert census.labels_exposed is False
    assert census.scope_rows[0].pair_count == 4
    assert census.ordinary_rows[0].ordinary_push_count == 12
    assert manifest.declaration.expected_observation_slots
    assert not hasattr(census, "labels")
    assert not hasattr(manifest, "authorize")


@pytest.mark.parametrize("target", ("self", "copied", "unknown", "forbidden", "empty"))
def test_review_policy_refuses_untrusted_or_copied_attestations(target: str) -> None:
    census, manifest, policy, resolver = _case()
    review = manifest.review
    if target == "self":
        review = replace(review, producer_identity=review.reviewer_identity)
    elif target == "copied":
        review = census.review
    elif target == "unknown":
        review = replace(review, reviewer_identity=_digest("unknown-reviewer"))
    elif target == "forbidden":
        policy = _policy(review.reviewer_identity, ((review.producer_identity, review.reviewer_identity),))
    else:
        empty_ref, empty_resolver = stored_artifact(b"", artifact_id="empty-v3-disclosure")
        review = _attestation(manifest.payload_digest, review.producer_identity, review.reviewer_identity, empty_ref)
        resolver = InMemoryContentResolver({**resolver.artifacts, **empty_resolver.artifacts})
    with pytest.raises((EvaluationPlanError, canonical.ArtifactResolutionError)):
        _validate((census, replace(manifest, review=review), policy, resolver))


def test_review_resolution_enforces_trusted_store_and_byte_limit_for_both_payloads() -> None:
    census, manifest, policy, resolver = _case()
    with pytest.raises(canonical.ArtifactValidationError):
        _validate((census, manifest, _policy(manifest.review.reviewer_identity, stores=("other-store",)), resolver))
    with pytest.raises(canonical.ArtifactValidationError):
        _validate((census, manifest, _policy(manifest.review.reviewer_identity, maximum_bytes=1), resolver))
    with pytest.raises(EvaluationPlanError, match="subject"):
        _validate((replace(census, review=manifest.review), manifest, policy, resolver))


def test_census_refuses_label_exposure_and_scope_or_ecosystem_substitution() -> None:
    census, manifest, policy, resolver = _case()
    mutations = (
        lambda: replace(census, labels_exposed=True),
        lambda: replace(census, scope_rows=()),
        lambda: replace(census, scope_rows=(replace(census.scope_rows[0], scope=ScopeKey("injection", "python")),)),
        lambda: replace(census, ordinary_rows=()),
        lambda: replace(census, ordinary_rows=(EcosystemOrdinaryCensusV3("javascript", 12),)),
        lambda: replace(census, population_digest=_digest("other-population")),
    )
    for mutation in mutations:
        with pytest.raises(EvaluationPlanError):
            changed = mutation()
            _validate((changed, replace(manifest, census=changed), policy, resolver))


def test_manifest_refuses_baseline_readiness_custody_and_slot_substitution() -> None:
    census, manifest, policy, resolver = _case()
    declaration = manifest.declaration
    mutations = (
        lambda: replace(manifest, baselines=manifest.baselines[:-1]),
        lambda: replace(manifest, readiness_digests=manifest.readiness_digests[:-1]),
        lambda: replace(manifest, custody_log_digest=_digest("other-custody")),
        lambda: replace(
            declaration,
            expected_observation_slots=(
                replace(declaration.expected_observation_slots[0], execution_identity="other-execution", slot_digest=""),
            )
            + declaration.expected_observation_slots[1:],
            declaration_digest="",
        ),
    )
    for mutation in mutations:
        with pytest.raises(EvaluationPlanError):
            changed = mutation()
            if isinstance(changed, EvaluationPlanManifestV3):
                _validate((census, changed, policy, resolver))


def test_census_counts_and_manifest_collections_are_exact_and_canonical() -> None:
    census, manifest, policy, resolver = _case()
    bad_rows = (
        lambda: replace(census.scope_rows[0], pair_count=-1),
        lambda: replace(census.scope_rows[0], pair_count=5),
        lambda: replace(census.scope_rows[0], vulnerable_side_count=True),
    )
    for mutation in bad_rows:
        with pytest.raises(EvaluationPlanError):
            row = mutation()
            _validate((replace(census, scope_rows=(row,)), manifest, policy, resolver))
    with pytest.raises(EvaluationPlanError):
        _validate((census, replace(manifest, readiness_digests=tuple(reversed(manifest.readiness_digests))), policy, resolver))


@pytest.mark.parametrize(
    ("helper_name", "value_kind"),
    (
        ("census_payload", "none"),
        ("census_digest", "duck"),
        ("manifest_payload", "none"),
        ("manifest_digest", "duck"),
    ),
)
def test_public_digest_helpers_reject_nonexact_roots(helper_name: str, value_kind: str) -> None:
    census, manifest, _, _ = _case()
    helpers = {
        "census_payload": derive_evaluation_census_payload_digest,
        "census_digest": derive_evaluation_census_digest,
        "manifest_payload": derive_evaluation_plan_manifest_payload_digest,
        "manifest_digest": derive_evaluation_plan_manifest_digest,
    }

    class Duck:
        payload_digest = census.payload_digest
        review = census.review

    value = None if value_kind == "none" else Duck()
    with pytest.raises(EvaluationPlanError, match="exact"):
        helpers[helper_name](value)  # type: ignore[arg-type]

    class DerivedCensus(PopulationCensusV3):
        pass

    if helper_name.startswith("census"):
        derived = object.__new__(DerivedCensus)
        with pytest.raises(EvaluationPlanError, match="exact"):
            helpers[helper_name](derived)  # type: ignore[arg-type]
    else:

        class DerivedManifest(EvaluationPlanManifestV3):
            pass

        derived_manifest = object.__new__(DerivedManifest)
        with pytest.raises(EvaluationPlanError, match="exact"):
            helpers[helper_name](derived_manifest)  # type: ignore[arg-type]


@pytest.mark.parametrize("resolver_kind", ("none", "returns_none", "malformed"))
def test_review_boundary_wraps_malformed_resolvers_with_contract_error(resolver_kind: str) -> None:
    census, manifest, policy, _ = _case()

    class ReturnsNone:
        def resolve(self, reference: canonical.ContentRef) -> None:
            del reference
            return None

    class Malformed:
        def resolve(self, reference: canonical.ContentRef) -> object:
            del reference
            return object()

    resolver: object = None if resolver_kind == "none" else ReturnsNone() if resolver_kind == "returns_none" else Malformed()
    with pytest.raises(EvaluationPlanError, match="resolver"):
        validate_reviewed_evaluation_plan(census, manifest, policy, resolver)  # type: ignore[arg-type]
