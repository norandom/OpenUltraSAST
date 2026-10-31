"""Structural fact-match validation and matcher-lineage contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, InMemoryPopulationCustody, custody_contract, stored_artifact

from openultrasast.core import canonical, provenance
from openultrasast.core.factmatch import (
    FACT_MATCH_SCHEMA,
    STRUCTURAL_OBSERVATION_SCHEMA,
    FactMatchDecision,
    FactMatchEvidence,
    FactMatchValidationError,
    StructuralObservation,
    derive_fact_match_digest,
    structural_observation_bytes,
    validate_fact_match,
)
from openultrasast.core.factpack import (
    FACT_PACK_SCHEMA,
    FactPack,
    RelationEffect,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
    derive_fact_pack_content_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.semantics import RelationKind, RelationStatus, SourceLocation


@dataclass(frozen=True)
class MatchCase:
    pack: FactPack
    match: FactMatchEvidence
    resolver: InMemoryContentResolver
    lineage: provenance.LineageManifest
    custody: InMemoryPopulationCustody
    custody_policy: provenance.PopulationCustodyPolicy
    review_policy: ReviewIndependencePolicy
    protected_population: str


def _requirements() -> tuple[StructuralRequirement, ...]:
    return (
        StructuralRequirement("qualified", StructuralRequirementKind.QUALIFIED_NAME, "callee", "pkg.Client.call"),
        StructuralRequirement("shape", StructuralRequirementKind.AST_SHAPE, "shape", {"node": "call"}),
        StructuralRequirement("receiver", StructuralRequirementKind.RECEIVER_TYPE, "receiver", "pkg.Client"),
        StructuralRequirement("target", StructuralRequirementKind.CALL_TARGET, "target", "pkg.Client.call"),
        StructuralRequirement("arguments", StructuralRequirementKind.ARGUMENT_SHAPE, "arguments", ("resource",)),
        StructuralRequirement("configuration", StructuralRequirementKind.CONFIGURATION, "config", {"mode": "strict"}),
    )


def _pack(requirements: tuple[StructuralRequirement, ...] | None = None) -> FactPack:
    policy = _review_policy()
    fact = SemanticFact(
        "stable.fact.v1",
        "flow",
        requirements or _requirements(),
        (RelationEffect(RelationKind.CALL, "flow", "source", "target", ("matched",)),),
    )
    provisional = FactPack(
        FACT_PACK_SCHEMA,
        canonical.content_digest("family-contract"),
        "reference-family",
        "python",
        "python",
        (fact,),
        "0" * 64,
        canonical.content_digest("reviewer"),
        (),
        canonical.content_digest(()),
        policy.policy_digest,
    )
    return replace(provisional, normalized_content_digest=derive_fact_pack_content_digest(provisional))


def _review_policy() -> ReviewIndependencePolicy:
    reviewers = (canonical.content_digest("reviewer"),)
    stores = ("trusted-store",)
    digest = derive_review_independence_policy_digest(reviewers, (), stores, 4096)
    return ReviewIndependencePolicy(reviewers, (), stores, 4096, digest)


def _matcher_lineage(
    behavior: str,
    *,
    labels_accessed: bool = False,
    purpose: provenance.LineagePurpose = provenance.LineagePurpose.MATCHING_BEHAVIOR,
) -> tuple[provenance.LineageManifest, InMemoryPopulationCustody, provenance.PopulationCustodyPolicy, str]:
    initial, policy, custodian = custody_contract()
    custody = InMemoryPopulationCustody(initial, policy)
    request = provenance.PopulationUseRequest(
        initial.population_digest,
        "matcher-arm",
        purpose,
        labels_accessed,
        behavior,
        initial.log_digest,
    )
    receipt = custody.append(request, custodian)
    use = provenance.LineageUse(
        request.purpose,
        request.population_digest,
        labels_accessed,
        behavior,
        receipt.receipt_digest,
    )
    manifest_digest = provenance.derive_lineage_manifest_digest("matcher-arm", behavior, (use,))
    return provenance.LineageManifest("matcher-arm", behavior, (use,), manifest_digest), custody, policy, initial.population_digest


def _observation(
    requirement: StructuralRequirement,
    location: SourceLocation,
    *,
    observed: canonical.JsonValue | None = None,
    suffix: str = "",
) -> tuple[StructuralObservation, InMemoryContentResolver]:
    value = requirement.expected if observed is None else observed
    provisional_reference = canonical.ContentRef("provisional", "0" * 64, "application/json", 0, "0" * 64, "0" * 64)
    provisional = StructuralObservation(requirement.requirement_id, location, value, provisional_reference)
    reference, resolver = stored_artifact(
        structural_observation_bytes(provisional),
        artifact_id=f"observation-{requirement.requirement_id}{suffix}",
    )
    return replace(provisional, evidence=reference), resolver


def _case(*, labels_accessed: bool = False) -> MatchCase:
    pack = _pack()
    location = SourceLocation("src/product.py", 17, 8, "run")
    artifacts: dict[str, canonical.ResolvedContent] = {}
    observations: list[StructuralObservation] = []
    for requirement in pack.facts[0].structural_requirements:
        observation, resolver = _observation(requirement, location)
        observations.append(observation)
        artifacts.update(resolver.artifacts)
    behavior = canonical.content_digest("matcher-behavior-v3")
    lineage, custody, custody_policy, protected = _matcher_lineage(behavior, labels_accessed=labels_accessed)
    provisional = FactMatchEvidence(
        pack.normalized_content_digest,
        pack.facts[0].fact_id,
        location,
        tuple(observations),
        "matcher-v3",
        behavior,
        lineage.manifest_digest,
        "0" * 64,
    )
    match = replace(provisional, match_digest=derive_fact_match_digest(provisional))
    return MatchCase(
        pack,
        match,
        InMemoryContentResolver(artifacts),
        lineage,
        custody,
        custody_policy,
        _review_policy(),
        protected,
    )


def _redigest(match: FactMatchEvidence) -> FactMatchEvidence:
    return replace(match, match_digest=derive_fact_match_digest(match))


def _validate(case: MatchCase, match: FactMatchEvidence | None = None) -> FactMatchDecision:
    return validate_fact_match(
        case.pack,
        case.pack.facts[0].fact_id,
        match or case.match,
        case.protected_population,
        (case.lineage,),
        case.custody,
        case.custody_policy,
        case.review_policy,
        case.resolver,
    )


def test_complete_match_requires_all_six_typed_observations_and_current_lineage() -> None:
    case = _case()

    decision = _validate(case)

    assert {item.kind for item in case.pack.facts[0].structural_requirements} == set(StructuralRequirementKind)
    assert decision.status is RelationStatus.COMPLETE
    assert decision.reasons == ()
    assert decision.effect_eligible
    assert decision.lineage_decision_digest is not None
    assert FACT_MATCH_SCHEMA.endswith(".v2") and STRUCTURAL_OBSERVATION_SCHEMA.endswith(".v2")


@pytest.mark.parametrize("missing", [item.requirement_id for item in _requirements()])
def test_missing_structural_observation_is_named_incomplete(missing: str) -> None:
    case = _case()
    observations = tuple(item for item in case.match.observations if item.requirement_id != missing)
    match = _redigest(replace(case.match, observations=observations))

    decision = _validate(case, match)

    assert decision.status is RelationStatus.INCOMPLETE
    assert f"missing_observation:{missing}" in decision.reasons
    assert not decision.effect_eligible


def test_name_only_match_can_never_be_complete() -> None:
    requirement = _requirements()[0]
    pack = _pack((requirement,))
    case = _case()
    match = _redigest(
        replace(
            case.match,
            pack_digest=pack.normalized_content_digest,
            observations=(case.match.observations[0],),
        )
    )
    case = replace(case, pack=pack)

    decision = _validate(case, match)

    assert decision.status is RelationStatus.INCOMPLETE
    assert decision.reasons == ("name_only_match",)
    assert not decision.effect_eligible


def test_typed_predicate_mismatch_is_incomplete() -> None:
    case = _case()
    requirement = case.pack.facts[0].structural_requirements[2]
    observation, resolver = _observation(requirement, case.match.product_location, observed="pkg.Other", suffix="-wrong")
    observations = tuple(observation if item.requirement_id == requirement.requirement_id else item for item in case.match.observations)
    match = _redigest(replace(case.match, observations=observations))
    case = replace(case, resolver=InMemoryContentResolver({**case.resolver.artifacts, **resolver.artifacts}))

    decision = _validate(case, match)

    assert decision.status is RelationStatus.INCOMPLETE
    assert decision.reasons == ("predicate_mismatch:receiver",)


@pytest.mark.parametrize("mode", ("duplicate", "conflict", "fabricated"))
def test_ambiguous_or_fabricated_identifier_sets_are_unresolved(mode: str) -> None:
    case = _case()
    observations = case.match.observations
    resolver = case.resolver
    if mode == "duplicate":
        observations += (observations[0],)
    elif mode == "conflict":
        requirement = case.pack.facts[0].structural_requirements[0]
        extra, extra_resolver = _observation(requirement, case.match.product_location, observed="pkg.Other", suffix="-conflict")
        observations += (extra,)
        resolver = InMemoryContentResolver({**resolver.artifacts, **extra_resolver.artifacts})
    else:
        fabricated = replace(observations[0], requirement_id="invented")
        reference, extra_resolver = stored_artifact(
            structural_observation_bytes(fabricated),
            artifact_id="observation-invented",
        )
        observations += (replace(fabricated, evidence=reference),)
        resolver = InMemoryContentResolver({**resolver.artifacts, **extra_resolver.artifacts})
    match = _redigest(replace(case.match, observations=observations))

    decision = _validate(replace(case, resolver=resolver), match)

    assert decision.status is RelationStatus.UNRESOLVED
    assert not decision.effect_eligible
    assert any(mode in reason or "ambiguous" in reason for reason in decision.reasons)


def test_observation_from_another_product_location_is_unresolved() -> None:
    case = _case()
    requirement = case.pack.facts[0].structural_requirements[1]
    other = SourceLocation("src/other.py", 4, 0, None)
    observation, resolver = _observation(requirement, other, suffix="-other-location")
    observations = tuple(observation if item.requirement_id == requirement.requirement_id else item for item in case.match.observations)
    match = _redigest(replace(case.match, observations=observations))
    case = replace(case, resolver=InMemoryContentResolver({**case.resolver.artifacts, **resolver.artifacts}))

    decision = _validate(case, match)

    assert decision.status is RelationStatus.UNRESOLVED
    assert decision.reasons == ("ambiguous_product_location:shape",)


def test_every_observation_artifact_must_resolve_to_its_exact_canonical_payload() -> None:
    case = _case()
    observation = case.match.observations[0]
    wrong_reference, resolver = stored_artifact(b'{"plausible":"but-wrong"}', artifact_id="wrong-payload")
    observations = (replace(observation, evidence=wrong_reference),) + case.match.observations[1:]
    match = _redigest(replace(case.match, observations=observations))
    case = replace(case, resolver=InMemoryContentResolver({**case.resolver.artifacts, **resolver.artifacts}))

    with pytest.raises(FactMatchValidationError, match="canonical observation payload"):
        _validate(case, match)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("pack_digest", "f" * 64, "pack digest"),
        ("fact_id", "other.fact", "fact identity"),
        ("match_digest", "f" * 64, "match digest"),
    ),
)
def test_tampered_named_match_identities_are_refused(field: str, value: str, message: str) -> None:
    case = _case()
    if field == "pack_digest":
        match = replace(case.match, pack_digest=value)
    elif field == "fact_id":
        match = replace(case.match, fact_id=value)
    else:
        match = replace(case.match, match_digest=value)

    with pytest.raises(FactMatchValidationError, match=message):
        _validate(case, match)


def test_match_digest_binds_revision_behavior_lineage_location_and_observations() -> None:
    case = _case()
    original = case.match.match_digest
    variants = (
        replace(case.match, matcher_revision="matcher-v4"),
        replace(case.match, matcher_behavior_digest=canonical.content_digest("other-behavior")),
        replace(case.match, matcher_lineage_manifest_digest="f" * 64),
        replace(case.match, product_location=SourceLocation("src/product.py", 18, 8, "run")),
        replace(case.match, observations=case.match.observations[:-1]),
    )

    assert all(derive_fact_match_digest(item) != original for item in variants)


def test_matcher_lineage_must_resolve_exact_behavior_and_current_receipt() -> None:
    case = _case()

    with pytest.raises(FactMatchValidationError, match="lineage manifest"):
        validate_fact_match(
            case.pack,
            case.pack.facts[0].fact_id,
            case.match,
            case.protected_population,
            (),
            case.custody,
            case.custody_policy,
            case.review_policy,
            case.resolver,
        )


def test_matcher_lineage_requires_exact_matching_behavior_use() -> None:
    case = _case()
    lineage, custody, policy, protected = _matcher_lineage(
        case.match.matcher_behavior_digest,
        purpose=provenance.LineagePurpose.PROMPT,
    )
    match = _redigest(replace(case.match, matcher_lineage_manifest_digest=lineage.manifest_digest))
    case = replace(case, match=match, lineage=lineage, custody=custody, custody_policy=policy, protected_population=protected)

    decision = _validate(case)

    assert decision.status is RelationStatus.UNRESOLVED
    assert any(reason.startswith("missing_required_use:matching_behavior:") for reason in decision.reasons)
    assert any(reason.startswith("unexpected_use:prompt:") for reason in decision.reasons)


def test_matcher_behavior_subject_substitution_is_refused() -> None:
    case = _case()
    match = _redigest(replace(case.match, matcher_behavior_digest=canonical.content_digest("substituted-behavior")))

    with pytest.raises(FactMatchValidationError, match="lineage contract"):
        _validate(case, match)


def test_lineage_receipt_must_remain_in_current_complete_custody_chain() -> None:
    case = _case()
    empty, policy, _ = custody_contract()
    empty_custody = InMemoryPopulationCustody(empty, policy)

    with pytest.raises(FactMatchValidationError, match="current complete custody chain"):
        _validate(replace(case, custody=empty_custody, custody_policy=policy))


def _append_current_matching_use(case: MatchCase, *, labels_accessed: bool) -> provenance.PopulationUseReceipt:
    current = case.custody.current_log(case.protected_population)
    request = provenance.PopulationUseRequest(
        case.protected_population,
        case.lineage.arm_id,
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        labels_accessed,
        case.match.matcher_behavior_digest,
        current.log_digest,
    )
    return case.custody.append(request, current.custodian_identity)


def test_omitted_later_protected_label_use_refuses_clean_match_manifest() -> None:
    case = _case()
    omitted = _append_current_matching_use(case, labels_accessed=True)

    decision = _validate(case)

    assert decision.status is RelationStatus.UNRESOLVED
    assert not decision.effect_eligible
    assert f"omitted_current_matching_use:{omitted.receipt_digest}" in decision.reasons
    assert f"protected_population_labels:{case.protected_population}" in decision.reasons


def test_omitted_later_benign_matching_use_makes_manifest_incomplete() -> None:
    case = _case()
    omitted = _append_current_matching_use(case, labels_accessed=False)

    decision = _validate(case)

    assert decision.status is RelationStatus.UNRESOLVED
    assert not decision.effect_eligible
    assert decision.reasons == (f"omitted_current_matching_use:{omitted.receipt_digest}",)


def test_protected_population_label_influence_refuses_effect_eligibility() -> None:
    case = _case(labels_accessed=True)

    decision = _validate(case)

    assert decision.status is RelationStatus.UNRESOLVED
    assert not decision.effect_eligible
    assert any(reason.startswith("protected_population_labels:") for reason in decision.reasons)
    assert any(reason.startswith("label_access_forbidden:") for reason in decision.reasons)


def test_structural_observations_deep_freeze_canonical_values() -> None:
    nested_shape: dict[str, canonical.JsonValue] = {"kind": "call"}
    nested: dict[str, canonical.JsonValue] = {"shape": nested_shape}
    reference, _ = stored_artifact(b"{}")
    observation = StructuralObservation("shape", SourceLocation("a.py", 1, None, None), nested, reference)
    nested_shape["kind"] = "changed"

    assert observation.observed == {"shape": {"kind": "call"}}
