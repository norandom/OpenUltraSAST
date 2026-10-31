"""Reviewed fact-effect materialization and reproducible provenance."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, InMemoryPopulationCustody, custody_contract, stored_artifact

from openultrasast.core import canonical, provenance
from openultrasast.core.evidence import NeutralOutcome
from openultrasast.core.factapply import FactApplicationError, apply_fact
from openultrasast.core.factmatch import (
    FactMatchEvidence,
    StructuralObservation,
    derive_fact_match_digest,
    fact_match_bytes,
    structural_observation_bytes,
)
from openultrasast.core.factpack import (
    FACT_PACK_SCHEMA,
    FactPack,
    FactPackValidationError,
    IndependenceAttestation,
    KnowledgeEvidence,
    KnowledgeEvidenceKind,
    RelationEffect,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
    derive_fact_pack_content_digest,
    derive_independence_attestation_digest,
    derive_review_evidence_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.family import (
    DecisionRule,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RelationOriginPolicy,
    ResidualQuestion,
    RoleSpec,
    family_contract_digest,
)
from openultrasast.core.semantics import (
    FieldKind,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticRelation,
    SourceLocation,
)


@dataclass(frozen=True)
class ApplyCase:
    pack: FactPack
    contract: FamilyContract
    match: FactMatchEvidence
    match_reference: canonical.ContentRef
    lineages: tuple[provenance.LineageManifest, ...]
    custody: InMemoryPopulationCustody
    custody_policy: provenance.PopulationCustodyPolicy
    review_policy: ReviewIndependencePolicy
    resolver: InMemoryContentResolver
    population_digest: str


def _contract() -> FamilyContract:
    return FamilyContract(
        "reference-family",
        "1",
        "family.v2",
        ("python",),
        ObjectSpec("resource", (FieldSpec("name", FieldKind.TEXT, True),), ("name",)),
        (
            RoleSpec("flow", (), (RelationKind.CALL,), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("source", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("target", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
        ),
        (DecisionRule("unknown", NeutralOutcome.INDETERMINATE, (), (RelationStatus.UNRESOLVED,)),),
        (ResidualQuestion("classify", ("flow",), ("unknown",)),),
        ("missing",),
    )


def _append_use(
    custody: InMemoryPopulationCustody,
    custodian: str,
    purpose: provenance.LineagePurpose,
    subject: str,
    *,
    labels_accessed: bool,
    arm_id: str,
) -> provenance.LineageUse:
    current = custody.current_log(canonical.content_digest("population"))
    request = provenance.PopulationUseRequest(
        current.population_digest,
        arm_id,
        purpose,
        labels_accessed,
        subject,
        current.log_digest,
    )
    receipt = custody.append(request, custodian)
    return provenance.LineageUse(purpose, current.population_digest, labels_accessed, subject, receipt.receipt_digest)


def _manifest(arm_id: str, subject: str, uses: tuple[provenance.LineageUse, ...]) -> provenance.LineageManifest:
    digest = provenance.derive_lineage_manifest_digest(arm_id, subject, uses)
    return provenance.LineageManifest(arm_id, subject, uses, digest)


def _review_policy(reviewer: str) -> ReviewIndependencePolicy:
    stores = ("trusted-store",)
    digest = derive_review_independence_policy_digest((reviewer,), (), stores, 4096)
    return ReviewIndependencePolicy((reviewer,), (), stores, 4096, digest)


def _review_evidence() -> tuple[KnowledgeEvidence, InMemoryContentResolver, str]:
    producer = canonical.content_digest("producer")
    reviewer = canonical.content_digest("reviewer")
    content, content_resolver = stored_artifact(b'{"reviewed":"content"}', artifact_id="knowledge")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="conflicts")
    provisional = IndependenceAttestation(content.content_digest, producer, reviewer, disclosure, "0" * 64)
    attestation = replace(provisional, attestation_digest=derive_independence_attestation_digest(provisional))
    evidence = KnowledgeEvidence(
        KnowledgeEvidenceKind.SOURCE_CODE,
        content,
        producer,
        reviewer,
        attestation,
        "0" * 64,
    )
    artifacts = {**content_resolver.artifacts, **disclosure_resolver.artifacts}
    return evidence, InMemoryContentResolver(artifacts), reviewer


def _requirements() -> tuple[StructuralRequirement, ...]:
    return (
        StructuralRequirement("qualified", StructuralRequirementKind.QUALIFIED_NAME, "callee", "pkg.Client.call"),
        StructuralRequirement("shape", StructuralRequirementKind.AST_SHAPE, "shape", {"node": "call"}),
    )


def _case(
    *,
    effects: tuple[RelationEffect, ...] | None = None,
    missing_requirement: str | None = None,
    matcher_labels: bool = False,
    promotion_labels: bool = False,
    omitted_promotion_labels: bool = False,
) -> ApplyCase:
    contract = _contract()
    evidence, review_resolver, reviewer = _review_evidence()
    review_policy = _review_policy(reviewer)
    effects = effects or (RelationEffect(RelationKind.CALL, "flow", "source", "target", ("matched",)),)
    fact = SemanticFact("stable.fact.v1", "flow", _requirements(), effects)
    provisional_pack = FactPack(
        FACT_PACK_SCHEMA,
        family_contract_digest(contract),
        contract.family_id,
        "python",
        "python",
        (fact,),
        "0" * 64,
        reviewer,
        (evidence,),
        "0" * 64,
        review_policy.policy_digest,
    )
    pack_digest = derive_fact_pack_content_digest(provisional_pack)
    initial, custody_policy, custodian = custody_contract()
    custody = InMemoryPopulationCustody(initial, custody_policy)
    fact_uses: tuple[provenance.LineageUse, ...] = (
        _append_use(
            custody,
            custodian,
            provenance.LineagePurpose.SEMANTIC_FACT,
            pack_digest,
            labels_accessed=False,
            arm_id="fact-arm",
        ),
    )
    if promotion_labels:
        fact_uses += (
            _append_use(
                custody,
                custodian,
                provenance.LineagePurpose.PROMOTION,
                pack_digest,
                labels_accessed=True,
                arm_id="fact-arm",
            ),
        )
    fact_lineage = _manifest("fact-arm", pack_digest, fact_uses)
    if omitted_promotion_labels:
        _append_use(
            custody,
            custodian,
            provenance.LineagePurpose.PROMOTION,
            pack_digest,
            labels_accessed=True,
            arm_id="fact-arm",
        )
    evidence = replace(evidence, lineage_manifest_digest=fact_lineage.manifest_digest)
    pack = replace(
        provisional_pack,
        normalized_content_digest=pack_digest,
        review_evidence=(evidence,),
        review_evidence_digest=derive_review_evidence_digest((evidence,)),
    )
    location = SourceLocation("src/product.py", 17, 8, "run")
    observations: list[StructuralObservation] = []
    artifacts = dict(review_resolver.artifacts)
    for requirement in fact.structural_requirements:
        if requirement.requirement_id == missing_requirement:
            continue
        provisional_observation = StructuralObservation(
            requirement.requirement_id,
            location,
            requirement.expected,
            canonical.ContentRef("provisional", "0" * 64, "application/json", 0, "0" * 64, "0" * 64),
        )
        reference, observation_resolver = stored_artifact(
            structural_observation_bytes(provisional_observation),
            artifact_id=f"observation-{requirement.requirement_id}",
        )
        observations.append(replace(provisional_observation, evidence=reference))
        artifacts.update(observation_resolver.artifacts)
    behavior = canonical.content_digest("matcher-behavior-v3")
    matcher_use = _append_use(
        custody,
        custodian,
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        behavior,
        labels_accessed=matcher_labels,
        arm_id="matcher-arm",
    )
    matcher_lineage = _manifest("matcher-arm", behavior, (matcher_use,))
    provisional_match = FactMatchEvidence(
        pack.normalized_content_digest,
        fact.fact_id,
        location,
        tuple(observations),
        "matcher-v3",
        behavior,
        matcher_lineage.manifest_digest,
        "0" * 64,
    )
    match = replace(provisional_match, match_digest=derive_fact_match_digest(provisional_match))
    match_reference, match_resolver = stored_artifact(fact_match_bytes(match), artifact_id="fact-match")
    artifacts.update(match_resolver.artifacts)
    return ApplyCase(
        pack,
        contract,
        match,
        match_reference,
        (fact_lineage, matcher_lineage),
        custody,
        custody_policy,
        review_policy,
        InMemoryContentResolver(artifacts),
        initial.population_digest,
    )


def _apply(case: ApplyCase) -> tuple[SemanticRelation, ...]:
    return apply_fact(
        case.pack,
        case.pack.facts[0].fact_id,
        case.match,
        case.match_reference,
        case.contract,
        case.population_digest,
        case.lineages,
        case.custody,
        case.custody_policy,
        case.review_policy,
        case.resolver,
    )


def test_complete_match_materializes_only_declared_effect_with_exact_provenance() -> None:
    case = _case()

    relations = _apply(case)

    assert case.match_reference.byte_length > 0
    assert len(relations) == 1
    relation = relations[0]
    assert relation.kind is RelationKind.CALL
    assert relation.role == "flow"
    assert relation.source.role == "source" and relation.target.role == "target"
    assert relation.location == case.match.product_location
    assert relation.conditions == ("matched",)
    assert relation.status is RelationStatus.COMPLETE and relation.reasons == ()
    assert relation.provenance.kind is ProvenanceKind.SEMANTIC_FACT
    assert relation.provenance.source_content_digest == case.match.match_digest
    assert relation.provenance.semantic_pack_digest == case.pack.normalized_content_digest
    assert relation.provenance.semantic_fact_id == case.match.fact_id
    assert relation.provenance.fact_match == case.match_reference


def test_partial_match_preserves_conditions_and_named_incomplete_evidence() -> None:
    case = _case(missing_requirement="shape")

    (relation,) = _apply(case)

    assert relation.status is RelationStatus.INCOMPLETE
    assert relation.conditions == ("matched",)
    assert "missing_observation:shape" in relation.reasons
    assert "unmet_condition:matched" in relation.reasons


def test_conflicting_eligible_effects_are_one_unresolved_ambiguity() -> None:
    effects = (
        RelationEffect(RelationKind.CALL, "flow", "source", "target", ("first",)),
        RelationEffect(RelationKind.CALL, "flow", "source", "target", ("second",)),
    )
    case = _case(effects=effects)

    (relation,) = _apply(case)

    assert relation.status is RelationStatus.UNRESOLVED
    assert relation.conditions == ("first", "second")
    assert any(reason.startswith("conflicting_complete_candidate:") for reason in relation.reasons)


def test_match_reference_must_resolve_to_exact_canonical_match_bytes() -> None:
    case = _case()
    wrong, wrong_resolver = stored_artifact(b'{"plausible":"but-wrong"}', artifact_id="wrong-match")
    changed = replace(
        case,
        match_reference=wrong,
        resolver=InMemoryContentResolver({**case.resolver.artifacts, **wrong_resolver.artifacts}),
    )

    with pytest.raises(FactApplicationError, match="match reference"):
        _apply(changed)


def test_label_influenced_matching_is_spent_before_relation_is_non_determinate() -> None:
    case = _case(matcher_labels=True)

    (relation,) = _apply(case)

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.SPENT
    assert relation.status is RelationStatus.UNRESOLVED
    assert f"protected_population_labels:{case.population_digest}" in relation.reasons


def test_label_influenced_promotion_is_spent_and_refused_before_materialization() -> None:
    case = _case(promotion_labels=True)

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactPackValidationError, match="label_access_forbidden"):
        _apply(case)


def test_omitted_current_promotion_spend_cannot_hide_behind_clean_pack_lineage() -> None:
    case = _case(omitted_promotion_labels=True)

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactApplicationError, match="promotion.*protected_population_labels"):
        _apply(case)
