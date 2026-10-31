"""Versioned semantic fact-pack and independent-review contracts."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, replace
from typing import cast

import pytest
from detection_core_fixtures import (
    InMemoryContentResolver,
    InMemoryPopulationCustody,
    custody_contract,
    stored_artifact,
)

from openultrasast.core import canonical, provenance
from openultrasast.core.evidence import NeutralOutcome
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
    validate_fact_pack,
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
from openultrasast.core.semantics import FieldKind, RelationKind, RelationStatus


@dataclass(frozen=True)
class PackCase:
    pack: FactPack
    contract: FamilyContract
    lineages: tuple[provenance.LineageManifest, ...]
    custody: InMemoryPopulationCustody
    custody_policy: provenance.PopulationCustodyPolicy
    review_policy: ReviewIndependencePolicy
    resolver: InMemoryContentResolver


def _contract() -> FamilyContract:
    return FamilyContract(
        family_id="reference-family",
        family_version="1",
        schema_version="family.v2",
        ecosystems=("python",),
        security_object=ObjectSpec("resource", (FieldSpec("name", FieldKind.TEXT, True),), ("name",)),
        roles=(
            RoleSpec("flow", (), (RelationKind.CALL,), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("source", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("target", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
        ),
        decisions=(DecisionRule("unknown", NeutralOutcome.INDETERMINATE, (), (RelationStatus.UNRESOLVED,)),),
        residual_questions=(ResidualQuestion("classify", ("flow",), ("unknown",)),),
        indeterminate_reasons=("missing",),
    )


def _manifest(
    subject: str,
    custody: InMemoryPopulationCustody,
    custody_policy: provenance.PopulationCustodyPolicy,
    custodian: str,
    *,
    labels_accessed: bool = False,
) -> provenance.LineageManifest:
    initial = custody.current_log(canonical.content_digest("population"))
    request = provenance.PopulationUseRequest(
        population_digest=initial.population_digest,
        arm_id="fact-arm",
        purpose=provenance.LineagePurpose.SEMANTIC_FACT,
        labels_accessed=labels_accessed,
        influenced_artifact_digest=subject,
        expected_log_digest=initial.log_digest,
    )
    receipt = custody.append(request, custodian)
    use = provenance.LineageUse(
        purpose=request.purpose,
        source_population_digest=request.population_digest,
        labels_accessed=labels_accessed,
        influenced_artifact_digest=subject,
        population_use_receipt_digest=receipt.receipt_digest,
    )
    digest = provenance.derive_lineage_manifest_digest("fact-arm", subject, (use,))
    return provenance.LineageManifest("fact-arm", subject, (use,), digest)


def _case(kind: KnowledgeEvidenceKind = KnowledgeEvidenceKind.SOURCE_CODE, *, labels_accessed: bool = False) -> PackCase:
    contract = _contract()
    producer = canonical.content_digest("producer")
    reviewer = canonical.content_digest("reviewer")
    content, content_resolver = stored_artifact(b'{"reviewed":"content"}', artifact_id="knowledge")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="conflicts")
    resolver = InMemoryContentResolver({**content_resolver.artifacts, **disclosure_resolver.artifacts})
    provisional_attestation = IndependenceAttestation(content.content_digest, producer, reviewer, disclosure, "0" * 64)
    attestation = replace(
        provisional_attestation,
        attestation_digest=derive_independence_attestation_digest(provisional_attestation),
    )
    provisional_evidence = KnowledgeEvidence(kind, content, producer, reviewer, attestation, "0" * 64)
    reviewer_digests = (reviewer,)
    forbidden_pairs: tuple[tuple[str, str], ...] = ()
    stores = ("trusted-store",)
    policy = ReviewIndependencePolicy(
        reviewer_digests,
        forbidden_pairs,
        stores,
        4096,
        derive_review_independence_policy_digest(reviewer_digests, forbidden_pairs, stores, 4096),
    )
    fact = SemanticFact(
        "stable.fact.v1",
        "flow",
        (StructuralRequirement("qualified-name", StructuralRequirementKind.QUALIFIED_NAME, "callee", "pkg.call"),),
        (RelationEffect(RelationKind.CALL, "flow", "source", "target", ("receiver_resolved",)),),
    )
    provisional_pack = FactPack(
        FACT_PACK_SCHEMA,
        family_contract_digest(contract),
        contract.family_id,
        "python",
        "python",
        (fact,),
        "0" * 64,
        reviewer,
        (provisional_evidence,),
        "0" * 64,
        policy.policy_digest,
    )
    normalized = derive_fact_pack_content_digest(provisional_pack)
    initial, custody_policy, custodian = custody_contract()
    custody = InMemoryPopulationCustody(initial, custody_policy)
    lineage = _manifest(normalized, custody, custody_policy, custodian, labels_accessed=labels_accessed)
    evidence = replace(provisional_evidence, lineage_manifest_digest=lineage.manifest_digest)
    pack = replace(
        provisional_pack,
        normalized_content_digest=normalized,
        review_evidence=(evidence,),
        review_evidence_digest=derive_review_evidence_digest((evidence,)),
    )
    return PackCase(pack, contract, (lineage,), custody, custody_policy, policy, resolver)


def _validate(case: PackCase) -> None:
    validate_fact_pack(
        case.pack,
        case.contract,
        None,
        case.lineages,
        case.custody,
        case.custody_policy,
        case.review_policy,
        case.resolver,
    )


def _with_policy(case: PackCase, policy: ReviewIndependencePolicy) -> PackCase:
    pack = replace(case.pack, review_policy_digest=policy.policy_digest)
    pack = replace(pack, normalized_content_digest=derive_fact_pack_content_digest(pack))
    initial, custody_policy, custodian = custody_contract()
    custody = InMemoryPopulationCustody(initial, custody_policy)
    lineage = _manifest(pack.normalized_content_digest, custody, custody_policy, custodian)
    evidence = replace(pack.review_evidence[0], lineage_manifest_digest=lineage.manifest_digest)
    pack = replace(pack, review_evidence=(evidence,), review_evidence_digest=derive_review_evidence_digest((evidence,)))
    return replace(
        case,
        pack=pack,
        lineages=(lineage,),
        custody=custody,
        custody_policy=custody_policy,
        review_policy=policy,
    )


@pytest.mark.parametrize("kind", tuple(KnowledgeEvidenceKind))
def test_reviewed_label_isolated_pack_accepts_each_evidence_kind(kind: KnowledgeEvidenceKind) -> None:
    case = _case(kind)

    _validate(case)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("schema_version", "fact-pack.v1", "schema"),
        ("family_id", "other-family", "family"),
        ("ecosystem", "javascript", "ecosystem"),
        ("family_contract_digest", "f" * 64, "contract digest"),
        ("normalized_content_digest", "f" * 64, "normalized content digest"),
        ("review_evidence_digest", "f" * 64, "review evidence digest"),
        ("review_policy_digest", "f" * 64, "review policy digest"),
    ),
)
def test_pack_rejects_scope_or_digest_substitution(field: str, value: str, message: str) -> None:
    case = _case()
    if field == "schema_version":
        pack = replace(case.pack, schema_version=value)
    elif field == "family_id":
        pack = replace(case.pack, family_id=value)
    elif field == "ecosystem":
        pack = replace(case.pack, ecosystem=value)
    elif field == "family_contract_digest":
        pack = replace(case.pack, family_contract_digest=value)
    elif field == "normalized_content_digest":
        pack = replace(case.pack, normalized_content_digest=value)
    elif field == "review_evidence_digest":
        pack = replace(case.pack, review_evidence_digest=value)
    else:
        assert field == "review_policy_digest"
        pack = replace(case.pack, review_policy_digest=value)
    changed = replace(case, pack=pack)

    with pytest.raises(FactPackValidationError, match=message):
        _validate(changed)


def test_pack_rejects_missing_review_and_duplicate_fact_ids() -> None:
    case = _case()
    missing = replace(case, pack=replace(case.pack, review_evidence=()))
    duplicate = replace(case, pack=replace(case.pack, facts=(case.pack.facts[0], case.pack.facts[0])))

    with pytest.raises(FactPackValidationError, match="review evidence"):
        _validate(missing)
    with pytest.raises(FactPackValidationError, match="duplicate fact"):
        _validate(duplicate)


@pytest.mark.parametrize("part", ("fact", "effect", "source", "target", "kind"))
def test_pack_rejects_undeclared_roles_and_relation_kinds(part: str) -> None:
    case = _case()
    fact = case.pack.facts[0]
    effect = fact.relation_effects[0]
    if part == "fact":
        fact = replace(fact, role="undeclared")
    elif part == "kind":
        fact = replace(fact, relation_effects=(replace(effect, kind=RelationKind.RETURN),))
    elif part == "effect":
        fact = replace(fact, relation_effects=(replace(effect, role="undeclared"),))
    elif part == "source":
        fact = replace(fact, relation_effects=(replace(effect, source_role="undeclared"),))
    else:
        assert part == "target"
        fact = replace(fact, relation_effects=(replace(effect, target_role="undeclared"),))
    changed = replace(case, pack=replace(case.pack, facts=(fact,)))

    with pytest.raises(FactPackValidationError, match="role|relation kind"):
        _validate(changed)


def test_pack_rejects_attestation_substitution_and_unreadable_conflict_disclosure() -> None:
    case = _case()
    evidence = case.pack.review_evidence[0]
    wrong_subject = replace(evidence.independence, subject_digest="f" * 64)
    changed = replace(case, pack=replace(case.pack, review_evidence=(replace(evidence, independence=wrong_subject),)))

    with pytest.raises(FactPackValidationError, match="attestation subject"):
        _validate(changed)

    unreadable = replace(
        case,
        resolver=InMemoryContentResolver({key: value for key, value in case.resolver.artifacts.items() if key != "conflicts"}),
    )
    with pytest.raises(canonical.ArtifactResolutionError):
        _validate(unreadable)


@pytest.mark.parametrize("failure", ("self_review", "unknown_reviewer", "forbidden_pair"))
def test_behavioral_evidence_requires_independent_trusted_review(failure: str) -> None:
    case = _case(KnowledgeEvidenceKind.INDEPENDENT_BEHAVIOR)
    evidence = case.pack.review_evidence[0]
    if failure == "self_review":
        evidence = replace(evidence, producer_identity=evidence.reviewer_identity)
    elif failure == "unknown_reviewer":
        unknown = canonical.content_digest("unknown")
        evidence = replace(evidence, reviewer_identity=unknown)
    else:
        pair = ((evidence.producer_identity, evidence.reviewer_identity),)
        policy = replace(
            case.review_policy,
            forbidden_identity_pairs=pair,
            policy_digest=derive_review_independence_policy_digest(
                case.review_policy.reviewed_reviewer_digests,
                pair,
                case.review_policy.trusted_store_identities,
                case.review_policy.maximum_evidence_bytes,
            ),
        )
        case = _with_policy(case, policy)
    changed = replace(case, pack=replace(case.pack, review_evidence=(evidence,)))

    with pytest.raises(FactPackValidationError, match="producer|reviewer|forbidden"):
        _validate(changed)


def test_source_evidence_may_be_produced_by_its_trusted_reviewer() -> None:
    case = _case(KnowledgeEvidenceKind.SOURCE_CODE)
    evidence = case.pack.review_evidence[0]
    same = evidence.reviewer_identity
    attestation = replace(evidence.independence, producer_identity=same)
    attestation = replace(attestation, attestation_digest=derive_independence_attestation_digest(attestation))
    evidence = replace(evidence, producer_identity=same, independence=attestation)
    pack = replace(case.pack, review_evidence=(evidence,))
    pack = replace(
        pack,
        normalized_content_digest=derive_fact_pack_content_digest(pack),
        review_evidence_digest=derive_review_evidence_digest((evidence,)),
    )
    # The lineage subject must follow the amended normalized review content.
    initial, policy, custodian = custody_contract()
    custody = InMemoryPopulationCustody(initial, policy)
    lineage = _manifest(pack.normalized_content_digest, custody, policy, custodian)
    evidence = replace(evidence, lineage_manifest_digest=lineage.manifest_digest)
    pack = replace(pack, review_evidence=(evidence,), review_evidence_digest=derive_review_evidence_digest((evidence,)))

    _validate(replace(case, pack=pack, lineages=(lineage,), custody=custody, custody_policy=policy))


def test_pack_rejects_missing_wrong_or_label_derived_lineage() -> None:
    case = _case()
    with pytest.raises(FactPackValidationError, match="lineage"):
        _validate(replace(case, lineages=()))

    wrong = replace(case.lineages[0], subject_digest=canonical.content_digest("other"))
    with pytest.raises((FactPackValidationError, provenance.LineageValidationError), match="lineage|subject"):
        _validate(replace(case, lineages=(wrong,)))

    labelled = _case(labels_accessed=True)
    with pytest.raises(FactPackValidationError, match="label_access_forbidden"):
        _validate(labelled)


def test_pack_revalidates_policy_and_resolver_trust_boundaries() -> None:
    case = _case()
    tampered = replace(case.review_policy, policy_digest="f" * 64)
    with pytest.raises(FactPackValidationError, match="policy digest"):
        _validate(replace(case, review_policy=tampered))

    too_small = replace(
        case.review_policy,
        maximum_evidence_bytes=1,
        policy_digest=derive_review_independence_policy_digest(
            case.review_policy.reviewed_reviewer_digests,
            case.review_policy.forbidden_identity_pairs,
            case.review_policy.trusted_store_identities,
            1,
        ),
    )
    with pytest.raises(canonical.ArtifactValidationError, match="maximum"):
        _validate(_with_policy(case, too_small))


def test_structural_requirement_defensively_freezes_nested_caller_json() -> None:
    nested_item: dict[str, canonical.JsonValue] = {"name": "original"}
    caller_sequence: tuple[canonical.JsonValue, ...] = ("first", nested_item, "last")
    caller_value: dict[str, canonical.JsonValue] = {"items": caller_sequence}
    requirement = StructuralRequirement("shape", StructuralRequirementKind.AST_SHAPE, "node", caller_value)
    case = _case()
    fact = replace(case.pack.facts[0], structural_requirements=(requirement,))
    pack = replace(case.pack, facts=(fact,))
    original_digest = derive_fact_pack_content_digest(pack)

    nested_item["name"] = "mutated"
    caller_value["added"] = True
    exposed = cast(MutableMapping[str, canonical.JsonValue], requirement.expected)
    with pytest.raises(TypeError):
        exposed["added"] = False

    frozen = cast(Mapping[str, canonical.JsonValue], requirement.expected)
    frozen_items = cast(tuple[canonical.JsonValue, ...], frozen["items"])
    frozen_nested = cast(Mapping[str, canonical.JsonValue], frozen_items[1])
    assert tuple(frozen_items) == ("first", frozen_items[1], "last")
    assert frozen_nested["name"] == "original"
    assert "added" not in frozen
    assert derive_fact_pack_content_digest(pack) == original_digest


def test_pack_revalidation_freezes_and_rejects_post_construction_expected_tamper() -> None:
    case = _case()
    requirement = case.pack.facts[0].structural_requirements[0]
    object.__setattr__(requirement, "expected", {"callee": "tampered"})

    with pytest.raises(FactPackValidationError, match="normalized content digest"):
        _validate(case)
    assert isinstance(requirement.expected, Mapping)
    with pytest.raises(TypeError):
        cast(MutableMapping[str, canonical.JsonValue], requirement.expected)["callee"] = "again"
