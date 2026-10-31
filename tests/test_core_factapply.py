"""Reviewed fact-effect materialization and reproducible provenance."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, InMemoryPopulationCustody, custody_contract, stored_artifact

from openultrasast.core import canonical, evidence, provenance
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
from openultrasast.core.factvalidate import FactRelationValidationError, validate_fact_relations
from openultrasast.core.family import (
    MISSING_REVIEWED_DEPENDENCY,
    DecisionRule,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RelationOriginPolicy,
    ResidualQuestion,
    RoleSpec,
    derive_security_object_id,
    family_contract_digest,
)
from openultrasast.core.semantics import (
    EvidenceProvenance,
    FieldKind,
    FieldValue,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticNode,
    SemanticRelation,
    SourceLocation,
    make_relation,
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


class MultiPopulationCustody(InMemoryPopulationCustody):
    def __init__(
        self,
        logs: tuple[provenance.PopulationCustodyLog, ...],
        policy: provenance.PopulationCustodyPolicy,
    ) -> None:
        self._logs = {log.population_digest: log for log in logs}
        self._multi_policy = policy

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        try:
            return self._logs[population_digest]
        except KeyError as exc:
            raise provenance.PopulationCustodyError("population custody log not found") from exc

    def append(self, request: provenance.PopulationUseRequest, custodian: str) -> provenance.PopulationUseReceipt:
        prior = self.current_log(request.population_digest)
        receipt = provenance.record_population_use(request, prior, custodian, self._multi_policy)
        self._logs[request.population_digest] = provenance.append_population_use(prior, receipt, self._multi_policy)
        return receipt


def _contract(*, fact_only: bool = False) -> FamilyContract:
    origin = RelationOriginPolicy.EXCLUDED_DEPENDENCY_FACT_ONLY if fact_only else RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT
    return FamilyContract(
        "reference-family",
        "1",
        evidence.EVIDENCE_PACKET_SCHEMA,
        ("python",),
        ObjectSpec("resource", (FieldSpec("name", FieldKind.TEXT, True),), ("name",)),
        (
            RoleSpec("flow", (), (RelationKind.CALL,), origin),
            RoleSpec("source", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
            RoleSpec("target", (FieldSpec("name", FieldKind.TEXT, False),), (), RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT),
        ),
        (
            DecisionRule("safe", NeutralOutcome.SATISFIED, ("flow",), (RelationStatus.COMPLETE,)),
            DecisionRule("unknown", NeutralOutcome.INDETERMINATE, (), (RelationStatus.INCOMPLETE, RelationStatus.UNRESOLVED)),
        ),
        (ResidualQuestion("classify", ("flow",), ("safe", "unknown")),),
        ("missing", MISSING_REVIEWED_DEPENDENCY),
    )


def _append_use(
    custody: InMemoryPopulationCustody,
    custodian: str,
    purpose: provenance.LineagePurpose,
    subject: str,
    *,
    labels_accessed: bool,
    arm_id: str,
    population_digest: str | None = None,
) -> provenance.LineageUse:
    current = custody.current_log(population_digest or canonical.content_digest("population"))
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
    fact_only: bool = False,
) -> ApplyCase:
    contract = _contract(fact_only=fact_only)
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


def _case_with_distinct_evaluation_population() -> ApplyCase:
    case = _case(fact_only=True)
    source_log = case.custody.current_log(case.population_digest)
    evaluation_digest = canonical.content_digest("distinct-evaluation-population")
    evaluation_log = provenance.empty_population_custody_log(
        evaluation_digest,
        case.custody_policy.reviewed_custodian_digests[0],
    )
    custody = MultiPopulationCustody((source_log, evaluation_log), case.custody_policy)
    return replace(case, custody=custody, population_digest=evaluation_digest)


def _case_with_three_populations() -> tuple[ApplyCase, str]:
    case = _case(fact_only=True)
    custodian = case.custody_policy.reviewed_custodian_digests[0]
    source_log = case.custody.current_log(case.population_digest)
    fact_empty = provenance.empty_population_custody_log(case.population_digest, custodian)
    fact_log = provenance.append_population_use(fact_empty, source_log.receipts[0], case.custody_policy)
    matcher_population = canonical.content_digest("distinct-matcher-population")
    matcher_empty = provenance.empty_population_custody_log(matcher_population, custodian)
    matcher_request = provenance.PopulationUseRequest(
        matcher_population,
        "matcher-arm",
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        False,
        case.match.matcher_behavior_digest,
        matcher_empty.log_digest,
    )
    matcher_receipt = provenance.record_population_use(matcher_request, matcher_empty, custodian, case.custody_policy)
    matcher_log = provenance.append_population_use(matcher_empty, matcher_receipt, case.custody_policy)
    matcher_use = provenance.LineageUse(
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        matcher_population,
        False,
        case.match.matcher_behavior_digest,
        matcher_receipt.receipt_digest,
    )
    matcher_lineage = _manifest("matcher-arm", case.match.matcher_behavior_digest, (matcher_use,))
    provisional_match = replace(
        case.match,
        matcher_lineage_manifest_digest=matcher_lineage.manifest_digest,
        match_digest="0" * 64,
    )
    match = replace(provisional_match, match_digest=derive_fact_match_digest(provisional_match))
    match_reference, match_resolver = stored_artifact(fact_match_bytes(match), artifact_id="fact-match")
    evaluation_digest = canonical.content_digest("third-evaluation-population")
    evaluation_log = provenance.empty_population_custody_log(evaluation_digest, custodian)
    custody = MultiPopulationCustody((fact_log, matcher_log, evaluation_log), case.custody_policy)
    artifacts = {**case.resolver.artifacts, **match_resolver.artifacts}
    changed = replace(
        case,
        match=match,
        match_reference=match_reference,
        lineages=(case.lineages[0], matcher_lineage),
        custody=custody,
        resolver=InMemoryContentResolver(artifacts),
        population_digest=evaluation_digest,
    )
    return changed, matcher_population


def _stamp(case: ApplyCase) -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        canonical.content_digest("analyzer"),
        family_contract_digest(case.contract),
        canonical.content_digest("fact-set"),
        canonical.content_digest("acquisition"),
        canonical.content_digest("configuration"),
        case.population_digest,
        canonical.content_digest("change-input"),
    )


def _record(case: ApplyCase, relation: SemanticRelation) -> evidence.EvidenceRecord:
    fields = (FieldValue("name", FieldKind.TEXT, "resource"),)
    scope = evidence.AnalyzedScope(
        "base",
        "head",
        canonical.content_digest("change"),
        (evidence.SourceRegion(case.match.product_location.path, 1, 30),),
    )
    reasons = relation.reasons if relation.status is not RelationStatus.COMPLETE else ()
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        case.contract.family_id,
        family_contract_digest(case.contract),
        derive_security_object_id(case.contract.security_object, fields),
        case.pack.ecosystem,
        scope,
        (relation,),
        (),
        fields,
        reasons,
        _stamp(case),
    )
    outcome = NeutralOutcome.SATISFIED if relation.status is RelationStatus.COMPLETE else NeutralOutcome.INDETERMINATE
    decision = evidence.Decision(
        "safe" if relation.status is RelationStatus.COMPLETE else "unknown",
        outcome,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        reasons,
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, decision, "")


def _validate(case: ApplyCase, record: evidence.EvidenceRecord, *, packs: tuple[FactPack, ...] | None = None) -> None:
    validate_fact_relations(
        record,
        case.contract,
        (case.pack,) if packs is None else packs,
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


def test_reviewed_dependency_relation_replays_from_every_named_input() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    record = _record(case, relation)

    _validate(case, record)


def test_product_only_dependency_behavior_is_refused() -> None:
    case = _case(fact_only=True)
    (reviewed,) = _apply(case)
    product = replace(
        reviewed,
        provenance=EvidenceProvenance(ProvenanceKind.PRODUCT_CODE, case.match.match_digest, None, None, None),
        relation_id="",
    )

    with pytest.raises(FactRelationValidationError, match="reviewed semantic fact"):
        _validate(case, _record(case, product))


def test_missing_dependency_fact_remains_named_and_indeterminate() -> None:
    case = _case(fact_only=True)
    location = case.match.product_location
    missing = make_relation(
        kind=RelationKind.CALL,
        role="flow",
        source=SemanticNode("source", "source", location),
        target=SemanticNode("target", "target", location),
        location=location,
        status=RelationStatus.INCOMPLETE,
        conditions=("matched",),
        reasons=(MISSING_REVIEWED_DEPENDENCY,),
        provenance=EvidenceProvenance(ProvenanceKind.PRODUCT_CODE, case.match.match_digest, None, None, None),
    )
    record = _record(case, missing)

    _validate(case, record)

    assert record.decision.outcome is NeutralOutcome.INDETERMINATE
    assert record.decision.reasons == (MISSING_REVIEWED_DEPENDENCY,)


def test_fact_relation_replay_refuses_undeclared_role_and_invalid_scope() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    undeclared = replace(relation, role="undeclared", relation_id="")
    with pytest.raises(FactRelationValidationError, match="undeclared semantic role"):
        _validate(case, _record(case, undeclared))

    record = _record(case, relation)
    packet = replace(record.packet, ecosystem="javascript")
    decision = replace(record.decision, packet_digest=evidence.derive_packet_digest(packet))
    with pytest.raises(FactRelationValidationError, match="unsupported ecosystem scope"):
        _validate(case, evidence.EvidenceRecord(packet, decision, ""))


def test_fact_relation_replay_refuses_inconsistent_relation_and_fact_identity() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    inconsistent = replace(relation, conditions=("substituted",), relation_id="")
    with pytest.raises(FactRelationValidationError, match="does not equal replayed"):
        _validate(case, _record(case, inconsistent))

    wrong_origin = replace(relation.provenance, semantic_fact_id="other.fact")
    wrong_fact = replace(relation, provenance=wrong_origin, relation_id="")
    with pytest.raises(FactRelationValidationError, match="fact identity"):
        _validate(case, _record(case, wrong_fact))


def test_fact_relation_replay_refuses_substituted_resolved_match_bytes() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    wrong_ref, wrong_resolver = stored_artifact(b'{"plausible":"but-wrong"}', artifact_id="wrong-replay-match")
    wrong_origin = replace(
        relation.provenance,
        source_content_digest=wrong_ref.content_digest,
        fact_match=wrong_ref,
    )
    wrong_relation = replace(relation, provenance=wrong_origin, relation_id="")
    changed = replace(
        case,
        resolver=InMemoryContentResolver({**case.resolver.artifacts, **wrong_resolver.artifacts}),
    )

    with pytest.raises(FactRelationValidationError, match="match artifact"):
        _validate(changed, _record(changed, wrong_relation))


def test_fact_relation_replay_refuses_ambiguous_pack_and_changed_current_custody() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    record = _record(case, relation)
    with pytest.raises(FactRelationValidationError, match="pack identity is missing or ambiguous"):
        _validate(case, record, packs=(case.pack, case.pack))

    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.PROMOTION,
        case.pack.normalized_content_digest,
        labels_accessed=True,
        arm_id="other-arm",
    )
    with pytest.raises(FactRelationValidationError, match="promotion lineage is contaminated"):
        _validate(case, record)


def test_fact_relation_replay_refuses_omitted_current_semantic_fact_label_use() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    record = _record(case, relation)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=True,
        arm_id="fact-arm",
    )

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactRelationValidationError, match="semantic fact.*protected_population_labels"):
        _validate(case, record)


def test_fact_relation_replay_refuses_cross_arm_protected_semantic_fact_label_use() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    record = _record(case, relation)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=True,
        arm_id="other-arm",
    )

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactRelationValidationError, match="semantic fact.*protected_population_labels"):
        _validate(case, record)


def test_fact_relation_replay_refuses_cross_arm_label_use_from_lineage_source_population() -> None:
    case = _case_with_distinct_evaluation_population()
    (relation,) = _apply(case)
    record = _record(case, relation)
    source_population = canonical.content_digest("population")
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=True,
        arm_id="other-arm",
    )

    assert source_population != case.population_digest
    assert case.custody.current_log(source_population).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactRelationValidationError, match="semantic fact.*label_access_forbidden"):
        _validate(case, record)


def test_fact_relation_replay_refuses_label_use_from_other_supplied_lineage_population() -> None:
    case, matcher_population = _case_with_three_populations()
    (relation,) = _apply(case)
    record = _record(case, relation)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=True,
        arm_id="other-arm",
        population_digest=matcher_population,
    )

    assert matcher_population not in {
        case.population_digest,
        case.lineages[0].uses[0].source_population_digest,
    }
    assert case.custody.current_log(matcher_population).status is provenance.PopulationStatus.SPENT
    with pytest.raises(FactRelationValidationError, match="semantic fact.*label_access_forbidden"):
        _validate(case, record)


@pytest.mark.parametrize(
    ("purpose", "subject", "labels_accessed"),
    (
        (provenance.LineagePurpose.SEMANTIC_FACT, "exact-pack", False),
        (provenance.LineagePurpose.MATCHING_BEHAVIOR, "exact-pack", True),
        (provenance.LineagePurpose.SEMANTIC_FACT, "wrong-digest", True),
    ),
)
def test_fact_relation_replay_ignores_unrelated_cross_arm_source_receipts(
    purpose: provenance.LineagePurpose,
    subject: str,
    labels_accessed: bool,
) -> None:
    case = _case_with_distinct_evaluation_population()
    (relation,) = _apply(case)
    record = _record(case, relation)
    influenced = case.pack.normalized_content_digest if subject == "exact-pack" else canonical.content_digest(subject)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        purpose,
        influenced,
        labels_accessed=labels_accessed,
        arm_id="other-arm",
    )

    _validate(case, record)


@pytest.mark.parametrize(
    ("purpose", "subject", "labels_accessed"),
    (
        (provenance.LineagePurpose.SEMANTIC_FACT, "exact-pack", False),
        (provenance.LineagePurpose.MATCHING_BEHAVIOR, "exact-pack", True),
        (provenance.LineagePurpose.SEMANTIC_FACT, "wrong-digest", True),
    ),
)
def test_fact_relation_replay_ignores_unrelated_receipts_in_other_lineage_population(
    purpose: provenance.LineagePurpose,
    subject: str,
    labels_accessed: bool,
) -> None:
    case, matcher_population = _case_with_three_populations()
    (relation,) = _apply(case)
    record = _record(case, relation)
    influenced = case.pack.normalized_content_digest if subject == "exact-pack" else canonical.content_digest(subject)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        purpose,
        influenced,
        labels_accessed=labels_accessed,
        arm_id="other-arm",
        population_digest=matcher_population,
    )

    _validate(case, record)


def test_fact_relation_replay_refuses_omitted_current_semantic_fact_use_without_labels() -> None:
    case = _case(fact_only=True)
    (relation,) = _apply(case)
    record = _record(case, relation)
    _append_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=False,
        arm_id="fact-arm",
    )

    assert case.custody.current_log(case.population_digest).status is provenance.PopulationStatus.AVAILABLE
    with pytest.raises(FactRelationValidationError, match="semantic fact lineage omitted current use"):
        _validate(case, record)
