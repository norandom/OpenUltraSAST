"""Externally bootstrapped access-control fact-authority contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical, provenance, semantics
from openultrasast.core.factpack import (
    FACT_PACK_SCHEMA,
    FactPack,
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
from openultrasast.mapping import fact_authority as authority_module
from openultrasast.mapping.fact_authority import (
    AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,
    EntryAuthorityBootstrapPolicy,
    EntryFactAuthorityBundle,
    EntryFactAuthorityError,
    authenticate_entry_fact_authority,
    derive_entry_authority_bootstrap_policy_digest,
    derive_entry_fact_authority_bundle_digest,
)
from openultrasast.semantic.obligations.core_contract import production_access_control_contract


@dataclass(frozen=True)
class AuthorityCase:
    bundle: EntryFactAuthorityBundle
    bootstrap: EntryAuthorityBootstrapPolicy
    resolver: InMemoryContentResolver


class UnusedCustody:
    """Authority authentication must not consume evaluation state or target packs."""

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"custody read before fact validation: {population_digest}")


def _merge_resolvers(*resolvers: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for resolver in resolvers:
        artifacts.update(resolver.artifacts)
    return InMemoryContentResolver(artifacts)


def _lineage(arm: str, subject: str, purpose: provenance.LineagePurpose) -> provenance.LineageManifest:
    population = canonical.content_digest(f"{arm}:population")
    receipt = canonical.content_digest(f"{arm}:receipt")
    use = provenance.LineageUse(purpose, population, False, subject, receipt)
    digest = provenance.derive_lineage_manifest_digest(arm, subject, (use,))
    return provenance.LineageManifest(arm, subject, (use,), digest)


def _review_policy(reviewer: str) -> ReviewIndependencePolicy:
    stores = ("authority-store",)
    maximum = 16_384
    digest = derive_review_independence_policy_digest((reviewer,), (), stores, maximum)
    return ReviewIndependencePolicy((reviewer,), (), stores, maximum, digest)


def _pack(
    language: str,
    reviewer: str,
    policy: ReviewIndependencePolicy,
    evidence_ref: canonical.ContentRef,
    disclosure_ref: canonical.ContentRef,
) -> tuple[FactPack, provenance.LineageManifest]:
    producer = canonical.content_digest(f"{language}:pack-producer")
    provisional_attestation = IndependenceAttestation(evidence_ref.content_digest, producer, reviewer, disclosure_ref, "0" * 64)
    attestation = replace(
        provisional_attestation,
        attestation_digest=derive_independence_attestation_digest(provisional_attestation),
    )
    provisional_evidence = KnowledgeEvidence(
        KnowledgeEvidenceKind.SOURCE_CODE,
        evidence_ref,
        producer,
        reviewer,
        attestation,
        "0" * 64,
    )
    contract = production_access_control_contract()
    fact = SemanticFact(
        f"entry:test:{language}",
        "entry_registration",
        (StructuralRequirement("qualified", StructuralRequirementKind.QUALIFIED_NAME, "qualified_target", "app.get"),),
        (
            RelationEffect(
                semantics.RelationKind.REGISTRATION,
                "entry_registration",
                "framework_instance",
                "entry_handler",
                (),
            ),
        ),
    )
    provisional_pack = FactPack(
        FACT_PACK_SCHEMA,
        canonical.content_digest(
            {
                "family_id": contract.family_id,
                "family_version": contract.family_version,
                "schema_version": contract.schema_version,
            }
        ),
        contract.family_id,
        "express",
        language,
        (fact,),
        "0" * 64,
        reviewer,
        (provisional_evidence,),
        "0" * 64,
        policy.policy_digest,
    )
    # Use the public contract digest required by FactPack rather than the local summary above.
    from openultrasast.core.family import family_contract_digest

    provisional_pack = replace(provisional_pack, family_contract_digest=family_contract_digest(contract))
    normalized = derive_fact_pack_content_digest(provisional_pack)
    lineage = _lineage(f"{language}:facts", normalized, provenance.LineagePurpose.SEMANTIC_FACT)
    evidence = replace(provisional_evidence, lineage_manifest_digest=lineage.manifest_digest)
    pack = replace(
        provisional_pack,
        normalized_content_digest=normalized,
        review_evidence=(evidence,),
        review_evidence_digest=derive_review_evidence_digest((evidence,)),
    )
    return pack, lineage


def _case() -> AuthorityCase:
    producer = canonical.content_digest("authority-producer")
    reviewer = canonical.content_digest("authority-reviewer")
    projection, projection_resolver = stored_artifact(
        b'{"schema_version":"projection.v1"}',
        artifact_id="recognition-projection",
        store_identity="authority-store",
    )
    evidence, evidence_resolver = stored_artifact(
        b'{"source":"reviewed"}',
        artifact_id="pack-review-evidence",
        store_identity="authority-store",
    )
    pack_disclosure, pack_disclosure_resolver = stored_artifact(
        b'{"conflicts":[]}',
        artifact_id="pack-conflicts",
        store_identity="authority-store",
    )
    disclosure_bytes = canonical.canonical_record_bytes(
        {
            "schema_version": AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,
            "conflicts": (),
            "resolved": True,
        },
        known_schema_versions=(AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,),
    )
    disclosure, disclosure_resolver = stored_artifact(
        disclosure_bytes,
        artifact_id="authority-conflicts",
        store_identity="authority-store",
    )
    resolver = _merge_resolvers(
        projection_resolver,
        evidence_resolver,
        pack_disclosure_resolver,
        disclosure_resolver,
    )
    review_policy = _review_policy(reviewer)
    javascript, javascript_lineage = _pack("javascript", reviewer, review_policy, evidence, pack_disclosure)
    typescript, typescript_lineage = _pack("typescript", reviewer, review_policy, evidence, pack_disclosure)
    matcher_behavior = canonical.content_digest("matcher-behavior")
    matcher_lineage = _lineage("entry-matcher", matcher_behavior, provenance.LineagePurpose.MATCHING_BEHAVIOR)
    custodian = canonical.content_digest("authority-custodian")
    custody_policy = provenance.PopulationCustodyPolicy(
        (custodian,),
        provenance.derive_population_custody_policy_digest((custodian,)),
    )
    provisional_review = IndependenceAttestation("0" * 64, producer, reviewer, disclosure, "0" * 64)
    provisional_bundle = EntryFactAuthorityBundle(
        production_access_control_contract(),
        (javascript, typescript),
        projection,
        (javascript_lineage, typescript_lineage, matcher_lineage),
        custody_policy,
        review_policy,
        "entry-matcher-v1",
        matcher_behavior,
        matcher_lineage.manifest_digest,
        provisional_review,
        "0" * 64,
    )
    bundle_digest = derive_entry_fact_authority_bundle_digest(provisional_bundle)
    review = replace(provisional_review, subject_digest=bundle_digest)
    review = replace(review, attestation_digest=derive_independence_attestation_digest(review))
    bundle = replace(provisional_bundle, authority_review=review, bundle_digest=bundle_digest)
    forbidden = ((canonical.content_digest("forbidden-producer"), reviewer),)
    maximum = 16_384
    bootstrap_digest = derive_entry_authority_bootstrap_policy_digest((reviewer,), forbidden, ("authority-store",), maximum)
    bootstrap = EntryAuthorityBootstrapPolicy((reviewer,), forbidden, ("authority-store",), maximum, bootstrap_digest)
    return AuthorityCase(bundle, bootstrap, resolver)


def _authenticate(case: AuthorityCase) -> None:
    context = authenticate_entry_fact_authority(case.bundle, case.bootstrap, UnusedCustody(), case.resolver)
    assert context.bundle is case.bundle
    assert context.resolver is case.resolver


def _with_unresolved_disclosure(case: AuthorityCase) -> AuthorityCase:
    unresolved_bytes = canonical.canonical_record_bytes(
        {
            "schema_version": AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,
            "conflicts": (),
            "resolved": False,
        },
        known_schema_versions=(AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,),
    )
    unresolved, unresolved_resolver = stored_artifact(
        unresolved_bytes,
        artifact_id="authority-conflicts",
        store_identity="authority-store",
    )
    review = replace(case.bundle.authority_review, conflict_disclosure=unresolved)
    review = replace(review, attestation_digest=derive_independence_attestation_digest(review))
    artifacts: Mapping[str, canonical.ResolvedContent] = {**case.resolver.artifacts, **unresolved_resolver.artifacts}
    return replace(
        case,
        bundle=replace(case.bundle, authority_review=review),
        resolver=InMemoryContentResolver(artifacts),
    )


def _with_independently_reviewed_bundle(case: AuthorityCase, bundle: EntryFactAuthorityBundle) -> AuthorityCase:
    bundle_digest = derive_entry_fact_authority_bundle_digest(bundle)
    review = replace(bundle.authority_review, subject_digest=bundle_digest)
    review = replace(review, attestation_digest=derive_independence_attestation_digest(review))
    return replace(case, bundle=replace(bundle, authority_review=review, bundle_digest=bundle_digest))


def test_independently_reviewed_authority_authenticates_without_consuming_target_state() -> None:
    _authenticate(_case())


@pytest.mark.parametrize("missing", ("custody", "resolver"))
def test_authority_refuses_missing_injected_ports(missing: str) -> None:
    case = _case()
    custody: object = object() if missing == "custody" else UnusedCustody()
    resolver: object = object() if missing == "resolver" else case.resolver

    with pytest.raises(EntryFactAuthorityError, match="missing"):
        authenticate_entry_fact_authority(case.bundle, case.bootstrap, custody, resolver)  # type: ignore[arg-type]


@pytest.mark.parametrize("missing", ("packs", "projection", "lineage"))
def test_authority_refuses_missing_prerequisites(missing: str) -> None:
    case = _case()
    if missing == "packs":
        bundle = replace(case.bundle, packs=())
        case = _with_independently_reviewed_bundle(case, bundle)
    elif missing == "projection":
        case = replace(case, resolver=InMemoryContentResolver({}))
    else:
        bundle = replace(case.bundle, lineages=case.bundle.lineages[:-1])
        case = _with_independently_reviewed_bundle(case, bundle)

    with pytest.raises(EntryFactAuthorityError):
        _authenticate(case)


@pytest.mark.parametrize("duplicate", ("pack", "lineage"))
def test_authority_refuses_duplicate_identities(duplicate: str) -> None:
    case = _case()
    if duplicate == "pack":
        bundle = replace(case.bundle, packs=(case.bundle.packs[0], case.bundle.packs[0]))
    else:
        bundle = replace(case.bundle, lineages=(*case.bundle.lineages, case.bundle.lineages[0]))
    case = _with_independently_reviewed_bundle(case, bundle)

    with pytest.raises(EntryFactAuthorityError, match="duplicate"):
        _authenticate(case)


@pytest.mark.parametrize("substitution", ("bundle", "projection", "matcher", "attestation"))
def test_authority_refuses_substituted_identity(substitution: str) -> None:
    case = _case()
    if substitution == "bundle":
        bundle = replace(case.bundle, bundle_digest="f" * 64)
    elif substitution == "projection":
        bundle = replace(case.bundle, recognition_projection=replace(case.bundle.recognition_projection, content_digest="f" * 64))
    elif substitution == "matcher":
        bundle = replace(case.bundle, matcher_behavior_digest="f" * 64)
    else:
        bundle = replace(case.bundle, authority_review=replace(case.bundle.authority_review, attestation_digest="f" * 64))

    with pytest.raises(EntryFactAuthorityError):
        _authenticate(replace(case, bundle=bundle))


@pytest.mark.parametrize("self_authored", ("same-identity", "forbidden-pair", "untrusted-reviewer"))
def test_authority_refuses_self_authored_or_untrusted_review(self_authored: str) -> None:
    case = _case()
    review = case.bundle.authority_review
    if self_authored == "same-identity":
        review = replace(review, producer_identity=review.reviewer_identity)
    elif self_authored == "forbidden-pair":
        review = replace(review, producer_identity=case.bootstrap.forbidden_identity_pairs[0][0])
    else:
        review = replace(review, reviewer_identity=canonical.content_digest("untrusted-reviewer"))
    review = replace(review, attestation_digest=derive_independence_attestation_digest(review))

    with pytest.raises(EntryFactAuthorityError):
        _authenticate(replace(case, bundle=replace(case.bundle, authority_review=review)))


@pytest.mark.parametrize("invalid_authority", ("untrusted-reviewer", "invalid-attestation", "unresolved-disclosure"))
def test_external_authority_failure_stops_before_pack_validation(
    invalid_authority: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case()
    if invalid_authority == "untrusted-reviewer":
        review = replace(case.bundle.authority_review, reviewer_identity=canonical.content_digest("untrusted-reviewer"))
        review = replace(review, attestation_digest=derive_independence_attestation_digest(review))
        case = replace(case, bundle=replace(case.bundle, authority_review=review))
    elif invalid_authority == "invalid-attestation":
        review = replace(case.bundle.authority_review, attestation_digest="f" * 64)
        case = replace(case, bundle=replace(case.bundle, authority_review=review))
    else:
        case = _with_unresolved_disclosure(case)
    reached_pack_validation = False

    def fail_if_reached(*args: object, **kwargs: object) -> None:
        nonlocal reached_pack_validation
        reached_pack_validation = True
        raise AssertionError("pack validation ran before external authority was established")

    monkeypatch.setattr(authority_module, "_validate_packs", fail_if_reached)

    with pytest.raises(EntryFactAuthorityError):
        _authenticate(case)
    assert not reached_pack_validation


@pytest.mark.parametrize("noncanonical", ("bootstrap", "bundle", "disclosure"))
def test_authority_refuses_noncanonical_policy_bundle_or_disclosure(noncanonical: str) -> None:
    case = _case()
    if noncanonical == "bootstrap":
        case = replace(case, bootstrap=replace(case.bootstrap, policy_digest="f" * 64))
    elif noncanonical == "bundle":
        case = replace(case, bundle=replace(case.bundle, matcher_revision="substituted"))
    else:
        case = _with_unresolved_disclosure(case)

    message = "unresolved" if noncanonical == "disclosure" else None
    with pytest.raises(EntryFactAuthorityError, match=message):
        _authenticate(case)
