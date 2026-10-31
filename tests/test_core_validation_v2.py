"""Closed evidence revalidation seam (Reqs 4.4, 10.1-10.4, 12.6, 14.1)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, InMemoryPopulationCustody, custody_contract, stored_artifact
from test_core_factapply import _append_use as append_fact_use
from test_core_factapply import _apply as apply_fact_case
from test_core_factapply import _case as fact_case
from test_core_factapply import _manifest as fact_manifest
from test_core_factapply import _record as fact_record
from test_core_family import _contract as family_contract
from test_core_family import _record as family_record
from test_core_model import _case as model_case

from openultrasast.core import canonical, evidence, family, provenance, validation
from openultrasast.core.factpack import (
    FactPack,
    ReviewIndependencePolicy,
    derive_review_evidence_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.family_catalog import FamilyCatalog, FamilyCatalogEntry, derive_catalog_digest


class CountingResolver:
    def __init__(self, delegate: InMemoryContentResolver) -> None:
        self.delegate = delegate
        self.resolved: list[str] = []

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        self.resolved.append(reference.artifact_id)
        return self.delegate.resolve(reference)


def _review_policy() -> ReviewIndependencePolicy:
    reviewer = canonical.content_digest("reviewer")
    stores = ("trusted-store",)
    digest = derive_review_independence_policy_digest((reviewer,), (), stores, 4096)
    return ReviewIndependencePolicy((reviewer,), (), stores, 4096, digest)


def _trust_policy() -> provenance.ProvenanceTrustPolicy:
    stores = ("trusted-store",)
    maximum = 4096
    return provenance.ProvenanceTrustPolicy(stores, maximum, provenance.derive_trust_policy_digest(stores, maximum))


def _catalog(contract: family.FamilyContract) -> FamilyCatalog:
    entry = FamilyCatalogEntry(contract, family.family_contract_digest(contract))
    entries = (entry,)
    return FamilyCatalog(entries, derive_catalog_digest(entries))


def _with_fact_set(record: evidence.EvidenceRecord, packs: tuple[FactPack, ...]) -> evidence.EvidenceRecord:
    digest = validation.derive_fact_set_digest(packs)
    stamp = replace(record.packet.provenance, fact_set_digest=digest)
    packet = replace(record.packet, provenance=stamp)
    decision = replace(record.decision, packet_digest=evidence.derive_packet_digest(packet))
    return evidence.EvidenceRecord(packet, decision, "")


def _named_inputs(
    record: evidence.EvidenceRecord,
    contract: family.FamilyContract,
    packs: tuple[FactPack, ...],
    *,
    fact_set_content: bytes | None = None,
) -> tuple[provenance.NamedInputs, InMemoryContentResolver]:
    def matching_preimage(identity: str, *values: str) -> bytes:
        matches = tuple(canonical.canonical_bytes(value) for value in values if canonical.content_digest(value) == identity)
        assert len(matches) == 1
        return matches[0]

    stamp = record.packet.provenance
    preimages: dict[provenance.ProvenanceInputRole, bytes] = {
        provenance.ProvenanceInputRole.ANALYZER: matching_preimage(stamp.analyzer_revision, "analyzer"),
        provenance.ProvenanceInputRole.FAMILY_CONTRACT: canonical.canonical_bytes(family._contract_value(contract)),
        provenance.ProvenanceInputRole.FACT_SET: fact_set_content or validation.fact_set_bytes(packs),
        provenance.ProvenanceInputRole.ACQUISITION: matching_preimage(stamp.acquisition_record_digest, "acquisition"),
        provenance.ProvenanceInputRole.CONFIGURATION: matching_preimage(stamp.configuration_digest, "configuration"),
        provenance.ProvenanceInputRole.POPULATION: matching_preimage(stamp.population_digest, "population"),
        provenance.ProvenanceInputRole.CHANGE_INPUT: matching_preimage(stamp.change_input_digest, "change", "change-input"),
    }
    items: list[provenance.NamedInput] = []
    artifacts: dict[str, canonical.ResolvedContent] = {}
    fields = {
        provenance.ProvenanceInputRole.ANALYZER: stamp.analyzer_revision,
        provenance.ProvenanceInputRole.FAMILY_CONTRACT: stamp.family_contract_digest,
        provenance.ProvenanceInputRole.FACT_SET: stamp.fact_set_digest,
        provenance.ProvenanceInputRole.ACQUISITION: stamp.acquisition_record_digest,
        provenance.ProvenanceInputRole.CONFIGURATION: stamp.configuration_digest,
        provenance.ProvenanceInputRole.POPULATION: stamp.population_digest,
        provenance.ProvenanceInputRole.CHANGE_INPUT: stamp.change_input_digest,
    }
    for role in provenance.ProvenanceInputRole:
        reference, resolver = stored_artifact(preimages[role], artifact_id=f"named-{role.value}")
        assert reference.byte_length > 0 and reference.content_digest == fields[role]
        items.append(provenance.NamedInput(role, fields[role], reference))
        artifacts.update(resolver.artifacts)
    values = tuple(items)
    return provenance.NamedInputs(values, provenance.derive_named_inputs_digest(values)), InMemoryContentResolver(artifacts)


def _deterministic_case() -> tuple[
    validation.EvidenceValidationInput,
    validation.EvidenceValidationContext,
    InMemoryPopulationCustody,
    InMemoryContentResolver,
]:
    contract = family_contract()
    record = _with_fact_set(family_record(contract), ())
    named, resolver = _named_inputs(record, contract, ())
    initial, custody_policy, _ = custody_contract()
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(contract),
        fact_packs=(),
        model_programs=(),
        lineages=(),
        fact_review_policy=_review_policy(),
        provenance_trust_policy=_trust_policy(),
        custody_policy=custody_policy,
    )
    return (
        validation.make_evidence_validation_input(record=record, named_inputs=named),
        context,
        InMemoryPopulationCustody(initial, custody_policy),
        resolver,
    )


def test_shared_context_revalidates_record_and_all_seven_named_inputs() -> None:
    value, context, custody, resolver = _deterministic_case()
    counting = CountingResolver(resolver)

    accepted = validation.validate_evidence_input(value, context, custody, counting)

    assert accepted is value.record
    assert set(counting.resolved) == {item.content.artifact_id for item in value.named_inputs.inputs}
    assert len(counting.resolved) == len(provenance.ProvenanceInputRole) == 7


def test_context_input_and_record_identities_are_rederived() -> None:
    value, context, custody, resolver = _deterministic_case()
    with pytest.raises(validation.EvidenceInputValidationError, match="context digest"):
        validation.validate_evidence_input(value, replace(context, context_digest="0" * 64), custody, resolver)
    with pytest.raises(validation.EvidenceInputValidationError, match="input digest"):
        validation.validate_evidence_input(replace(value, input_digest="0" * 64), context, custody, resolver)

    forged = object.__new__(evidence.EvidenceRecord)
    object.__setattr__(forged, "packet", value.record.packet)
    object.__setattr__(forged, "decision", value.record.decision)
    object.__setattr__(forged, "record_id", "0" * 64)
    forged_value = validation.make_evidence_validation_input(record=forged, named_inputs=value.named_inputs)
    with pytest.raises(validation.EvidenceInputValidationError, match="record"):
        validation.validate_evidence_input(forged_value, context, custody, resolver)

    changed_contract = replace(family_contract(), family_version="2.0.0")
    mismatched = validation.make_evidence_validation_context(
        family_catalog=_catalog(changed_contract),
        fact_packs=context.fact_packs,
        model_programs=context.model_programs,
        lineages=context.lineages,
        fact_review_policy=context.fact_review_policy,
        provenance_trust_policy=context.provenance_trust_policy,
        custody_policy=context.custody_policy,
    )
    with pytest.raises(validation.EvidenceInputValidationError, match="family, digest, and ecosystem"):
        validation.validate_evidence_input(value, mismatched, custody, resolver)


def test_context_fact_set_and_named_inputs_cannot_be_substituted() -> None:
    value, context, custody, resolver = _deterministic_case()
    changed = replace(value.record.packet.provenance, fact_set_digest=canonical.content_digest("other-facts"))
    packet = replace(value.record.packet, provenance=changed)
    decision = replace(value.record.decision, packet_digest=evidence.derive_packet_digest(packet))
    record = evidence.EvidenceRecord(packet, decision, "")
    named, changed_resolver = _named_inputs(
        record,
        family_contract(),
        (),
        fact_set_content=canonical.canonical_bytes("other-facts"),
    )
    substituted = validation.make_evidence_validation_input(record=record, named_inputs=named)
    with pytest.raises(validation.EvidenceInputValidationError, match="fact set"):
        validation.validate_evidence_input(substituted, context, custody, changed_resolver)

    first = value.named_inputs.inputs[0]
    forged_named = replace(first, identity="0" * 64)
    inputs = (forged_named, *value.named_inputs.inputs[1:])
    bad_named = provenance.NamedInputs(inputs, provenance.derive_named_inputs_digest(inputs))
    bad_value = validation.make_evidence_validation_input(record=value.record, named_inputs=bad_named)
    with pytest.raises(validation.EvidenceInputValidationError, match="provenance"):
        validation.validate_evidence_input(bad_value, context, custody, resolver)


def test_fact_derived_record_is_replayed_from_context_pack_and_match_bytes() -> None:
    case = fact_case(fact_only=True)
    (relation,) = apply_fact_case(case)
    record = _with_fact_set(fact_record(case, relation), (case.pack,))
    named, named_resolver = _named_inputs(record, case.contract, (case.pack,))
    resolver = InMemoryContentResolver({**case.resolver.artifacts, **named_resolver.artifacts})
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(case.contract),
        fact_packs=(case.pack,),
        model_programs=(),
        lineages=case.lineages,
        fact_review_policy=case.review_policy,
        provenance_trust_policy=_trust_policy(),
        custody_policy=case.custody_policy,
    )
    value = validation.make_evidence_validation_input(record=record, named_inputs=named)

    assert validation.validate_evidence_input(value, context, case.custody, resolver) is record

    missing_pack = validation.make_evidence_validation_context(
        family_catalog=context.family_catalog,
        fact_packs=(),
        model_programs=(),
        lineages=context.lineages,
        fact_review_policy=context.fact_review_policy,
        provenance_trust_policy=context.provenance_trust_policy,
        custody_policy=context.custody_policy,
    )
    with pytest.raises(validation.EvidenceInputValidationError, match="fact set|semantic pack"):
        validation.validate_evidence_input(value, missing_pack, case.custody, resolver)


def test_context_binds_exact_model_declarations_and_their_lineages() -> None:
    handoff = model_case()
    record = _with_fact_set(handoff.record, ())
    named, resolver = _named_inputs(record, handoff.contract, ())
    initial, custody_policy, _ = custody_contract()
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(handoff.contract),
        fact_packs=(),
        model_programs=(handoff.request.program,),
        lineages=(handoff.request.lineage,),
        fact_review_policy=_review_policy(),
        provenance_trust_policy=_trust_policy(),
        custody_policy=custody_policy,
    )
    value = validation.make_evidence_validation_input(record=record, named_inputs=named)
    custody = InMemoryPopulationCustody(initial, custody_policy)

    assert validation.validate_evidence_input(value, context, custody, resolver) is record

    missing_lineage = validation.make_evidence_validation_context(
        family_catalog=context.family_catalog,
        fact_packs=(),
        model_programs=context.model_programs,
        lineages=(),
        fact_review_policy=context.fact_review_policy,
        provenance_trust_policy=context.provenance_trust_policy,
        custody_policy=context.custody_policy,
    )
    with pytest.raises(validation.EvidenceInputValidationError, match="model declaration lineage"):
        validation.validate_evidence_input(value, missing_lineage, custody, resolver)


def test_context_digest_binds_pack_review_evidence_to_its_exact_lineage() -> None:
    case = fact_case(fact_only=True)
    alternate_use = append_fact_use(
        case.custody,
        case.custody_policy.reviewed_custodian_digests[0],
        provenance.LineagePurpose.SEMANTIC_FACT,
        case.pack.normalized_content_digest,
        labels_accessed=False,
        arm_id="alternate-fact-arm",
    )
    alternate = fact_manifest("alternate-fact-arm", case.pack.normalized_content_digest, (alternate_use,))
    lineages = (*case.lineages, alternate)
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(case.contract),
        fact_packs=(case.pack,),
        model_programs=(),
        lineages=lineages,
        fact_review_policy=case.review_policy,
        provenance_trust_policy=_trust_policy(),
        custody_policy=case.custody_policy,
    )
    changed_evidence = replace(case.pack.review_evidence[0], lineage_manifest_digest=alternate.manifest_digest)
    swapped = replace(
        case.pack,
        review_evidence=(changed_evidence,),
        review_evidence_digest=derive_review_evidence_digest((changed_evidence,)),
    )
    substituted = replace(context, fact_packs=(swapped,))
    (relation,) = apply_fact_case(case)
    record = _with_fact_set(fact_record(case, relation), (case.pack,))
    named, named_resolver = _named_inputs(record, case.contract, (case.pack,))
    resolver = InMemoryContentResolver({**case.resolver.artifacts, **named_resolver.artifacts})
    value = validation.make_evidence_validation_input(record=record, named_inputs=named)

    assert validation.derive_evidence_validation_context_digest(substituted) != context.context_digest
    with pytest.raises(validation.EvidenceInputValidationError, match="context digest"):
        validation.validate_evidence_input(value, substituted, case.custody, resolver)
