"""Closed validation context for raw detection-core evidence records."""

from __future__ import annotations

from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._validation_model import validate_and_replay_model_derivation
from openultrasast.core._validation_shape import evidence_context_problem
from openultrasast.core.custody import (
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    derive_population_custody_policy_digest,
    validate_population_custody_log,
)
from openultrasast.core.evidence import EvidenceRecord, derive_record_id
from openultrasast.core.factpack import (
    FactPack,
    ReviewIndependencePolicy,
    derive_fact_pack_content_digest,
    derive_review_evidence_digest,
    derive_review_independence_policy_digest,
    validate_fact_pack,
)
from openultrasast.core.factvalidate import validate_fact_relations
from openultrasast.core.family import validate_record
from openultrasast.core.family_catalog import FamilyCatalog, resolve_contract, validate_catalog
from openultrasast.core.lineage import LineageManifest, derive_lineage_manifest_digest
from openultrasast.core.model import (
    ModelProgramDeclaration,
    ModelRequest,
    ModelResult,
    derive_model_program_declaration_digest,
)
from openultrasast.core.provenance import (
    NamedInputs,
    ProvenanceTrustPolicy,
    derive_trust_policy_digest,
    validate_provenance,
)

EVIDENCE_VALIDATION_CONTEXT_SCHEMA = "openultrasast.detection-core.evidence-validation-context.v2"
EVIDENCE_VALIDATION_INPUT_SCHEMA = "openultrasast.detection-core.evidence-validation-input.v2"
FACT_SET_SCHEMA = "openultrasast.detection-core.fact-set.v2"


class EvidenceInputValidationError(ValueError):
    """A raw evidence input cannot be reproduced in its closed context."""


@dataclass(frozen=True)
class EvidenceValidationContext:
    family_catalog: FamilyCatalog
    fact_packs: tuple[FactPack, ...]
    model_programs: tuple[ModelProgramDeclaration, ...]
    lineages: tuple[LineageManifest, ...]
    fact_review_policy: ReviewIndependencePolicy
    provenance_trust_policy: ProvenanceTrustPolicy
    custody_policy: PopulationCustodyPolicy
    context_digest: str


@dataclass(frozen=True)
class EvidenceValidationInput:
    record: EvidenceRecord
    named_inputs: NamedInputs
    model_request: ModelRequest | None
    model_result: ModelResult | None
    input_digest: str


def fact_set_bytes(packs: tuple[FactPack, ...]) -> bytes:
    if not isinstance(packs, tuple) or not all(isinstance(pack, FactPack) for pack in packs):
        raise EvidenceInputValidationError("fact packs must be a tuple of FactPack values")
    return canonical.canonical_bytes(
        {
            "schema_version": FACT_SET_SCHEMA,
            "fact_pack_digests": tuple(sorted(pack.normalized_content_digest for pack in packs)),
        }
    )


def derive_fact_set_digest(packs: tuple[FactPack, ...]) -> str:
    return canonical.bytes_digest(fact_set_bytes(packs))


def derive_evidence_validation_context_digest(context: EvidenceValidationContext) -> str:
    packs = tuple(
        sorted(
            context.fact_packs,
            key=lambda pack: (
                pack.normalized_content_digest,
                pack.review_evidence_digest,
                pack.review_policy_digest,
                pack.review_identity,
            ),
        )
    )
    return canonical.content_digest(
        {
            "schema_version": EVIDENCE_VALIDATION_CONTEXT_SCHEMA,
            "family_catalog_digest": context.family_catalog.catalog_digest,
            "fact_pack_review_bindings": tuple(
                {
                    "normalized_content_digest": pack.normalized_content_digest,
                    "review_evidence_digest": pack.review_evidence_digest,
                    "review_policy_digest": pack.review_policy_digest,
                    "review_identity": pack.review_identity,
                }
                for pack in packs
            ),
            "model_program_digests": tuple(sorted(program.declaration_digest for program in context.model_programs)),
            "lineage_manifest_digests": tuple(sorted(lineage.manifest_digest for lineage in context.lineages)),
            "fact_review_policy_digest": context.fact_review_policy.policy_digest,
            "provenance_trust_policy_digest": context.provenance_trust_policy.policy_digest,
            "custody_policy_digest": context.custody_policy.policy_digest,
        }
    )


def make_evidence_validation_context(
    *,
    family_catalog: FamilyCatalog,
    fact_packs: tuple[FactPack, ...],
    model_programs: tuple[ModelProgramDeclaration, ...],
    lineages: tuple[LineageManifest, ...],
    fact_review_policy: ReviewIndependencePolicy,
    provenance_trust_policy: ProvenanceTrustPolicy,
    custody_policy: PopulationCustodyPolicy,
) -> EvidenceValidationContext:
    provisional = EvidenceValidationContext(
        family_catalog,
        fact_packs,
        model_programs,
        lineages,
        fact_review_policy,
        provenance_trust_policy,
        custody_policy,
        "0" * 64,
    )
    return EvidenceValidationContext(
        family_catalog,
        fact_packs,
        model_programs,
        lineages,
        fact_review_policy,
        provenance_trust_policy,
        custody_policy,
        derive_evidence_validation_context_digest(provisional),
    )


def derive_evidence_validation_input_digest(value: EvidenceValidationInput) -> str:
    return canonical.content_digest(
        {
            "schema_version": EVIDENCE_VALIDATION_INPUT_SCHEMA,
            "record_id": value.record.record_id,
            "named_inputs_digest": value.named_inputs.manifest_digest,
            "model_request_digest": None if value.model_request is None else value.model_request.request_id,
            "model_result_digest": None if value.model_result is None else value.model_result.result_digest,
        }
    )


def make_evidence_validation_input(
    *,
    record: EvidenceRecord,
    named_inputs: NamedInputs,
    model_request: ModelRequest | None = None,
    model_result: ModelResult | None = None,
) -> EvidenceValidationInput:
    provisional = EvidenceValidationInput(record, named_inputs, model_request, model_result, "0" * 64)
    return EvidenceValidationInput(
        record,
        named_inputs,
        model_request,
        model_result,
        derive_evidence_validation_input_digest(provisional),
    )


def _unique(values: tuple[str, ...], field: str) -> None:
    if len(set(values)) != len(values):
        raise EvidenceInputValidationError(f"duplicate {field} identity")


def _validate_context_collections(context: EvidenceValidationContext) -> None:
    collections = (
        (context.fact_packs, FactPack, "fact_packs"),
        (context.model_programs, ModelProgramDeclaration, "model_programs"),
        (context.lineages, LineageManifest, "lineages"),
    )
    for values, expected, field in collections:
        if not isinstance(values, tuple) or not all(isinstance(item, expected) for item in values):
            raise EvidenceInputValidationError(f"{field} must be a tuple of {expected.__name__} values")
    _unique(tuple(pack.normalized_content_digest for pack in context.fact_packs), "fact pack")
    _unique(tuple(program.declaration_digest for program in context.model_programs), "model program")
    _unique(tuple(lineage.manifest_digest for lineage in context.lineages), "lineage manifest")


def _validate_context_types(context: EvidenceValidationContext) -> None:
    fields = (
        (context.family_catalog, FamilyCatalog, "family_catalog"),
        (context.fact_review_policy, ReviewIndependencePolicy, "fact_review_policy"),
        (context.provenance_trust_policy, ProvenanceTrustPolicy, "provenance_trust_policy"),
        (context.custody_policy, PopulationCustodyPolicy, "custody_policy"),
    )
    for value, expected, field in fields:
        if not isinstance(value, expected):
            raise EvidenceInputValidationError(f"{field} must be a {expected.__name__}")
    _validate_context_collections(context)


def _validate_context_policies(context: EvidenceValidationContext) -> None:
    review = context.fact_review_policy
    review.__post_init__()
    expected_review = derive_review_independence_policy_digest(
        review.reviewed_reviewer_digests,
        review.forbidden_identity_pairs,
        review.trusted_store_identities,
        review.maximum_evidence_bytes,
    )
    if review.policy_digest != expected_review:
        raise EvidenceInputValidationError("fact review policy digest cannot be re-derived")
    trust = context.provenance_trust_policy
    trust.__post_init__()
    if trust.policy_digest != derive_trust_policy_digest(trust.trusted_store_identities, trust.maximum_input_bytes):
        raise EvidenceInputValidationError("provenance trust policy digest cannot be re-derived")
    custody = context.custody_policy
    custody.__post_init__()
    if custody.policy_digest != derive_population_custody_policy_digest(custody.reviewed_custodian_digests):
        raise EvidenceInputValidationError("custody policy digest cannot be re-derived")


def _validate_context_members(context: EvidenceValidationContext) -> None:
    catalog_digests = {entry.contract_digest for entry in context.family_catalog.entries}
    lineage_digests = {lineage.manifest_digest for lineage in context.lineages}
    for lineage in context.lineages:
        expected = derive_lineage_manifest_digest(lineage.arm_id, lineage.subject_digest, lineage.uses)
        if lineage.manifest_digest != expected:
            raise EvidenceInputValidationError("lineage manifest digest cannot be re-derived")
    for pack in context.fact_packs:
        pack.__post_init__()
        if pack.normalized_content_digest != derive_fact_pack_content_digest(pack):
            raise EvidenceInputValidationError("fact pack content digest cannot be re-derived")
        if pack.review_evidence_digest != derive_review_evidence_digest(pack.review_evidence):
            raise EvidenceInputValidationError("fact pack review evidence digest cannot be re-derived")
    for program in context.model_programs:
        program.__post_init__()
        if program.declaration_digest != derive_model_program_declaration_digest(program):
            raise EvidenceInputValidationError("model declaration digest cannot be re-derived")
        if program.family_contract_digest not in catalog_digests:
            raise EvidenceInputValidationError("model declaration family contract is absent from the catalog")
        if program.lineage_manifest_digest not in lineage_digests:
            raise EvidenceInputValidationError("model declaration lineage is absent from the context")


def _validate_context(context: EvidenceValidationContext) -> None:
    problem = evidence_context_problem(context, EvidenceValidationContext)
    if problem is not None:
        raise EvidenceInputValidationError(f"closed evidence context violation: {problem}")
    if not isinstance(context, EvidenceValidationContext):
        raise EvidenceInputValidationError("context must be an EvidenceValidationContext")
    _validate_context_types(context)
    expected = derive_evidence_validation_context_digest(context)
    if context.context_digest != expected:
        raise EvidenceInputValidationError("context digest cannot be re-derived")
    validate_catalog(context.family_catalog)
    _validate_context_policies(context)
    _validate_context_members(context)


def validate_evidence_validation_context(context: EvidenceValidationContext) -> None:
    """Re-derive a closed evidence context without requiring a case record."""
    try:
        _validate_context(context)
    except EvidenceInputValidationError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvidenceInputValidationError(f"evidence validation context is invalid: {exc}") from exc


def _validate_record_identity(record: EvidenceRecord) -> None:
    if not isinstance(record, EvidenceRecord):
        raise EvidenceInputValidationError("record must be an EvidenceRecord")
    record.packet.__post_init__()
    record.decision.__post_init__()
    expected = derive_record_id(record.packet, record.decision)
    if record.record_id != expected:
        raise EvidenceInputValidationError("record identity cannot be re-derived")
    record.__post_init__()


def _validate_input_types(value: EvidenceValidationInput) -> None:
    if not isinstance(value.record, EvidenceRecord):
        raise EvidenceInputValidationError("record must be an EvidenceRecord")
    if not isinstance(value.named_inputs, NamedInputs):
        raise EvidenceInputValidationError("named_inputs must be NamedInputs")
    if value.model_request is not None and not isinstance(value.model_request, ModelRequest):
        raise EvidenceInputValidationError("model_request must be a ModelRequest or None")
    if value.model_result is not None and not isinstance(value.model_result, ModelResult):
        raise EvidenceInputValidationError("model_result must be a ModelResult or None")


def _validate_packs(
    context: EvidenceValidationContext,
    population_digest: str,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    for pack in context.fact_packs:
        contract = resolve_contract(
            context.family_catalog,
            pack.family_id,
            pack.family_contract_digest,
            pack.ecosystem,
        )
        validate_fact_pack(
            pack,
            contract,
            population_digest,
            context.lineages,
            custody,
            context.custody_policy,
            context.fact_review_policy,
            resolver,
        )


def validate_evidence_input(
    value: EvidenceValidationInput,
    context: EvidenceValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvidenceRecord:
    try:
        if not isinstance(value, EvidenceValidationInput):
            raise EvidenceInputValidationError("value must be an EvidenceValidationInput")
        _validate_context(context)
        _validate_input_types(value)
        if value.input_digest != derive_evidence_validation_input_digest(value):
            raise EvidenceInputValidationError("input digest cannot be re-derived")
        _validate_record_identity(value.record)
        record = value.record
        contract = resolve_contract(
            context.family_catalog,
            record.packet.family_id,
            record.packet.family_contract_digest,
            record.packet.ecosystem,
        )
        record = validate_and_replay_model_derivation(
            record,
            value.model_request,
            value.model_result,
            contract,
            context.model_programs,
            context.lineages,
            resolver,
            custody,
            context.custody_policy,
        )
        validate_record(contract, record)
        validate_provenance(record.packet.provenance, value.named_inputs, resolver, context.provenance_trust_policy)
        if record.packet.provenance.fact_set_digest != derive_fact_set_digest(context.fact_packs):
            raise EvidenceInputValidationError("record fact set does not match the validation context")
        population = record.packet.provenance.population_digest
        validate_population_custody_log(custody.current_log(population), context.custody_policy, current=custody)
        _validate_packs(context, population, custody, resolver)
        validate_fact_relations(
            record,
            contract,
            context.fact_packs,
            population,
            context.lineages,
            custody,
            context.custody_policy,
            context.fact_review_policy,
            resolver,
        )
        return record
    except EvidenceInputValidationError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        message = str(exc)
        if "provenance" not in message and exc.__class__.__module__.endswith("provenance"):
            message = f"provenance validation failed: {message}"
        raise EvidenceInputValidationError(f"evidence input validation failed: {message}") from exc


__all__ = [
    "EVIDENCE_VALIDATION_CONTEXT_SCHEMA",
    "EVIDENCE_VALIDATION_INPUT_SCHEMA",
    "FACT_SET_SCHEMA",
    "EvidenceInputValidationError",
    "EvidenceValidationContext",
    "EvidenceValidationInput",
    "derive_evidence_validation_context_digest",
    "derive_evidence_validation_input_digest",
    "derive_fact_set_digest",
    "fact_set_bytes",
    "make_evidence_validation_context",
    "make_evidence_validation_input",
    "validate_evidence_validation_context",
    "validate_evidence_input",
]
