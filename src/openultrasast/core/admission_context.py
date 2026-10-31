"""Exact, label-blind admission context validation before feasibility."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._closed_graph import closed_graph_problem, exact_dataclass_problem
from openultrasast.core.admission_review import AdmissionManifestV2, validate_reviewed_admission_payloads
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyPort,
    PopulationStatus,
    validate_population_custody_log,
)
from openultrasast.core.factpack import FACT_PACK_SCHEMA, ReviewIndependencePolicy
from openultrasast.core.family_catalog import FamilyCatalog, FamilyCatalogEntry, validate_catalog
from openultrasast.core.lineage import LineageExpectation, LineageManifest, validate_lineage
from openultrasast.core.measurement import (
    BaselineIdentity,
    DenominatorPolicy,
    ScopeKey,
    derive_denominator_policy_digest,
    derive_identity_set_digest,
    validate_denominator_policy,
)
from openultrasast.core.model import ModelProgramDeclaration
from openultrasast.core.proof import ProofTrustPolicy, derive_proof_trust_policy_digest
from openultrasast.core.readiness import (
    AnalysisIdentity,
    ReadinessResult,
    ReadinessStage,
    authorize_stage,
)
from openultrasast.core.semantics import (
    OBSERVATION_SCHEMA,
    SEMANTIC_RELATION_SCHEMA,
    FieldKind,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
)
from openultrasast.core.validation import (
    EvidenceValidationContext,
    derive_fact_set_digest,
    validate_evidence_validation_context,
)

ADMISSION_VALIDATION_CONTEXT_SCHEMA = "openultrasast.detection-core.admission-validation-context.v2"
OUTCOME_MAPPING_SCHEMA = "openultrasast.detection-core.outcome-mapping.v2"
SEMANTIC_VOCABULARY_SCHEMA = "openultrasast.detection-core.semantic-vocabulary.v2"


class AdmissionContextError(ValueError):
    """Admission inputs disagree before any feasibility work or label access."""


@dataclass(frozen=True)
class AdmissionValidationContext:
    evidence: EvidenceValidationContext
    admission_review_policy: ReviewIndependencePolicy
    proof_trust_policy: ProofTrustPolicy | None
    context_digest: str


def derive_fact_schema_digest() -> str:
    return canonical.content_digest(FACT_PACK_SCHEMA)


def derive_semantic_vocabulary_digest() -> str:
    return canonical.content_digest(
        {
            "schema_version": SEMANTIC_VOCABULARY_SCHEMA,
            "relation_schema": SEMANTIC_RELATION_SCHEMA,
            "observation_schema": OBSERVATION_SCHEMA,
            "field_kinds": tuple(item.value for item in FieldKind),
            "relation_kinds": tuple(item.value for item in RelationKind),
            "relation_statuses": tuple(item.value for item in RelationStatus),
            "provenance_kinds": tuple(item.value for item in ProvenanceKind),
        }
    )


def _decision_value(entry: FamilyCatalogEntry) -> canonical.JsonValue:
    contract = entry.contract
    return {
        "contract_digest": entry.contract_digest,
        "decisions": tuple(
            {
                "family_code": rule.family_code,
                "outcome": rule.outcome.value,
                "required_roles": rule.required_roles,
                "allowed_statuses": tuple(status.value for status in rule.allowed_statuses),
            }
            for rule in contract.decisions
        ),
    }


def derive_outcome_mapping_digest(catalog: FamilyCatalog) -> str:
    validate_catalog(catalog)
    return canonical.content_digest(
        {"schema_version": OUTCOME_MAPPING_SCHEMA, "contracts": tuple(_decision_value(entry) for entry in catalog.entries)}
    )


def derive_admission_validation_context_digest(context: AdmissionValidationContext) -> str:
    proof_digest = None
    if context.proof_trust_policy is not None:
        proof_digest = derive_proof_trust_policy_digest(context.proof_trust_policy)
    return canonical.content_digest(
        {
            "schema_version": ADMISSION_VALIDATION_CONTEXT_SCHEMA,
            "evidence_context_digest": context.evidence.context_digest,
            "admission_review_policy_digest": context.admission_review_policy.policy_digest,
            "proof_trust_policy_digest": proof_digest,
        }
    )


def make_admission_validation_context(
    *,
    evidence: EvidenceValidationContext,
    admission_review_policy: ReviewIndependencePolicy,
    proof_trust_policy: ProofTrustPolicy | None,
) -> AdmissionValidationContext:
    provisional = AdmissionValidationContext(evidence, admission_review_policy, proof_trust_policy, "0" * 64)
    return AdmissionValidationContext(
        evidence,
        admission_review_policy,
        proof_trust_policy,
        derive_admission_validation_context_digest(provisional),
    )


def _contract_for_scope(catalog: FamilyCatalog, scope: ScopeKey) -> FamilyCatalogEntry:
    matches = tuple(
        entry for entry in catalog.entries if entry.contract.family_id == scope.family_id and scope.ecosystem in entry.contract.ecosystems
    )
    if len(matches) != 1:
        raise AdmissionContextError("each claimed scope must resolve one exact family contract")
    return matches[0]


def derive_analysis_identity(
    baseline: BaselineIdentity,
    catalog: FamilyCatalog,
    scope: ScopeKey,
    model_program_digest: str | None,
) -> AnalysisIdentity:
    entry = _contract_for_scope(catalog, scope)
    return AnalysisIdentity(
        entry.contract.schema_version,
        derive_semantic_vocabulary_digest(),
        baseline.analyzer_revision,
        entry.contract_digest,
        baseline.fact_set_digest,
        baseline.acquisition_record_digest,
        baseline.configuration_digest,
        model_program_digest,
        baseline.outcome_mapping_digest,
    )


def _validate_context(context: AdmissionValidationContext) -> None:
    problem = exact_dataclass_problem(context, AdmissionValidationContext, "admission validation context")
    if problem is not None:
        raise AdmissionContextError(f"closed admission context violation: {problem}")
    validate_evidence_validation_context(context.evidence)
    context.admission_review_policy.__post_init__()
    if context.proof_trust_policy is not None:
        problem = closed_graph_problem(
            context.proof_trust_policy,
            dataclass_types=(ProofTrustPolicy,),
            enum_types=(),
            path="proof trust policy",
        )
        if problem is not None:
            raise AdmissionContextError(f"closed proof policy violation: {problem}")
        context.proof_trust_policy.__post_init__()
    expected = derive_admission_validation_context_digest(context)
    if context.context_digest != expected:
        raise AdmissionContextError("admission validation context digest cannot be re-derived")


def _validate_scopes_and_sets(manifest: AdmissionManifestV2, denominator: DenominatorPolicy, context: AdmissionValidationContext) -> None:
    baseline = manifest.identity
    evidence = context.evidence
    catalog = evidence.family_catalog
    validate_denominator_policy(denominator)
    entries = tuple(entry.contract_digest for entry in catalog.entries)
    if baseline.family_contract_digests != tuple(sorted(entries)) or baseline.family_contract_set_digest != catalog.catalog_digest:
        raise AdmissionContextError("baseline family catalog set does not match canonical catalog objects")
    census_scopes = tuple(row.scope for row in manifest.census.rows)
    if baseline.claimed_scopes != census_scopes:
        raise AdmissionContextError("claimed scopes do not match the reviewed census")
    for scope in baseline.claimed_scopes:
        _contract_for_scope(catalog, scope)
    expected_fact_set = derive_fact_set_digest(evidence.fact_packs)
    if baseline.fact_schema_digest != derive_fact_schema_digest() or baseline.fact_set_digest != expected_fact_set:
        raise AdmissionContextError("baseline fact set does not match canonical fact objects")
    programs = tuple(sorted(item.declaration_digest for item in evidence.model_programs))
    expected_program_set = derive_identity_set_digest("model_program", programs) if programs else None
    if baseline.model_program_digests != programs or baseline.model_program_set_digest != expected_program_set:
        raise AdmissionContextError("baseline model program set does not match canonical model objects")
    if baseline.outcome_mapping_digest != derive_outcome_mapping_digest(catalog):
        raise AdmissionContextError("baseline outcome mapping does not match ordered contract decisions")
    if denominator.policy_digest != derive_denominator_policy_digest(denominator):
        raise AdmissionContextError("denominator policy digest cannot be re-derived")
    if denominator.policy_digest != baseline.denominator_policy_digest or denominator.policy_digest != manifest.denominator_policy_digest:
        raise AdmissionContextError("denominator policy does not match the reviewed manifest")
    if any(rule.scopes != baseline.claimed_scopes for rule in denominator.rules):
        raise AdmissionContextError("denominator scope does not exactly match claimed scopes")


def _expectations_for_program(program: ModelProgramDeclaration) -> tuple[LineageExpectation, ...]:
    expected = [
        LineageExpectation(LineagePurpose.PROMPT, program.prompt_digest, 1, 1),
        LineageExpectation(LineagePurpose.DECISION_MAPPING, program.decision_mapping_digest, 1, 1),
    ]
    if program.example_set_digest is not None:
        expected.append(LineageExpectation(LineagePurpose.EXAMPLE, program.example_set_digest, 1, 1))
    if program.fitted_component_digest is not None:
        expected.append(LineageExpectation(LineagePurpose.FITTED_MODEL, program.fitted_component_digest, 1, 1))
    return tuple(expected)


def _register(
    expected: dict[str, tuple[str, tuple[LineageExpectation, ...]]],
    digest: str,
    subject: str,
    expectations: tuple[LineageExpectation, ...],
) -> None:
    value = (subject, expectations)
    if digest in expected and expected[digest] != value:
        raise AdmissionContextError("lineage manifest is ambiguously owned by canonical objects")
    expected[digest] = value


def _lineage_expectations(
    manifest: AdmissionManifestV2,
    context: AdmissionValidationContext,
) -> dict[str, tuple[str, tuple[LineageExpectation, ...]]]:
    expected: dict[str, tuple[str, tuple[LineageExpectation, ...]]] = {}
    _register(
        expected,
        manifest.threshold_lineage_manifest_digest,
        manifest.threshold_set_digest,
        (LineageExpectation(LineagePurpose.THRESHOLD, manifest.threshold_set_digest, 1, 1),),
    )
    for program in context.evidence.model_programs:
        _register(expected, program.lineage_manifest_digest, program.input_bundle_digest, _expectations_for_program(program))
    for pack in context.evidence.fact_packs:
        expectations = (
            LineageExpectation(LineagePurpose.SEMANTIC_FACT, pack.normalized_content_digest, 1, 1),
            LineageExpectation(LineagePurpose.PROMOTION, pack.normalized_content_digest, 0, 1),
        )
        for review in pack.review_evidence:
            _register(expected, review.lineage_manifest_digest, pack.normalized_content_digest, expectations)
    return expected


def _orphan_expectations(lineage: LineageManifest) -> tuple[LineageExpectation, ...]:
    if not lineage.uses:
        raise AdmissionContextError("unowned lineage must not be empty")
    allowed = {LineagePurpose.MATCHING_BEHAVIOR, LineagePurpose.PROMOTION}
    if any(use.purpose not in allowed or use.influenced_artifact_digest != lineage.subject_digest for use in lineage.uses):
        raise AdmissionContextError("lineage is not owned by a canonical matcher or promotion object")
    purposes = tuple(sorted({use.purpose for use in lineage.uses}, key=lambda item: item.value))
    return tuple(
        LineageExpectation(
            purpose,
            lineage.subject_digest,
            sum(use.purpose is purpose for use in lineage.uses),
            sum(use.purpose is purpose for use in lineage.uses),
        )
        for purpose in purposes
    )


def _refuse_omitted_lineage_uses(
    lineage: LineageManifest,
    expectations: tuple[LineageExpectation, ...],
    populations: set[str],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> None:
    expected = {(item.purpose, item.influenced_artifact_digest) for item in expectations}
    declared = {use.population_use_receipt_digest for use in lineage.uses}
    for population in sorted(populations):
        log = custody.current_log(population)
        validate_population_custody_log(log, context.evidence.custody_policy, current=custody)
        for receipt in log.receipts:
            request = receipt.request
            key = (request.purpose, request.influenced_artifact_digest)
            relevant = key in expected and (request.arm_id == lineage.arm_id or request.labels_accessed)
            if relevant and receipt.receipt_digest not in declared:
                label = "label-influenced " if request.labels_accessed else ""
                raise AdmissionContextError(f"lineage omitted current {label}use: {receipt.receipt_digest}")


def _validate_lineages(manifest: AdmissionManifestV2, context: AdmissionValidationContext, custody: PopulationCustodyPort) -> None:
    lineages = context.evidence.lineages
    indexed = {item.manifest_digest: item for item in lineages}
    if len(indexed) != len(lineages):
        raise AdmissionContextError("duplicate lineage manifest identity")
    expected = _lineage_expectations(manifest, context)
    if any(digest not in indexed for digest in expected):
        raise AdmissionContextError("required threshold, model, or fact lineage is absent")
    populations = {manifest.identity.population_digest, *(use.source_population_digest for item in lineages for use in item.uses)}
    for lineage in lineages:
        binding = expected.get(lineage.manifest_digest)
        subject, expectations = binding if binding is not None else (lineage.subject_digest, _orphan_expectations(lineage))
        decision = validate_lineage(
            lineage,
            subject,
            expectations,
            manifest.identity.population_digest,
            True,
            custody,
            context.evidence.custody_policy,
        )
        if not decision.allowed:
            raise AdmissionContextError("lineage validation refused: " + ",".join(decision.reasons))
        _refuse_omitted_lineage_uses(lineage, expectations, populations, context, custody)


def _model_for_scope(context: AdmissionValidationContext, contract_digest: str) -> str | None:
    programs = tuple(item.declaration_digest for item in context.evidence.model_programs if item.family_contract_digest == contract_digest)
    if len(programs) > 1:
        raise AdmissionContextError("a readiness scope cannot select multiple model programs")
    return programs[0] if programs else None


def _validate_readiness(manifest: AdmissionManifestV2, readiness: Sequence[ReadinessResult], context: AdmissionValidationContext) -> None:
    if type(readiness) is not tuple:
        raise AdmissionContextError("readiness container must be an exact tuple")
    values = tuple(readiness)
    digests = tuple(sorted(item.result_digest for item in values))
    if digests != manifest.readiness_digests or len(set(digests)) != len(digests):
        raise AdmissionContextError("readiness result set does not match the reviewed manifest")
    consumed: set[str] = set()
    for scope in manifest.identity.claimed_scopes:
        receipts = tuple(
            item
            for item in values
            if item.arm_id == manifest.identity.arm_id and item.family_id == scope.family_id and item.ecosystem == scope.ecosystem
        )
        entry = _contract_for_scope(context.evidence.family_catalog, scope)
        model = _model_for_scope(context, entry.contract_digest)
        current = derive_analysis_identity(manifest.identity, context.evidence.family_catalog, scope, model)
        authorization = authorize_stage(ReadinessStage.ADMISSION, receipts, current)
        if not authorization.authorized:
            raise AdmissionContextError("current instrument-through-development readiness refused: " + ",".join(authorization.reasons))
        consumed.update(item.result_digest for item in receipts)
    if consumed != set(digests):
        raise AdmissionContextError("readiness contains a scope, arm, or identity outside the reviewed manifest")


def _validate_custody(manifest: AdmissionManifestV2, context: AdmissionValidationContext, custody: PopulationCustodyPort) -> None:
    log = custody.current_log(manifest.identity.population_digest)
    validate_population_custody_log(log, context.evidence.custody_policy, current=custody)
    if log.log_digest != manifest.custody_log_digest:
        raise AdmissionContextError("manifest custody head is not the current complete custody log")
    if log.status is not PopulationStatus.AVAILABLE:
        raise AdmissionContextError("admission population is spent and no longer available")


def validate_admission_context(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    """Validate every pre-opening identity and lineage; feasibility is deliberately absent."""
    try:
        _validate_context(context)
        if manifest.validation_context_digest != context.context_digest:
            raise AdmissionContextError("manifest validation context has been substituted")
        validate_reviewed_admission_payloads(manifest.census, manifest, context.admission_review_policy, resolver)
        _validate_scopes_and_sets(manifest, denominator, context)
        _validate_custody(manifest, context, custody)
        _validate_lineages(manifest, context, custody)
        _validate_readiness(manifest, readiness, context)
    except AdmissionContextError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionContextError(f"admission context validation failed: {exc}") from exc


__all__ = [
    "ADMISSION_VALIDATION_CONTEXT_SCHEMA",
    "AdmissionContextError",
    "AdmissionValidationContext",
    "derive_admission_validation_context_digest",
    "derive_analysis_identity",
    "derive_fact_schema_digest",
    "derive_outcome_mapping_digest",
    "derive_semantic_vocabulary_digest",
    "make_admission_validation_context",
    "validate_admission_context",
]
