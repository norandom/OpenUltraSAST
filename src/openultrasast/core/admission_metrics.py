"""Canonical, scoped admission metric derivation from revalidated cases."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._admission_funnel import aggregate_funnels, derive_case_funnel
from openultrasast.core.admission_case import (
    AdmissionCaseRelease,
    AdmissionCaseResult,
    AdmissionCaseRole,
    ReleasedCaseBinding,
    derive_admission_case_result_digest,
    derive_case_coverage_digest,
    validate_admission_case_release,
    validate_admission_case_shape,
)
from openultrasast.core.admission_case import (
    create_admission_case_result as create_admission_case_result,
)
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_review import AdmissionManifestV2, ScopeCensus, validate_reviewed_admission_payloads
from openultrasast.core.admission_spend import AdmissionPreparation
from openultrasast.core.budget import check_budget
from openultrasast.core.coverage import CoverageFunnel, ReasonCount, validate_instrument
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evidence import EvidenceBasis, EvidenceRecord, NeutralOutcome, derive_packet_digest
from openultrasast.core.family import FamilyContract
from openultrasast.core.family_catalog import resolve_contract
from openultrasast.core.measurement import DenominatorPolicy, MetricId, MetricResult, ScopeKey, evaluate_metric, validate_denominator_policy
from openultrasast.core.measurement_record import BasisCount, OutcomeCount
from openultrasast.core.model import ModelStatus
from openultrasast.core.proof import ProofAttachment, attach_differential_proof
from openultrasast.core.readiness import ReadinessResult
from openultrasast.core.validation import validate_evidence_input
from openultrasast.core.verdict_v2 import DefectClaim, derive_verdict_outputs


class AdmissionMetricsError(ValueError):
    """Admission cases cannot produce trustworthy metrics."""


@dataclass(frozen=True)
class AdmissionMetricEvidence:
    family_decision_vocabulary: tuple[str, ...]
    family_decision_counts: tuple[ReasonCount, ...]
    neutral_outcome_counts: tuple[OutcomeCount, ...]
    evidence_basis_counts: tuple[BasisCount, ...]
    metrics: tuple[MetricResult, ...]
    stage_funnel: CoverageFunnel
    model_outcome_counts: tuple[ReasonCount, ...]
    model_failures: tuple[str, ...]
    runtime_ms: int
    whole_population_funnel: CoverageFunnel
    whole_population_runtime_ms: int
    in_scope_case_count: int
    whole_population_case_count: int
    case_result_digests: tuple[str, ...]


@dataclass(frozen=True)
class _ValidatedCase:
    supplied: AdmissionCaseResult
    binding: ReleasedCaseBinding
    records: tuple[EvidenceRecord, ...]
    claims: tuple[DefectClaim, ...]
    funnel: CoverageFunnel


@dataclass(frozen=True)
class _DerivedCounts:
    vocabulary: tuple[str, ...]
    decisions: tuple[ReasonCount, ...]
    outcomes: tuple[OutcomeCount, ...]
    bases: tuple[BasisCount, ...]
    metrics: tuple[MetricResult, ...]
    model_outcomes: tuple[ReasonCount, ...]
    model_failures: tuple[str, ...]


def _case_shape(case: AdmissionCaseResult) -> None:
    try:
        validate_admission_case_shape(case)
    except (TypeError, ValueError) as exc:
        raise AdmissionMetricsError(str(exc)) from exc
    if not case.evidence_inputs:
        raise AdmissionMetricsError("case requires evidence inputs")


def _contract(case: AdmissionCaseResult, records: tuple[EvidenceRecord, ...], context: AdmissionValidationContext) -> FamilyContract:
    digests = {item.packet.family_contract_digest for item in records}
    if len(digests) != 1:
        raise AdmissionMetricsError("case records must use one exact family contract")
    contract = resolve_contract(context.evidence.family_catalog, case.scope.family_id, next(iter(digests)), case.scope.ecosystem)
    for record in records:
        packet = record.packet
        if (packet.family_id, packet.ecosystem) != (case.scope.family_id, case.scope.ecosystem):
            raise AdmissionMetricsError("case scope does not match validated evidence")
    return contract


def _apply_proofs(
    claims: tuple[DefectClaim, ...],
    attachments: tuple[ProofAttachment, ...],
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[DefectClaim, ...]:
    if not attachments:
        return claims
    if context.proof_trust_policy is None:
        raise AdmissionMetricsError("proof attachments require the context-bound trust policy")
    keys = {
        (item.record.packet.family_id, derive_packet_digest(item.record.packet), item.location): index for index, item in enumerate(claims)
    }
    if len(keys) != len(claims):
        raise AdmissionMetricsError("proof target is ambiguous")
    result = list(claims)
    consumed: set[int] = set()
    for attachment in attachments:
        key = (attachment.family_id, attachment.packet_digest, attachment.location)
        if key not in keys or keys[key] in consumed:
            raise AdmissionMetricsError("proof attachment does not target one exact claim")
        index = keys[key]
        result[index] = attach_differential_proof(result[index], attachment, context.proof_trust_policy, resolver)
        consumed.add(index)
    return tuple(result)


def _validated_records(
    case: AdmissionCaseResult, context: AdmissionValidationContext, custody: PopulationCustodyPort, resolver: canonical.ContentResolver
) -> tuple[EvidenceRecord, ...]:
    _case_shape(case)
    try:
        validate_instrument(case.input_manifest, case.input_receipts)
    except (TypeError, ValueError) as exc:
        raise AdmissionMetricsError(f"instrument validation failed: {exc}") from exc
    try:
        check_budget(case.complexity, case.total_reply_ms, case.budget, resolver)
    except (TypeError, ValueError) as exc:
        raise AdmissionMetricsError(f"budget validation failed: {exc}") from exc
    try:
        records = tuple(validate_evidence_input(item, context.evidence, custody, resolver) for item in case.evidence_inputs)
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionMetricsError(f"evidence validation failed: {exc}") from exc
    if len({item.record_id for item in records}) != len(records):
        raise AdmissionMetricsError("evidence inputs contain duplicate record identities")
    scopes = {record.packet.scope for record in records}
    if len(scopes) != 1:
        raise AdmissionMetricsError("case records must share one exact analyzed scope")
    analyzed_scope = next(iter(scopes))
    expected_complexity = (
        analyzed_scope.change_digest,
        len(analyzed_scope.regions),
        sum(len(record.packet.transitions) for record in records),
    )
    actual_complexity = (case.complexity.change_id, case.complexity.changed_regions, case.complexity.transition_count)
    if actual_complexity != expected_complexity:
        raise AdmissionMetricsError("case complexity does not match revalidated evidence")
    return records


def _validated_verdict(
    case: AdmissionCaseResult,
    records: tuple[EvidenceRecord, ...],
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[tuple[DefectClaim, ...], CoverageFunnel]:
    contract = _contract(case, records, context)
    base_outputs = derive_verdict_outputs(records, contract, canonical.content_digest("admission-coverage-pending"))
    funnel = derive_case_funnel(case, records, len(base_outputs.defects))
    coverage_digest = derive_case_coverage_digest(case.case_id_digest, case.scope, funnel)
    outputs = derive_verdict_outputs(records, contract, coverage_digest)
    claims = _apply_proofs(outputs.defects, case.proof_attachments, context, resolver)
    if (claims, outputs.satisfactions, outputs.silence) != (case.defect_claims, case.satisfactions, case.silence):
        raise AdmissionMetricsError("supplied verdict differs from the revalidated canonical verdict")
    funnel = derive_case_funnel(case, records, len(claims))
    if case.coverage != funnel:
        raise AdmissionMetricsError("coverage aggregate does not match revalidated case evidence")
    if case.result_digest != derive_admission_case_result_digest(case):
        raise AdmissionMetricsError("case result digest cannot be re-derived")
    return claims, funnel


def _validate_case(
    case: AdmissionCaseResult,
    binding: ReleasedCaseBinding,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> _ValidatedCase:
    records = _validated_records(case, context, custody, resolver)
    claims, funnel = _validated_verdict(case, records, context, resolver)
    return _ValidatedCase(case, binding, records, claims, funnel)


def _validate_population(cases: tuple[_ValidatedCase, ...], rows: tuple[ScopeCensus, ...]) -> None:
    by_scope = {row.scope: row for row in rows}
    missing_scopes = tuple(sorted({item.binding.scope for item in cases if item.binding.scope not in by_scope}))
    if missing_scopes:
        raise AdmissionMetricsError("case scope has no reviewed census row")
    if len(cases) != sum(row.total_cases for row in rows):
        raise AdmissionMetricsError("case population count does not reconcile with the reviewed census")
    for row in rows:
        selected = tuple(item for item in cases if item.binding.scope == row.scope)
        roles = Counter(item.binding.role for item in selected)
        model_calls = sum(
            value.model_result is not None for item in selected for value in item.supplied.evidence_inputs
        )
        actual = (
            len(selected),
            roles[AdmissionCaseRole.VULNERABLE],
            roles[AdmissionCaseRole.FIXED],
            roles[AdmissionCaseRole.ORDINARY],
            sum(item.funnel.sites_considered for item in selected),
            model_calls,
        )
        expected = (
            row.total_cases,
            row.vulnerable_side_count,
            row.fixed_side_count,
            row.ordinary_case_count,
            row.semantic_site_capacity,
            row.model_call_capacity,
        )
        if actual != expected:
            raise AdmissionMetricsError("case counts do not reconcile with the reviewed census")
        paired: dict[str, list[AdmissionCaseRole]] = {}
        for item in selected:
            binding = item.binding
            if binding.role is AdmissionCaseRole.ORDINARY and binding.pair_id_digest is not None:
                raise AdmissionMetricsError("ordinary case cannot carry a pair identity")
            if binding.pair_id_digest is not None:
                paired.setdefault(binding.pair_id_digest, []).append(binding.role)
        valid = {AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED}
        if len(paired) != row.pair_count or any(len(values) != 2 or set(values) != valid for values in paired.values()):
            raise AdmissionMetricsError("case pairs do not reconcile with the reviewed census")


def _vocabulary(context: AdmissionValidationContext, scopes: tuple[ScopeKey, ...]) -> tuple[str, ...]:
    values: list[str] = []
    for entry in context.evidence.family_catalog.entries:
        if any(scope.family_id == entry.contract.family_id and scope.ecosystem in entry.contract.ecosystems for scope in scopes):
            values.extend(rule.family_code for rule in entry.contract.decisions)
    if not values or len(values) != len(set(values)):
        raise AdmissionMetricsError("exact catalog decision vocabulary is empty or ambiguous")
    return tuple(values)


def derive_scoped_pair_key(scope: ScopeKey, pair_id_digest: str) -> tuple[str, str, str]:
    return scope.family_id, scope.ecosystem, pair_id_digest


def _metric_counts(cases: tuple[_ValidatedCase, ...], funnel: CoverageFunnel) -> dict[MetricId, tuple[int, int]]:
    by_pair: dict[tuple[str, str, str], dict[AdmissionCaseRole, _ValidatedCase]] = {}
    for item in cases:
        if item.binding.pair_id_digest is not None:
            key = derive_scoped_pair_key(item.binding.scope, item.binding.pair_id_digest)
            by_pair.setdefault(key, {})[item.binding.role] = item
    correct = sum(bool(pair[AdmissionCaseRole.VULNERABLE].claims) and not pair[AdmissionCaseRole.FIXED].claims for pair in by_pair.values())
    vulnerable = tuple(item for item in cases if item.binding.role is AdmissionCaseRole.VULNERABLE)
    fixed = tuple(item for item in cases if item.binding.role is AdmissionCaseRole.FIXED)
    ordinary = tuple(item for item in cases if item.binding.role is AdmissionCaseRole.ORDINARY)
    defects = tuple(item for item in cases if item.claims)
    model_results = tuple(value.model_result for item in cases for value in item.supplied.evidence_inputs if value.model_result is not None)
    return {
        MetricId.PAIRED_CORRECTNESS: (correct, len(by_pair)),
        MetricId.VULNERABLE_RECALL: (sum(bool(item.claims) for item in vulnerable), len(vulnerable)),
        MetricId.FIXED_FALSE_ALARM_RATE: (sum(bool(item.claims) for item in fixed), len(fixed)),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (sum(bool(item.claims) for item in ordinary), len(ordinary)),
        MetricId.PRECISION: (sum(bool(item.claims) for item in vulnerable), len(defects)),
        MetricId.SEMANTIC_STAGE_COVERAGE: (funnel.sites_recognized, funnel.sites_considered),
        MetricId.MODEL_SUCCESS_RATE: (sum(item.status is ModelStatus.SUCCEEDED for item in model_results), len(model_results)),
    }


def _validated_cases(
    manifest: AdmissionManifestV2,
    release: AdmissionCaseRelease,
    cases: tuple[AdmissionCaseResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[_ValidatedCase, ...]:
    selected = cases
    if not selected or len({item.case_id_digest for item in selected}) != len(selected):
        raise AdmissionMetricsError("case population must be nonempty with unique identities")
    bindings = {item.case_id_digest: item for item in release.bindings}
    validated = tuple(_validate_case(item, bindings[item.case_id_digest], context, custody, resolver) for item in selected)
    input_ids = tuple(value.input_digest for item in validated for value in item.supplied.evidence_inputs)
    record_ids = tuple(record.record_id for item in validated for record in item.records)
    if len(input_ids) != len(set(input_ids)) or len(record_ids) != len(set(record_ids)):
        raise AdmissionMetricsError("case population repeats canonical evidence identities")
    _validate_population(validated, manifest.census.rows)
    return validated


def _derive_counts(
    cases: tuple[_ValidatedCase, ...],
    funnel: CoverageFunnel,
    denominator: DenominatorPolicy,
    context: AdmissionValidationContext,
    scopes: tuple[ScopeKey, ...],
) -> _DerivedCounts:
    counts = _metric_counts(cases, funnel)
    metrics = tuple(
        evaluate_metric(rule, numerator=counts[rule.metric_id][0], denominator=counts[rule.metric_id][1]) for rule in denominator.rules
    )
    records = tuple(record for item in cases for record in item.records)
    vocabulary = _vocabulary(context, scopes)
    by_decision = Counter(record.decision.family_code for record in records)
    decisions = tuple(ReasonCount(name, by_decision[name]) for name in vocabulary)
    by_outcome = Counter(record.decision.outcome for record in records)
    outcomes = tuple(OutcomeCount(outcome, by_outcome[outcome]) for outcome in NeutralOutcome)
    by_basis = Counter(claim.basis for item in cases for claim in item.claims)
    bases = tuple(BasisCount(basis, by_basis[basis]) for basis in EvidenceBasis)
    model_results = tuple(value.model_result for item in cases for value in item.supplied.evidence_inputs if value.model_result is not None)
    model_counts = Counter("success" if item.status is ModelStatus.SUCCEEDED else "failure" for item in model_results)
    model_outcomes = tuple(ReasonCount(name, model_counts[name]) for name in ("failure", "success") if model_counts[name])
    failures = tuple(sorted({item.failure_reason for item in model_results if item.failure_reason is not None}))
    return _DerivedCounts(vocabulary, decisions, outcomes, bases, metrics, model_outcomes, failures)


def _derive_validated_metrics(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    release: AdmissionCaseRelease,
    cases: tuple[AdmissionCaseResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionMetricEvidence:
    validate_reviewed_admission_payloads(manifest.census, manifest, context.admission_review_policy, resolver)
    validate_denominator_policy(denominator)
    if manifest.validation_context_digest != context.context_digest:
        raise AdmissionMetricsError("validation context does not match the reviewed manifest")
    if denominator.policy_digest != manifest.denominator_policy_digest:
        raise AdmissionMetricsError("denominator does not match the reviewed manifest")
    validated = _validated_cases(manifest, release, cases, context, custody, resolver)
    scopes = manifest.identity.claimed_scopes
    in_scope = tuple(item for item in validated if item.binding.scope in scopes)
    funnel = aggregate_funnels(tuple(item.funnel for item in in_scope))
    whole_funnel = aggregate_funnels(tuple(item.funnel for item in validated))
    counts = _derive_counts(in_scope, funnel, denominator, context, scopes)
    return AdmissionMetricEvidence(
        counts.vocabulary,
        counts.decisions,
        counts.outcomes,
        counts.bases,
        counts.metrics,
        funnel,
        counts.model_outcomes,
        counts.model_failures,
        sum(item.supplied.total_reply_ms for item in in_scope),
        whole_funnel,
        sum(item.supplied.total_reply_ms for item in validated),
        len(in_scope),
        len(validated),
        tuple(sorted(item.supplied.result_digest for item in validated)),
    )


def derive_admission_metrics(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    preparation: AdmissionPreparation,
    label_release_receipt: PopulationUseReceipt,
    case_release: AdmissionCaseRelease,
    cases: Sequence[AdmissionCaseResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionMetricEvidence:
    """Revalidate immutable case evidence and derive only pre-registered quality metrics."""
    try:
        frozen_cases = tuple(cases)
        frozen_readiness = tuple(readiness)
        validate_admission_case_release(
            manifest,
            denominator,
            frozen_readiness,
            context,
            preparation,
            label_release_receipt,
            case_release,
            frozen_cases,
            custody,
            resolver,
        )
        return _derive_validated_metrics(manifest, denominator, case_release, frozen_cases, context, custody, resolver)
    except AdmissionMetricsError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionMetricsError(f"admission metric derivation failed before metric production: {exc}") from exc
