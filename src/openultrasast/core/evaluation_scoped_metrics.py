"""Non-authorizing exact-scope quality partitions for evaluation admission V3."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.coverage import CoverageFunnel
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3, EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_case_validation import validate_released_case_associations_v3
from openultrasast.core.evaluation_measurement import ArmScopeKey, DenominatorPolicyV3
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    ReleasedArmCaseBindingV3,
    validate_admission_case_release_v3,
)
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.evidence import EvidenceBasis, NeutralOutcome
from openultrasast.core.family_catalog import resolve_contract
from openultrasast.core.model import ModelStatus

_DIGEST = re.compile(r"[0-9a-f]{64}")


class ScopedQualityPartitionError(ValueError):
    """Released quality evidence cannot be isolated to exact reviewed keys."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ScopedQualityPartitionError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _exact_tuple(value: object, expected: type[object], field: str, *, nonempty: bool = False) -> tuple[object, ...]:
    if type(value) is not tuple or (nonempty and not value) or any(type(item) is not expected for item in value):
        raise ScopedQualityPartitionError(f"{field} must be an exact tuple of {expected.__name__}")
    return value


@dataclass(frozen=True)
class ScopedCaseQualityEvidenceV3(EvaluationV3Contract, NonAuthorizingV3):
    """One released case projected into exactly one quality partition."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    case_id_digest: str
    case_result_digest: str
    binding_digest: str
    role: AdmissionCaseRole
    pair_id_digest: str | None
    has_findings: bool
    neutral_outcome: NeutralOutcome
    family_decision_codes: tuple[str, ...]
    evidence_bases: tuple[EvidenceBasis, ...]
    model_outcomes: tuple[ModelStatus, ...]
    semantic_coverage: CoverageFunnel

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopedCaseQualityEvidenceV3, field="scoped case quality evidence")
        if type(self.key) is not ArmScopeKey or type(self.role) is not AdmissionCaseRole:
            raise ScopedQualityPartitionError("case key and role must use exact closed values")
        self.key.__post_init__()
        for value, field in (
            (self.case_id_digest, "case identity"),
            (self.case_result_digest, "case result identity"),
            (self.binding_digest, "release binding identity"),
        ):
            _digest(value, field)
        if self.pair_id_digest is not None:
            _digest(self.pair_id_digest, "pair identity")
        if type(self.has_findings) is not bool or type(self.neutral_outcome) is not NeutralOutcome:
            raise ScopedQualityPartitionError("finding presence and neutral outcome must use exact closed values")
        _validate_case_sequences(self)


def _validate_case_sequences(value: ScopedCaseQualityEvidenceV3) -> None:
    if type(value.family_decision_codes) is not tuple or not value.family_decision_codes:
        raise ScopedQualityPartitionError("family decision codes must be a nonempty exact tuple")
    if any(type(code) is not str or not code for code in value.family_decision_codes):
        raise ScopedQualityPartitionError("family decision codes must be nonempty exact text")
    _exact_tuple(value.evidence_bases, EvidenceBasis, "evidence bases")
    _exact_tuple(value.model_outcomes, ModelStatus, "model outcomes")
    if type(value.semantic_coverage) is not CoverageFunnel:
        raise ScopedQualityPartitionError("semantic coverage must use exact CoverageFunnel")
    value.semantic_coverage.__post_init__()
    if value.has_findings != bool(value.evidence_bases):
        raise ScopedQualityPartitionError("finding presence must match the preserved evidence bases")
    if value.role is AdmissionCaseRole.ORDINARY and value.pair_id_digest is not None:
        raise ScopedQualityPartitionError("ordinary case cannot enter a scoped pair")
    if value.role is not AdmissionCaseRole.ORDINARY and value.pair_id_digest is None:
        raise ScopedQualityPartitionError("vulnerable and fixed cases require a scoped pair identity")


@dataclass(frozen=True)
class ScopedPairQualityEvidenceV3(EvaluationV3Contract, NonAuthorizingV3):
    """Exact vulnerable/fixed membership used for one key's pair correctness."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    pair_id_digest: str
    vulnerable_case_id_digest: str
    fixed_case_id_digest: str
    is_correct: bool

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopedPairQualityEvidenceV3, field="scoped pair quality evidence")
        if type(self.key) is not ArmScopeKey:
            raise ScopedQualityPartitionError("pair key must use exact ArmScopeKey")
        self.key.__post_init__()
        for value, field in (
            (self.pair_id_digest, "pair identity"),
            (self.vulnerable_case_id_digest, "vulnerable case identity"),
            (self.fixed_case_id_digest, "fixed case identity"),
        ):
            _digest(value, field)
        if type(self.is_correct) is not bool:
            raise ScopedQualityPartitionError("pair correctness must be an exact boolean")


@dataclass(frozen=True)
class ScopedQualityPartitionV3(EvaluationV3Contract, NonAuthorizingV3):
    """All quality evidence assigned to one reviewed arm/family/ecosystem key."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    denominator_policy: DenominatorPolicyV3
    family_decision_vocabulary: tuple[str, ...]
    cases: tuple[ScopedCaseQualityEvidenceV3, ...]
    pairs: tuple[ScopedPairQualityEvidenceV3, ...]
    precision_numerator_case_digests: tuple[str, ...]
    precision_denominator_case_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopedQualityPartitionV3, field="scoped quality partition")
        if type(self.key) is not ArmScopeKey or type(self.denominator_policy) is not DenominatorPolicyV3:
            raise ScopedQualityPartitionError("partition key and denominator policy must use exact V3 values")
        self.key.__post_init__()
        self.denominator_policy.__post_init__()
        if self.denominator_policy.key != self.key:
            raise ScopedQualityPartitionError("partition denominator policy belongs to another key")
        _validate_partition_sequences(self)


def _validate_partition_sequences(value: ScopedQualityPartitionV3) -> None:
    vocabulary = value.family_decision_vocabulary
    if type(vocabulary) is not tuple or not vocabulary or len(vocabulary) != len(set(vocabulary)):
        raise ScopedQualityPartitionError("family decision vocabulary must be nonempty and unique")
    if any(type(code) is not str or not code for code in vocabulary):
        raise ScopedQualityPartitionError("family decision vocabulary must contain exact text")
    _exact_tuple(value.cases, ScopedCaseQualityEvidenceV3, "partition cases", nonempty=True)
    _exact_tuple(value.pairs, ScopedPairQualityEvidenceV3, "partition pairs")
    for case in value.cases:
        case.__post_init__()
    for pair in value.pairs:
        pair.__post_init__()
    if any(case.key != value.key for case in value.cases) or any(pair.key != value.key for pair in value.pairs):
        raise ScopedQualityPartitionError("cross-key evidence cannot enter a quality partition")
    if value.cases != tuple(sorted(value.cases, key=lambda item: item.case_id_digest)):
        raise ScopedQualityPartitionError("partition cases must use canonical case order")
    observed_codes = {code for case in value.cases for code in case.family_decision_codes}
    if not observed_codes <= set(vocabulary):
        raise ScopedQualityPartitionError("observed decisions escape the preserved family vocabulary")
    if value.pairs != _pair_evidence(value.key, value.cases):
        raise ScopedQualityPartitionError("pair membership must derive only from the exact partition")
    expected_denominator = tuple(case.case_id_digest for case in value.cases if case.has_findings)
    expected_numerator = tuple(
        case.case_id_digest for case in value.cases if case.has_findings and case.role is AdmissionCaseRole.VULNERABLE
    )
    if value.precision_denominator_case_digests != expected_denominator or value.precision_numerator_case_digests != expected_numerator:
        raise ScopedQualityPartitionError("precision membership must derive only from the exact partition")


def _case_evidence(case: ArmAdmissionCaseResultV3, binding: ReleasedArmCaseBindingV3) -> ScopedCaseQualityEvidenceV3:
    decision_codes = tuple(sorted(value.record.decision.family_code for value in case.evidence_inputs))
    bases = tuple(claim.basis for claim in case.claims)
    models = tuple(value.model_result.status for value in case.evidence_inputs if value.model_result is not None)
    return ScopedCaseQualityEvidenceV3(
        case.key,
        case.case_id_digest,
        case.result_digest,
        binding.binding_digest,
        case.role,
        case.pair_id_digest,
        bool(case.claims),
        case.outcome_projection.normalized_outcome,
        decision_codes,
        bases,
        models,
        case.coverage,
    )


def _pair_evidence(key: ArmScopeKey, cases: tuple[ScopedCaseQualityEvidenceV3, ...]) -> tuple[ScopedPairQualityEvidenceV3, ...]:
    by_pair: dict[str, dict[AdmissionCaseRole, ScopedCaseQualityEvidenceV3]] = defaultdict(dict)
    for case in cases:
        if case.pair_id_digest is not None:
            if case.role in by_pair[case.pair_id_digest]:
                raise ScopedQualityPartitionError("scoped pair repeats one role")
            by_pair[case.pair_id_digest][case.role] = case
    rows = []
    for pair_id, roles in sorted(by_pair.items()):
        if set(roles) != {AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED}:
            raise ScopedQualityPartitionError("scoped pair requires one vulnerable and one fixed case")
        vulnerable = roles[AdmissionCaseRole.VULNERABLE]
        fixed = roles[AdmissionCaseRole.FIXED]
        rows.append(
            ScopedPairQualityEvidenceV3(
                key, pair_id, vulnerable.case_id_digest, fixed.case_id_digest, vulnerable.has_findings and not fixed.has_findings
            )
        )
    return tuple(rows)


def _planned_policies(manifest: EvaluationAdmissionManifestV3) -> dict[ArmScopeKey, DenominatorPolicyV3]:
    policies = {
        policy.key: policy
        for configuration in manifest.plan_manifest.declaration.arm_configurations
        for policy in configuration.denominator_policies
    }
    expected = {
        ArmScopeKey(configuration.arm_id, scope)
        for configuration in manifest.plan_manifest.declaration.arm_configurations
        for scope in configuration.exact_scopes
    }
    if set(policies) != expected:
        raise ScopedQualityPartitionError("reviewed denominator policies do not equal every planned exact scope")
    return policies


def _decision_vocabulary(
    cases: tuple[ArmAdmissionCaseResultV3, ...],
    context: AdmissionValidationContext,
) -> tuple[str, ...]:
    vocabularies = set()
    for case in cases:
        for value in case.evidence_inputs:
            packet = value.record.packet
            contract = resolve_contract(
                context.evidence.family_catalog,
                case.key.scope.family_id,
                packet.provenance.family_contract_digest,
                case.key.scope.ecosystem,
            )
            vocabularies.add(tuple(rule.family_code for rule in contract.decisions))
    if len(vocabularies) != 1:
        raise ScopedQualityPartitionError("one exact scope must preserve one family decision vocabulary")
    return next(iter(vocabularies))


def _partition_one(
    key: ArmScopeKey,
    policy: DenominatorPolicyV3,
    cases: tuple[ArmAdmissionCaseResultV3, ...],
    bindings_by_case: dict[tuple[ArmScopeKey, str], ReleasedArmCaseBindingV3],
    context: AdmissionValidationContext,
) -> ScopedQualityPartitionV3:
    rows = tuple(
        sorted((_case_evidence(case, bindings_by_case[(key, case.case_id_digest)]) for case in cases), key=lambda item: item.case_id_digest)
    )
    vocabulary = _decision_vocabulary(cases, context)
    pairs = _pair_evidence(key, rows)
    precision_denominator = tuple(case.case_id_digest for case in rows if case.has_findings)
    precision_numerator = tuple(case.case_id_digest for case in rows if case.has_findings and case.role is AdmissionCaseRole.VULNERABLE)
    return ScopedQualityPartitionV3(key, policy, vocabulary, rows, pairs, precision_numerator, precision_denominator)


def partition_scoped_quality_evidence_v3(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    cases_by_arm: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ScopedQualityPartitionV3, ...]:
    """Validate the reviewed release graph and isolate quality evidence by exact key."""
    try:
        if type(cases_by_arm) is not tuple:
            raise ScopedQualityPartitionError("cases_by_arm must use an exact tuple")
        validate_admission_case_release_v3(
            manifest, authority, preparation, receipt, spend, release, cases_by_arm, context, custody, resolver
        )
        bindings = validate_released_case_associations_v3(manifest, release, cases_by_arm, context, custody, resolver)
        bindings_by_case = {(binding.key, binding.case_id_digest): binding for binding in bindings}
        cases = tuple(case for group in cases_by_arm for case in group.cases)
        if len(bindings_by_case) != len(bindings) or set(bindings_by_case) != {(case.key, case.case_id_digest) for case in cases}:
            raise ScopedQualityPartitionError("released case and binding identities do not match exactly")
        cases_by_key = {key: tuple(case for case in cases if case.key == key) for key in _planned_policies(manifest)}
        if any(not selected for selected in cases_by_key.values()):
            raise ScopedQualityPartitionError("every planned exact scope requires released cases")
        policies = _planned_policies(manifest)
        return tuple(_partition_one(key, policies[key], cases_by_key[key], bindings_by_case, context) for key in sorted(policies))
    except ScopedQualityPartitionError:
        raise
    except (
        canonical.ArtifactResolutionError,
        canonical.ArtifactValidationError,
        AttributeError,
        LookupError,
        TypeError,
        ValueError,
    ) as exc:
        raise ScopedQualityPartitionError(f"scoped quality partition refused by reviewed release: {exc}") from exc


__all__ = [
    "ScopedCaseQualityEvidenceV3",
    "ScopedPairQualityEvidenceV3",
    "ScopedQualityPartitionError",
    "ScopedQualityPartitionV3",
    "partition_scoped_quality_evidence_v3",
]
