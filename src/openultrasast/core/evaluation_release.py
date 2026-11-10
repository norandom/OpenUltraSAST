"""Exact reviewed post-spend case-release graph for evaluation admission V3."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.admission_case import (
    AdmissionCaseResult,
    AdmissionCaseRole,
    validate_admission_case_shape,
)
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.budget import BudgetDerivation, ChangeComplexity
from openultrasast.core.coverage import CoverageFunnel, InputManifest, InputReadReceipt, validate_instrument
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3, EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_measurement import ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_spend import (
    EvaluationPreparationV3,
    EvaluationSpendBindingV3,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.measurement import ScopeKey as LegacyScopeKey
from openultrasast.core.proof import ProofAttachment
from openultrasast.core.validation import EvidenceValidationInput
from openultrasast.core.verdict import BoundedSatisfaction, BoundedSilence, DefectClaim

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ZERO = "0" * 64
_CANDIDATE_SCHEMA = "openultrasast.detection-core.proof-candidate-identity.v3"
_BINDING_SCHEMA = "openultrasast.detection-core.released-arm-case-binding.v3"
_ARM_CASES_SCHEMA = "openultrasast.detection-core.arm-admission-cases.v3"
_RELEASE_PAYLOAD_SCHEMA = "openultrasast.detection-core.admission-case-release-payload.v3"
_RELEASE_SCHEMA = "openultrasast.detection-core.admission-case-release.v3"


class EvaluationReleaseError(ValueError):
    """A V3 release graph is incomplete, cross-bound, or unreviewed."""


def _digest(value: object, field: str, *, nonzero: bool = False) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationReleaseError(f"{field} must be a full lowercase SHA-256 digest")
    if nonzero and value == _ZERO:
        raise EvaluationReleaseError(f"{field} must be nonzero")
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise EvaluationReleaseError(f"{field} must be nonempty exact text")
    return value


def _digests(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationReleaseError(f"{field} must be a nonempty exact tuple")
    for item in value:
        _digest(item, field)
    if value != tuple(sorted(set(value))):
        raise EvaluationReleaseError(f"{field} must be unique and canonical")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationReleaseError(f"{field} does not match canonical content")


def _scope_value(scope: ScopeKey) -> canonical.JsonValue:
    return {"family_id": scope.family_id, "ecosystem": scope.ecosystem}


@dataclass(frozen=True)
class ProofCandidateIdentityV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    component_arm_id: str
    observation_digest: str
    family_id: str
    scope: ScopeKey
    finding_location_digest: str
    change_input_digest: str
    candidate_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ProofCandidateIdentityV3, field="proof candidate identity")
        _text(self.component_arm_id, "candidate component arm")
        _digest(self.observation_digest, "candidate observation digest")
        _text(self.family_id, "candidate family")
        if type(self.scope) is not ScopeKey:
            raise EvaluationReleaseError("candidate scope must use exact V3 ScopeKey")
        self.scope.__post_init__()
        _digest(self.finding_location_digest, "candidate finding location digest")
        _digest(self.change_input_digest, "candidate change input digest")
        _digest(self.candidate_digest, "candidate digest")


def _candidate_value(value: ProofCandidateIdentityV3) -> canonical.JsonValue:
    return {
        "schema_version": _CANDIDATE_SCHEMA,
        "component_arm_id": value.component_arm_id,
        "observation_digest": value.observation_digest,
        "family_id": value.family_id,
        "scope": _scope_value(value.scope),
        "finding_location_digest": value.finding_location_digest,
        "change_input_digest": value.change_input_digest,
        "candidate_digest": value.candidate_digest,
    }


@dataclass(frozen=True)
class ArmAdmissionCaseResultV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    observation_slot_digest: str
    observation_digest: str
    underlying_push_digest: str
    case_id_digest: str
    role: AdmissionCaseRole
    pair_id_digest: str | None
    evidence_inputs: tuple[EvidenceValidationInput, ...]
    claims: tuple[DefectClaim, ...]
    satisfactions: tuple[BoundedSatisfaction, ...]
    silence: tuple[BoundedSilence, ...]
    proof_candidate: ProofCandidateIdentityV3 | None
    proof_attachments: tuple[ProofAttachment, ...]
    coverage: CoverageFunnel
    input_manifest: InputManifest
    input_receipts: tuple[InputReadReceipt, ...]
    complexity: ChangeComplexity
    budget: BudgetDerivation
    total_reply_ms: int
    result_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ArmAdmissionCaseResultV3, field="arm admission case result")
        _validate_case_identity(self)
        _validate_case_sequences(self)
        validate_admission_case_shape(_legacy_case(self))
        validate_instrument(self.input_manifest, self.input_receipts)


def _validate_case_identity(value: ArmAdmissionCaseResultV3) -> None:
    if type(value.key) is not ArmScopeKey:
        raise EvaluationReleaseError("case key must use exact ArmScopeKey")
    value.key.__post_init__()
    for field in ("observation_slot_digest", "observation_digest", "underlying_push_digest", "case_id_digest", "result_digest"):
        _digest(getattr(value, field), field)
    if type(value.role) is not AdmissionCaseRole:
        raise EvaluationReleaseError("case role must use exact AdmissionCaseRole")
    if value.pair_id_digest is not None:
        _digest(value.pair_id_digest, "pair identity digest")
    if value.proof_candidate is not None:
        if type(value.proof_candidate) is not ProofCandidateIdentityV3:
            raise EvaluationReleaseError("proof candidate must use exact ProofCandidateIdentityV3")
        value.proof_candidate.__post_init__()
    if type(value.total_reply_ms) is not int or value.total_reply_ms < 0:
        raise EvaluationReleaseError("case total reply time must be a non-negative integer")


def _validate_case_sequences(value: ArmAdmissionCaseResultV3) -> None:
    for items, expected, field in (
        (value.evidence_inputs, EvidenceValidationInput, "evidence inputs"),
        (value.claims, DefectClaim, "claims"),
        (value.satisfactions, BoundedSatisfaction, "satisfactions"),
        (value.silence, BoundedSilence, "silence"),
        (value.proof_attachments, ProofAttachment, "proof attachments"),
        (value.input_receipts, InputReadReceipt, "input receipts"),
    ):
        if type(items) is not tuple or any(type(item) is not expected for item in items):
            raise EvaluationReleaseError(f"{field} must be an exact tuple of {expected.__name__}")
    if not value.evidence_inputs or not value.input_receipts:
        raise EvaluationReleaseError("case must carry nonempty evidence inputs and input-read receipts")


def _legacy_case(value: ArmAdmissionCaseResultV3) -> AdmissionCaseResult:
    return AdmissionCaseResult(
        value.case_id_digest,
        LegacyScopeKey(value.key.scope.family_id, value.key.scope.ecosystem),
        value.role,
        value.pair_id_digest,
        value.evidence_inputs,
        value.claims,
        value.satisfactions,
        value.silence,
        value.proof_attachments,
        value.coverage,
        value.input_manifest,
        value.input_receipts,
        value.complexity,
        value.budget,
        value.total_reply_ms,
        value.result_digest,
    )


def _binding_value(value: ReleasedArmCaseBindingV3) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": _BINDING_SCHEMA,
        "key": {"arm_id": value.key.arm_id, "scope": _scope_value(value.key.scope)},
        "baseline_digest": value.baseline_digest,
        "observation_slot_digest": value.observation_slot_digest,
        "observation_digest": value.observation_digest,
        "underlying_push_digest": value.underlying_push_digest,
        "case_id_digest": value.case_id_digest,
        "role": value.role.value,
        "pair_id_digest": value.pair_id_digest,
        "case_result_digest": value.case_result_digest,
        "evidence_input_digests": value.evidence_input_digests,
        "change_input_digests": value.change_input_digests,
        "input_manifest_digest": value.input_manifest_digest,
        "proof_candidate_digest": value.proof_candidate_digest,
    }


@dataclass(frozen=True)
class ReleasedArmCaseBindingV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    baseline_digest: str
    observation_slot_digest: str
    observation_digest: str
    underlying_push_digest: str
    case_id_digest: str
    role: AdmissionCaseRole
    pair_id_digest: str | None
    case_result_digest: str
    evidence_input_digests: tuple[str, ...]
    change_input_digests: tuple[str, ...]
    input_manifest_digest: str
    proof_candidate_digest: str | None
    binding_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ReleasedArmCaseBindingV3, field="released arm case binding")
        if type(self.key) is not ArmScopeKey or type(self.role) is not AdmissionCaseRole:
            raise EvaluationReleaseError("release binding key and role must use exact closed values")
        self.key.__post_init__()
        for field in (
            "baseline_digest",
            "observation_slot_digest",
            "observation_digest",
            "underlying_push_digest",
            "case_id_digest",
            "case_result_digest",
            "input_manifest_digest",
        ):
            _digest(getattr(self, field), field)
        if self.pair_id_digest is not None:
            _digest(self.pair_id_digest, "pair identity digest")
        _digests(self.evidence_input_digests, "evidence input digest")
        _digests(self.change_input_digests, "change input digest")
        if self.proof_candidate_digest is not None:
            _digest(self.proof_candidate_digest, "proof candidate digest")
        _bind(self, "binding_digest", canonical.content_digest(_binding_value(self)))


def derive_released_arm_case_binding(case: ArmAdmissionCaseResultV3, plan: object) -> ReleasedArmCaseBindingV3:
    from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3

    if type(case) is not ArmAdmissionCaseResultV3 or type(plan) is not EvaluationPlanManifestV3:
        raise EvaluationReleaseError("binding derivation requires exact V3 case and plan")
    case.__post_init__()
    baseline = next((item.baseline_digest for item in plan.baselines if item.arm_id == case.key.arm_id), None)
    if baseline is None:
        raise EvaluationReleaseError("case arm has no planned baseline")
    evidence = tuple(sorted(item.input_digest for item in case.evidence_inputs))
    changes = tuple(sorted({item.record.packet.provenance.change_input_digest for item in case.evidence_inputs}))
    candidate = case.proof_candidate.candidate_digest if case.proof_candidate is not None else None
    return ReleasedArmCaseBindingV3(
        case.key,
        baseline,
        case.observation_slot_digest,
        case.observation_digest,
        case.underlying_push_digest,
        case.case_id_digest,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        evidence,
        changes,
        case.input_manifest.manifest_digest,
        candidate,
        "",
    )


def _arm_cases_value(value: ArmAdmissionCasesV3) -> canonical.JsonValue:
    return {
        "schema_version": _ARM_CASES_SCHEMA,
        "arm_id": value.arm_id,
        "baseline_digest": value.baseline_digest,
        "case_result_digests": tuple(item.result_digest for item in value.cases),
    }


@dataclass(frozen=True)
class ArmAdmissionCasesV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    arm_id: str
    baseline_digest: str
    cases: tuple[ArmAdmissionCaseResultV3, ...]
    cases_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ArmAdmissionCasesV3, field="arm admission cases")
        _text(self.arm_id, "arm case group identity")
        _digest(self.baseline_digest, "arm case baseline digest")
        if type(self.cases) is not tuple or any(type(item) is not ArmAdmissionCaseResultV3 for item in self.cases):
            raise EvaluationReleaseError("arm cases must be an exact tuple of ArmAdmissionCaseResultV3")
        for item in self.cases:
            item.__post_init__()
            if item.key.arm_id != self.arm_id:
                raise EvaluationReleaseError("arm case belongs to another arm")
        order = tuple(sorted(self.cases, key=lambda item: (item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest)))
        if self.cases != order or len({item.case_id_digest for item in self.cases}) != len(self.cases):
            raise EvaluationReleaseError("arm cases must be unique and canonical")
        _bind(self, "cases_digest", canonical.content_digest(_arm_cases_value(self)))


def _review_value(review: IndependenceAttestation) -> canonical.JsonValue:
    ref = review.conflict_disclosure
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": {
            "artifact_id": ref.artifact_id,
            "content_digest": ref.content_digest,
            "media_type": ref.media_type,
            "byte_length": ref.byte_length,
            "retention_policy_digest": ref.retention_policy_digest,
            "storage_receipt_digest": ref.storage_receipt_digest,
        },
        "attestation_digest": review.attestation_digest,
    }


def _release_payload_value(value: AdmissionCaseReleaseV3) -> canonical.JsonValue:
    return {
        "schema_version": _RELEASE_PAYLOAD_SCHEMA,
        "plan_manifest_digest": value.plan_manifest_digest,
        "admission_manifest_digest": value.admission_manifest_digest,
        "authority_digest": value.authority_digest,
        "preparation_digest": value.preparation_digest,
        "spend_binding_digest": value.spend_binding_digest,
        "bindings": tuple({**_binding_value(item), "binding_digest": item.binding_digest} for item in value.bindings),
    }


@dataclass(frozen=True)
class AdmissionCaseReleaseV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    plan_manifest_digest: str
    admission_manifest_digest: str
    authority_digest: str
    preparation_digest: str
    spend_binding_digest: str
    bindings: tuple[ReleasedArmCaseBindingV3, ...]
    payload_digest: str
    review: IndependenceAttestation
    release_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AdmissionCaseReleaseV3, field="admission case release")
        for field in (
            "plan_manifest_digest",
            "admission_manifest_digest",
            "authority_digest",
            "preparation_digest",
            "spend_binding_digest",
            "payload_digest",
            "release_digest",
        ):
            _digest(getattr(self, field), field)
        if (
            type(self.bindings) is not tuple
            or not self.bindings
            or any(type(item) is not ReleasedArmCaseBindingV3 for item in self.bindings)
        ):
            raise EvaluationReleaseError("release bindings must be a nonempty exact tuple")
        for item in self.bindings:
            item.__post_init__()
        order = tuple(
            sorted(
                self.bindings, key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest)
            )
        )
        if self.bindings != order or len({(item.key.arm_id, item.case_id_digest) for item in self.bindings}) != len(self.bindings):
            raise EvaluationReleaseError("release bindings must be unique and canonical")
        if type(self.review) is not IndependenceAttestation:
            raise EvaluationReleaseError("release review must use exact IndependenceAttestation")
        self.review.__post_init__()


def derive_admission_case_release_payload_digest_v3(value: AdmissionCaseReleaseV3) -> str:
    if type(value) is not AdmissionCaseReleaseV3:
        raise EvaluationReleaseError("release must use exact AdmissionCaseReleaseV3")
    value.__post_init__()
    return canonical.content_digest(_release_payload_value(value))


def derive_admission_case_release_digest_v3(value: AdmissionCaseReleaseV3) -> str:
    return canonical.content_digest(
        {"schema_version": _RELEASE_SCHEMA, "payload_digest": value.payload_digest, "review": _review_value(value.review)}
    )


def validate_admission_case_release_v3(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionCaseReleaseV3:
    """Revalidate one complete reviewed post-spend release before metric production."""
    from openultrasast.core._evaluation_release_validation import validate_release

    return validate_release(manifest, authority, preparation, receipt, spend, release, arm_cases, context, custody, resolver)


__all__ = [
    "AdmissionCaseReleaseV3",
    "ArmAdmissionCaseResultV3",
    "ArmAdmissionCasesV3",
    "EvaluationReleaseError",
    "ProofCandidateIdentityV3",
    "ReleasedArmCaseBindingV3",
    "derive_admission_case_release_digest_v3",
    "derive_admission_case_release_payload_digest_v3",
    "derive_released_arm_case_binding",
    "validate_admission_case_release_v3",
]
