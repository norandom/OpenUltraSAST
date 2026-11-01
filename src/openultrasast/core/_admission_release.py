"""Validation helpers for authenticated post-spend admission-case releases."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from openultrasast.core import canonical
from openultrasast.core.admission_case import (
    ADMISSION_CASE_RELEASE_SCHEMA,
    AdmissionCaseRelease,
    AdmissionCaseReleaseError,
    AdmissionCaseResult,
    AdmissionCaseRole,
    ReleasedCaseBinding,
    derive_admission_case_release_digest,
    derive_admission_case_release_payload_digest,
    derive_admission_case_result_digest,
    derive_released_case_binding_digest,
    validate_admission_case_shape,
)
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.admission_spend import AdmissionAuthorization, AdmissionPreparation
from openultrasast.core.coverage import derive_input_manifest_digest, validate_instrument
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.measurement import ScopeKey
from openultrasast.core.provenance import ProvenanceInputRole
from openultrasast.core.validation import derive_evidence_validation_input_digest, validate_evidence_input

_DIGEST = re.compile(r"[0-9a-f]{64}")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionCaseReleaseError(f"{field} must be a full lowercase SHA-256 digest")


def _digest_tuple(value: object, field: str, *, nonempty: bool = True) -> None:
    if type(value) is not tuple or (nonempty and not value):
        raise AdmissionCaseReleaseError(f"{field} must be a{' nonempty' if nonempty else ''} exact tuple")
    for item in value:
        _digest(item, field)
    if value != tuple(sorted(set(value))):
        raise AdmissionCaseReleaseError(f"{field} must be unique and canonically ordered")


def _validate_policy(policy: ReviewIndependencePolicy) -> None:
    try:
        policy.__post_init__()
    except FactPackValidationError as exc:
        raise AdmissionCaseReleaseError(f"release review policy is invalid: {exc}") from exc
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise AdmissionCaseReleaseError("release review policy digest cannot be re-derived")


def _validate_review(
    release: AdmissionCaseRelease,
    receipt: PopulationUseReceipt,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    review = release.review
    if type(review) is not IndependenceAttestation:
        raise AdmissionCaseReleaseError("release review must be an exact independence attestation")
    try:
        review.__post_init__()
        review.conflict_disclosure.__post_init__()
    except (FactPackValidationError, ValueError) as exc:
        raise AdmissionCaseReleaseError(f"release review is invalid: {exc}") from exc
    if review.subject_digest != release.release_payload_digest:
        raise AdmissionCaseReleaseError("release review subject does not match payload digest")
    if review.producer_identity != release.custodian_identity or review.producer_identity != receipt.custodian_identity:
        raise AdmissionCaseReleaseError("release review producer must be the exact spend custodian")
    if review.producer_identity == review.reviewer_identity:
        raise AdmissionCaseReleaseError("release review producer and reviewer must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise AdmissionCaseReleaseError("release reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise AdmissionCaseReleaseError("release producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise AdmissionCaseReleaseError("release review attestation digest cannot be re-derived")
    content = canonical.resolve_content(
        review.conflict_disclosure,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_evidence_bytes,
    )
    if not content:
        raise AdmissionCaseReleaseError("release conflict disclosure must be nonempty")


def _validate_binding_shape(binding: ReleasedCaseBinding) -> None:
    if type(binding) is not ReleasedCaseBinding:
        raise AdmissionCaseReleaseError("release binding must use the exact contract type")
    if type(binding.scope) is not ScopeKey or type(binding.role) is not AdmissionCaseRole:
        raise AdmissionCaseReleaseError("release binding scope and role must use exact contract types")
    binding.scope.__post_init__()
    for value, field in (
        (binding.case_id_digest, "case identity digest"),
        (binding.case_result_digest, "case result digest"),
        (binding.input_manifest_digest, "input manifest digest"),
        (binding.binding_digest, "binding digest"),
    ):
        _digest(value, field)
    if binding.role is AdmissionCaseRole.ORDINARY:
        if binding.pair_id_digest is not None:
            raise AdmissionCaseReleaseError("ordinary release binding cannot carry a pair identity")
    else:
        _digest(binding.pair_id_digest, "pair identity digest")
    _digest_tuple(binding.evidence_input_digests, "evidence input digests")
    _digest_tuple(binding.change_input_digests, "change input digests")
    if binding.binding_digest != derive_released_case_binding_digest(binding):
        raise AdmissionCaseReleaseError("release binding digest cannot be re-derived")


def _validate_pair_integrity(bindings: tuple[ReleasedCaseBinding, ...]) -> None:
    pairs: dict[tuple[str, str, str], Counter[AdmissionCaseRole]] = {}
    for binding in bindings:
        if binding.pair_id_digest is None:
            continue
        key = (binding.scope.family_id, binding.scope.ecosystem, binding.pair_id_digest)
        pairs.setdefault(key, Counter())[binding.role] += 1
    expected = Counter({AdmissionCaseRole.VULNERABLE: 1, AdmissionCaseRole.FIXED: 1})
    if any(counts != expected for counts in pairs.values()):
        raise AdmissionCaseReleaseError("every scoped release pair must contain one vulnerable and one fixed case")


def _validate_release_shape(release: AdmissionCaseRelease) -> None:
    if type(release) is not AdmissionCaseRelease or release.schema_version != ADMISSION_CASE_RELEASE_SCHEMA:
        raise AdmissionCaseReleaseError("unknown or substituted admission case-release schema")
    for value, field in (
        (release.population_digest, "population digest"),
        (release.manifest_digest, "manifest digest"),
        (release.authorization_digest, "authorization digest"),
        (release.preparation_digest, "preparation digest"),
        (release.label_release_receipt_digest, "label release receipt digest"),
        (release.custodian_identity, "custodian identity"),
        (release.release_payload_digest, "release payload digest"),
        (release.release_digest, "release digest"),
    ):
        _digest(value, field)
    if type(release.bindings) is not tuple or not release.bindings:
        raise AdmissionCaseReleaseError("release bindings must be a nonempty exact tuple")
    for binding in release.bindings:
        _validate_binding_shape(binding)
    case_ids = tuple(item.case_id_digest for item in release.bindings)
    if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
        raise AdmissionCaseReleaseError("release bindings must have unique canonical case identities")
    _validate_pair_integrity(release.bindings)
    if release.release_payload_digest != derive_admission_case_release_payload_digest(release):
        raise AdmissionCaseReleaseError("release payload digest cannot be re-derived")
    if release.release_digest != derive_admission_case_release_digest(release):
        raise AdmissionCaseReleaseError("release digest cannot be re-derived")


def _validate_header(
    manifest: AdmissionManifestV2,
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt,
    authorization: AdmissionAuthorization,
    release: AdmissionCaseRelease,
) -> None:
    expected = (
        manifest.identity.population_digest,
        manifest.manifest_digest,
        authorization.authorization_digest,
        preparation.preparation_digest,
        receipt.receipt_digest,
        receipt.custodian_identity,
    )
    actual = (
        release.population_digest,
        release.manifest_digest,
        release.authorization_digest,
        release.preparation_digest,
        release.label_release_receipt_digest,
        release.custodian_identity,
    )
    if actual != expected:
        fields = (
            "population digest",
            "manifest digest",
            "authorization digest",
            "preparation digest",
            "label release receipt digest",
            "custodian",
        )
        changed = next(field for field, left, right in zip(fields, actual, expected, strict=True) if left != right)
        raise AdmissionCaseReleaseError(f"release {changed} does not match the exact spent admission")


def _validated_case_inputs(
    case: AdmissionCaseResult,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    evidence: list[str] = []
    changes: set[str] = set()
    for value in case.evidence_inputs:
        if value.input_digest != derive_evidence_validation_input_digest(value):
            raise AdmissionCaseReleaseError("case evidence input digest cannot be re-derived")
        validate_evidence_input(value, context.evidence, custody, resolver)
        evidence.append(value.input_digest)
        matches = tuple(item.identity for item in value.named_inputs.inputs if item.role is ProvenanceInputRole.CHANGE_INPUT)
        if len(matches) != 1 or matches[0] != value.record.packet.provenance.change_input_digest:
            raise AdmissionCaseReleaseError("case change input cannot be re-derived from validated provenance")
        changes.add(matches[0])
    ordered_evidence = tuple(sorted(evidence))
    ordered_changes = tuple(sorted(changes))
    _digest_tuple(ordered_evidence, "case evidence input digests")
    _digest_tuple(ordered_changes, "case change input digests")
    return ordered_evidence, ordered_changes


def _binding_for_case(
    case: AdmissionCaseResult,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> ReleasedCaseBinding:
    validate_admission_case_shape(case)
    expected_manifest = derive_input_manifest_digest(case.input_manifest.tracked_input_ids)
    if case.input_manifest.manifest_digest != expected_manifest:
        raise AdmissionCaseReleaseError("case input manifest digest cannot be re-derived")
    validate_instrument(case.input_manifest, case.input_receipts)
    if case.result_digest != derive_admission_case_result_digest(case):
        raise AdmissionCaseReleaseError("case result digest cannot be re-derived")
    evidence, changes = _validated_case_inputs(case, context, custody, resolver)
    draft = ReleasedCaseBinding(
        case.case_id_digest,
        case.scope,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        evidence,
        changes,
        case.input_manifest.manifest_digest,
        "0" * 64,
    )
    return draft


def _canonical_binding(
    case: AdmissionCaseResult,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> ReleasedCaseBinding:
    draft = _binding_for_case(case, context, custody, resolver)
    return ReleasedCaseBinding(
        draft.case_id_digest,
        draft.scope,
        draft.role,
        draft.pair_id_digest,
        draft.case_result_digest,
        draft.evidence_input_digests,
        draft.change_input_digests,
        draft.input_manifest_digest,
        derive_released_case_binding_digest(draft),
    )


def validate_case_bindings(
    release: AdmissionCaseRelease,
    cases: Sequence[AdmissionCaseResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    selected = tuple(cases)
    if not selected:
        raise AdmissionCaseReleaseError("case population must be nonempty")
    case_ids = tuple(case.case_id_digest for case in selected)
    if len(case_ids) != len(set(case_ids)):
        raise AdmissionCaseReleaseError("case population contains duplicate identities")
    expected = tuple(
        sorted(
            (_canonical_binding(case, context, custody, resolver) for case in selected),
            key=lambda item: item.case_id_digest,
        )
    )
    if release.bindings != expected:
        raise AdmissionCaseReleaseError("authenticated release binding does not match the exact case population")
