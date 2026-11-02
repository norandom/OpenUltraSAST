"""Benchmark-owned guarded population custody for v2 admission."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from openultrasast.core import canonical
from openultrasast.core.admission_case import (
    ADMISSION_CASE_RELEASE_SCHEMA,
    AdmissionCaseRelease,
    AdmissionCaseResult,
    ReleasedCaseBinding,
    derive_admission_case_release_digest,
    derive_admission_case_release_payload_digest,
    derive_released_case_binding_digest,
    validate_admission_case_release,
)
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.admission_spend import (
    AdmissionPreparation,
    AdmissionSpendError,
    authorize_admission,
    validate_pre_label_spend,
)
from openultrasast.core.custody import (
    PopulationCustodyError,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationUseReceipt,
    append_population_use,
    record_population_use,
    validate_population_custody_log,
)
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.measurement import DenominatorPolicy
from openultrasast.core.readiness import ReadinessResult

ReleaseReview = Callable[[str, str], IndependenceAttestation]


class GuardedCustodyError(RuntimeError):
    """A guarded append or label release did not complete."""


class CompareAndSwapCustodyStore(Protocol):
    """Durable storage seam owned by the benchmark custodian."""

    def current_log(self, population_digest: str) -> PopulationCustodyLog: ...

    def compare_and_swap(self, expected_log_digest: str, replacement: PopulationCustodyLog) -> bool: ...


@dataclass(frozen=True)
class GuardedLabelRelease:
    receipt: PopulationUseReceipt
    labels: bytes


@dataclass(frozen=True)
class AdmissionSpendAuthority:
    manifest: AdmissionManifestV2
    denominator: DenominatorPolicy
    readiness: tuple[ReadinessResult, ...]
    context: AdmissionValidationContext
    resolver: canonical.ContentResolver


class GuardedPopulationCustodian:
    """Sole writer for one admission population."""

    def __init__(
        self,
        population_digest: str,
        custodian_identity: str,
        policy: PopulationCustodyPolicy,
        store: CompareAndSwapCustodyStore,
        background: PopulationCustodyPort,
    ) -> None:
        self.population_digest = population_digest
        self.custodian_identity = custodian_identity
        self.policy = policy
        self.store = store
        self.background = background

    def current_log(self, population_digest: str) -> PopulationCustodyLog:
        if population_digest == self.population_digest:
            return self.store.current_log(population_digest)
        return self.background.current_log(population_digest)

    def spend_and_release_labels(
        self,
        authority: AdmissionSpendAuthority,
        preparation: AdmissionPreparation,
        load_labels: Callable[[], bytes],
    ) -> GuardedLabelRelease:
        expected = self._authorize(authority)
        if preparation != expected:
            raise GuardedCustodyError("supplied preparation is not the authoritative core preparation")
        request = preparation.label_release_request
        if request.population_digest != self.population_digest:
            raise GuardedCustodyError("label-release request names another population")
        prior = self.store.current_log(self.population_digest)
        try:
            validate_population_custody_log(prior, self.policy)
            receipt = record_population_use(request, prior, self.custodian_identity, self.policy)
            replacement = append_population_use(prior, receipt, self.policy)
        except PopulationCustodyError as exc:
            raise GuardedCustodyError(f"custody successor refused: {exc}") from exc
        if not self.store.compare_and_swap(prior.log_digest, replacement):
            raise GuardedCustodyError("compare-and-swap lost the current custody head")
        committed = self.store.current_log(self.population_digest)
        validate_population_custody_log(committed, self.policy)
        if committed != replacement:
            raise GuardedCustodyError("durable custody append does not match the committed successor")
        self._validate_spend(authority, preparation, receipt)
        labels = load_labels()
        if type(labels) is not bytes or not labels:
            raise GuardedCustodyError("label release returned a zero-byte or invalid input")
        return GuardedLabelRelease(receipt, labels)

    def _authorize(self, authority: AdmissionSpendAuthority) -> AdmissionPreparation:
        try:
            return authorize_admission(
                authority.manifest,
                authority.denominator,
                authority.readiness,
                authority.context,
                self,
                authority.resolver,
            )
        except AdmissionSpendError as exc:
            raise GuardedCustodyError(f"admission preparation refused: {exc}") from exc

    def _validate_spend(
        self,
        authority: AdmissionSpendAuthority,
        preparation: AdmissionPreparation,
        receipt: PopulationUseReceipt,
    ) -> None:
        try:
            validate_pre_label_spend(
                authority.manifest,
                authority.denominator,
                authority.readiness,
                authority.context,
                preparation,
                receipt,
                self,
                authority.resolver,
            )
        except AdmissionSpendError as exc:
            raise GuardedCustodyError(f"committed admission spend refused: {exc}") from exc

    def release_cases(
        self,
        authority: AdmissionSpendAuthority,
        preparation: AdmissionPreparation,
        receipt: PopulationUseReceipt,
        cases: Sequence[AdmissionCaseResult],
        review_release: ReleaseReview,
    ) -> AdmissionCaseRelease:
        selected = tuple(cases)
        release = _build_release(
            authority.manifest,
            preparation,
            receipt,
            selected,
            review_release,
            self.custodian_identity,
        )
        return validate_admission_case_release(
            authority.manifest,
            authority.denominator,
            authority.readiness,
            authority.context,
            preparation,
            receipt,
            release,
            selected,
            self,
            authority.resolver,
        )


def _binding(case: AdmissionCaseResult) -> ReleasedCaseBinding:
    evidence = tuple(sorted(item.input_digest for item in case.evidence_inputs))
    changes = tuple(sorted({item.record.packet.provenance.change_input_digest for item in case.evidence_inputs}))
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
    return replace(draft, binding_digest=derive_released_case_binding_digest(draft))


def _build_release(
    manifest: AdmissionManifestV2,
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt,
    cases: tuple[AdmissionCaseResult, ...],
    review_release: ReleaseReview,
    custodian_identity: str,
) -> AdmissionCaseRelease:
    bindings = tuple(sorted((_binding(case) for case in cases), key=lambda item: item.case_id_digest))
    draft = AdmissionCaseRelease(
        ADMISSION_CASE_RELEASE_SCHEMA,
        manifest.identity.population_digest,
        manifest.manifest_digest,
        preparation.authorization.authorization_digest,
        preparation.preparation_digest,
        receipt.receipt_digest,
        custodian_identity,
        bindings,
        "0" * 64,
        manifest.review,
        "0" * 64,
    )
    payload = derive_admission_case_release_payload_digest(draft)
    review = review_release(payload, custodian_identity)
    if type(review) is not IndependenceAttestation:
        raise GuardedCustodyError("release reviewer returned an invalid attestation")
    reviewed = replace(draft, release_payload_digest=payload, review=review)
    return replace(reviewed, release_digest=derive_admission_case_release_digest(reviewed))


__all__ = [
    "AdmissionSpendAuthority",
    "CompareAndSwapCustodyStore",
    "GuardedCustodyError",
    "GuardedLabelRelease",
    "GuardedPopulationCustodian",
    "ReleaseReview",
]
