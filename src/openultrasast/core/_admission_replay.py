"""Immutable transport identity for authoritative admission replay inputs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from openultrasast.core import canonical
from openultrasast.core.admission_case import (
    AdmissionCaseRelease,
    AdmissionCaseResult,
    derive_admission_case_release_digest,
    derive_admission_case_result_digest,
)
from openultrasast.core.admission_review import AdmissionManifestV2, derive_manifest_digest
from openultrasast.core.admission_spend import AdmissionPreparation, derive_admission_preparation_digest
from openultrasast.core.custody import (
    PopulationUseReceipt,
    derive_population_use_receipt_digest,
)
from openultrasast.core.measurement import DenominatorPolicy, derive_denominator_policy_digest
from openultrasast.core.readiness import ReadinessResult, validate_readiness_result

if TYPE_CHECKING:
    from openultrasast.core.admission_report import AdmissionReportV2

ADMISSION_REPLAY_SCHEMA = "openultrasast.detection-core.admission-replay.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AdmissionReplay:
    manifest: AdmissionManifestV2
    denominator: DenominatorPolicy
    readiness: tuple[ReadinessResult, ...]
    preparation: AdmissionPreparation
    label_release_receipt: PopulationUseReceipt
    case_release: AdmissionCaseRelease
    cases: tuple[AdmissionCaseResult, ...]
    report: AdmissionReportV2
    replay_digest: str

    def __post_init__(self) -> None:
        validate_admission_replay_structure(self)


def _replay_value(value: AdmissionReplay) -> canonical.JsonValue:
    manifest_digest = derive_manifest_digest(value.manifest)
    denominator_digest = derive_denominator_policy_digest(value.denominator)
    preparation_digest = derive_admission_preparation_digest(value.preparation)
    receipt_digest = derive_population_use_receipt_digest(value.label_release_receipt)
    release_digest = derive_admission_case_release_digest(value.case_release)
    for item in value.readiness:
        validate_readiness_result(item)
    case_digests = tuple(derive_admission_case_result_digest(item) for item in value.cases)
    claimed = (
        value.manifest.manifest_digest,
        value.denominator.policy_digest,
        value.preparation.preparation_digest,
        value.label_release_receipt.receipt_digest,
        value.case_release.release_digest,
        tuple(item.result_digest for item in value.cases),
    )
    derived = (manifest_digest, denominator_digest, preparation_digest, receipt_digest, release_digest, case_digests)
    if claimed != derived:
        raise ValueError("replay component identity cannot be re-derived")
    return {
        "schema_version": ADMISSION_REPLAY_SCHEMA,
        "manifest_digest": manifest_digest,
        "denominator_policy_digest": denominator_digest,
        "readiness_result_digests": tuple(item.result_digest for item in value.readiness),
        "preparation_digest": preparation_digest,
        "label_release_receipt_digest": receipt_digest,
        "case_release_digest": release_digest,
        "case_result_digests": case_digests,
        "report_digest": value.report.report_digest,
    }


def _validate_components(value: AdmissionReplay) -> None:
    exact_components = (
        (value.manifest, AdmissionManifestV2, "manifest"),
        (value.denominator, DenominatorPolicy, "denominator"),
        (value.preparation, AdmissionPreparation, "preparation"),
        (value.label_release_receipt, PopulationUseReceipt, "label release receipt"),
        (value.case_release, AdmissionCaseRelease, "case release"),
    )
    for item, expected, field in exact_components:
        if type(item) is not expected:
            raise ValueError(f"replay {field} must use the exact contract type")
    if not all(type(item) is ReadinessResult for item in value.readiness):
        raise ValueError("replay readiness must contain exact ReadinessResult values")
    if not all(type(item) is AdmissionCaseResult for item in value.cases):
        raise ValueError("replay cases must contain exact AdmissionCaseResult values")
    case_ids = tuple(item.case_id_digest for item in value.cases)
    if case_ids != tuple(sorted(set(case_ids))):
        raise ValueError("replay cases must use unique canonical case identity order")


def validate_admission_replay_structure(value: AdmissionReplay) -> None:
    from openultrasast.core.admission_report import AdmissionReportError, AdmissionReportV2, _validate_report_structure

    if type(value) is not AdmissionReplay:
        raise AdmissionReportError("replay must be an exact AdmissionReplay")
    if type(value.readiness) is not tuple or not value.readiness:
        raise AdmissionReportError("replay readiness must be an exact nonempty tuple")
    if type(value.cases) is not tuple or not value.cases:
        raise AdmissionReportError("replay cases must be an exact nonempty tuple")
    try:
        _validate_components(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AdmissionReportError(str(exc)) from exc
    if type(value.report) is not AdmissionReportV2:
        raise AdmissionReportError("replay report must be an exact AdmissionReportV2")
    _validate_report_structure(value.report)
    if not isinstance(value.replay_digest, str) or _DIGEST.fullmatch(value.replay_digest) is None:
        raise AdmissionReportError("replay digest must be a full lowercase SHA-256 digest")
    try:
        expected = canonical.content_digest(_replay_value(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AdmissionReportError(str(exc)) from exc
    if value.replay_digest != expected:
        raise AdmissionReportError("replay digest does not match authoritative input identities")


def admission_replay_value(value: AdmissionReplay) -> canonical.JsonValue:
    validate_admission_replay_structure(value)
    return _replay_value(value)


__all__ = [
    "ADMISSION_REPLAY_SCHEMA",
    "AdmissionReplay",
    "admission_replay_value",
]
