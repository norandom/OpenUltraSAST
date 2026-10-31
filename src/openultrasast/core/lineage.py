"""Pure lineage contracts bound to authoritative population custody chains."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from openultrasast.core import canonical
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationStatus,
    PopulationUseReceipt,
    validate_population_custody_log,
)

LINEAGE_MANIFEST_SCHEMA = "openultrasast.detection-core.lineage-manifest.v2"
LINEAGE_DECISION_SCHEMA = "openultrasast.detection-core.lineage-decision.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class LineageValidationError(ValueError):
    """A lineage identity or custody join cannot be reproduced."""


def _require_digest(value: object, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise canonical.DigestFormatError(f"{field_name} must be a full lowercase SHA-256 digest")


def _require_text(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be nonempty text")


def _require_count(value: object, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a nonnegative integer")


@dataclass(frozen=True)
class LineageUse:
    purpose: LineagePurpose
    source_population_digest: str
    labels_accessed: bool
    influenced_artifact_digest: str
    population_use_receipt_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.purpose, LineagePurpose):
            raise TypeError("purpose must be a LineagePurpose")
        _require_digest(self.source_population_digest, "source_population_digest")
        if not isinstance(self.labels_accessed, bool):
            raise TypeError("labels_accessed must be boolean")
        _require_digest(self.influenced_artifact_digest, "influenced_artifact_digest")
        _require_digest(self.population_use_receipt_digest, "population_use_receipt_digest")


@dataclass(frozen=True)
class LineageManifest:
    arm_id: str
    subject_digest: str
    uses: tuple[LineageUse, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        _require_text(self.arm_id, "arm_id")
        _require_digest(self.subject_digest, "subject_digest")
        if not isinstance(self.uses, tuple) or not all(isinstance(use, LineageUse) for use in self.uses):
            raise TypeError("uses must be a tuple of LineageUse values")
        _require_digest(self.manifest_digest, "manifest_digest")


@dataclass(frozen=True)
class LineageExpectation:
    purpose: LineagePurpose
    influenced_artifact_digest: str
    minimum_uses: int
    maximum_uses: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.purpose, LineagePurpose):
            raise TypeError("purpose must be a LineagePurpose")
        _require_digest(self.influenced_artifact_digest, "influenced_artifact_digest")
        _require_count(self.minimum_uses, "minimum_uses")
        if self.maximum_uses is not None:
            _require_count(self.maximum_uses, "maximum_uses")
            if self.maximum_uses < self.minimum_uses:
                raise ValueError("maximum_uses must be at least minimum_uses")


@dataclass(frozen=True)
class LineageDecision:
    allowed: bool
    spent_population_digests: tuple[str, ...]
    reasons: tuple[str, ...]
    decision_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be boolean")
        if not isinstance(self.spent_population_digests, tuple):
            raise TypeError("spent_population_digests must be a tuple")
        for digest in self.spent_population_digests:
            _require_digest(digest, "spent_population_digest")
        if tuple(sorted(set(self.spent_population_digests))) != self.spent_population_digests:
            raise ValueError("spent_population_digests must be sorted and unique")
        if not isinstance(self.reasons, tuple) or not all(isinstance(reason, str) and reason for reason in self.reasons):
            raise TypeError("reasons must be a tuple of nonempty text")
        if tuple(sorted(set(self.reasons))) != self.reasons:
            raise ValueError("reasons must be sorted and unique")
        _require_digest(self.decision_digest, "decision_digest")


def _use_value(use: LineageUse) -> canonical.JsonValue:
    return {
        "purpose": use.purpose.value,
        "source_population_digest": use.source_population_digest,
        "labels_accessed": use.labels_accessed,
        "influenced_artifact_digest": use.influenced_artifact_digest,
        "population_use_receipt_digest": use.population_use_receipt_digest,
    }


def derive_lineage_manifest_digest(arm_id: str, subject_digest: str, uses: tuple[LineageUse, ...]) -> str:
    _require_text(arm_id, "arm_id")
    _require_digest(subject_digest, "subject_digest")
    return canonical.content_digest(
        {
            "schema_version": LINEAGE_MANIFEST_SCHEMA,
            "arm_id": arm_id,
            "subject_digest": subject_digest,
            "uses": tuple(_use_value(use) for use in uses),
        }
    )


def _decision_value(decision: LineageDecision) -> canonical.JsonValue:
    return {
        "schema_version": LINEAGE_DECISION_SCHEMA,
        "allowed": decision.allowed,
        "spent_population_digests": decision.spent_population_digests,
        "reasons": decision.reasons,
    }


def derive_lineage_decision_digest(decision: LineageDecision) -> str:
    return canonical.content_digest(_decision_value(decision))


def _validate_manifest(lineage: LineageManifest, expected_subject_digest: str) -> None:
    _require_digest(expected_subject_digest, "expected_subject_digest")
    expected = derive_lineage_manifest_digest(lineage.arm_id, lineage.subject_digest, lineage.uses)
    if lineage.manifest_digest != expected:
        raise LineageValidationError("lineage manifest digest cannot be re-derived")
    if lineage.subject_digest != expected_subject_digest:
        raise LineageValidationError("lineage subject does not match expected subject")
    receipt_digests = tuple(use.population_use_receipt_digest for use in lineage.uses)
    if len(set(receipt_digests)) != len(receipt_digests):
        raise LineageValidationError("duplicate lineage receipt")


def _expectation_index(
    expectations: tuple[LineageExpectation, ...],
) -> dict[tuple[LineagePurpose, str], LineageExpectation]:
    if not isinstance(expectations, tuple) or not all(isinstance(item, LineageExpectation) for item in expectations):
        raise TypeError("expectations must be a tuple of LineageExpectation values")
    indexed: dict[tuple[LineagePurpose, str], LineageExpectation] = {}
    for expectation in expectations:
        key = (expectation.purpose, expectation.influenced_artifact_digest)
        if key in indexed:
            raise LineageValidationError("duplicate lineage expectation")
        indexed[key] = expectation
    return indexed


def _receipt_for_use(
    use: LineageUse,
    arm_id: str,
    custody: PopulationCustodyPort,
    policy: PopulationCustodyPolicy,
) -> PopulationUseReceipt:
    log = custody.current_log(use.source_population_digest)
    validate_population_custody_log(log, policy, current=custody)
    matches = tuple(receipt for receipt in log.receipts if receipt.receipt_digest == use.population_use_receipt_digest)
    if len(matches) != 1:
        raise LineageValidationError("lineage receipt is absent from the current complete custody chain")
    receipt = matches[0]
    request = receipt.request
    if request.arm_id != arm_id:
        raise LineageValidationError("lineage arm does not match its current-chain receipt")
    if (
        request.population_digest != use.source_population_digest
        or request.purpose is not use.purpose
        or request.labels_accessed is not use.labels_accessed
        or request.influenced_artifact_digest != use.influenced_artifact_digest
    ):
        raise LineageValidationError("lineage use does not match its current-chain receipt")
    if use.labels_accessed and receipt.status is not PopulationStatus.SPENT:
        raise LineageValidationError("labelled lineage receipt did not spend its population")
    return receipt


def _count_reasons(
    uses: tuple[LineageUse, ...],
    expected: dict[tuple[LineagePurpose, str], LineageExpectation],
) -> list[str]:
    counts = {key: 0 for key in expected}
    reasons: list[str] = []
    for use in uses:
        key = (use.purpose, use.influenced_artifact_digest)
        if key not in expected:
            reasons.append(f"unexpected_use:{use.purpose.value}:{use.influenced_artifact_digest}")
        else:
            counts[key] += 1
    for key, expectation in expected.items():
        count = counts[key]
        label = f"{key[0].value}:{key[1]}"
        if count < expectation.minimum_uses:
            reasons.append(f"missing_required_use:{label}")
        if expectation.maximum_uses is not None and count > expectation.maximum_uses:
            reasons.append(f"too_many_uses:{label}")
    return reasons


def _decision(allowed: bool, spent: tuple[str, ...], reasons: tuple[str, ...]) -> LineageDecision:
    provisional = LineageDecision(allowed, spent, reasons, "0" * 64)
    return replace(provisional, decision_digest=derive_lineage_decision_digest(provisional))


def validate_lineage(
    lineage: LineageManifest,
    expected_subject_digest: str,
    expectations: tuple[LineageExpectation, ...],
    protected_population_digest: str | None,
    forbid_label_access: bool,
    custody: PopulationCustodyPort,
    policy: PopulationCustodyPolicy,
) -> LineageDecision:
    """Bind every lineage use to an exact expected artifact and current receipt."""
    _validate_manifest(lineage, expected_subject_digest)
    if protected_population_digest is not None:
        _require_digest(protected_population_digest, "protected_population_digest")
    if not isinstance(forbid_label_access, bool):
        raise TypeError("forbid_label_access must be boolean")
    expected = _expectation_index(expectations)
    reasons = _count_reasons(lineage.uses, expected)
    spent: set[str] = set()
    for use in lineage.uses:
        _receipt_for_use(use, lineage.arm_id, custody, policy)
        if use.labels_accessed:
            spent.add(use.source_population_digest)
            if forbid_label_access:
                reasons.append(f"label_access_forbidden:{use.source_population_digest}")
            if use.source_population_digest == protected_population_digest:
                reasons.append(f"protected_population_labels:{use.source_population_digest}")
    normalized_reasons = tuple(sorted(set(reasons)))
    return _decision(not normalized_reasons, tuple(sorted(spent)), normalized_reasons)


__all__ = [
    "LINEAGE_DECISION_SCHEMA",
    "LINEAGE_MANIFEST_SCHEMA",
    "LineageDecision",
    "LineageExpectation",
    "LineageManifest",
    "LineageUse",
    "LineageValidationError",
    "derive_lineage_decision_digest",
    "derive_lineage_manifest_digest",
    "validate_lineage",
]
