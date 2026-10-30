"""Admission contract for the detection core (Req 7, 10, 12).

Family-agnostic generalization of the prover's consume-only manifest validation:
only manifests produced and reviewed by the benchmark workflow are consumed, never
produced, mutated or re-labeled here. Refusal order is fixed and deterministic.
Reports must carry the claimed families so numbers are never read across families
the arm does not cover.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openultrasast.tools.fact_init import FORBIDDEN_LABEL_MARKERS


class AdmissionManifestError(ValueError):
    """Raised when an admission manifest is refused; the message names the reason."""


@dataclass(frozen=True)
class AdmissionManifest:
    """A validated, immutable admission manifest with its claimed families."""

    produced_by: str
    reviewed: bool
    label_isolated: bool
    spent: bool
    population_role: str
    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    population_digest: str
    labels: tuple[str, ...]
    families: tuple[str, ...] = ()


_REQUIRED_FIELDS = (
    "produced_by",
    "reviewed",
    "label_isolated",
    "spent",
    "population_role",
    "analyzer_revision",
    "fact_set_digest",
    "acquisition_record_digest",
    "configuration_digest",
    "population_digest",
    "labels",
)

_BENCHMARK_PRODUCER = "valid-detection-benchmark"

# The fixed report schema every admission report must carry (Req 7.3, 10.2, 12.1).
REPORT_SCHEMA_KEYS = frozenset(
    {
        "manifest",
        "families",
        "pairs",
        "pair_correctness",
        "fix_recall",
        "verified_location_recall",
        "flagged_ordinary_per_100",
        "precision",
        "indeterminate_rate",
        "coverage",
        "runtime",
        "instrument_failures",
        "failed_gates",
        "decision",
    }
)


def validate_admission_manifest(payload: dict[str, object], *, expected_acquisition_digest: str | None = None) -> AdmissionManifest:
    """Validate an externally produced admission manifest and return it, or refuse.

    Refusal reasons, in check order: malformed, producer, unreviewed,
    label-isolated, label-exposure, acquisition-output-changed, spent.
    """
    if not all(field in payload for field in _REQUIRED_FIELDS):
        raise AdmissionManifestError("malformed: missing required manifest fields")
    if payload["produced_by"] != _BENCHMARK_PRODUCER:
        raise AdmissionManifestError(f"producer: only {_BENCHMARK_PRODUCER} manifests are consumed")
    if payload["reviewed"] is not True:
        raise AdmissionManifestError("unreviewed: manifest lacks external review")
    if payload["label_isolated"] is not True:
        raise AdmissionManifestError("label-isolated: isolation attestation missing")
    raw_labels = payload["labels"]
    if not isinstance(raw_labels, (tuple, list)) or any(marker in str(label) for label in raw_labels for marker in FORBIDDEN_LABEL_MARKERS):
        raise AdmissionManifestError("label-exposure: manifest carries admission labels")
    if expected_acquisition_digest is not None and payload["acquisition_record_digest"] != expected_acquisition_digest:
        raise AdmissionManifestError("acquisition-output-changed: digest mismatch")
    if payload["spent"] is True:
        raise AdmissionManifestError("spent: population already consumed")
    raw_families = payload.get("families", ())
    if not isinstance(raw_families, (tuple, list)):
        raise AdmissionManifestError("malformed: families must be a sequence")
    return AdmissionManifest(
        produced_by=str(payload["produced_by"]),
        reviewed=True,
        label_isolated=True,
        spent=False,
        population_role=str(payload["population_role"]),
        analyzer_revision=str(payload["analyzer_revision"]),
        fact_set_digest=str(payload["fact_set_digest"]),
        acquisition_record_digest=str(payload["acquisition_record_digest"]),
        configuration_digest=str(payload["configuration_digest"]),
        population_digest=str(payload["population_digest"]),
        labels=tuple(str(label) for label in raw_labels),
        families=tuple(str(family) for family in raw_families),
    )


def validate_report_schema(report: dict[str, Any]) -> None:
    """Refuse an admission report missing any fixed-schema key (Req 12.1)."""
    missing = sorted(REPORT_SCHEMA_KEYS - set(report))
    if missing:
        raise AdmissionManifestError(f"report schema: missing keys {missing}")
    for rate_key in (
        "pair_correctness",
        "fix_recall",
        "verified_location_recall",
        "flagged_ordinary_per_100",
        "precision",
        "indeterminate_rate",
    ):
        rate = report[rate_key]
        if not {"n", "count", "rate", "wilson95"} <= set(rate):
            raise AdmissionManifestError(f"report schema: {rate_key} lacks n/count/rate/wilson95")


__all__ = [
    "REPORT_SCHEMA_KEYS",
    "AdmissionManifest",
    "AdmissionManifestError",
    "validate_admission_manifest",
    "validate_report_schema",
]
