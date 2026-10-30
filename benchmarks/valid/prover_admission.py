"""Admission manifest consumption for the access-control prover arm.

Task 12.5 of the access-control-prover specification (Reqs 12.1, 12.2, 12.3,
12.6, 12.8). The admission runner only CONSUMES manifests that valid-detection-benchmark
produces and reviews; it never produces, mutates or re-labels one. A manifest is
accepted only when it names the producing benchmark, carries review and
label-isolation attestations, exposes no admission labels, matches the frozen
acquisition digest and marks its population unspent.
"""

from dataclasses import dataclass

from openultrasast.tools.fact_init import FORBIDDEN_LABEL_MARKERS

__all__ = ["AdmissionManifest", "AdmissionManifestError", "validate_admission_manifest"]


class AdmissionManifestError(ValueError):
    """Raised when an admission manifest is refused; the message names the reason."""


@dataclass(frozen=True)
class AdmissionManifest:
    """A validated, immutable admission manifest (design.md run-manifest fields)."""

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


def _has_required_fields(payload: dict[str, object]) -> bool:
    return all(field in payload for field in _REQUIRED_FIELDS)


def validate_admission_manifest(payload: dict[str, object], *, expected_acquisition_digest: str | None = None) -> AdmissionManifest:
    """Validate an externally produced admission manifest and return it, or refuse.

    Refusal reasons, in check order: malformed, producer, unreviewed,
    label-isolated, label-exposure, acquisition-output-changed, spent.
    """
    if not _has_required_fields(payload):
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
    labels = tuple(str(label) for label in raw_labels)
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
        labels=labels,
    )
