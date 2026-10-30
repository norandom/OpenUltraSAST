"""Admission manifest consumption for the access-control prover arm.

Task 12.5 of the access-control-prover specification (Reqs 12.1, 12.2, 12.3,
12.6, 12.8). The admission runner only CONSUMES manifests that valid-detection-benchmark
produces and reviews; it never produces, mutates or re-labels one.

Since detection-core task 4.1 this module is a thin compatibility wrapper: the
generalized, family-agnostic contract lives in ``openultrasast.core.admission``.
"""

from openultrasast.core.admission import (
    REPORT_SCHEMA_KEYS,
    AdmissionManifest,
    AdmissionManifestError,
    validate_admission_manifest,
)

__all__ = [
    "REPORT_SCHEMA_KEYS",
    "AdmissionManifest",
    "AdmissionManifestError",
    "validate_admission_manifest",
]
