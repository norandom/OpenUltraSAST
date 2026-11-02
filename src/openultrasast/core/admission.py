"""Temporary explicit import shim for the pre-v2 admission contract."""

from openultrasast.core.legacy_v1.contracts import (
    REPORT_SCHEMA_KEYS,
    AdmissionManifest,
    AdmissionManifestError,
    validate_admission_manifest,
    validate_report_schema,
)

__all__ = [
    "REPORT_SCHEMA_KEYS",
    "AdmissionManifest",
    "AdmissionManifestError",
    "validate_admission_manifest",
    "validate_report_schema",
]
