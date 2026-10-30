"""Admission contract tests for detection-core tasks 4.1-4.2 (Req 7, 10, 12)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.admission import (  # noqa: E402
    REPORT_SCHEMA_KEYS,
    AdmissionManifest,
    AdmissionManifestError,
    validate_admission_manifest,
)


def _payload(**over: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "produced_by": "valid-detection-benchmark",
        "reviewed": True,
        "label_isolated": True,
        "spent": False,
        "population_role": "admission",
        "analyzer_revision": "d063167",
        "fact_set_digest": "3eb5bf699434",
        "acquisition_record_digest": "none",
        "configuration_digest": "095b5a4905ad",
        "population_digest": "c866c0e812c0",
        "labels": [],
        "families": ["access_control"],
    }
    payload.update(over)
    return payload


def test_valid_manifest_accepted_with_family_scope() -> None:
    manifest = validate_admission_manifest(_payload())
    assert isinstance(manifest, AdmissionManifest)
    assert manifest.population_role == "admission"
    assert manifest.families == ("access_control",)


def test_refusal_order_is_deterministic() -> None:
    cases = [
        ({}, "malformed"),
        (_payload(produced_by="other"), "producer"),
        (_payload(reviewed=False), "unreviewed"),
        (_payload(label_isolated=False), "label-isolated"),
        (_payload(labels=["vulnerability"]), "label-exposure"),
        (_payload(spent=True), "spent"),
    ]
    for payload, reason in cases:
        try:
            validate_admission_manifest(payload)
            raise AssertionError(f"{reason} must be refused")
        except AdmissionManifestError as error:
            assert reason in str(error)


def test_acquisition_output_changed_refusal() -> None:
    try:
        validate_admission_manifest(_payload(), expected_acquisition_digest="different")
        raise AssertionError("acquisition mismatch must be refused")
    except AdmissionManifestError as error:
        assert "acquisition-output-changed" in str(error)


def test_report_schema_requires_family_scope_and_counts() -> None:
    for key in (
        "manifest",
        "families",
        "pairs",
        "fix_recall",
        "flagged_ordinary_per_100",
        "precision",
        "indeterminate_rate",
        "coverage",
        "runtime",
        "instrument_failures",
        "failed_gates",
        "decision",
    ):
        assert key in REPORT_SCHEMA_KEYS
