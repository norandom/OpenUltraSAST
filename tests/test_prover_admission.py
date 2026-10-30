"""Task 12.5 tests: consume and validate an externally reviewed admission manifest.

Reqs 12.1, 12.2, 12.3, 12.6, 12.8. Valid, malformed, exposed and spent fixture
manifests must produce deterministic accept/refuse results.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import prover_admission  # noqa: E402


def _manifest() -> dict[str, object]:
    return {
        "produced_by": "valid-detection-benchmark",
        "reviewed": True,
        "label_isolated": True,
        "spent": False,
        "population_role": "admission",
        "analyzer_revision": "a" * 40,
        "fact_set_digest": "b" * 12,
        "acquisition_record_digest": "c" * 12,
        "configuration_digest": "d" * 12,
        "population_digest": "e" * 12,
        "labels": (),
    }


def test_valid_manifest_is_accepted() -> None:
    manifest = prover_admission.validate_admission_manifest(_manifest())
    assert manifest.produced_by == "valid-detection-benchmark"
    assert manifest.reviewed is True
    assert manifest.label_isolated is True
    assert manifest.population_role == "admission"


def test_malformed_manifest_is_refused() -> None:
    payload = _manifest()
    del payload["reviewed"]
    with pytest.raises(prover_admission.AdmissionManifestError, match="malformed"):
        prover_admission.validate_admission_manifest(payload)


def test_unreviewed_manifest_is_refused() -> None:
    payload = _manifest()
    payload["reviewed"] = False
    with pytest.raises(prover_admission.AdmissionManifestError, match="unreviewed"):
        prover_admission.validate_admission_manifest(payload)


def test_label_exposing_manifest_is_refused() -> None:
    payload = _manifest()
    payload["labels"] = ("vulnerability:case-9",)
    with pytest.raises(prover_admission.AdmissionManifestError, match="label-exposure"):
        prover_admission.validate_admission_manifest(payload)


def test_not_label_isolated_manifest_is_refused() -> None:
    payload = _manifest()
    payload["label_isolated"] = False
    with pytest.raises(prover_admission.AdmissionManifestError, match="label-isolated"):
        prover_admission.validate_admission_manifest(payload)


def test_non_sequence_labels_are_refused() -> None:
    payload = _manifest()
    payload["labels"] = None
    with pytest.raises(prover_admission.AdmissionManifestError, match="label-exposure"):
        prover_admission.validate_admission_manifest(payload)


def test_changed_acquisition_output_is_refused() -> None:
    payload = _manifest()
    with pytest.raises(prover_admission.AdmissionManifestError, match="acquisition-output-changed"):
        prover_admission.validate_admission_manifest(payload, expected_acquisition_digest="f" * 12)


def test_matching_acquisition_digest_is_accepted() -> None:
    manifest = prover_admission.validate_admission_manifest(_manifest(), expected_acquisition_digest="c" * 12)
    assert manifest.acquisition_record_digest == "c" * 12


def test_spent_population_is_refused() -> None:
    payload = _manifest()
    payload["spent"] = True
    with pytest.raises(prover_admission.AdmissionManifestError, match="spent"):
        prover_admission.validate_admission_manifest(payload)


def test_validation_is_deterministic() -> None:
    first = prover_admission.validate_admission_manifest(_manifest())
    second = prover_admission.validate_admission_manifest(copy.deepcopy(_manifest()))
    assert first == second


def test_admission_manifest_is_frozen() -> None:
    manifest = prover_admission.validate_admission_manifest(_manifest())
    with pytest.raises(Exception):  # noqa: B017
        manifest.reviewed = False  # type: ignore[misc]


def test_non_benchmark_producer_is_refused() -> None:
    payload = _manifest()
    payload["produced_by"] = "someone-else"
    with pytest.raises(prover_admission.AdmissionManifestError, match="producer"):
        prover_admission.validate_admission_manifest(payload)
