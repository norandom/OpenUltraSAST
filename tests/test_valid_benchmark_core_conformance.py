"""Benchmark-only conformance gate for the validated core V3 predecessor."""

from __future__ import annotations

import json
import sys
import tomllib
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_core_evaluation_end_to_end import _assert_conformance, _complete_replay

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid.core_conformance import (
    ScopedAdmissionV3ConformanceError,
    decode_scoped_admission_v3,
    require_scoped_admission_v3,
    validate_scoped_admission_replay,
)
from openultrasast.core import evaluation_admission

REPO = Path(__file__).resolve().parents[1]
V2_REPORT_SCHEMA = "openultrasast.detection-core.admission-report.v2"
V3_SCHEMA = "openultrasast.detection-core.evaluation-admission.v3"
FROZEN_HISTORY = {
    "benchmarks/valid/pilot/freeze-valid.json": "fc6c97a034a6e2828bc003d72a2ab03445a18a3f64387310f26c7cd3ae9bf6ba",
    "benchmarks/valid/pilot/pool-valid.toml": "48765c7703c6465f0f7fc00df81c07618b52065ed637cf97c112fdea98896c3f",
    "tests/fixtures/detection_core/admission_v2/go_replay.json": "16dfa63087ac7ef11404196df1766961c16a3f0f148e743251df191a8070f7be",
    "tests/fixtures/detection_core/admission_v2/go_report.json": "bf5d839c9c29f22db4a54ce2bbfff986315bf910248ea1a28ac64de0660ac59f",
    "tests/fixtures/detection_core/admission_v2/manifest.json": "c470ccd0d27eaf98de1ac50846c2281d2ec777a96def4211e92051b158317b2b",
    "tests/fixtures/detection_core/admission_v2/no_go_replay.json": "a385eee59970fba07d615172524c90038997911f3bd302e56bb23be029e50e6e",
    "tests/fixtures/detection_core/admission_v2/no_go_report.json": "3c0d8698bb72157de384fa1ad63c4c1b5bafbd1001235e416aaeced9cb5da8b7",
    "tests/fixtures/detection_core/admission_v2/validation_failures.json": (
        "c80a1214c59c26e25db0978c85ce07ced9642baf9dc57ef0a5f0f1504f11c49f"
    ),
    "tests/fixtures/detection_core/admission_v2/zero_model_replay.json": "c17ab6fc00c5aea7e981a07dbb28aaa9b3da399429948029aaeb1f67eebecfd9",
    "tests/fixtures/detection_core/admission_v2/zero_model_report.json": "336f07de37ec15eeaffb6711ce398762c6091d49b7993fd7a38f7cdebf33f85c",
}


def _read_frozen_history() -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    for relative, expected_digest in FROZEN_HISTORY.items():
        path = REPO / relative
        assert path.is_file(), f"historical fixture is missing: {relative}"
        content = path.read_bytes()
        assert len(content) > 0, f"historical fixture read zero bytes: {relative}"
        assert sha256(content).hexdigest() == expected_digest
        contents[relative] = content
    return contents


def test_shipped_facade_satisfies_pinned_v3_startup_contract() -> None:
    capability = require_scoped_admission_v3()

    assert capability.schema == V3_SCHEMA
    assert capability.operations == (
        "authorize_evaluation",
        "decode_evaluation_v3",
        "preflight_evaluation",
        "score_and_replay",
        "validate_evaluation_replay",
        "validate_shared_spend",
    )


def test_startup_refuses_missing_schema_export() -> None:
    values = {name: getattr(evaluation_admission, name) for name in evaluation_admission.__all__}
    values["__all__"] = tuple(name for name in evaluation_admission.__all__ if name != "EVALUATION_ADMISSION_V3_SCHEMA")
    values.pop("EVALUATION_ADMISSION_V3_SCHEMA")

    with pytest.raises(ScopedAdmissionV3ConformanceError, match="missing"):
        require_scoped_admission_v3(SimpleNamespace(**values))


def test_startup_refuses_absent_required_capability() -> None:
    values = {name: getattr(evaluation_admission, name) for name in evaluation_admission.__all__}
    values["__all__"] = tuple(evaluation_admission.__all__)
    values["score_and_replay"] = None

    with pytest.raises(ScopedAdmissionV3ConformanceError, match="required callable capabilities are missing"):
        require_scoped_admission_v3(SimpleNamespace(**values))


def test_startup_refuses_changed_schema() -> None:
    values = {name: getattr(evaluation_admission, name) for name in evaluation_admission.__all__}
    values["__all__"] = tuple(evaluation_admission.__all__)
    values["EVALUATION_ADMISSION_V3_SCHEMA"] = "openultrasast.detection-core.evaluation-admission.v4"

    with pytest.raises(ScopedAdmissionV3ConformanceError, match="schema"):
        require_scoped_admission_v3(SimpleNamespace(**values))


def test_complete_v3_replay_validates_through_benchmark_consumer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, replay, *_, scopes = _complete_replay(monkeypatch)

    decoded = decode_scoped_admission_v3(V3_SCHEMA, replay, type(replay))
    reports = validate_scoped_admission_replay(
        replay,
        bundle[5][0].context,
        bundle[5][0].port,
        bundle[4],
    )

    assert decoded is replay
    assert reports == replay.reports
    _assert_conformance(bundle, replay, scopes)


def test_history_is_nonzero_readable_frozen_and_never_inferred_as_v3() -> None:
    before = _read_frozen_history()
    report = json.loads(before["tests/fixtures/detection_core/admission_v2/go_report.json"])
    freeze = json.loads(before["benchmarks/valid/pilot/freeze-valid.json"])
    pool = tomllib.loads(before["benchmarks/valid/pilot/pool-valid.toml"].decode())

    assert report["schema_version"] == V2_REPORT_SCHEMA
    assert freeze["freeze_digest"]
    assert pool["status"] == "frozen"
    with pytest.raises(evaluation_admission.EvaluationAdmissionV3Error, match="schema|contract|refused"):
        decode_scoped_admission_v3(V2_REPORT_SCHEMA, report, object)
    with pytest.raises(evaluation_admission.EvaluationAdmissionV3Error, match="contract|refused"):
        decode_scoped_admission_v3(V3_SCHEMA, report, object)
    with pytest.raises(evaluation_admission.EvaluationAdmissionV3Error, match="schema|contract|refused"):
        decode_scoped_admission_v3("unknown-evaluation-root", report, object)
    with pytest.raises(evaluation_admission.EvaluationAdmissionV3Error, match="contract|refused"):
        decode_scoped_admission_v3(V3_SCHEMA, {"schema_version": V3_SCHEMA}, object)

    assert _read_frozen_history() == before
