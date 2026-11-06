"""Frozen compatibility evidence for the V2 admission aggregate."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from test_core_admission_report import (
    _failed_quality_bundle,
    _rehashed,
    _rehashed_replay,
    _score_bundle,
    _ScoredAdmission,
    _setup,
    _validate_authoritatively,
    _without_models,
)

from openultrasast.core import canonical
from openultrasast.core.admission_report import (
    AdmissionDecision,
    AdmissionReportError,
    admission_replay_value,
    admission_report_value,
    validate_admission_replay,
)

FIXTURES = Path(__file__).parent / "fixtures/detection_core/admission_v2"


@pytest.fixture(scope="module")
def scored_cases() -> dict[str, _ScoredAdmission]:
    return {
        "go": _score_bundle(_without_models(_setup())),
        "no_go": _failed_quality_bundle(),
        "zero_model": _score_bundle(_setup()),
    }


def _read_nonzero(name: str) -> bytes:
    path = FIXTURES / name
    assert path.is_file(), f"compatibility fixture is missing: {path.relative_to(Path(__file__).parents[1])}"
    content = path.read_bytes()
    assert content, f"compatibility fixture read zero bytes: {path.relative_to(Path(__file__).parents[1])}"
    return content


def _manifest() -> dict[str, object]:
    return json.loads(_read_nonzero("manifest.json"))


def _read_canonical(name: str) -> bytes:
    content = _read_nonzero(name)
    assert content.endswith(b"\n"), f"compatibility fixture lacks its single storage newline: {name}"
    payload = content[:-1]
    assert payload and not payload.endswith(b"\n"), f"compatibility fixture has a non-canonical storage layout: {name}"
    return payload


def _capture_failure(name: str, operation: Callable[[], object]) -> dict[str, str]:
    try:
        operation()
    except AdmissionReportError as exc:
        return {"name": name, "exception": type(exc).__name__, "message": str(exc)}
    pytest.fail(f"V2 compatibility mutation did not fail: {name}")


def _validation_failures(scored: _ScoredAdmission) -> tuple[dict[str, str], ...]:
    return (
        _capture_failure(
            "raw_report",
            lambda: validate_admission_replay(scored.report, scored.setup.context, scored.setup.custody, scored.setup.resolver),  # type: ignore[arg-type]
        ),
        _capture_failure(
            "replay_digest",
            lambda: replace(scored.replay, replay_digest=canonical.content_digest("forged-replay")),
        ),
        _capture_failure(
            "decision",
            lambda: replace(scored.report, decision=AdmissionDecision.NO_GO, report_digest="0" * 64),
        ),
        _capture_failure(
            "report_digest",
            lambda: replace(scored.report, report_digest=canonical.content_digest("forged-report")),
        ),
        _capture_failure(
            "readiness_order",
            lambda: _validate_authoritatively(
                _rehashed_replay(scored.replay, readiness=tuple(reversed(scored.readiness))),
                scored,
            ),
        ),
        _capture_failure(
            "authoritative_report",
            lambda: _validate_authoritatively(
                _rehashed_replay(
                    scored.replay,
                    report=_rehashed(scored.report, census_digest=canonical.content_digest("other-census")),
                ),
                scored,
            ),
        ),
    )


def test_v2_report_and_replay_bytes_digests_decisions_are_frozen(
    scored_cases: dict[str, _ScoredAdmission],
) -> None:
    manifest = _manifest()
    assert manifest["schema_version"] == "openultrasast.detection-core.admission-v2-compatibility-fixtures.v1"
    rows = manifest["cases"]
    assert isinstance(rows, list)
    assert tuple(row["name"] for row in rows) == ("go", "no_go", "zero_model")

    for row in rows:
        scored = scored_cases[row["name"]]
        report_bytes = canonical.canonical_bytes(admission_report_value(scored.report))
        replay_bytes = canonical.canonical_bytes(admission_replay_value(scored.replay))
        expected_report = _read_canonical(row["report_file"])
        expected_replay = _read_canonical(row["replay_file"])

        assert report_bytes == expected_report
        assert replay_bytes == expected_replay
        assert json.loads(expected_report)["schema_version"] == "openultrasast.detection-core.admission-report.v2"
        assert json.loads(expected_replay)["schema_version"] == "openultrasast.detection-core.admission-replay.v2"
        assert len(expected_report) == row["report_bytes"]
        assert len(expected_replay) == row["replay_bytes"]
        assert sha256(expected_report).hexdigest() == row["report_sha256"]
        assert sha256(expected_replay).hexdigest() == row["replay_sha256"]
        assert scored.report.report_digest == row["report_digest"]
        assert scored.replay.replay_digest == row["replay_digest"]
        assert scored.report.decision.value == row["decision"]
        assert (
            validate_admission_replay(
                scored.replay,
                scored.setup.context,
                scored.setup.custody,
                scored.setup.resolver,
            )
            == scored.report
        )


def test_v2_compatibility_detects_byte_digest_and_decision_mutations(
    scored_cases: dict[str, _ScoredAdmission],
) -> None:
    manifest = _manifest()
    rows = manifest["cases"]
    assert isinstance(rows, list)

    for row in rows:
        scored = scored_cases[row["name"]]
        frozen_outputs = (
            ("report", canonical.canonical_bytes(admission_report_value(scored.report))),
            ("replay", canonical.canonical_bytes(admission_replay_value(scored.replay))),
        )
        for kind, actual in frozen_outputs:
            expected = _read_canonical(row[f"{kind}_file"])
            mutated = expected[:-1] + (b" " if expected[-1:] != b" " else b"\n")
            assert mutated != actual
            assert sha256(mutated).hexdigest() != row[f"{kind}_sha256"]

    with pytest.raises(AdmissionReportError, match="decision does not match every re-derived mandatory gate"):
        admission_report_value(_rehashed(scored_cases["go"].report, decision=AdmissionDecision.NO_GO))


def test_v2_validation_failure_class_message_and_order_are_frozen(
    scored_cases: dict[str, _ScoredAdmission],
) -> None:
    failures = _validation_failures(scored_cases["go"])
    actual = canonical.canonical_bytes(
        {
            "schema_version": "openultrasast.detection-core.admission-v2-validation-failures.v1",
            "failures": failures,
        }
    )
    expected = _read_canonical("validation_failures.json")

    assert actual == expected
    assert canonical.canonical_bytes({"failures": tuple(reversed(failures))}) != expected
