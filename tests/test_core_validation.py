"""Validation tests for detection-core tasks 7.1-7.2 (Req 5, 7, 11, 12)."""

import json
import sys
from pathlib import Path

from test_core_native import _legacy_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.admission import AdmissionManifestError, validate_report_schema  # noqa: E402
from openultrasast.core.consumer import PushRequest, consume_verdict  # noqa: E402
from openultrasast.core.verdict import Judgment, ProvenClaim  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def test_committed_admission_report_satisfies_schema() -> None:
    report = json.loads((REPO / "benchmarks/measurements/2026-10-30-access-control-admission/report.json").read_text(encoding="utf-8"))
    validate_report_schema(report)


def test_schema_validator_refuses_incomplete_report() -> None:
    report = json.loads((REPO / "benchmarks/measurements/2026-10-30-access-control-admission/report.json").read_text(encoding="utf-8"))
    del report["precision"]
    try:
        validate_report_schema(report)
        raise AssertionError("report missing precision must be refused")
    except AdmissionManifestError:
        pass


def test_end_to_end_push_through_core_contracts() -> None:
    record = _legacy_record()
    claim = ProvenClaim(trace_id="t1", witness="fact:f", path="src/app.py", line=30, family="access_control")
    verdict = consume_verdict(PushRequest(base="b", head="h", budget_class="dev-pool"), record, (claim,), ())
    assert verdict.claims[0].witness == "fact:f"
    assert record.judgment is Judgment.UNGUARDED
    assert record.canonical() == record.canonical()
