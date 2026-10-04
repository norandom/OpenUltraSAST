"""Synthetic push-level statistical controls; no corpus reads."""

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
s = importlib.import_module("benchmarks.unseen.score")


def record(kind="introducing", **updates):
    return {
        "id": "a",
        "repo": "opaque",
        "kind": kind,
        "family": "injection",
        "function": "handler",
        "files": [{"path": "app.py", "head_lines": [[20, 22]]}],
        "instrument": {
            "head_verified": True,
            "base_verified": True,
            "changed_bytes": {"app.py": 20},
            "hook_exit": 0,
            "hook_bytes_read": 20,
        },
        "push": {"quick_tier": [{"bytes_read": 20, "findings": []}]},
        **updates,
    }


def test_coverage_and_failure_denominator():
    r = record()
    assert s.coverage(r) == "quick_only"
    r["push"]["scans"] = [{"side": "head", "scan": {"question_outcomes": [{"status": "completed", "identity": {"path": "app.py"}}]}}]
    assert s.coverage(r) == "engine_covered"
    r["instrument"]["suspect_fast"] = True
    assert s.coverage(r) == "instrument_failure"
    assert s.coverage(record(push={"skipped": ["language_not_covered:other:1:1"]})) == "unanalysable"
    assert s.coverage({}) == "instrument_failure"
    with pytest.raises(ValueError, match="5%"):
        s.score([record(), r])


@pytest.mark.parametrize(
    "p,width,n", [(0.05, 0.03, 315), (0.1, 0.03, 483), (0.2, 0.03, 756), (0.1, 0.1, 62), (0.25, 0.1, 88), (0.4, 0.1, 97)]
)
def test_sample_sizes(p, width, n):
    assert s.required_n(p, width) == n


def test_catch_and_all_stream_false_alarm():
    r = record()
    r["push"]["quick_tier"][0]["findings"] = [{"cwe": "CWE-89", "path": "app.py", "line": 20}]
    assert s.catches(r) == ["quick"]
    r["push"]["quick_tier"][0]["findings"][0]["line"] = 100
    assert not s.catches(r)
    r["kind"] = "ordinary"
    assert s.false_alarm(r)
    assert not s.false_alarm(r, alerts_only=True)


def test_location_rules():
    assert s.location_match(record(family="access_control"), {"path": "app.py", "function": "handler", "line": 200})
    assert not s.location_match(record(family="config_secrets"), {"path": "app.py", "function": "handler", "line": 200})
    assert s.location_match(record(family="config_secrets"), {"path": "app.py", "line": 30})
    assert not s.location_match(record(), {"path": "else.py", "function": "handler", "line": 20})


def test_bootstrap_icc_mcnemar():
    rows = [("a", 1), ("a", 1), ("b", 0), ("b", 0)]
    assert s.cluster_interval(rows, seed=7) == s.cluster_interval(rows, seed=7)
    assert s.icc(rows) == pytest.approx(1)
    assert s.mcnemar([True] * 6, [False] * 6) == pytest.approx(0.03125)
    assert s.mcnemar([True], [True]) == 1


def test_budgets():
    rows = [{"kind": "ordinary", "score": x} for x in range(100)] + [{"kind": "introducing", "score": 99}]
    result = s.budgets(rows)
    assert result["5%"]["threshold"] == 95
    assert result["5%"]["label"] == "exploratory"
    assert s.budgets(rows, thresholds={"5%": 96})["5%"]["label"] == "fixed"
    binary = s.budgets([{"kind": "ordinary", "prediction": False}, {"kind": "introducing", "prediction": True}], binary=True)
    assert binary["budgets_met"] == ["1%", "5%", "10%"]


def test_gate():
    a = [record(kind="ordinary", id=str(i), repo=str(i)) for i in range(10)] + [record(id="v")]
    b = [
        record(kind="ordinary", id=str(i), repo=str(i), push={"quick_tier": [{"findings": [{"cwe": "CWE-89", "path": "x", "line": 1}]}]})
        for i in range(10)
    ] + [record(id="v")]
    assert s.gate(a, b, slice_id="p1/2")["gate"] == "regression"
    assert s.gate(a, b)["gate"] == "not_run"
    assert s.gate(a, b, slice_id="p1/2", informed=True)["gate"] == "not_run"
    assert s.gate(a, [{}], slice_id="p1/2")["gate"] == "not_run"


def test_real_artifact_coverage_and_location_binding():
    r = record(path="app.py", function_lines=[1, 100], files=[{"path": "other.py", "head_lines": [[200, 210]]}])
    assert not s.location_match(r, {"path": "other.py", "line": 40})
    assert (
        s.coverage(
            record(
                instrument={"head_verified": True, "base_verified": True, "changed_bytes": {"x": 20}, "hook_exit": 0, "hook_bytes_read": 0},
                push={"admission": {"coverage_reasons": ["language_not_covered:unknown:1:1"]}},
            )
        )
        == "unanalysable"
    )
    r["push"]["quick_tier"][0]["findings"] = [{"cwe": None, "path": "other.py", "line": 200}]
    assert not s.catches(r)
    assert s.false_alarm(r)


def test_committed_synthetic_fixture():
    import json

    fixture = Path(__file__).resolve().parents[1] / "benchmarks/unseen/fixtures/scorer.json"
    payload = fixture.read_bytes()
    assert len(payload) > 0
    report = s.score(json.loads(payload))
    assert report["catch"]["n"] == 4 and report["catch"]["count"] == 2
    assert report["false_alarm"]["n"] == 16 and report["false_alarm"]["count"] == 1
    assert report["coverage"]["quick_only"] == 20
