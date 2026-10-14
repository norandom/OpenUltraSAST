"""Checks that search scoring follows the benchmark's location rule."""

from types import SimpleNamespace

import pytest

from benchmarks.unseen.score import catches
from openultrasast.hunt.metric import search_metric, search_outcome


@pytest.mark.parametrize(
    "change",
    [
        {"family": "injection", "path": "app.py", "function": "handler", "function_lines": [100, 140]},
        {"family": "path", "path": "other.py", "function": "read", "function_lines": [100, 140]},
        {"family": "config_secrets", "path": "app.py", "function": "handler", "function_lines": [100, 140]},
    ],
)
def test_matches_score_catches(change):
    change = {**change, "kind": "vulnerability", "files": [{"path": "app.py", "head_lines": [[20, 22]]}]}
    for path in ("app.py", "other.py"):
        for line in (9, 10, 22, 32, 33, 110, 500):
            for function in ("handler", "other"):
                for family in (change["family"], "unknown"):
                    finding = {"path": path, "line": line, "function": function, "family": family}
                    record = {**change, "push": {"admission": {"defects": [{**finding, "locations": [[path, line]]}]}}}
                    assert search_outcome(change, [finding]).hit == bool(catches(record))


def test_counts_scope_feedback_and_tolerance():
    change = {
        "kind": "vulnerability",
        "path": "app.py",
        "function": "handle",
        "family": "path",
        "function_lines": [20, 22],
        "files": [{"path": "app.py", "head_lines": [[20, 22]]}],
    }
    findings = [{"path": "app.py", "line": 10, "family": "path"}, {"path": "other.py", "line": 30, "family": "path"}]
    outcome = search_outcome(change, findings)
    assert (outcome.hit, outcome.suspicions, outcome.on_diff) == (True, 2, 1)
    assert "other.py:30" in outcome.feedback
    missed = search_outcome(change, findings, tolerance=0)
    assert not missed.hit
    assert "missed app.py:20 handle family path" in missed.feedback
    assert search_metric({"change": change}, {"findings": findings}) == 1.0
    assert search_metric(SimpleNamespace(change=change), SimpleNamespace(findings=[])) == 0.0


@pytest.mark.parametrize("count,expected", [(0, 1.0), (1, 0.8), (5, 0.0), (7, 0.0)])
def test_ordinary_metric(count, expected):
    assert search_metric({"kind": "ordinary", "files": []}, {"findings": [{}] * count}) == expected
