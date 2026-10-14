"""Checks for fix-site and ordinary labels."""

import pytest

from openultrasast.hunt.labels import label_rows
from openultrasast.hunt.table import FeatureTable


def positive():
    return {
        "kind": "vulnerability",
        "path": "app.py",
        "function": "handle",
        "function_lines": [10, 20],
        "family": "injection",
        "case_id": "verified-case",
    }


def test_labels_match_name_or_span_on_same_path():
    rows = [
        {"path": "app.py", "function": "handle", "line": 1},
        {"path": "app.py", "function": "nested", "line": 12},
        {"path": "other.py", "function": "handle", "line": 12},
        {"path": "app.py", "function": "other", "line": 30},
    ]
    labelled = label_rows(rows, positive())
    assert [r["label"] for r in labelled] == [1, 1, None, None]
    for data in labelled[:2]:
        assert data["family"] == "injection"
        assert data["fix_span"] == [10, 20]
        assert data["label_ref"] == "verified-case"
        assert data["verification"] is None
    assert "label" not in rows[0]


def test_feature_function_and_ordinary_rows():
    rows = [{"path": "app.py", "line": 1, "feature.source.function": "handle"}]
    assert label_rows(rows, positive())[0]["label"] == 1
    ordinary = label_rows([{"path": "app.py", "line": 1}], {"kind": "ordinary", "case_id": "draw"})
    assert ordinary[0]["label"] == 0
    assert len(FeatureTable(ordinary).labelled().rows) == 1


@pytest.mark.parametrize("kind", [None, "fix", "unknown"])
def test_unknown_change_kind_rejected(kind):
    with pytest.raises(ValueError):
        label_rows([], {"kind": kind})


def test_positive_requires_traceable_reference():
    change = positive()
    del change["case_id"]
    with pytest.raises(ValueError, match="case_id"):
        label_rows([], change)


def test_every_verified_target_of_a_change_is_a_positive():
    change = {
        **positive(),
        "case_id": "c1",
        "targets": [
            {"case_id": "c1", "path": "app.py", "function": "handle", "function_lines": [10, 20]},
            {"case_id": "c2", "path": "lib.py", "function": "check", "function_lines": [3, 8]},
        ],
    }
    rows = [
        {"path": "app.py", "line": 12, "function": "handle"},
        {"path": "lib.py", "line": 5, "function": "check"},
        {"path": "lib.py", "line": 40, "function": "other"},
    ]
    out = label_rows(rows, change)
    assert [r["label"] for r in out] == [1, 1, None]
    assert out[1]["label_ref"] == "c2" and out[1]["fix_span"] == [3, 8] and out[2]["label_ref"] is None
