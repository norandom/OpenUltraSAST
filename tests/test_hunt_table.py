"""Checks for the versioned hunter table."""

import builtins
import json

import pytest

from openultrasast.hunt.table import SCHEMA_VERSION, FeatureTable


def row(label=1):
    return {
        "change_id": "c", "repo": "r", "head": "h", "path": "app.py", "line": 1,
        "kind": "vulnerability", "fold": 0, "label": label, "family": "injection",
        "fix_span": [1, 3], "label_ref": "case", "verification": None,
        "feature.diff.distance": 0, "provenance.diff.ok": True,
        "provenance.diff.reason": None, "provenance.diff.version": "1", "provenance.diff.bytes_read": 10,
    }


def test_round_trip_digest_and_mask(tmp_path):
    table = FeatureTable([row(), row(None), row(0)])
    path = tmp_path / "table.jsonl"
    table.write_jsonl(path)
    restored = FeatureTable.read_jsonl(path)
    assert restored.rows == table.rows
    assert restored.digest() == table.digest()
    assert SCHEMA_VERSION == 1
    assert len(table.labelled().rows) == 2
    masked = table.mask(["diff"])
    assert masked.masked == ("diff",)
    assert masked.feature_columns() == []
    assert table.feature_columns() == ["feature.diff.distance"]
    assert masked.digest() != table.digest()
    masked.write_jsonl(path)
    assert FeatureTable.read_jsonl(path).masked == ("diff",)
    assert table.mask(["feature.diff.distance"]).feature_columns() == []
    assert table.digest() == FeatureTable([dict(reversed(list(row().items()))), row(None), row(0)]).digest()


@pytest.mark.parametrize("extra", [{"unknown": 1}, {"feature.diff.typo": 1}, {"provenance.diff.secret": 1}])
def test_unknown_columns_rejected(extra):
    with pytest.raises(ValueError):
        FeatureTable([{**row(), **extra}])


def test_missing_provenance_rejected():
    data = row()
    del data["provenance.diff.ok"]
    with pytest.raises(ValueError, match="provenance"):
        FeatureTable([data])


def test_schema_version_and_empty_table(tmp_path):
    path = tmp_path / "table.jsonl"
    FeatureTable([]).write_jsonl(path)
    assert FeatureTable.read_jsonl(path).rows == []
    path.write_text(json.dumps({"schema_version": 99, "masked": []}) + "\n")
    with pytest.raises(ValueError, match="schema"):
        FeatureTable.read_jsonl(path)


def test_pandas_is_optional(monkeypatch):
    real_import = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == "pandas":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    with pytest.raises(RuntimeError, match="pandas.*hunt"):
        FeatureTable([row()]).to_pandas()
