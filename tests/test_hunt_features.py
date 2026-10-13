"""Engineered features from the feature table, their tie to the annotations, and the separation screen."""

from __future__ import annotations

import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("sklearn")

from openultrasast.hunt import features  # noqa: E402

ROW = {
    "change_id": "c1",
    "repo": "r",
    "head": "h",
    "path": "app.py",
    "line": 5,
    "kind": "vulnerability",
    "fold": 1,
    "label": 1,
    "family": "injection",
    "feature.diff.hunks": [[3, 3], [10, 12]],
    "feature.diff.on_changed_line": False,
    "feature.diff.distance": 2,
    "feature.source.function": "second",
    "feature.source.span": [5, 7],
    "feature.source.callers": [["web.py", 2], ["web.py", 9], ["cli.py", 1]],
    "feature.source.entry_points": [{"path": "web.py", "line": 1, "kind": "route"}],
    "feature.source.language": "python",
    "feature.semantic.roles": {"input": "source", "eval": "sink", "escape": "sanitizer", "x": "sink"},
    "feature.semantic.def_use": {"binds": [{"line": 6}], "calls": [{"line": 6}, {"line": 7}]},
    "feature.semantic.obligations": [
        {"operation": "auth", "line": 6, "discharged": False},
        {"operation": "csrf", "line": 7, "discharged": True},
    ],
    "feature.taxonomy.families": [{"id": "injection", "definition": "x"}],
    "provenance.diff.ok": True,
    "provenance.source.ok": True,
    "provenance.semantic.ok": True,
    "provenance.taxonomy.ok": True,
}


def test_feature_frame_engineers_counts_distances_and_flags():
    absent = {
        **ROW,
        "change_id": "c2",
        "label": 0,
        "feature.source.function": "<module>",
        "feature.source.span": None,
        "feature.semantic.roles": None,
        "feature.semantic.def_use": None,
        "feature.semantic.obligations": None,
        "provenance.semantic.ok": False,
    }
    frame = features.feature_frame([ROW, absent])
    first = frame.iloc[0]
    assert first["diff.distance"] == 2 and first["diff.on_changed_line"] == 0
    assert first["diff.hunk_count"] == 2 and first["diff.hunk_lines"] == 4
    assert first["source.span_lines"] == 3 and first["source.is_module"] == 0
    assert first["source.caller_count"] == 3 and first["source.caller_files"] == 2 and first["source.entry_point_count"] == 1
    assert (first["semantic.sources"], first["semantic.sinks"], first["semantic.sanitizers"]) == (1, 2, 1)
    assert first["semantic.binds"] == 1 and first["semantic.calls"] == 2
    assert first["semantic.obligations"] == 2 and first["semantic.obligations_undischarged"] == 1
    second = frame.iloc[1]
    assert second["source.is_module"] == 1 and pd.isna(second["source.span_lines"])
    assert pd.isna(second["semantic.sinks"]) and second["ok.semantic"] is False or second["ok.semantic"] == False  # noqa: E712
    assert list(frame["label"]) == [1, 0]


def test_every_engineered_feature_maps_to_an_annotation_and_masks_follow():
    from openultrasast.hunt.program import INPUTS

    inputs = {name for name, _, _ in INPUTS}
    assert all(annotation in inputs for _, annotation in features.ENGINEERED.values())
    assert set(features.features_of("roles")) == {"semantic.sources", "semantic.sinks", "semantic.sanitizers"}
    assert features.annotations_of(["semantic"]) == {"roles", "def_use", "obligations"}
    assert features.annotations_of(["feature.source.callers"]) == {"callers"}
    assert features.annotations_of(["hunks"]) == {"hunks"}
    assert features.annotations_of([]) == set()


def test_screen_reports_the_strongest_feature_per_annotation():
    rows = []
    for i in range(12):
        label = i % 2
        rows.append(
            {
                **ROW,
                "change_id": f"c{i}",
                "label": label,
                "feature.diff.distance": 0 if label else 30,
                "feature.source.callers": [["a.py", 1]] * (3 if label else 1),
                "feature.semantic.roles": {"eval": "sink"},
            }
        )
    frame = features.feature_frame(rows)
    out = features.screen(frame).set_index("annotation")
    assert out.loc["hunks", "strongest_feature"] == "diff.distance" and out.loc["hunks", "auc"] == 0.0
    assert out.loc["callers", "strongest_feature"] == "source.caller_count" and out.loc["callers", "auc"] == 1.0
    assert out.loc["roles", "auc"] == 0.5  # constant: no signal
