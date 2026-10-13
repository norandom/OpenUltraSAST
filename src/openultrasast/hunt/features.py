"""Feature engineering over the feature table, and the tie between engineered features and the DSPy annotations.

The table's raw columns (`feature.<producer>.<name>`) are what the producers measured. This module turns them
into the numeric frame the statistics read (distances, counts, flags), and keeps the map from every engineered
feature back to the annotation the model is shown. An ablation that masks an annotation therefore drops both the
rendered input and the engineered features that came from the same column, and the separation screen can say
which annotation carries signal before any model call is spent on it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .table import FeatureTable

# engineered feature -> (raw column, annotation input name in program.INPUTS)
ENGINEERED: dict[str, tuple[str, str]] = {
    "diff.distance": ("feature.diff.distance", "hunks"),
    "diff.on_changed_line": ("feature.diff.on_changed_line", "hunks"),
    "diff.hunk_count": ("feature.diff.hunks", "hunks"),
    "diff.hunk_lines": ("feature.diff.hunks", "hunks"),
    "diff.deletion_count": ("feature.diff.deletions", "hunks"),
    "source.span_lines": ("feature.source.span", "function_text"),
    "source.is_module": ("feature.source.function", "change_summary"),
    "source.caller_count": ("feature.source.callers", "callers"),
    "source.caller_files": ("feature.source.callers", "callers"),
    "source.entry_point_count": ("feature.source.entry_points", "entry_points"),
    "semantic.sources": ("feature.semantic.roles", "roles"),
    "semantic.sinks": ("feature.semantic.roles", "roles"),
    "semantic.sanitizers": ("feature.semantic.roles", "roles"),
    "semantic.binds": ("feature.semantic.def_use", "def_use"),
    "semantic.calls": ("feature.semantic.def_use", "def_use"),
    "semantic.obligations": ("feature.semantic.obligations", "obligations"),
    "semantic.obligations_undischarged": ("feature.semantic.obligations", "obligations"),
}
KEYS = ("change_id", "repo", "head", "path", "line", "kind", "fold", "label", "family")


def _count(value: object) -> int | None:
    return None if value is None else len(value) if isinstance(value, (list, dict, tuple)) else None


def _engineer(row: Mapping[str, Any]) -> dict[str, Any]:
    hunks = row.get("feature.diff.hunks")
    span = row.get("feature.source.span")
    callers = row.get("feature.source.callers")
    roles = row.get("feature.semantic.roles") or None
    def_use = row.get("feature.semantic.def_use") or None
    obligations = row.get("feature.semantic.obligations")
    function = row.get("feature.source.function")
    out: dict[str, Any] = {key: row.get(key) for key in KEYS}
    out.update(
        {
            "diff.distance": row.get("feature.diff.distance"),
            "diff.on_changed_line": None
            if row.get("feature.diff.on_changed_line") is None
            else int(bool(row["feature.diff.on_changed_line"])),
            "diff.hunk_count": _count(hunks),
            "diff.hunk_lines": None if hunks is None else sum(end - start + 1 for start, end in hunks),
            "diff.deletion_count": _count(row.get("feature.diff.deletions")),
            "source.span_lines": None if not span else span[1] - span[0] + 1,
            "source.is_module": None if function is None else int(function == "<module>"),
            "source.caller_count": _count(callers),
            "source.caller_files": None if callers is None else len({path for path, _ in callers}),
            "source.entry_point_count": _count(row.get("feature.source.entry_points")),
            "semantic.sources": None if roles is None else sum(1 for role in roles.values() if role == "source"),
            "semantic.sinks": None if roles is None else sum(1 for role in roles.values() if role == "sink"),
            "semantic.sanitizers": None if roles is None else sum(1 for role in roles.values() if role == "sanitizer"),
            "semantic.binds": None if def_use is None else len(def_use.get("binds", [])),
            "semantic.calls": None if def_use is None else len(def_use.get("calls", [])),
            "semantic.obligations": _count(obligations),
            "semantic.obligations_undischarged": None if obligations is None else sum(1 for o in obligations if not o.get("discharged")),
        }
    )
    for producer in ("diff", "source", "semantic", "taxonomy"):
        out[f"ok.{producer}"] = row.get(f"provenance.{producer}.ok")
    return out


def feature_frame(table: FeatureTable | Sequence[Mapping[str, Any]]) -> Any:
    """The engineered frame: one row per candidate, key and label columns, numeric features, provenance flags."""
    import pandas as pd

    rows = table.rows if isinstance(table, FeatureTable) else list(table)
    return pd.DataFrame([_engineer(row) for row in rows])


def features_of(annotation: str) -> list[str]:
    """The engineered features that come from one annotation (what an ablation mask on it also drops)."""
    return [name for name, (_, input_name) in ENGINEERED.items() if input_name == annotation]


def annotations_of(mask: Iterable[str]) -> set[str]:
    """Annotations an ablation mask removes, whether it names a producer, a column or an input."""
    dropped = set(mask)
    out = set()
    for name, (column, input_name) in ENGINEERED.items():
        producer = column.split(".")[1]
        if input_name in dropped or column in dropped or producer in dropped or name in dropped:
            out.add(input_name)
    return out


def screen(frame: Any, *, label: str = "label") -> Any:
    """Separation of every engineered feature against the label, grouped by the annotation it renders into.

    The caller reads it two ways: an annotation with no feature above 0.5 carries no signal the model could use
    from this column alone, and an annotation near 1.0 on training data is a leak to audit before it is trusted."""
    import pandas as pd

    from ..stats import separation

    columns = [name for name in ENGINEERED if name in frame.columns]
    table = separation(frame, label, columns)
    table["annotation"] = [ENGINEERED[name][1] for name in table["column"]]
    best = (
        table.dropna(subset=["auc"])
        .assign(distance=lambda t: (t["auc"] - 0.5).abs())
        .sort_values("distance", ascending=False)
        .groupby("annotation", as_index=False)
        .first()[["annotation", "column", "auc", "n"]]
        .rename(columns={"column": "strongest_feature"})
    )
    return pd.DataFrame(best).sort_values("annotation").reset_index(drop=True)
