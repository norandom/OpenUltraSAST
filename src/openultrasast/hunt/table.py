"""Versioned rows of repository features, labels and producer provenance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
KEY_COLUMNS = ("change_id", "repo", "head", "path", "line", "kind", "fold")
LABEL_COLUMNS = ("label", "family", "fix_span", "label_ref", "verification")
FEATURE_NAMES = {
    "diff": ("hunks", "deletions", "on_changed_line", "distance"),
    "source": ("function", "span", "callers", "entry_points", "language"),
    "semantic": ("roles", "def_use", "obligations"),
    "taxonomy": ("families",),
}
PROVENANCE_NAMES = ("ok", "reason", "version", "bytes_read")
FEATURE_COLUMNS = tuple(f"feature.{producer}.{name}" for producer, names in FEATURE_NAMES.items() for name in names)
PROVENANCE_COLUMNS = tuple(f"provenance.{producer}.{name}" for producer in FEATURE_NAMES for name in PROVENANCE_NAMES)


def canonical_json(value: object) -> str:
    """Serialize data with stable keys and no ambiguous non-finite numbers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class FeatureTable:
    """Hold flat schema-v1 rows; JSONL starts with a version and mask header."""

    schema_version = SCHEMA_VERSION

    def __init__(self, rows: Iterable[dict[str, Any]], *, masked: Iterable[str] = ()) -> None:
        self.rows = deepcopy(list(rows))
        self.masked = tuple(sorted(set(masked)))
        self._validate()

    def _validate(self) -> None:
        allowed = set(KEY_COLUMNS + LABEL_COLUMNS + FEATURE_COLUMNS + PROVENANCE_COLUMNS)
        for row in self.rows:
            if set(row) - allowed:
                raise ValueError("unknown feature table column")
            label = row.get("label")
            if label is not None and (type(label) is not int or label not in (0, 1)):
                raise ValueError("label must be 1, 0 or None")
            for column in row:
                if column.startswith("feature."):
                    producer = column.split(".")[1]
                    if any(f"provenance.{producer}.{name}" not in row for name in PROVENANCE_NAMES):
                        raise ValueError("feature column is missing producer provenance")
        canonical_json(self.rows)

    def write_jsonl(self, path: Path | str) -> None:
        self._validate()
        with Path(path).open("w", encoding="utf-8") as stream:
            stream.write(canonical_json({"schema_version": self.schema_version, "masked": self.masked}) + "\n")
            for row in self.rows:
                stream.write(canonical_json(row) + "\n")

    @classmethod
    def read_jsonl(cls, path: Path | str) -> FeatureTable:
        with Path(path).open(encoding="utf-8") as stream:
            header = json.loads(next(stream, "{}"))
            if header.get("schema_version") != SCHEMA_VERSION:
                raise ValueError("unsupported feature table schema version")
            return cls((json.loads(line) for line in stream if line.strip()), masked=header.get("masked", ()))

    def to_pandas(self) -> Any:
        """Create a dataframe only when the optional research dependency is installed."""
        try:
            import pandas
        except ImportError as error:
            raise RuntimeError("pandas is required; install openultrasast[hunt]") from error
        return pandas.DataFrame(deepcopy(self.rows))

    def digest(self) -> str:
        self._validate()
        payload = {"schema_version": self.schema_version, "rows": self.rows}
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def mask(self, drop: Iterable[str]) -> FeatureTable:
        names = set(drop)
        unknown = names - set(FEATURE_NAMES) - set(FEATURE_COLUMNS)
        if unknown:
            raise ValueError("mask names an unknown producer or feature column")
        columns = {c for c in FEATURE_COLUMNS if c in names or c.split(".")[1] in names}
        return FeatureTable(({k: v for k, v in row.items() if k not in columns} for row in self.rows), masked=(*self.masked, *names))

    def feature_columns(self) -> list[str]:
        return sorted({column for row in self.rows for column in row if column.startswith("feature.")})

    def labelled(self) -> FeatureTable:
        return FeatureTable((row for row in self.rows if row.get("label") is not None), masked=self.masked)
