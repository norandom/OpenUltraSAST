"""The judge resume boundary accepts only complete ordered v2 artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import judge_pass  # noqa: E402


def test_load_done_refuses_stripped_metadata_and_duplicate_ids(tmp_path: Path) -> None:
    out = tmp_path / "judge"
    out.mkdir()
    path = out / "judgments.jsonl"
    path.write_text(json.dumps({"id": "one", "judgment": "keep"}) + "\n")
    with pytest.raises(ValueError, match="metadata"):
        judge_pass._load_done(out)

    from benchmarks.valid.artifact_contract import write_benchmark_jsonl

    write_benchmark_jsonl(
        path,
        "judge-pass",
        ({"key": "one", "judgment": "keep"}, {"key": "one", "judgment": "drop"}),
        replace=True,
    )
    with pytest.raises(ValueError, match="duplicate"):
        judge_pass._load_done(out)
