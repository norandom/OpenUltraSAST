"""The plane task `features` (learned-decision-engine task 1) on validation-46's recorded lmdeploy case
(``tests/fixtures/plane-remember``), and `remember` storing its records as `features` rows."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from openultrasast.plane.memory import FileStore
from openultrasast.plane.tasks import features
from openultrasast.plane.tasks.remember import remember_run

FIXTURE = Path(__file__).parent / "fixtures" / "plane-remember" / "validation-46"
CASE = "lmdeploy-media-url-ssrf"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    target = tmp_path / "plane" / "validation-46"
    shutil.copytree(FIXTURE, target)
    return target


def test_the_task_writes_records_and_remember_stores_them(run_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    env = {
        "OUSAST_OUTPUT_DIR": str(out), "OUSAST_INPUT_FACTS": str(run_dir / f"{CASE}-facts" / "facts.json"),
        "OUSAST_INPUT_AGREED": str(run_dir / f"{CASE}-final" / "agreed.json"),
        **{f"OUSAST_INPUT_PASS_{p.upper()}": str(run_dir / f"{CASE}-v{p}" / "units.jsonl") for p in "abc"},
        **{f"OUSAST_INPUT_SUMMARY_{p.upper()}": str(run_dir / f"{CASE}-v{p}" / "summary.json") for p in "abc"},
    }  # fmt: skip
    assert features.main(env) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert (summary["status"], summary["records"], summary["usd"], summary["calls"]) == ("done", 1, 0, 0)
    assert summary["instruments"]["verify"] == {"ran": 1} and summary["instruments"]["quick"] == {"none": 1}
    (run_dir / f"{CASE}-features").mkdir()
    shutil.copy(out / features.OUTPUT, run_dir / f"{CASE}-features" / features.OUTPUT)
    store = FileStore(tmp_path / "memory")
    [result] = remember_run(run_dir, store, population="population-v2", split="validation")
    assert result.kinds == {"facts": 1, "unit_cost": 2, "verdict": 1, "features": 1}
    [row] = store.rows(kind="features")
    assert row.row["candidate"] == "lmdeploy/vl/media/connection.py::_load_http_url" and row.row["family"] == "untrusted_destination"
    assert row.row["repo"] == "example.com/reserved/lmdeploy" and row.row["x"]["agree.final"] == "agreed"


def test_the_task_fails_loudly_without_an_output_dir() -> None:
    assert features.main({}) == 2
