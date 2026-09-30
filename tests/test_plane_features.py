"""The plane task `features` (learned-decision-engine task 1) on validation-46's recorded lmdeploy case
(``tests/fixtures/plane-remember``), and `remember` storing its records as `features` rows."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from openultrasast.learn.schema import FeatureRecordError, feature_set_digest
from openultrasast.plane.memory import FileStore
from openultrasast.plane.tasks import features
from openultrasast.plane.tasks.remember import Context, remember_run, rows_for

FIXTURE = Path(__file__).parent / "fixtures" / "plane-remember" / "validation-46"
CASE = "lmdeploy-media-url-ssrf"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    target = tmp_path / "plane" / "validation-46"
    shutil.copytree(FIXTURE, target)
    return target


def _checkout(root: Path) -> Path:
    media = root / "lmdeploy" / "vl" / "media"
    media.mkdir(parents=True)
    (media / "connection.py").write_text("def _is_safe_url(u):\n    return True\n\n\ndef _load_http_url(u):\n    x = 1\n    return x\n")
    return root


def test_features_of_the_recorded_case(run_dir: Path, tmp_path: Path) -> None:
    [rec] = features.recorded_case(run_dir, CASE, workspace=_checkout(tmp_path / "checkout"))
    assert (rec["candidate"], rec["family"], rec["profile"], rec["unit"]) == (
        "lmdeploy/vl/media/connection.py::_load_http_url", "untrusted_destination", "plane", "pin",
    )  # fmt: skip
    x, states = rec["x"], {k: v["state"] for k, v in rec["instruments"].items()}
    assert (x["verify.flag_a"], x["verify.flag_b"], x["verify.flag_c"], x["verify.votes"]) == (True, True, None, 2)
    assert x["agree.final"] == "agreed" and x["facts.callers"] == 0 and x["facts.is_global"] is False
    assert x["facts.function_lines"] == 3 and x["lang.python"] is True and x["verify.site_offset"] == 0
    assert states["verify"] == states["agree"] == states["facts"] == states["source"] == "ran"
    assert states["quick"] == states["engine"] == "none", "no alerts task in this Run: no coverage, not zero hits"
    assert rec["instruments"]["verify"]["version"] == "deepseek-flash" and rec["feature_set_digest"] == feature_set_digest()
    assert "site_match" not in json.dumps(rec), "the fixture's site_match: true was dropped on read"
    [without] = features.recorded_case(run_dir, CASE)
    assert without["instruments"]["source"]["state"] == "none" and without["x"]["facts.function_lines"] is None


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


def test_remember_refuses_a_record_outside_the_allow_list(run_dir: Path) -> None:
    [rec] = features.recorded_case(run_dir, CASE)
    rec["x"]["site_match"] = True
    ctx = Context("r", "c-remember", "https://github.com/o/r.git", "0" * 40, "sha256:" + "1" * 64)
    with pytest.raises(FeatureRecordError, match="site_match"):
        rows_for(ctx, facts=None, passes={}, models={}, agreed=None, features=[rec])


def test_the_task_fails_loudly_without_an_output_dir() -> None:
    assert features.main({}) == 2
