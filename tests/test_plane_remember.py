"""`remember` (harnessx-removal §4) on a recorded Run: a few KB of validation-46's lmdeploy case under
``tests/fixtures/plane-remember`` (witness texts cut, facts.json cut to the files its callers name, the repository
URL replaced: the population is reserved, ``tests/test_independent_population.py``)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from openultrasast import cli
from openultrasast.plane import memory
from openultrasast.plane.memory import FileStore, MemoryStoreError, ingest, row_id
from openultrasast.plane.tasks import remember
from openultrasast.plane.tasks.remember import Context, candidates_digest, remember_run, rows_for

FIXTURE = Path(__file__).parent / "fixtures" / "plane-remember" / "validation-46"
CASE = "lmdeploy-media-url-ssrf"
PIN = "71648d239c978452720a6d6692fe914efc8a7b94"
IMAGE = "sha256:200e335877b52d68ea0bc53b4c9ba49ef2ee19e8a5ec2c874148b969123ef7ab"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    target = tmp_path / "plane" / "validation-46"
    shutil.copytree(FIXTURE, target)
    return target


def _by_kind(store: FileStore) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {}
    for record in store.rows():
        rows.setdefault(record.row["kind"], []).append(record.row)
    return rows


def test_remember_turns_the_recorded_case_into_rows(run_dir: Path, tmp_path: Path) -> None:
    facts = (run_dir / f"{CASE}-facts" / "facts.json").read_bytes()
    assert len(facts) > 100, "the fixture was read"
    store = FileStore(tmp_path / "memory")
    results = remember_run(run_dir, store, population="population-v2", split="validation")
    assert [(r.task, r.skipped, r.kinds) for r in results] == [(f"{CASE}-remember", False, {"facts": 1, "unit_cost": 2, "verdict": 1})]
    rows = _by_kind(store)
    for row in (r for kind in rows.values() for r in kind):
        assert (row["repo"], row["pin"], row["run"], row["image"]) == ("example.com/reserved/lmdeploy", PIN, "validation-46", IMAGE)
        assert (row["task"], row["population"], row["split"]) == (f"{CASE}-remember", "population-v2", "validation")
    sha = hashlib.sha256(facts).hexdigest()
    assert rows["facts"][0]["sha256"] == sha and store.get_facts(sha) == facts
    assert rows["facts"][0]["candidates_digest"] == candidates_digest(json.loads(facts))
    agreed = json.loads((run_dir / f"{CASE}-final" / "agreed.json").read_text())["candidates"]
    assert [(v["candidate"], v["passes"], v["site_match"], v["usd"], v["turns"]) for v in rows["verdict"]] == [
        (c["candidate"], {"a": c["a"], "b": c["b"], "c": c["c"]}, c["site_match"], c["usd"], c["turns"]) for c in agreed
    ], "a verdict row per agree row, from the final (tie-break) decision"
    assert rows["verdict"][0]["final"] == "agreed" and rows["verdict"][0]["family"] == "untrusted_destination"
    costs = {(u["pass"], u["path"]): (u["usd"], u["calls"], u["model"]) for u in rows["unit_cost"]}
    assert costs == {
        ("a", "lmdeploy/vl/media/connection.py"): (0.01237569, 7, "deepseek-flash"),
        ("b", "lmdeploy/vl/media/connection.py"): (costs[("b", "lmdeploy/vl/media/connection.py")][0], 7, "deepseek-flash"),
    }
    assert sum(u["usd"] for u in rows["unit_cost"]) == pytest.approx(rows["verdict"][0]["usd"], abs=1e-6)
    assert not list(run_dir.glob("*-remember")), "the by-hand path writes nothing into the run directory"


def test_re_ingest_of_the_same_run_is_a_no_op(run_dir: Path, tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    remember_run(run_dir, store)
    before = {p: p.read_bytes() for p in store.root.rglob("*") if p.is_file()}
    again = remember_run(run_dir, store)
    assert [r.skipped for r in again] == [True]
    assert {p: p.read_bytes() for p in store.root.rglob("*") if p.is_file()} == before


def test_rows_carry_every_final_the_tiebreak_and_alerts() -> None:
    ctx = Context("r", "c-remember", "https://github.com/o/r.git", "0" * 40, "sha256:" + "1" * 64)
    agreed = {
        "family": "injection",
        "candidates": [
            {"candidate": "a.py::f", "a": True, "b": True, "c": None, "agreed": True},
            {"candidate": "a.py::g", "a": True, "b": False, "c": True, "agreed": True},
            {"candidate": "a.py::h", "a": True, "b": False, "c": False, "agreed": False},
            {"candidate": "a.py::i", "a": False, "b": False, "c": None, "agreed": False},
        ],
        "disputed": [{"candidate": "a.py::h"}],
    }
    alert = {"rule_id": "py-ssrf", "rule_status": "shadow", "path": "a.py", "line": 3, "function": "f", "pin_role": "vulnerable"}
    rows = rows_for(ctx, facts=None, passes={}, models={}, agreed=agreed, alerts=[alert])
    verdicts = {r["candidate"]: (r["final"], r["tiebreak"]) for r in rows if r["kind"] == "verdict"}
    expected = {"a.py::f": ("agreed", False), "a.py::g": ("agreed", True), "a.py::h": ("disputed", True), "a.py::i": ("rejected", False)}
    assert verdicts == expected
    (alert_row,) = [r for r in rows if r["kind"] == "alert"]
    assert {k: alert_row[k] for k in alert} == alert and alert_row["repo"] == "github.com/o/r"
    assert alert_row["id"] == row_id("alert", "r", "c-remember", "py-ssrf:a.py:3")
    assert len({r["id"] for r in rows}) == len(rows)
    assert rows == rows_for(ctx, facts=None, passes={}, models={}, agreed=agreed, alerts=[alert]), "deterministic"


COVERAGE_SUMMARY = {
    "status": "done", "pins": {"vulnerable": "0" * 40, "fixed": "f" * 40},
    "coverage": {
        "javascript": {"coverage": "quick", "files": {"vulnerable": 2}},
        "php": {"coverage": "none", "files": {"vulnerable": 9, "fixed": 9}},
    },
}  # fmt: skip


def test_the_alerts_coverage_becomes_one_row_per_language_and_pin() -> None:
    ctx = Context("r", "c-remember", "https://github.com/o/r.git", "0" * 40, "sha256:" + "1" * 64)
    rows = rows_for(ctx, facts=None, passes={}, models={}, agreed=None, alerts=[], alerts_summary=COVERAGE_SUMMARY)
    got = sorted((r["language"], r["pin_role"], r["pin"], r["coverage"], r["files"]) for r in rows if r["kind"] == "coverage")
    assert got == [
        ("javascript", "vulnerable", "0" * 40, "quick", 2), ("php", "fixed", "f" * 40, "none", 9),
        ("php", "vulnerable", "0" * 40, "none", 9),
    ]  # fmt: skip
    assert rows_for(ctx, facts=None, passes={}, models={}, agreed=None, alerts_summary={"status": "done"}) == [], "unknown stays unknown"


def test_remember_run_carries_the_alerts_coverage_into_the_store(run_dir: Path, tmp_path: Path) -> None:
    (run_dir / f"{CASE}-alerts").mkdir()
    (run_dir / f"{CASE}-alerts" / "alerts.jsonl").write_text("")  # zero alerts: meaningful only through the coverage
    summary = {**COVERAGE_SUMMARY, "pins": {"vulnerable": PIN, "fixed": "f" * 40}}
    (run_dir / f"{CASE}-alerts" / "summary.json").write_text(json.dumps(summary))
    store = FileStore(tmp_path / "memory")
    [result] = remember_run(run_dir, store)
    assert result.kinds["coverage"] == 3
    php = sorted((r["pin"], r["coverage"]) for r in _by_kind(store)["coverage"] if r["language"] == "php")
    assert php == [(PIN, "none"), ("f" * 40, "none")]


def test_the_task_entrypoint_writes_memory_and_passes_facts_through(run_dir: Path, tmp_path: Path) -> None:
    docs = list(yaml.safe_load_all((run_dir / f"{CASE}-facts" / "task.yaml").read_text()))
    task = next(d for d in docs if d["kind"] == "Task")
    pins = next(e["value"] for e in task["spec"]["env"] if e["name"] == "OUSAST_GIT_PINS")
    out = run_dir / f"{CASE}-remember"
    env = {
        "OUSAST_OUTPUT_DIR": str(out), "OUSAST_RUN": "validation-46", "OUSAST_TASK": f"{CASE}-remember", "OUSAST_GIT_PINS": pins,
        "AX_TASK_YAML": yaml.safe_dump(task), "AX_WORKSPACES_YAML": yaml.safe_dump_all([d for d in docs if d["kind"] == "Workspace"]),
        "OUSAST_INPUT_FACTS": str(run_dir / f"{CASE}-facts" / "facts.json"),
        "OUSAST_INPUT_AGREED": str(run_dir / f"{CASE}-final" / "agreed.json"),
        "OUSAST_POPULATION": "population-v2", "OUSAST_SPLIT": "validation",
        **{f"OUSAST_INPUT_PASS_{p.upper()}": str(run_dir / f"{CASE}-v{p}" / "units.jsonl") for p in "abc"},
        **{f"OUSAST_INPUT_SUMMARY_{p.upper()}": str(run_dir / f"{CASE}-v{p}" / "summary.json") for p in "abc"},
    }  # fmt: skip
    assert remember.main(env) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert (summary["status"], summary["units_done"], summary["usd"], summary["calls"], summary["rows"]) == ("done", 1, 0, 0, 4)
    assert (out / "facts.json").read_bytes() == (run_dir / f"{CASE}-facts" / "facts.json").read_bytes()
    delivered = FileStore(tmp_path / "delivered")
    assert [r.task for r in ingest(run_dir, delivered)] == [f"{CASE}-remember"]
    by_hand = FileStore(tmp_path / "by-hand")
    (out / "memory.jsonl").rename(tmp_path / "memory.jsonl")
    remember_run(run_dir, by_hand, population="population-v2", split="validation")
    assert [r.row for r in delivered.rows()] == [r.row for r in by_hand.rows()], "the task and the host path agree"
    assert remember.main({**env, "AX_TASK_YAML": "{}"}) == 2
    assert "names no image" in json.loads((out / "summary.json").read_text())["reason"]


def test_ingest_without_remember_outputs_is_a_no_op(run_dir: Path, tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    assert ingest(run_dir, store) == [] and not store.root.exists()


def test_a_malformed_delivered_row_fails_naming_file_and_line(run_dir: Path, tmp_path: Path) -> None:
    out = run_dir / f"{CASE}-remember"
    out.mkdir()
    good = rows_for(Context("validation-46", out.name, "https://github.com/o/r", PIN, IMAGE), facts=None, passes={}, models={}, agreed=None,
                    alerts=[{"rule_id": "x", "path": "a.py", "line": 1}])  # fmt: skip
    (out / "memory.jsonl").write_text(json.dumps(good[0]) + "\n" + json.dumps({**good[0], "kind": "vibes"}) + "\n")
    store = FileStore(tmp_path / "memory")
    with pytest.raises(MemoryStoreError, match=rf"{out.name}/memory.jsonl:2: unknown kind"):
        remember_run(run_dir, store)
    assert not store.root.exists()


def test_plane_remember_cli_reads_population_from_the_run_and_reports_counts(
    run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path))
    monkeypatch.setenv("OUSAST_MEMORY", f"file://{tmp_path}/memory")
    assert cli.main(["plane", "remember", "validation-46"]) == 0
    out = capsys.readouterr().out
    assert "1 tasks ingested, 0 already in the index; rows facts=1 unit_cost=2 verdict=1" in out
    rows = FileStore(tmp_path / "memory").rows()
    assert {(r.row["population"], r.row["split"]) for r in rows} == {("population-v2", "validation")}  # plane/runs/validation-46.yaml
    assert cli.main(["plane", "remember", "validation-46"]) == 0
    assert "0 tasks ingested, 1 already in the index" in capsys.readouterr().out


def test_plane_run_seeds_before_and_ingests_after(run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.plane import reconciler

    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path))
    monkeypatch.setenv("OUSAST_MEMORY", f"file://{tmp_path}/memory")
    calls: list[str] = []
    monkeypatch.setattr(memory, "seed", lambda manifest, store: calls.append(f"seed {manifest.name}") or [])
    monkeypatch.setattr(reconciler, "run", lambda manifest, **kw: calls.append("run") or "done")
    assert cli.main(["plane", "run", "plane/runs/validation-46.yaml"]) == 0
    assert calls == ["seed validation-46.yaml", "run"]
    assert len(FileStore(tmp_path / "memory").rows(kind="verdict")) == 1, "the run's rows were ingested after it"
