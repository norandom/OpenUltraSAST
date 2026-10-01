"""The leakage audit (``ousast learn audit-leaks``): a signal that alone names the side of a pair is flagged, one that
does not is not; rows pair by case, candidate and family; an empty store is an error, never a clean audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from learn_fixtures import x_record

from openultrasast.cli import main
from openultrasast.learn.leaks import Pair, Signal, audit, pair_rows, separation
from openultrasast.learn.schema import BY_NAME
from openultrasast.plane.memory import FileStore


def _pairs(n: int = 20) -> list[Pair]:
    """``n`` pairs: the engine state tracks the side (ran on the vulnerable side, failed on the fixed one) in all but
    two; quick hits differ in half the pairs, in alternating directions (no information)."""
    out = []
    for i in range(n):
        leaks = i >= 2
        vulnerable = x_record(hits=(i % 2) * 2, engine="ran", findings=1)
        fixed = x_record(hits=((i + 1) % 2) * 2, engine="failed" if leaks else "ran", findings=1)
        out.append(Pair("injection", vulnerable, fixed))
    return out


def test_a_leaking_signal_is_flagged_and_a_clean_one_is_not() -> None:
    report = audit(_pairs(), "static")
    assert report["pairs"] == {"all": 20, "injection": 20}
    engine = report["signals"]["state.engine"]["all"]
    assert engine == {"pairs": 20, "differ": 18, "correct": 18, "wrong": 0, "separation": 0.9}
    assert "state.engine" in report["flagged_signals"] and "eng.findings" in report["flagged_signals"]
    hits = report["signals"]["qr.enabled_hits"]["all"]
    assert hits["differ"] == 20 and hits["correct"] == hits["wrong"] == 10 and hits["separation"] == 0.0
    assert "qr.enabled_hits" not in report["flagged_signals"] and "state.quick" not in report["flagged_signals"]
    assert report["flagged"][0]["separation"] == 0.9 and all(c["separation"] >= 0.2 for c in report["flagged"])
    few = audit(_pairs()[:9], "static")  # under min_pairs: never flagged, however clean the split
    assert few["flagged"] == [] and few["signals"]["state.engine"]["all"]["separation"] > 0.7


def test_an_ordered_signal_has_one_direction() -> None:
    spec = BY_NAME["qr.enabled_hits"]
    signal = Signal(spec.name, spec.instrument, True, spec)
    higher = [Pair("f", x_record(hits=3), x_record(hits=1)) for _ in range(6)] + [Pair("f", x_record(hits=0), x_record(hits=2))] * 2
    cell = separation(signal, higher)
    assert cell["direction"] == "higher on vulnerable" and (cell["correct"], cell["wrong"]) == (6, 2) and cell["separation"] == 0.5


def _row(task: str, family: str = "injection", candidate: str = "a.py::f", **kw: object) -> dict:
    rec = x_record(**kw)  # type: ignore[arg-type]
    pin = ("0" if task.endswith("v") else "1") * 40
    return {"id": f"{task}:{candidate}", "kind": "features", "repo": "github.com/o/r", "pin": pin, "run": "harvest", "task": task,
            "population": "pairs", "split": "pairs", "image": "none", **rec}  # fmt: skip


def test_rows_pair_by_case_candidate_and_family() -> None:
    sides = {"u1v": ("case-1", "vulnerable"), "u1f": ("case-1", "fixed"), "u2v": ("case-2", "vulnerable")}
    rows = [_row("u1v"), _row("u1f", engine="failed"), _row("u2v"), _row("u9")]
    pairs, skipped = pair_rows(rows, sides, "static")
    assert len(pairs) == 1 and pairs[0].vulnerable["instruments"]["engine"]["state"] == "ran"
    assert pairs[0].fixed["instruments"]["engine"]["state"] == "failed"
    assert skipped == {"no side": 1, "one side only": 1}
    assert pair_rows(rows, sides, "plane")[0] == []  # another profile's rows are not read


def test_cli_audits_the_store_and_refuses_an_empty_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = FileStore(tmp_path / "memory")
    units = tmp_path / "units.json"
    sides = {}
    rows = []
    for i in range(12):
        sides[f"c{i}v"], sides[f"c{i}f"] = {"ref": f"case-{i}", "side": "vulnerable"}, {"ref": f"case-{i}", "side": "fixed"}
        rows += [_row(f"c{i}v", findings=1), _row(f"c{i}f", engine="failed")]
    store.put_rows(rows)
    units.write_text(json.dumps(sides))
    out = tmp_path / "audit.json"
    args = ["learn", "audit-leaks", "--memory", f"file://{tmp_path / 'memory'}", "--units", str(units), "--profile", "static"]
    assert main([*args, "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["rows_read"] == 24 and report["pairs"]["all"] == 12 and "state.engine" in report["flagged_signals"]
    assert "a.py" not in out.read_text()  # counts only: no candidate reaches the report
    empty = ["learn", "audit-leaks", "--memory", f"file://{tmp_path / 'empty'}", "--units", str(units)]
    assert main(empty) == 2 and "no pair to audit" in capsys.readouterr().err


def test_drop_rows_removes_only_the_named_rows(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    store.put_rows([_row("u1v"), _row("u1v", candidate="a.py::g")])
    assert store.drop_rows("github.com/o/r", "0" * 40, ["u1v:a.py::g", "absent"]) == 1
    assert [r.row["id"] for r in store.rows(kind="features")] == ["u1v:a.py::f"]
    assert store.drop_rows("github.com/o/r", "0" * 40, ["u1v:a.py::f"]) == 1 and store.rows(kind="features") == []
