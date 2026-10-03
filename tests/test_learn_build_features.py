"""Recorded scan names, repository coverage, and the feature builder's read-only audit."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from openultrasast.learn.features import SourceIndex, _signals
from openultrasast.learn.labels import LabelSourceError
from openultrasast.learn.roles import RoleSet

SPEC = importlib.util.spec_from_file_location("build_features", Path(__file__).parents[1] / "benchmarks/learn/build_features.py")
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def scan(steps: int = 5) -> dict:
    return {
        "questions": 4,
        "completed": 3,
        "findings": [{"site": "a.ts:2:handler", "family": "injection", "rung": "model_entailed", "witness": f"flow ({steps} steps)"}],
        "degradations": [],
    }


def write_scan(root: Path, name: str, result: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{name}.json").write_text(json.dumps(result))


@pytest.mark.parametrize("side", ["vulnerable", "fixed"])
def test_feature_scan_names_and_repeat_union(tmp_path: Path, side: str) -> None:
    single = scan()
    write_scan(tmp_path, f"v1--{side}", single)
    assert builder.resolve_scan(tmp_path, "v1", side) == single
    write_scan(tmp_path, f"v2--{side}_a", single)
    other = scan(2)
    other["findings"].extend(single["findings"])
    other["completed"] = 1
    write_scan(tmp_path, f"v2--{side}_b", other)
    result = builder.resolve_scan(tmp_path, "v2", side)
    part = builder.recorded_engine("typescript", result["findings"], result, True)
    assert part.state == "ran"
    assert part.values["eng.findings"] == 2  # duplicate from the other repeat counted once
    assert part.values["eng.witness_steps_min"] == 2
    assert part.values["eng.rung_max"] == "model_entailed"
    assert part.values["eng.completion"] == 0.5
    assert part.values["eng.degraded"] is False
    # v1 is authoritative when both naming schemes are present.
    write_scan(tmp_path, f"v2--{side}", single)
    assert builder.resolve_scan(tmp_path, "v2", side) == single


@pytest.mark.parametrize("peer", [None, {"state": "failed", "questions": 4, "completed": 0}])
def test_feature_successful_repeat_survives_missing_or_failed_peer(tmp_path: Path, peer: dict | None) -> None:
    write_scan(tmp_path, "case--fixed_b", scan())
    if peer is not None:
        write_scan(tmp_path, "case--fixed_a", peer)
    result = builder.resolve_scan(tmp_path, "case", "fixed")
    assert builder.engine_for(result) is None
    assert result["findings"] == scan()["findings"]
    assert "repeat_missing_or_failed" in result["degradations"]


def test_feature_missing_scan_is_not_run_and_failed_scan_is_recorded(tmp_path: Path) -> None:
    result = builder.resolve_scan(tmp_path, "absent", "vulnerable")
    part = builder.recorded_engine("python", [], result, True)
    assert part.state == "failed" and part.version == "missing:not-run"
    write_scan(tmp_path, "failed--vulnerable_a", {"questions": 0, "findings": []})
    result = builder.resolve_scan(tmp_path, "failed", "vulnerable")
    part = builder.recorded_engine("python", [], result, True)
    assert part.state == "failed" and part.version == "recorded"


def test_feature_typescript_repository_witness_reaches_static_record(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("function handler(req) {\n  return eval(req.query);\n}\n")
    index = SourceIndex(tmp_path)
    result = scan()
    quick, engine = _signals(index, [], result, {})
    parts = builder.static_parts(
        tmp_path, index, quick, engine, None, result, RoleSet(), {}, "test", "a.ts", "handler", "injection", True, None
    )
    assert parts["engine"].state == "ran"
    assert parts["engine"].values["eng.witness_steps_min"] == 5
    assert parts["engine"].values["eng.findings"] == 1
    assert builder.recorded_engine("typescript", [], None, True).state == "none"
    assert builder.recorded_engine("typescript", [], result, False).state == "none"
    assert builder.recorded_engine("typescript", [], result, True).values["eng.findings"] == 0


def test_feature_dry_run_counts_sources_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    script = tmp_path / "benchmarks/learn/build_features.py"
    script.parent.mkdir(parents=True)
    monkeypatch.setattr(builder, "__file__", str(script))
    manifests = tmp_path / "benchmarks/independent"
    manifests.mkdir()
    for version in (1, 2):
        (manifests / f"population-v{version}.toml").write_text(
            '[[case]]\nid="case"\nrepo="https://github.com/o/r"\nvulnerable="pin"\nfixed="fix"\n'
        )
    results = tmp_path / "results"
    write_scan(results / "independent-v2/scans", "case--vulnerable_b", scan())
    base = {"repo": "github.com/o/r", "pin": "pin", "pin_role": "vulnerable", "split": "population-v2",
            "candidate": "a.ts::handler", "family": "injection", "language": "typescript"}  # fmt: skip
    rows = [
        base | {"source": "population-v2", "instruments": {"engine": {"state": "failed", "version": "missing:not-run"}}},
        base | {"source": "adjudications", "instruments": {"engine": {"state": "none"}}},
    ]
    monkeypatch.setattr(builder.memory.FileStore, "rows", lambda *a, **kw: [SimpleNamespace(row=r) for r in rows])
    monkeypatch.setattr(builder.PinSourceIndex, "__init__", lambda self, *a: None)
    monkeypatch.setattr(builder.PinSourceIndex, "lines", lambda *a: ["function handler(req) {", "return eval(req.query);", "}"])

    def no_write(*args: object, **kwargs: object) -> None:
        pytest.fail("dry run attempted a store write")

    for method in ("_put", "ingest_rows", "put_rows", "drop_rows", "put_blob"):
        monkeypatch.setattr(builder.memory.FileStore, method, no_write)
    counts = tmp_path / "counts.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_features.py",
            "--dry-run",
            "--results-root",
            str(results),
            "--store",
            f"file://{tmp_path / 'memory'}",
            "--counts",
            str(counts),
        ],
    )
    assert builder.main() == 0
    report = json.loads(capsys.readouterr().out)["by_source"]
    assert report["population-v2"]["not_run_to_ran"] == 1
    assert report["adjudications"]["none_to_ran"] == 1
    assert not counts.exists() and not (tmp_path / "memory").exists()


def test_feature_unread_pin_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(LabelSourceError, match="no clone"):
        builder.PinSourceIndex(tmp_path, "pin")


def test_feature_dry_run_rejects_network_store_before_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["build_features.py", "--dry-run", "--store", "s3://bucket"])
    monkeypatch.setattr(builder.memory, "open_store", lambda *a: pytest.fail("remote store was opened"))
    with pytest.raises(SystemExit) as exc:
        builder.main()
    assert exc.value.code == 2
