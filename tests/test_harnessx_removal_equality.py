"""The equality instrument (harnessx-removal design section 3) sees a difference when there is one.

A comparison that always says "equal" would prove nothing, so these tests feed it records that differ in one
place each and require it to name that place, and records that differ only in excluded fields and require it
to pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("hxr_equality", ROOT / "benchmarks" / "archive" / "harnessx_removal_equality.py")
assert _SPEC is not None and _SPEC.loader is not None
equality = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(equality)


def _record(path: Path, *, findings: object, suite: dict[str, str], stdout: str = "findings=3\n") -> Path:
    (path / "scan").mkdir(parents=True)
    (path / "suite.json").write_text(equality.dump(suite))
    (path / "scan" / "findings.json").write_text(equality.dump(findings))
    (path / "scan" / "stdout.txt").write_text(stdout)
    (path / "env.json").write_text(json.dumps({"tree_ish": str(path)}))
    return path


def _normalized(raw: dict[str, object], root: str) -> object:
    return equality.normalize(raw, root, "/tmp/x")


def test_excluded_fields_and_run_ids_do_not_count(tmp_path: Path) -> None:
    a = _normalized({"rule": "sqli", "runtime_seconds": 1.2, "path": "/r1/runs/20260930T101010Z-0123abcd/f.py", "t_ms": 4}, "/r1")
    b = _normalized({"rule": "sqli", "runtime_seconds": 9.9, "path": "/r2/runs/20261001T111111Z-ffffffff/f.py", "t_ms": 7}, "/r2")
    suite = {"tests.test_x::test_a": "passed"}
    diffs = equality.compare(_record(tmp_path / "a", findings=a, suite=suite), _record(tmp_path / "b", findings=b, suite=suite), {})
    assert diffs == []


def test_a_changed_finding_is_reported_with_its_key(tmp_path: Path) -> None:
    suite = {"tests.test_x::test_a": "passed"}
    a = _record(tmp_path / "a", findings=[{"rule": "sqli", "line": 3}], suite=suite)
    b = _record(tmp_path / "b", findings=[{"rule": "sqli", "line": 4}], suite=suite)
    assert equality.compare(a, b, {}) == ["scan/findings.json: $[0].line: 3 -> 4"]
    assert equality.main(["compare", str(a), str(b)]) == 1


def test_a_changed_outcome_or_unmapped_test_is_reported(tmp_path: Path) -> None:
    a = _record(tmp_path / "a", findings=[], suite={"t::a": "passed", "t::gone": "passed", "t::old": "skipped"})
    b = _record(tmp_path / "b", findings=[], suite={"t::a": "failure", "t::new": "skipped", "t::extra": "passed"}, stdout="findings=2\n")
    diffs = equality.compare(a, b, {"deleted": ["t::gone"], "renamed": {"t::old": "t::new"}})
    assert diffs == [
        "suite.json: t::a passed -> failure",
        "suite.json: t::extra new in candidate",
        "scan/stdout.txt: first differing line 1: 'findings=3' -> 'findings=2'",
    ]


def test_a_file_present_on_one_side_only_is_reported(tmp_path: Path) -> None:
    a = _record(tmp_path / "a", findings=[], suite={})
    b = _record(tmp_path / "b", findings=[], suite={})
    (b / "scan" / "fusion.json").write_text("[]\n")
    assert equality.compare(a, b, {}) == ["scan/fusion.json: present only in candidate"]
