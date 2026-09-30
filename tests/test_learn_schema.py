"""The candidate feature schema (learned-decision-engine task 1; Req 1.2, 7.2): a closed allow-list with no
identities, missing distinct from zero, and no label-carrying field reaching a feature."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

import pytest

from openultrasast.findings import quick_scan_findings
from openultrasast.learn import schema
from openultrasast.learn.features import Delta, Part, build_for_scan, record
from openultrasast.learn.schema import EXCLUDED_FIELDS, FEATURES, FeatureRecordError, validate_record
from openultrasast.mapping import analyze_entry_points, attach_reachability_hints
from openultrasast.plane.tasks.features import case_features
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets

ROOT = Path(__file__).resolve().parents[1]
APP = """import os


def {inner}(value):
    os.system(value)


def {outer}():
    {inner}("x")
"""


def _scan(root: Path) -> list[dict[str, Any]]:
    _, targets = preprocess_repository(root)
    assert targets and all((root / t.path).stat().st_size > 0 for t in targets), "the fixture was read"
    targets = attach_reachability_hints(targets, analyze_entry_points(root, targets))
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    assert findings, "the fixture's os.system fires a quick rule"
    engine = {"questions": 3, "completed": 3, "degradations": [], "findings": []}
    return build_for_scan(root, findings, engine)


def _repo(root: Path, path: str, inner: str, outer: str) -> Path:
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / path).write_text(APP.format(inner=inner, outer=outer))
    return root


# --- the allow-list ----------------------------------------------------------------------------------------------


def test_features_are_allow_listed(tmp_path: Path) -> None:
    names = [spec.name for spec in FEATURES]
    assert len(names) == len(set(names)), "a feature name is declared twice"
    for spec in FEATURES:
        assert spec.type in ("bool", "int", "float", "enum"), f"{spec.name}: no free text"
        assert spec.instrument in schema.INSTRUMENTS and spec.profile in schema.PROFILES
        assert (spec.type == "int") == (spec.cap is not None), spec.name
        assert (spec.type == "enum") == bool(spec.vocabulary), spec.name
        assert spec.name.rsplit(".", 1)[-1] not in EXCLUDED_FIELDS, f"{spec.name} names a label or identity field"
    mechanisms = tomllib.loads((ROOT / "benchmarks" / "pairs" / "mechanisms.toml").read_text())["mechanism"]
    assert tuple(m["id"] for m in mechanisms) == schema.MECHANISMS, "the mechanism buckets are the closed vocabulary"
    assert set(schema.RULE_TAG_MECHANISM.values()) <= set(schema.MECHANISMS)
    records = _scan(_repo(tmp_path, "app/one.py", "alpha", "beta"))
    assert records
    for rec in records:
        assert set(rec["x"]) == {s.name for s in schema.features_for("static")}, "every emitted key is in FEATURES"
        assert rec["profile"] == "static" and not any(k.startswith(("verify.", "agree.", "ms.")) for k in rec["x"])
    assert {s.name for s in schema.features_for("static")} < set(names)
    assert [s.name for s in FEATURES if s.prior] == ["qr.prior_hits"]


def test_record_is_name_invariant(tmp_path: Path) -> None:
    """Two repositories that differ only in repository name, paths, file and function names and commit ids give the
    same features: nothing identifies a repository."""
    first = _scan(_repo(tmp_path / "acme-shop", "app/one.py", "alpha", "beta"))
    second = _scan(_repo(tmp_path / "other-thing", "lib/sub/two.py", "gamma", "delta"))
    assert [r["x"] for r in first] == [r["x"] for r in second]
    assert [r["instruments"] for r in first] == [r["instruments"] for r in second]
    assert first[0]["candidate"] != second[0]["candidate"], "the key differs; it lives only in the envelope"
    assert first[0]["x"]["qr.enabled_hits"] >= 1 and first[0]["x"]["facts.entry_distance"] is not None
    root = tmp_path / "acme-shop"
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    changed = {"app/one.py": [(5, 5)]}
    one = build_for_scan(root, findings, None, base=Delta(root, changed, pin="a" * 40))
    two = build_for_scan(root, findings, None, base=Delta(root, changed, pin="b" * 40))
    assert len(one) == 1 and one[0]["unit"] == "delta" and one[0]["base"] == "a" * 40
    assert one[0]["x"]["delta.novelty"] == "new" and one[0]["x"]["delta.changed_lines"] == 1
    assert [r["x"] for r in one] == [r["x"] for r in two], "a commit id is envelope, never a feature"


# --- label fields ------------------------------------------------------------------------------------------------

AGREED = {
    "family": "injection",
    "candidates": [
        {"candidate": "a.py::f", "site": "a.py:4:f", "a": True, "b": False, "c": True, "agreed": True, "site_match": True,
         "finding": {"family": "injection", "reported_at": "a.py:5"}},
    ],
    "disputed": [],
}  # fmt: skip
PASSES = {
    "a": [{"path": "a.py", "candidates": [["a.py", "f", 4]], "flagged": [{"candidate": "a.py::f", "reported_at": "a.py:5"}], "turns": 4}],
    "b": [{"path": "a.py", "candidates": [["a.py", "f", 4]], "flagged": [], "turns": 6}],
    "c": [{"path": "a.py", "candidates": [["a.py", "f", 4]], "flagged": [{"candidate": "a.py::f", "reported_at": "a.py:4"}], "turns": 5}],
}
ALERTS = [
    {"rule_id": "python-os-command", "rule_status": "enabled", "path": "a.py", "line": 5, "function": "f", "pin_role": "vulnerable",
     "in_fix_range": True},
]  # fmt: skip
SUMMARY = {"status": "done", "quick_languages": ["python"], "engine_languages": ["php"]}


def _plane(**overrides: Any) -> list[dict[str, Any]]:
    inputs: dict[str, Any] = {
        "facts": {"callers": {"a.py::f": [{"path": "b.py", "line": 2}]}}, "passes": PASSES, "models": {"a": "m", "b": "m", "c": "m"},
        "agreed": AGREED, "alerts": ALERTS, "alerts_summary": SUMMARY,
    }  # fmt: skip
    return case_features(**{**inputs, **overrides})


def test_label_fields_never_reach_features() -> None:
    baseline = _plane()
    assert [r["candidate"] for r in baseline] == ["a.py::f"] and baseline[0]["profile"] == "plane"
    x = baseline[0]["x"]
    assert (x["verify.flag_a"], x["verify.flag_b"], x["verify.flag_c"], x["verify.votes"]) == (True, False, True, 2)
    assert x["agree.final"] == "agreed" and x["qr.enabled_hits"] == 1 and x["verify.site_offset"] == 0
    flipped = copy.deepcopy(AGREED)
    flipped["candidates"][0]["site_match"] = False
    outside = [{**ALERTS[0], "in_fix_range": False}]
    fixed_pin = [*ALERTS, {**ALERTS[0], "pin_role": "fixed", "line": 9}, {**ALERTS[0], "pin_role": "fixed", "function": "g"}]
    for variant in (_plane(agreed=flipped), _plane(alerts=outside), _plane(alerts=fixed_pin)):
        assert variant == baseline, "site_match, in_fix_range and fixed-pin alerts change nothing"
    for field in ("site_match", "in_fix_range", "rule_id", "path", "repo", "usd"):
        smuggled = copy.deepcopy(baseline[0])
        smuggled["x"][field] = True
        with pytest.raises(FeatureRecordError, match="allow-list"):
            validate_record(smuggled)
        with pytest.raises(FeatureRecordError):
            validate_record({**baseline[0], field: True})


# --- missing is not zero -----------------------------------------------------------------------------------------


def test_missing_is_not_zero() -> None:
    uncovered = _plane(alerts=[], alerts_summary={**SUMMARY, "quick_languages": ["php"]})[0]
    assert uncovered["instruments"]["quick"]["state"] == "none"
    assert all(v is None for k, v in uncovered["x"].items() if k.startswith("qr."))
    covered = _plane(alerts=[])[0]
    assert covered["instruments"]["quick"]["state"] == "ran"
    assert covered["x"]["qr.enabled_hits"] == 0 and covered["x"]["qr.shadow_hits"] == 0, "ran and found nothing is 0"
    no_alerts = _plane(alerts=[], alerts_summary=None)[0]
    assert no_alerts["instruments"]["quick"]["state"] == "none" and no_alerts["x"]["qr.enabled_hits"] is None
    assert covered["instruments"]["engine"]["state"] == "none" and covered["x"]["eng.findings"] is None
    assert covered["instruments"]["delta"]["state"] == "not_applicable" and covered["x"]["delta.novelty"] is None
    failed = _plane(alerts_summary={**SUMMARY, "status": "failed"})[0]
    assert failed["instruments"]["quick"]["state"] == "failed" and failed["x"]["qr.enabled_hits"] is None
    php = {"path": "p.php", "line": 3, "function": "q", "pin_role": "vulnerable", "rule_id": "engine:injection", "rule_status": "enabled"}
    engine = {**SUMMARY, "engine": {"vulnerable": {"questions": 0, "completed": 0, "files": 5, "degradations": []}}}
    [_, unread] = _plane(alerts=[*ALERTS, php], alerts_summary=engine)
    assert unread["instruments"]["engine"]["state"] == "failed" and unread["x"]["eng.findings"] is None, "no question is not zero"


def test_build_for_scan_marks_an_engine_that_did_not_run_or_read(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r", "app/one.py", "alpha", "beta")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    unread = build_for_scan(root, findings, {"questions": 0, "findings": []})
    absent = build_for_scan(root, findings, None)
    assert {r["instruments"]["engine"]["state"] for r in unread} == {"failed"}
    assert {r["instruments"]["engine"]["state"] for r in absent} == {"none"}
    assert all(r["x"]["eng.findings"] is None for r in (*unread, *absent))


def test_validate_record_refuses_values_outside_their_type() -> None:
    good = _plane()[0]
    validate_record(good)
    for name, value in (("agree.final", "maybe"), ("verify.votes", 4), ("qr.enabled_hits", -1), ("lang.python", 1)):
        bad = copy.deepcopy(good)
        bad["x"][name] = value
        with pytest.raises(FeatureRecordError, match=name.replace(".", r"\.")):
            validate_record(bad)
    null = copy.deepcopy(good)
    null["x"]["agree.final"] = None
    with pytest.raises(FeatureRecordError, match="null is not allowed"):
        validate_record(null)
    value = copy.deepcopy(good)
    value["x"]["ms.flagged"] = False
    with pytest.raises(FeatureRecordError, match="must be null"):
        validate_record(value)
    with pytest.raises(FeatureRecordError, match="outside the static profile"):
        record("a.py::f", "injection", "python", "static", {"verify": Part("ran", {})})
