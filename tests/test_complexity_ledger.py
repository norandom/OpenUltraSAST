import json
from pathlib import Path
from types import SimpleNamespace

from openultrasast.complexity.ledger import (
    NOT_TRIGGERABLE_DELTA,
    TRIGGERABLE_DELTA,
    LedgerEntry,
    apply_overlay,
    hotspot_key,
    load_ledger,
    must_keep_as_candidate,
    persist_verdicts,
    record_verdict,
    select_forced_candidates,
    write_ledger,
)
from openultrasast.complexity.map import Hotspot, build_complexity_map
from openultrasast.findings import StaticFinding
from openultrasast.policy import CwePolicy
from openultrasast.preprocess import FileTarget


def _target(
    path: str,
    *,
    loc: int,
    tags: list[str] | None = None,
    language: str = "python",
    hints: list[dict[str, object]] | None = None,
    has_fuzz_entry_point: bool = False,
) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language=language,
        loc=loc,
        tags=list(tags or []),
        has_fuzz_entry_point=has_fuzz_entry_point,
        reachability_hints=list(hints or []),
    )


def _hit(
    path: str,
    finding_id: str,
    *,
    function_name: str | None = None,
    reachability: str = "unknown",
    severity: str = "low",
    rationale: str = "inventory",
) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path=path,
        title="pattern hit",
        severity=severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale=rationale,
        line=1,
        function_name=function_name,
        reachability_status=reachability,
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[],
        ranking_priority=1.0,
    )


def _hotspot(
    path: str,
    *,
    function_name: str | None = None,
    score: float = 4.0,
    band: str = "medium",
    inventory_finding_ids: tuple[str, ...] = (),
) -> Hotspot:
    return Hotspot(
        path=path,
        function_name=function_name,
        score=score,
        band=band,
        signals={"loc": 10, "inventory_hit_count": len(inventory_finding_ids)},
        rationale=f"{band} band: score {score}",
        test_hint=None,
        inventory_finding_ids=inventory_finding_ids,
    )


def test_hotspot_key_joins_path_and_function_or_empty() -> None:
    assert hotspot_key("parser.c", "parse_header") == "parser.c:parse_header"
    assert hotspot_key("src/app.py", None) == "src/app.py:"
    assert hotspot_key("src/app.py", "") == "src/app.py:"


def test_triggerable_overlay_raises_later_score() -> None:
    hotspot = _hotspot("parser.c", function_name="parse_header", score=4.0, inventory_finding_ids=("hit:1",))
    ledger = record_verdict({}, path="parser.c", function_name="parse_header", verdict="triggerable")

    overlaid = apply_overlay((hotspot,), ledger)
    raised = overlaid[0]

    assert ledger[hotspot_key("parser.c", "parse_header")].score_delta == TRIGGERABLE_DELTA
    assert TRIGGERABLE_DELTA > 0
    assert raised.score == hotspot.score + TRIGGERABLE_DELTA
    assert raised.score > hotspot.score
    assert raised.inventory_finding_ids == ("hit:1",)


def test_not_triggerable_overlay_drops_score_and_keeps_inventory_hit() -> None:
    hotspot = _hotspot("src/auth.py", function_name="login", score=5.0, inventory_finding_ids=("cmd:src/auth.py:12",))
    ledger = {
        hotspot_key("src/auth.py", "login"): LedgerEntry(
            score_delta=NOT_TRIGGERABLE_DELTA,
            last_verdict="not_triggerable",
            round=1,
        )
    }

    overlaid = apply_overlay((hotspot,), ledger)
    demoted = overlaid[0]

    assert NOT_TRIGGERABLE_DELTA < 0
    assert demoted.score == hotspot.score + NOT_TRIGGERABLE_DELTA
    assert demoted.score < hotspot.score
    assert demoted.inventory_finding_ids == ("cmd:src/auth.py:12",)
    assert demoted.path == hotspot.path
    assert demoted.function_name == hotspot.function_name


def test_not_triggerable_overlay_drops_map_score_and_sev5_reachable_stays_candidate(tmp_path: Path) -> None:
    auth = _target(
        "src/auth.py",
        loc=80,
        tags=["auth_boundary"],
        hints=[{"kind": "route", "access_level": "public", "function_name": "login"}],
    )
    helper = _target("src/helper.py", loc=12, tags=[])
    sev5 = _hit(
        "src/auth.py",
        "cmd:src/auth.py:12",
        function_name="login",
        reachability="reachable",
        severity="critical",
        rationale="Static pattern cmd (CWE-78) matched os.system on line 12; manual verification still required.",
    )
    noise = _hit("src/helper.py", "print:src/helper.py:1", reachability="unknown", severity="low")
    artifact = tmp_path / "complexity_map.json"

    baseline = build_complexity_map([auth, helper], [sev5, noise], artifact)
    original = next(item for item in baseline.hotspots if item.path == "src/auth.py")
    assert sev5.finding_id in original.inventory_finding_ids

    ledger_path = tmp_path / ".openultrasast" / "calibration" / "complexity_ledger.json"
    write_ledger(
        ledger_path,
        record_verdict({}, path=original.path, function_name=original.function_name, verdict="not_triggerable"),
    )

    overlaid = build_complexity_map([auth, helper], [sev5, noise], artifact, ledger_path=ledger_path)
    demoted = next(item for item in overlaid.hotspots if item.path == "src/auth.py")

    assert demoted.score < original.score
    assert demoted.score == original.score + NOT_TRIGGERABLE_DELTA
    assert demoted.inventory_finding_ids == original.inventory_finding_ids
    assert sev5.finding_id in demoted.inventory_finding_ids
    assert sev5.severity == "critical"
    assert sev5.rationale == ("Static pattern cmd (CWE-78) matched os.system on line 12; manual verification still required.")

    policy = {
        sev5.finding_id: 5,
        noise.finding_id: 2,
    }
    forced = select_forced_candidates([sev5, noise], policy)
    assert forced == (sev5,)
    assert must_keep_as_candidate(sev5, 5, "reachable") is True
    assert must_keep_as_candidate(noise, 2, "unknown") is False


def test_must_keep_as_candidate_requires_sev5_and_reachable_surface() -> None:
    reachable = _hit("a.py", "a:1", reachability="reachable")
    inferred = _hit("b.py", "b:1", reachability="inferred-file-surface")
    unknown = _hit("c.py", "c:1", reachability="unknown")

    assert must_keep_as_candidate(reachable, 5, "reachable") is True
    assert must_keep_as_candidate(inferred, 5, "inferred-file-surface") is True
    assert must_keep_as_candidate(unknown, 5, "unknown") is False
    assert must_keep_as_candidate(reachable, 4, "reachable") is False
    assert must_keep_as_candidate(reachable, 5, None) is True


def test_select_forced_candidates_resolves_policy_severity() -> None:
    sev5 = _hit("src/auth.py", "cmd:src/auth.py:12", reachability="reachable")
    inferred = _hit("src/upload.py", "sql:src/upload.py:4", reachability="inferred-file-surface")
    mild = _hit("src/helper.py", "print:src/helper.py:1", reachability="reachable")
    policy = {
        "CWE-78": CwePolicy("Command Injection", 5, True, False),
        "CWE-89": CwePolicy("SQL Injection", 5, True, False),
        "CWE-116": CwePolicy("Encode Output", 2, True, False),
    }

    forced = select_forced_candidates(
        [mild, sev5, inferred],
        policy,
        rule_cwe={
            sev5.finding_id: "CWE-78",
            inferred.finding_id: "CWE-89",
            mild.finding_id: "CWE-116",
        },
    )

    assert forced == (sev5, inferred)


def test_ledger_round_trip_matches_design_schema(tmp_path: Path) -> None:
    path = tmp_path / "complexity_ledger.json"
    key = hotspot_key("parser.c", "parse_header")
    write_ledger(
        path,
        {key: LedgerEntry(score_delta=1.5, last_verdict="triggerable", round=3)},
    )
    payload = json.loads(path.read_text())

    assert payload == {
        key: {
            "last_verdict": "triggerable",
            "round": 3,
            "score_delta": 1.5,
        }
    }
    loaded = load_ledger(path)
    assert loaded[key] == LedgerEntry(score_delta=1.5, last_verdict="triggerable", round=3)
    assert load_ledger(tmp_path / "missing.json") == {}
    assert load_ledger(None) == {}


def test_overlay_reorders_and_rebands_without_dropping_hits() -> None:
    high = _hotspot("src/auth.py", function_name="login", score=3.2, band="medium", inventory_finding_ids=("sev5:1",))
    other = _hotspot("src/helper.py", score=2.0, band="low", inventory_finding_ids=("low:1",))
    ledger = record_verdict({}, path="src/auth.py", function_name="login", verdict="not_triggerable")

    overlaid = apply_overlay((high, other), ledger)

    assert [item.path for item in overlaid] == ["src/helper.py", "src/auth.py"]
    demoted = overlaid[1]
    assert demoted.score == round(3.2 + NOT_TRIGGERABLE_DELTA, 4)
    assert demoted.band == "low"
    assert demoted.inventory_finding_ids == ("sev5:1",)
    assert overlaid[0].inventory_finding_ids == ("low:1",)


def test_persist_verdicts_records_triggerable_and_skips_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / ".openultrasast" / "calibration" / "complexity_ledger.json"
    persist_verdicts(
        path,
        [
            SimpleNamespace(path="app.py", function_name="admin", verdict="triggerable"),
            SimpleNamespace(path="safe.py", function_name=None, verdict="not_triggerable"),
            SimpleNamespace(path="other.py", function_name="skip", verdict="inconclusive"),
        ],
    )
    loaded = load_ledger(path)

    assert loaded[hotspot_key("app.py", "admin")].last_verdict == "triggerable"
    assert loaded[hotspot_key("app.py", "admin")].score_delta == TRIGGERABLE_DELTA
    assert loaded[hotspot_key("safe.py", None)].last_verdict == "not_triggerable"
    assert loaded[hotspot_key("safe.py", None)].score_delta == NOT_TRIGGERABLE_DELTA
    assert hotspot_key("other.py", "skip") not in loaded


def test_build_complexity_map_without_ledger_path_skips_overlay(tmp_path: Path) -> None:
    target = _target("src/app.py", loc=20)
    finding = _hit("src/app.py", "rule:src/app.py:1")
    artifact = tmp_path / "complexity_map.json"

    first = build_complexity_map([target], [finding], artifact)
    second = build_complexity_map([target], [finding], artifact)

    assert first.hotspots[0].score == second.hotspots[0].score
    assert first.hotspots[0].inventory_finding_ids == (finding.finding_id,)
