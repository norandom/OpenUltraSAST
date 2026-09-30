"""The tie-break of the first increment's revisit (ai-service-plane Requirement 6.4, task 8.1): `verify` restricted
to the candidates passes a and b disputed (`OUSAST_INPUT_ONLY`), and `agree` deciding 2-of-3 where pass c asked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_plane_verify import CANDIDATES, FACTS, FLASH, HuntClient, _two_passes, _workspace

from openultrasast.plane.budget import MeteredClient
from openultrasast.plane.tasks import agree, verify
from openultrasast.tool_hunter import CLIENT_ENV

SITES = {"id": "case", "family": "injection", "sites": ["app.py::run", "db.py::query"], "ranges": {"app.py": [[40, 41]]}}


def _verify(root: Path, out: Path, client: HuntClient, only: set[str] | None, label: str = "c") -> dict:
    metered = MeteredClient(client, prices=FLASH)  # type: ignore[arg-type]
    return verify.run(root, out, CANDIDATES, FACTS, client=client, budget=metered, model="deepseek-chat", pass_label=label, only=only)


def test_only_restricts_the_hunt_to_the_named_candidates(tmp_path: Path) -> None:
    client = HuntClient({"app.py::other"})
    summary = _verify(_workspace(tmp_path), tmp_path / "c", client, {"app.py::other", "gone.py::f"})
    assert summary["status"] == "done" and summary["units_total"] == 1 and summary["only"] == 1 and summary["pass"] == "c"
    prompts = client.prompts()
    assert prompts and all("`other`" in p and "`run`" not in p and "db.py" not in p for p in prompts)
    rows = [json.loads(line) for line in (tmp_path / "c" / "units.jsonl").read_text().splitlines()]
    assert [r["candidates"] for r in rows] == [[["app.py", "other", 5]]]
    assert [f["candidate"] for f in rows[0]["flagged"]] == ["app.py::other"]


def test_only_names_reads_disputed_json_rows_and_names() -> None:
    disputed = [{"candidate": "a.py::f", "site": "a.py:1:f", "passes": 1}]
    assert verify.only_names(disputed) == {"a.py::f"}
    assert verify.only_names({"disputed": disputed}) == {"a.py::f"}
    assert verify.only_names([["b.py", "g", 3], "c.py::h"]) == {"b.py::g", "c.py::h"}
    with pytest.raises(ValueError):
        verify.only_names("a.py::f")


def test_an_empty_restriction_is_done_with_zero_units_and_no_call(tmp_path: Path) -> None:
    client = HuntClient({"app.py::run"})
    summary = _verify(_workspace(tmp_path), tmp_path / "c", client, set())
    assert summary["status"] == "done" and (summary["units_done"], summary["units_total"], summary["calls"]) == (0, 0, 0)
    assert client.calls == [] and (tmp_path / "c" / "units.jsonl").read_text() == ""


def test_main_with_an_empty_only_list_needs_no_model_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, out = _workspace(tmp_path), tmp_path / "out"
    (tmp_path / "candidates.json").write_text(json.dumps(CANDIDATES))
    (tmp_path / "disputed.json").write_text("[]\n")
    for name in ("DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", CLIENT_ENV, "OUSAST_CLIENT"):
        monkeypatch.delenv(name, raising=False)
    env = {
        "OUSAST_WORKSPACE_DIR": str(root), "OUSAST_OUTPUT_DIR": str(out), "OUSAST_INPUT_CANDIDATES": str(tmp_path / "candidates.json"),
        "OUSAST_INPUT_ONLY": str(tmp_path / "disputed.json"), "OUSAST_MODEL": "deepseek-chat", "OUSAST_PASS": "c",
    }  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert verify.main() == 0
    summary = json.loads((out / "summary.json").read_text())
    assert (summary["status"], summary["units_total"], summary["calls"], summary["only"]) == ("done", 0, 0, 0)


def _pass_c(tmp_path: Path, root: Path, disputed: Path, flag: set[str]) -> list[dict]:
    only = verify.only_names(json.loads(disputed.read_text()))
    _verify(root, tmp_path / "pass-c", HuntClient(flag), only)
    return agree.load_pass(tmp_path / "pass-c")


def _final(tmp_path: Path, a: Path, b: Path, c: list[dict] | None) -> dict:
    return agree.run(tmp_path / "final", CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=SITES, pass_c=c)


def test_a_and_c_agreeing_flips_a_disputed_candidate_to_agreed(tmp_path: Path) -> None:
    root, a, b = _two_passes(tmp_path)  # a: run, query; b: run, other -> disputed: other (b), query (a)
    first = agree.run(tmp_path / "agree", CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=SITES)
    c = _pass_c(tmp_path, root, tmp_path / "agree" / "disputed.json", {"db.py::query", "app.py::run"})
    summary = _final(tmp_path, a, b, c)
    report = json.loads((tmp_path / "final" / "agreed.json").read_text())
    rows = {r["candidate"]: (r["a"], r["b"], r["c"], r["agreed"]) for r in report["candidates"]}
    assert rows == {
        "app.py::run": (True, True, None, True),  # not asked in c: the a/b rule
        "app.py::other": (False, True, False, False),  # b alone
        "db.py::query": (True, False, True, True),  # a + c
    }
    assert [f["candidate"] for f in report["agreed"]] == ["app.py::run", "db.py::query"]
    assert [f["candidate"] for f in report["disputed"]] == ["app.py::other"]
    metrics = summary["metrics"]
    assert metrics["tiebreak"]["asked"] == 2 and metrics["tiebreak"]["flipped_to_agreed"] == 1
    assert metrics["tiebreak"]["flipped_to_rejected"] == 0 and "2 of passes a, b, c" in metrics["tiebreak"]["rule"]
    assert metrics["agreed"] == 2 and metrics["disputed"] == 1
    assert first["metrics"]["declared_sites_matched_agreed"] == 1 and metrics["declared_sites_matched_agreed"] == 2
    assert metrics["hunts"] == first["metrics"]["hunts"] + 2 and metrics["usd_total"] > first["metrics"]["usd_total"]
    assert set(first["metrics"]) - {"tiebreak"} <= set(metrics)


def test_b_and_c_agreeing_flips_to_agreed_and_a_lone_a_is_rejected(tmp_path: Path) -> None:
    root, a, b = _two_passes(tmp_path)
    agree.run(tmp_path / "agree", CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=SITES)
    c = _pass_c(tmp_path, root, tmp_path / "agree" / "disputed.json", {"app.py::other"})
    report_metrics = _final(tmp_path, a, b, c)["metrics"]
    report = json.loads((tmp_path / "final" / "agreed.json").read_text())
    assert [f["candidate"] for f in report["agreed"]] == ["app.py::other", "app.py::run"]
    assert [f["candidate"] for f in report["disputed"]] == ["db.py::query"]
    assert report_metrics["declared_sites_matched_agreed"] == 1 and report_metrics["tiebreak"]["flipped_to_agreed"] == 1


def test_without_pass_c_the_a_b_rule_and_numbers_are_unchanged(tmp_path: Path) -> None:
    _, a, b = _two_passes(tmp_path)
    before = agree.run(tmp_path / "ab", CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=SITES)["metrics"]
    empty = _final(tmp_path, a, b, [])["metrics"]
    assert before["tiebreak"] == {"asked": 0, "flipped_to_agreed": 0, "flipped_to_rejected": 0, "rule": agree.RULE_A_B}
    assert empty["tiebreak"]["rule"] == agree.RULE_2_OF_3 and empty["tiebreak"]["asked"] == 0
    assert {k: v for k, v in empty.items() if k != "tiebreak"} == {k: v for k, v in before.items() if k != "tiebreak"}


def test_pass_c_alone_never_decides(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    a, b = tmp_path / "pass-a", tmp_path / "pass-b"
    for out in (a, b):
        _verify(root, out, HuntClient({"app.py::run"}), None, label=out.name[-1])
    c = tmp_path / "pass-c"
    _verify(root, c, HuntClient({"app.py::other"}), None)  # asked about everything, flags only what a and b rejected
    metrics = _final(tmp_path, a, b, agree.load_pass(c))["metrics"]
    report = json.loads((tmp_path / "final" / "agreed.json").read_text())
    assert [f["candidate"] for f in report["agreed"]] == ["app.py::run"]  # 2 of 3 without c's vote
    assert [f["candidate"] for f in report["disputed"]] == ["app.py::other"]  # 1 of 3
    assert metrics["tiebreak"] == {"asked": 3, "flipped_to_agreed": 0, "flipped_to_rejected": 0, "rule": agree.RULE_2_OF_3}


def test_agree_main_reads_pass_c(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, a, b = _two_passes(tmp_path)
    agree.run(tmp_path / "agree", CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=SITES)
    _pass_c(tmp_path, root, tmp_path / "agree" / "disputed.json", {"db.py::query"})
    (tmp_path / "candidates.json").write_text(json.dumps(CANDIDATES))
    (tmp_path / "case.json").write_text(json.dumps(SITES))
    env = {
        "OUSAST_OUTPUT_DIR": str(tmp_path / "final"), "OUSAST_INPUT_PASS_A": str(a / "units.jsonl"),
        "OUSAST_INPUT_PASS_B": str(b / "units.jsonl"), "OUSAST_INPUT_PASS_C": str(tmp_path / "pass-c" / "units.jsonl"),
        "OUSAST_INPUT_CANDIDATES": str(tmp_path / "candidates.json"), "OUSAST_INPUT_SITES": str(tmp_path / "case.json"),
    }  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert agree.main() == 0
    metrics = json.loads((tmp_path / "final" / "summary.json").read_text())["metrics"]
    assert metrics["agreed"] == 2 and metrics["tiebreak"]["flipped_to_agreed"] == 1
