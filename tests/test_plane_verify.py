"""verify and agree tasks (ai-service-plane task 6): callers in the prompt, per-unit resume, 402 -> failed,
budget -> unfinished, the bound model and summed usage in summary.json, agreement and metrics over two passes."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from openultrasast.plane.budget import MeteredClient
from openultrasast.plane.tasks import agree, verify
from openultrasast.tool_hunter import ChatResponse, ToolCall

FLASH = {"cache_hit_per_m": 0.014, "input_per_m": 0.44, "output_per_m": 1.32}
ROW = {"prompt_tokens": 1000, "prompt_cache_hit_tokens": 200, "completion_tokens": 50}


class HuntClient:
    """A scripted hunter that answers from the conversation: a read_file turn first, then a JSON verdict naming
    the candidates in `flag` for the file the prompt asked about. Records provider usage rows like
    `DeepSeekChatClient`, so `MeteredClient` can price it; a step index in `raise_at` raises instead."""

    def __init__(self, flag: set[str], *, raise_at: dict[int, Exception] | None = None) -> None:
        self.flag = flag
        self.raise_at = raise_at or {}
        self.usage: list[dict[str, object]] = []
        self.calls: list[list[dict[str, object]]] = []

    def complete(self, *, model: str, messages: list[dict[str, object]], tools: list[dict[str, object]], **_: object) -> ChatResponse:
        index = len(self.calls)
        self.calls.append(list(messages))
        if index in self.raise_at:
            raise self.raise_at[index]
        self.usage.append(dict(ROW))
        prompt = str(messages[1]["content"])
        path = re.search(r"all in `([^`]+)`", prompt).group(1)  # type: ignore[union-attr]
        if not any(m.get("role") == "tool" for m in messages):
            return ChatResponse(tool_calls=(ToolCall(id="c1", name="read_file", arguments={"path": path}),))
        names = re.findall(r"- function `([^`]+)` around line (\d+)", prompt)
        found = [
            {
                "path": path,
                "line": int(line),
                "function_name": fn,
                "title": f"{fn} sink",
                "rationale": "request -> sink",
                "family": "injection",
            }
            for fn, line in names
            if f"{path}::{fn}" in self.flag
        ]
        return ChatResponse(content=json.dumps(found))

    def prompts(self) -> list[str]:
        return [str(call[1]["content"]) for call in self.calls]


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run(q):\n    return eval(q)\n\ndef other(x):\n    return exec(x)\n")
    (root / "db.py").write_text("def query(sql):\n    return cursor.execute(sql)\n")
    return root


CANDIDATES = {
    "id": "case",
    "family": "injection",
    "candidates": [["app.py", "run", 2], ["app.py", "other", 5], ["db.py", "query", 2], ["app.py", "run", 2]],
}
FACTS = {
    "files": {"app.py": {"functions": ["run", "other"]}, "db.py": {"functions": ["query"]}},
    "callers": {
        "app.py::run": [{"path": "web.py", "line": 12, "enclosing": "handler"}, {"path": "cli.py", "line": 40, "enclosing": ""}],
        "db.py::query": [{"path": f"m{i}.py", "line": i, "enclosing": f"f{i}"} for i in range(12)],
    },
    "counts": {},
}


def _run(root: Path, out: Path, client: HuntClient, *, facts: dict | None = FACTS, **budget: object) -> dict:
    metered = MeteredClient(client, prices=FLASH, **budget)  # type: ignore[arg-type]
    return verify.run(root, out, CANDIDATES, facts, client=client, budget=metered, model="deepseek-chat", pass_label="a")


def test_prompt_carries_the_known_callers_line_capped_at_eight(tmp_path: Path) -> None:
    client = HuntClient({"app.py::run"})
    summary = _run(_workspace(tmp_path), tmp_path / "out", client)
    assert summary["status"] == "done", summary
    app = next(p for p in client.prompts() if "all in `app.py`" in p)
    # candidates in the reference's sorted order; the callers line follows the candidate it belongs to
    assert (
        "- function `other` around line 5\n- function `run` around line 2\n"
        "  Known callers: web.py:12 in handler(), cli.py:40\nThe file is above." in app
    )
    assert (
        "Known callers" not in app.split("- function `other`")[1].split("- function `run`")[0]
    )  # nothing known: no line, no claim of absence
    db = next(p for p in client.prompts() if "all in `db.py`" in p)
    assert db.count("m") >= 8 and "and 4 more" in db and "m8.py" not in db
    assert verify.SYSTEM in str(client.calls[0][0]["content"])  # the reference's system prompt, unchanged


def test_without_facts_the_prompt_is_the_reference_prompt(tmp_path: Path) -> None:
    client = HuntClient(set())
    _run(_workspace(tmp_path), tmp_path / "out", client, facts=None)
    assert all("Known callers" not in p for p in client.prompts())
    assert any(
        p.endswith("The file is above. For each, trace where the operation's data comes from and whether it is guarded.")
        for p in client.prompts()
    )


def test_units_are_one_row_per_file_hunt_with_anchored_sites(tmp_path: Path) -> None:
    client = HuntClient({"app.py::other", "db.py::query"})
    out = tmp_path / "out"
    summary = _run(_workspace(tmp_path), out, client)
    rows = [json.loads(t) for t in (out / "units.jsonl").read_text().splitlines()]
    assert [(r["path"], [c[1] for c in r["candidates"]], r["turns"], r["pass"]) for r in rows] == [
        ("app.py", ["other", "run"], 1, "a"),
        ("db.py", ["query"], 1, "a"),
    ]
    assert [f["site"] for r in rows for f in r["flagged"]] == ["app.py:5:other", "db.py:2:query"]
    assert rows[0]["usage"] == {**ROW, "prompt_tokens": 2000, "prompt_cache_hit_tokens": 400, "completion_tokens": 100, "calls": 2}
    assert summary["units_done"] == summary["units_total"] == 2


def test_resume_asks_only_the_unfinished_file(tmp_path: Path) -> None:
    root, out = _workspace(tmp_path), tmp_path / "out"
    out.mkdir()
    done_row = {
        "path": "app.py",
        "candidates": [["app.py", "other", 5], ["app.py", "run", 2]],
        "flagged": [],
        "turns": 3,
        "usage": {**ROW, "calls": 4},
        "usd": 0.01,
        "pass": "a",
    }
    errored = {
        "path": "db.py",
        "candidates": [["db.py", "query", 2]],
        "error": "TimeoutError: x",
        "usage": {**ROW, "calls": 1},
        "usd": 0.001,
        "pass": "a",
    }
    (out / "units.jsonl").write_text(json.dumps(done_row) + "\n" + json.dumps(errored) + "\n")
    client = HuntClient({"db.py::query"})
    summary = _run(root, out, client)
    assert [p for p in client.prompts() if "all in `" in p] and all("all in `db.py`" in p for p in client.prompts())
    assert summary["status"] == "done" and summary["units_done"] == 2 and summary["units_total"] == 2
    assert summary["calls"] == 4 + 1 + 2  # the finished row, the errored attempt and this run's hunt all cost money
    rows = [json.loads(t) for t in (out / "units.jsonl").read_text().splitlines()]
    assert len(rows) == 3 and rows[-1]["path"] == "db.py" and "error" not in rows[-1]


def test_a_scripted_402_yields_failed_with_the_provider_message(tmp_path: Path) -> None:
    client = HuntClient(set(), raise_at={1: RuntimeError("HTTP Error 402: Insufficient Balance")})
    out = tmp_path / "out"
    summary = _run(_workspace(tmp_path), out, client)
    assert summary["status"] == "failed" and "402" in summary["reason"] and summary["units_done"] == 0
    assert len(client.calls) == 2  # nothing further was asked
    rows = [json.loads(t) for t in (out / "units.jsonl").read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["error"].startswith("AccountError") and rows[0]["usage"]["calls"] == 1
    assert json.loads((out / "summary.json").read_text())["status"] == "failed"


def test_a_budget_stop_yields_unfinished_and_resumes_under_a_larger_one(tmp_path: Path) -> None:
    root, out = _workspace(tmp_path), tmp_path / "out"
    client = HuntClient({"db.py::query"})
    summary = _run(root, out, client, budget_calls=3)
    assert summary["status"] == "unfinished" and "calls budget exhausted" in summary["reason"]
    assert summary["units_done"] == 1 and summary["units_total"] == 2 and summary["calls"] == 3
    rows = [json.loads(t) for t in (out / "units.jsonl").read_text().splitlines()]
    assert [("error" in r) for r in rows] == [False, True]  # the cut-short hunt is on record, marked for a re-ask
    again = HuntClient({"db.py::query"})
    summary = _run(root, out, again, budget_calls=10)
    assert summary["status"] == "done" and all("all in `db.py`" in p for p in again.prompts())
    assert summary["units_done"] == 2


def test_summary_records_the_bound_model_and_summed_usage(tmp_path: Path) -> None:
    client = HuntClient(set())
    out = tmp_path / "out"
    summary = _run(_workspace(tmp_path), out, client)
    assert summary["model"] == "deepseek-chat" and summary["pass"] == "a" and summary["priced"] is True
    assert summary["usage"] == {"prompt_tokens": 4000, "prompt_cache_hit_tokens": 800, "completion_tokens": 200} and summary["calls"] == 4
    per_call = (200 * 0.014 + 800 * 0.44 + 50 * 1.32) / 1_000_000
    assert summary["usd"] == pytest.approx(4 * per_call, abs=1e-6)
    on_disk = json.loads((out / "summary.json").read_text())
    assert on_disk == summary


def test_an_unpriced_model_reports_usd_none_not_zero(tmp_path: Path) -> None:
    client = HuntClient(set())
    summary = verify.run(_workspace(tmp_path), tmp_path / "out", CANDIDATES, None, client=client, budget=MeteredClient(client), model="m")
    assert summary["usd"] is None and summary["priced"] is False and summary["calls"] == 4


def test_main_runs_the_env_contract_with_the_scripted_seam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, out = _workspace(tmp_path), tmp_path / "out"
    (tmp_path / "candidates.json").write_text(json.dumps(CANDIDATES))
    (tmp_path / "facts.json").write_text(json.dumps(FACTS))
    env = {
        "OUSAST_WORKSPACE_DIR": str(root), "OUSAST_OUTPUT_DIR": str(out), "OUSAST_INPUT_CANDIDATES": str(tmp_path / "candidates.json"),
        "OUSAST_INPUT_FACTS": str(tmp_path / "facts.json"), "OUSAST_MODEL": "deepseek-chat", "OUSAST_MODEL_PARAMS": json.dumps(FLASH),
        "OUSAST_BUDGET_USD": "1.0", "OUSAST_BUDGET_CALLS": "100", "OUSAST_PASS": "b", "OUSAST_CLIENT": "scripted",
    }  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert verify.main() == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "done" and summary["model"] == "deepseek-chat" and summary["pass"] == "b" and summary["units_total"] == 2
    monkeypatch.delenv("OUSAST_MODEL")
    assert verify.main() == 2
    assert "OUSAST_MODEL" in json.loads((out / "summary.json").read_text())["reason"]


def _two_passes(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = _workspace(tmp_path)
    a, b = tmp_path / "pass-a", tmp_path / "pass-b"
    _run(root, a, HuntClient({"app.py::run", "db.py::query"}))
    _run(root, b, HuntClient({"app.py::run", "app.py::other"}))
    return root, a, b


def test_agree_over_two_scripted_passes_computes_agreement_and_metrics(tmp_path: Path) -> None:
    _, a, b = _two_passes(tmp_path)
    out = tmp_path / "agree"
    sites = {"id": "case", "family": "injection", "sites": ["app.py::run", "db.py::query"]}
    summary = agree.run(out, CANDIDATES, agree.load_pass(a), agree.load_pass(b), sites=sites, matcher=agree.load_matcher())
    assert summary["status"] == "done" and summary["usd"] == 0 and summary["calls"] == 0 and summary["model"] is None
    report = json.loads((out / "agreed.json").read_text())
    by_name = {r["candidate"]: r for r in report["candidates"]}
    assert {n: (r["a"], r["b"], r["agreed"], r["site_match"]) for n, r in by_name.items()} == {
        "app.py::run": (True, True, True, True),
        "app.py::other": (False, True, False, False),
        "db.py::query": (True, False, False, True),
    }
    assert [f["candidate"] for f in report["agreed"]] == ["app.py::run"] and report["agreed"][0]["passes"] == 2
    assert sorted(f["candidate"] for f in report["disputed"]) == ["app.py::other", "db.py::query"]
    assert json.loads((out / "disputed.json").read_text()) == report["disputed"]
    metrics = summary["metrics"]
    per_call = (200 * 0.014 + 800 * 0.44 + 50 * 1.32) / 1_000_000
    assert metrics["candidates"] == 3 and metrics["agreed"] == 1 and metrics["disputed"] == 2 and metrics["hunts"] == 4
    assert metrics["declared_sites"] == 2 and metrics["declared_sites_matched"] == 2 and metrics["declared_sites_matched_agreed"] == 1
    assert metrics["usd_total"] == pytest.approx(8 * per_call, abs=1e-6)
    assert metrics["cost_per_candidate"] == pytest.approx(8 * per_call / 3, abs=1e-6)
    assert metrics["turns_per_hunt"] == 1.0 and metrics["calls_per_hunt"] == 2.0 and metrics["site_matching"] == "assessed"
    # a hunt's usd is split over its candidates: app.py's two share one hunt per pass, db.py's one has a hunt alone
    assert by_name["db.py::query"]["usd"] == pytest.approx(4 * per_call, abs=1e-6)
    assert by_name["app.py::run"]["usd"] == pytest.approx(2 * per_call, abs=1e-6)


def test_agree_without_sites_leaves_site_matching_unassessed_and_flags_unasked_candidates(tmp_path: Path) -> None:
    _, a, b = _two_passes(tmp_path)
    rows_b = [r for r in agree.load_pass(b) if r["path"] != "db.py"]
    summary = agree.run(tmp_path / "agree", CANDIDATES, agree.load_pass(a), rows_b)
    assert summary["status"] == "unfinished" and "db.py::query" in summary["reason"]
    report = json.loads((tmp_path / "agree" / "agreed.json").read_text())
    assert {r["candidate"]: (r["b"], r["site_match"]) for r in report["candidates"]}["db.py::query"] == (None, None)
    assert summary["metrics"]["site_matching"] == "not assessed: no sites given"


def test_agree_main_reads_the_env_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, a, b = _two_passes(tmp_path)
    (tmp_path / "candidates.json").write_text(json.dumps(CANDIDATES))
    (tmp_path / "case.toml").write_text(
        '[[case]]\nid = "case"\nfamily = "injection"\nsites = ["app.py::run"]\n\n[[case]]\nid = "x"\nfamily = "injection"\nsites = []\n'
    )
    env = {
        "OUSAST_OUTPUT_DIR": str(tmp_path / "agree"), "OUSAST_INPUT_PASS_A": str(a), "OUSAST_INPUT_PASS_B": str(b / "units.jsonl"),
        "OUSAST_INPUT_CANDIDATES": str(tmp_path / "candidates.json"), "OUSAST_INPUT_SITES": str(tmp_path / "case.toml"),
        "OUSAST_CASE_ID": "case",
    }  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert agree.main() == 0
    summary = json.loads((tmp_path / "agree" / "summary.json").read_text())
    assert summary["metrics"]["declared_sites_matched"] == 1 and summary["metrics"]["agreed"] == 1
    monkeypatch.delenv("OUSAST_CASE_ID")
    assert agree.main() == 2  # two cases match: the record is ambiguous, not silently the first
