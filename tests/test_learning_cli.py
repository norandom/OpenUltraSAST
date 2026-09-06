"""learning-harness task 3.9: the learning subcommands (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.cli import main

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "from flask import request\nimport subprocess\n\n\ndef run():\n    subprocess.run(['echo', 'x'], check=False)\n"
CATALOG = (
    '[[pair]]\nname = "{name}"\nslice = "vibe-py"\nlanguage = "python"\nvuln = "{name}-v.py"\nfixed = "{name}-f.py"\n'
    'relpath = "app.py"\nsplit = "{split}"\nreview_tier = "seeded"\n\n'
    '[[pair.expected]]\ncwe = "CWE-78"\nclass = "command injection"\npath = "app.py"\nfunction = "run"\n'
    'sink = "system"\nmechanism = "source_reaches_sink"\nfamily = "injection"\n'
)


def _detector(monkeypatch: pytest.MonkeyPatch, line: int = 6) -> None:
    """A deterministic detector that reads the file it was given and answers differently on the two sides.

    The shipped `scripted` stub answers twice and then goes quiet, and its finding sits at line 3, outside `run`.
    Both make every family number zero, and a scoreboard assertion against zeros passes with the detector missing
    entirely — which is what these tests used to assert."""
    from openultrasast.learning.endpoint import ChatEndpoint
    from openultrasast.tool_hunter import ChatResponse, ToolCall

    class Detector:
        def __init__(self) -> None:
            self.turn = 0

        def complete(self, *, model: str, messages, tools=None, **options):  # type: ignore[no-untyped-def]
            del model, tools, options
            self.turn += 1
            if self.turn % 2 == 1:
                return ChatResponse(tool_calls=(ToolCall(id=f"c{self.turn}", name="grep_repo", arguments={"pattern": "system"}),))
            body = "\n".join(str(message.get("content") or "") for message in messages)
            if "os.system" not in body:
                return ChatResponse(content="[]")  # the fixed side really is different, and the detector sees it
            return ChatResponse(content=json.dumps([{"path": "app.py", "line": line, "title": "t", "rationale": "r"}]))

    endpoint = ChatEndpoint(provider="scripted", base_url="", thinking=False)
    monkeypatch.setattr("openultrasast.learning.endpoint.resolve_chat_endpoint", lambda *a, **k: (Detector(), endpoint))


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("train-a", "hold-a"):
        (tmp_path / f"{name}-v.py").write_text(VULN)
        (tmp_path / f"{name}-f.py").write_text(FIXED)
    (tmp_path / "pairs.toml").write_text(
        CATALOG.format(name="train-a", split="train") + "\n" + CATALOG.format(name="hold-a", split="holdout")
    )
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    return tmp_path  # no chdir: the mechanism vocabulary is found relative to the repository root


def test_classify_reports_the_corpus_and_writes_the_queue(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["learning", "classify", "--catalog", str(workspace / "pairs.toml"), "--out", str(workspace / "learning")]) == 0
    payload = json.loads((workspace / "learning" / "classifier.json").read_text())
    assert payload["classified"] == 2 and payload["per_family"]["injection"] == 2
    assert payload["hierarchical_credit"] is False
    assert "classified 2" in capsys.readouterr().out


def test_score_reports_family_numbers_for_a_catalog(
    workspace: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scripted client detects the vulnerable side and is silent on the fix, so this is a real 2/2, not a zero.

    An all-zero scoreboard would satisfy "the family key exists"; it is what a generalist detector scoring every
    family produced before round zero ran each family's own configuration."""
    _detector(monkeypatch)
    assert main(["learning", "score", "--catalog", str(workspace / "pairs.toml"), "--out", str(workspace / "learning"), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    block = payload["families"]["injection"]
    assert block["taxonomy_version"] and block["scorable"] == 2
    assert block["outcomes"] == {"pair_correct": 2} and block["recall"] == 1.0 and block["youden"] == 1.0


def test_baseline_writes_the_noise_floor_and_publish_reads_it(
    workspace: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _detector(monkeypatch)
    assert (
        main(
            [
                "learning",
                "baseline",
                "--catalog",
                str(workspace / "pairs.toml"),
                "--out",
                str(workspace / "learning"),
                "--k-runs",
                "3",
                "--model",
                "scripted",
            ]
        )
        == 0
    )
    floors = json.loads((workspace / "learning" / "baseline" / "scripted" / "noise-floors.json").read_text())
    assert floors["k_runs"] == 3 and floors["floors"]["injection"]["pairs"] == 2
    report = json.loads((workspace / "learning" / "baseline" / "scripted" / "report.json").read_text())
    # Measured with the injection configuration, not the generalist: `family:unknown` earns no credit against any
    # real family, so a baseline built from one shared detector reports a structural zero here.
    assert report["metrics"]["injection"]["recall"] == 1.0
    assert report["per_slice"]["vibe-py/injection"]["scorable"] == 2
    capsys.readouterr()
    roadmap = workspace / "roadmap.md"
    roadmap.write_text("# Roadmap\n\n## Overview\n\ntext\n")
    assert (
        main(
            ["learning", "publish", "--out", str(workspace / "learning"), "--measurements", str(workspace / "m"), "--roadmap", str(roadmap)]
        )
        == 0
    )
    assert "learning-harness:begin" in roadmap.read_text()
    assert "| injection |" in roadmap.read_text()


def test_a_round_runs_from_the_command_line_and_journals_its_outcome(workspace: Path) -> None:
    assert (
        main(
            [
                "learning",
                "baseline",
                "--catalog",
                str(workspace / "pairs.toml"),
                "--out",
                str(workspace / "learning"),
                "--k-runs",
                "3",
                "--model",
                "scripted",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "learning",
                "round",
                "--catalog",
                str(workspace / "pairs.toml"),
                "--out",
                str(workspace / "learning"),
                "--family",
                "injection",
                "--k-runs",
                "3",
            ]
        )
        == 0
    )
    rounds = [json.loads(line) for line in (workspace / "learning" / "journal.jsonl").read_text().splitlines() if line.strip()]
    assert len(rounds) == 1 and rounds[0]["family"] == "injection"
    # Without the extra there is no meta-agent, so the honest outcome is exactly this one. Accepting any member of
    # the enum would have hidden that the round could never propose anything at all.
    assert (rounds[0]["outcome"], rounds[0]["reason"]) == ("rejected", "no_proposal")
    assert (workspace / "learning" / "rounds" / "1" / "attribution.json").is_file()


def test_a_recorded_proposal_makes_the_round_do_something(workspace: Path) -> None:
    """`--proposals` is what makes a round runnable at all without the optional extra."""
    for command in (
        ["learning", "baseline", "--catalog", str(workspace / "pairs.toml"), "--out", str(workspace / "learning"), "--k-runs", "3"],
    ):
        assert main([*command, "--model", "scripted"]) == 0
    proposals = workspace / "proposals.json"
    proposals.write_text(
        json.dumps([{"hypothesis": "ask about quoting", "lever": "checklist", "change": {"checklist.md": "- ask about quoting\n"}}])
    )
    assert (
        main(
            [
                "learning",
                "round",
                "--catalog",
                str(workspace / "pairs.toml"),
                "--out",
                str(workspace / "learning"),
                "--family",
                "injection",
                "--k-runs",
                "3",
                "--proposals",
                str(proposals),
            ]
        )
        == 0
    )
    (record,) = [json.loads(line) for line in (workspace / "learning" / "journal.jsonl").read_text().splitlines() if line.strip()]
    assert record["reason"] != "no_proposal", "a recorded proposal reached the round"
    assert json.loads((workspace / "learning" / "rounds" / "1" / "proposal.json").read_text())["lever"] == "checklist"


def test_a_missing_endpoint_is_recorded_and_the_rest_still_runs(workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:  # type: ignore[no-untyped-def]
    for name in ("OPENULTRASAST_HUNTER_CLIENT", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert (
        main(
            [
                "learning",
                "baseline",
                "--catalog",
                str(workspace / "pairs.toml"),
                "--out",
                str(workspace / "learning"),
                "--k-runs",
                "3",
                "--model",
                "none",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "learning_endpoint_unavailable" in out
    assert (workspace / "learning" / "baseline" / "none" / "report.json").is_file()  # the run still recorded what it could


def test_every_subcommand_is_listed_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["learning", "--help"])
    out = capsys.readouterr().out
    for name in ("classify", "score", "baseline", "round", "publish"):
        assert name in out


def test_the_pairs_command_scores_k_runs_per_side(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Grepping `--help` for the flag passes with the capability entirely absent, which is what it used to be."""
    from openultrasast import pairs as pairs_module

    calls: list[str] = []
    real = pairs_module.make_hunter_scan

    def counting(client: object, model: str, **kwargs: object):  # type: ignore[no-untyped-def]
        inner = real(client, model, **kwargs)  # type: ignore[arg-type]

        def scan(root: Path):  # type: ignore[no-untyped-def]
            calls.append(root.name)
            return inner(root)

        return scan

    monkeypatch.setattr(pairs_module, "make_hunter_scan", counting)
    monkeypatch.setattr("openultrasast.cli.make_hunter_scan", counting)
    monkeypatch.setenv("OPENULTRASAST_HUNTER_MODEL", "scripted")
    assert main(["pairs", "--catalog", str(workspace / "pairs.toml"), "--hunter", "--hunter-model", "scripted", "--k-runs", "4"]) == 0
    assert calls.count("vuln") == 8 and calls.count("fixed") == 8  # two pairs, four runs per side
