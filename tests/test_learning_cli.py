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


def test_score_reports_family_numbers_for_a_catalog(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["learning", "score", "--catalog", str(workspace / "pairs.toml"), "--out", str(workspace / "learning"), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "injection" in payload["families"]
    assert payload["families"]["injection"]["taxonomy_version"]


def test_baseline_writes_the_noise_floor_and_publish_reads_it(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
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
    assert floors["k_runs"] == 3 and "injection" in floors["floors"]
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
    assert rounds[0]["outcome"] in {"accepted", "rejected", "reverted_cost"}
    assert (workspace / "learning" / "rounds" / "1" / "attribution.json").is_file()


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


def test_the_pairs_command_takes_a_k_runs_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["pairs", "--help"])
    assert "--k-runs" in capsys.readouterr().out
