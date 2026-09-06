"""Rows fixed after the detector's training cutoff are reported apart (learning-harness 4.3, Req 10.5).

A model that may have read the fix cannot be measured on it the same way as one that cannot have. The corpus
carries the date at the precision the recipe recorded — a year for every row harvested so far — so a row counts as
post-cutoff only when its *earliest possible* date is after the cutoff. Rows with no date at all are counted
separately rather than quietly folded into either side.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.learning.families import load_families
from openultrasast.learning.scoring import PairFamilyScore, aggregate
from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_vendored


def _score(pair: str, outcome: str, *, fix_date: str = "") -> PairFamilyScore:
    return PairFamilyScore(pair=pair, family="injection", slice="vibe-py", runs=(outcome,), outcome=outcome, fix_date=fix_date)  # type: ignore[arg-type]


def test_every_vendored_row_carries_the_date_its_recipe_recorded() -> None:
    cases = select_vendored(load_pair_catalog(DEFAULT_CATALOG))
    dated = [case for case in cases if case.fix_date]
    assert len(dated) >= 250, "the generator fills the date from the recipe; almost every row has a year"
    assert all(len(case.fix_date) in {4, 10} for case in dated), "a date is a year or a full ISO day, never anything else"
    by_name = {case.name: case for case in cases}
    for slice_name in ("vibe-py", "agent-vfc"):
        for recipe in tomllib.loads((Path("benchmarks/pairs") / slice_name / "recipes.toml").read_text())["recipe"]:
            case = by_name.get(str(recipe["name"]))
            if case is not None and recipe.get("year"):
                assert case.fix_date.startswith(str(recipe["year"]))


@pytest.mark.parametrize(
    ("fix_date", "cutoff", "expected"),
    [
        ("2026", "2025-07-01", True),  # every day of 2026 is after the cutoff
        ("2026", "2026-03-01", False),  # a year-precision row that might be before it is not claimed
        ("2026-04-02", "2026-03-01", True),
        ("2024", "2025-07-01", False),
        ("2026-05", "2026-03-01", True),  # month precision: the earliest day of May is after 1 March
        ("2026-05", "2026-06-01", False),  # and before 1 June, so the row is not claimed
        ("2025", "2025", False),  # a cutoff coarser than a day is refused rather than compared
        ("", "2025-07-01", False),
    ],
)
def test_a_row_is_post_cutoff_only_when_its_earliest_possible_date_is_after_it(fix_date: str, cutoff: str, expected: bool) -> None:
    from openultrasast.learning.scoring import is_post_cutoff

    assert is_post_cutoff(fix_date, cutoff) is expected


def test_the_scoreboard_reports_the_post_cutoff_slice_the_cutoff_and_the_undated_count() -> None:
    scores = [
        _score("new-correct", "pair_correct", fix_date="2026"),
        _score("new-missed", "both_silent", fix_date="2026"),
        _score("old-correct", "pair_correct", fix_date="2021"),
        _score("undated", "pair_correct"),
    ]
    block = aggregate(scores, taxonomy=load_families(), cutoff="2025-07-01")["injection"]
    assert block.cutoff == "2025-07-01" and block.undated == 1
    assert block.post_cutoff["scorable"] == 2 and block.post_cutoff["recall"] == 0.5
    assert block.scorable == 4, "the slice is reported beside the whole number, never instead of it"
    payload = block.to_dict()
    json.dumps(payload)
    assert payload["cutoff"] == "2025-07-01" and payload["post_cutoff"]["scorable"] == 2


def test_without_a_configured_cutoff_the_scoreboard_says_so_rather_than_inventing_one() -> None:
    block = aggregate([_score("a", "pair_correct", fix_date="2026")], taxonomy=load_families())["injection"]
    assert block.cutoff == "" and block.post_cutoff == {} and block.undated == 0


def test_the_score_carries_the_date_from_the_pair(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    (tmp_path / "v.py").write_text("def run():\n    return 1\n")
    case = PairCase(
        name="p",
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / "v.py",
        fixed_file=tmp_path / "v.py",
        relpath="app.py",
        expected=(ExpectedFinding(cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other"),),
        min_recall=1.0,
        fix_policy="silent",
        fix_date="2026",
    )
    score = score_pair_family(case, "injection", [[]], [[]], ranges={"app.py": (("run", 1, 2),)}, taxonomy=load_families())
    assert score.fix_date == "2026"


def test_the_published_table_names_the_post_cutoff_slice(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    directory = out / "baseline" / "m"
    directory.mkdir(parents=True)
    (directory / "report.json").write_text(
        json.dumps(
            {
                "model": "m",
                "k_runs": 5,
                "cost_usd": 1.0,
                "taxonomy_version": "1",
                "metrics": {
                    "injection": {
                        "family": "injection",
                        "scorable": 4,
                        "unscorable": {},
                        "recall": 0.5,
                        "youden": 0.25,
                        "hierarchical_credit": False,
                        "cutoff": "2025-07-01",
                        "undated": 1,
                        "post_cutoff": {"scorable": 2, "recall": 0.5, "youden": 0.5},
                    }
                },
                "floors": {},
            }
        )
    )
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text("# Roadmap\n")
    report = publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    assert "2025-07-01" in report.table
    assert "post-cutoff" in report.table.lower()
    assert "undated" in report.table.lower()


def test_the_command_line_reports_the_slice_the_cutoff_and_the_undated_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 10.5 says every scoreboard, which includes the one an operator actually reads."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from test_learning_cli import CATALOG, FIXED, VULN, _detector  # noqa: PLC0415

    from openultrasast.cli import main

    for name in ("train-a", "hold-a"):
        (tmp_path / f"{name}-v.py").write_text(VULN)
        (tmp_path / f"{name}-f.py").write_text(FIXED)
    catalog = CATALOG.format(name="train-a", split="train") + "\n" + CATALOG.format(name="hold-a", split="holdout")
    (tmp_path / "pairs.toml").write_text(catalog.replace('review_tier = "seeded"', 'review_tier = "seeded"\nfix_date = "2026"'))
    (tmp_path / "openultrasast.toml").write_text('[learning]\nenabled = true\ncutoff_date = "2025-07-01"\n')
    _detector(monkeypatch)
    captured: list[str] = []
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: captured.append(" ".join(str(item) for item in args)))
    assert (
        main(
            [
                "learning",
                "score",
                "--catalog",
                str(tmp_path / "pairs.toml"),
                "--out",
                str(tmp_path / "learning"),
                "--config",
                str(tmp_path / "openultrasast.toml"),
            ]
        )
        == 0
    )
    line = next(item for item in captured if item.startswith("learning score injection"))
    assert "post-cutoff(2025-07-01)=2" in line and "undated=0" in line
