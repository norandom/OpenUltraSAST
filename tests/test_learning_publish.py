"""learning-harness task 3.8: publishing every number from its committed artifacts (offline)."""

from __future__ import annotations

import json
from pathlib import Path

ROADMAP = "# Roadmap\n\n## Overview\n\nSomething about the project.\n\n## Constraints\n\nCore dependencies stay empty.\n"


def _baseline(out: Path, model: str, *, recall: float = 1.0, cost: float = 0.5) -> None:
    directory = out / "baseline" / model
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(
        json.dumps(
            {
                "model": model,
                "k_runs": 5,
                "taxonomy_version": "1",
                "slices": ["vibe-py"],
                "cost_usd": cost,
                "floors": {"injection": {"family": "injection", "budget_flips": 1, "negative_flip_rate": 0.1, "k_runs": 5, "gates": True}},
                "metrics": {
                    "injection": {
                        "family": "injection",
                        "taxonomy_version": "1",
                        "scorable": 10,
                        "unscorable": {"identical_twin": 2},
                        "outcomes": {"pair_correct": round(recall * 10)},  # keep the fixture internally consistent
                        "recall": recall,
                        "silence": 1.0,
                        "youden": recall,
                        "directional_bias": 0.0,
                        "leak_rate": 0.0,
                        "fixed_fpr_recall": recall,
                        "hierarchical_credit": False,
                    }
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def test_publishing_twice_without_new_artifacts_is_byte_identical(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash")
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    measurements = tmp_path / "measurements"
    first = publish(learning_dir=out, measurements_dir=measurements, roadmap=roadmap)
    text = roadmap.read_text()
    second = publish(learning_dir=out, measurements_dir=measurements, roadmap=roadmap)
    assert roadmap.read_text() == text
    assert first.table == second.table and first.families == second.families


def test_every_number_carries_its_denominator_floor_and_cost(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash", recall=0.9, cost=1.8)
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    report = publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    table = report.table
    assert "| injection |" in table
    assert "10" in table and "identical_twin: 2" in table  # scorable and why the rest are not
    assert "taxonomy 1" in table and "budget 1" in table
    assert "0.20" in table  # cost per pair-correct: 1.8 over 9
    assert "hierarchical partial credit could not apply" in table
    assert report.command and report.command in roadmap.read_text()


def test_a_second_model_appears_beside_the_first(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash", recall=0.9)
    _baseline(out, "deepseek-v4-pro", recall=1.0)
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    report = publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    assert "deepseek-v4-flash" in report.table and "deepseek-v4-pro" in report.table
    assert set(report.families) == {"injection"}


def test_the_corrected_lever_number_replaces_the_earlier_one(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash")
    measurements = tmp_path / "m"
    measurements.mkdir()
    (measurements / "2026-09-06-mechanism-lever-split.json").write_text(
        json.dumps(
            {
                "slice": "vibe-py",
                "holdout_pairs": 17,
                "before": {"detected": 7, "youden": 0.0588},
                "after": {"detected": 5, "youden": -0.0588},
            }
        )
    )
    roadmap = tmp_path / "roadmap.md"
    stale = "human holdout profile pair_correct 0 -> 6 of 17, Youden 0 -> +0.353, round 2 `no_proposals`."
    roadmap.write_text(f"{ROADMAP}\nMeasured 2026-09-05 with the vibe-py candidates: {stale}\n")
    report = publish(learning_dir=out, measurements_dir=measurements, roadmap=roadmap)
    text = roadmap.read_text()
    assert "-0.0588" in report.table or "-0.059" in report.table
    assert "5 of 17" in report.table or "detected 5" in report.table
    assert "holdout pairs stopped teaching" in report.table.lower() or "train split only" in report.table.lower()
    assert text.count("learning-harness:begin") == 1
    # Req 5.3 says *in place of* the earlier one. Leaving the old claim above the new section is how a document
    # ends up asserting two different numbers for the same measurement.
    assert stale not in text
    assert "superseded" in text and "learning-harness" in text
    assert "Measured 2026-09-05 with the vibe-py candidates:" in text, "the sentence is corrected, not deleted"
    before = roadmap.read_text()
    publish(learning_dir=out, measurements_dir=measurements, roadmap=roadmap)
    assert roadmap.read_text() == before, "a second publish must be a no-op once the claim is corrected"


def test_the_roadmap_section_is_replaced_not_appended_again(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash", recall=0.5)
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    _baseline(out, "deepseek-v4-flash", recall=0.9)
    publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    text = roadmap.read_text()
    assert text.count("learning-harness:begin") == 1 and text.count("learning-harness:end") == 1
    assert "## Overview" in text and "## Constraints" in text  # nothing else in the roadmap is disturbed
    assert "0.5" not in text.split("learning-harness:begin")[1]  # the stale number is gone


def test_the_raw_artifacts_are_written_where_the_numbers_are_read_from(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    _baseline(out, "deepseek-v4-flash")
    measurements = tmp_path / "m"
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    publish(learning_dir=out, measurements_dir=measurements, roadmap=roadmap)
    written = sorted(path.name for path in measurements.iterdir())
    assert any(name.endswith("-learning-families.json") for name in written)
    payload = json.loads((measurements / next(name for name in written if name.endswith("-learning-families.json"))).read_text())
    # keyed by what identifies the run, so two slices of one model cannot collapse into one entry
    assert payload["models"]["deepseek-v4-flash (vibe-py)"]["injection"]["scorable"] == 10
    assert payload["command"]


def test_publishing_with_no_baseline_says_so_rather_than_inventing_a_table(tmp_path: Path) -> None:
    from openultrasast.learning.publish import publish

    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(ROADMAP)
    report = publish(learning_dir=tmp_path / "empty", measurements_dir=tmp_path / "m", roadmap=roadmap)
    assert report.families == () and "no baseline" in report.table.lower()
    assert "learning-harness:begin" in roadmap.read_text()


def test_two_slices_of_one_model_are_two_rows_not_one_overwriting_the_other(tmp_path: Path) -> None:
    """Keyed by model alone, the vibe-py run silently replaced the agent-vfc run and the published table showed
    hand-written teaching code as if it were the corpus — the exact failure Req 3 exists to prevent."""
    from openultrasast.learning.publish import publish

    out = tmp_path / "learning"
    for key, slice_name, recall in (("deepseek-v4-flash-vibe-py", "vibe-py", 0.833), ("deepseek-v4-flash-agent-vfc", "agent-vfc", 0.444)):
        directory = out / "baseline" / key
        directory.mkdir(parents=True)
        (directory / "report.json").write_text(
            json.dumps(
                {
                    "model": "deepseek-v4-flash",
                    "slices": [slice_name],
                    "k_runs": 5,
                    "cost_usd": 1.0,
                    "taxonomy_version": "1",
                    "metrics": {
                        "injection": {
                            "family": "injection", "scorable": 10, "unscorable": {}, "recall": recall,
                            "silence": 1.0, "youden": recall, "hierarchical_credit": False,
                            "outcomes": {"pair_correct": 5},
                        }
                    },
                    "floors": {},
                }
            )
        )
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text("# Roadmap\n")
    report = publish(learning_dir=out, measurements_dir=tmp_path / "m", roadmap=roadmap)
    assert "vibe-py" in report.table and "agent-vfc" in report.table
    assert report.table.count("| injection |") == 2, "one row per slice, not one row that survived"
    assert "0.833" in report.table and "0.444" in report.table
