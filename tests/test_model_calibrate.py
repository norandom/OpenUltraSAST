"""model-grounded-detection task 5.1: the corpus calibrates the MODEL, not an LLM vote (Req 9).

The inversion this feature rests on. Previously a pair the detector missed was a detector failure to be
averaged away over K runs. Here a pair the model cannot split is a *named gap in the model*, with the reason
recorded, because the model is deterministic: it will miss that pair the same way every time, and the only
thing that changes it is better modelling.

`covered` therefore means the model reached a strictly higher rung on the vulnerable side than on its fix --
not that it flagged something. Flagging both sides equally distinguishes nothing.
"""

from __future__ import annotations


def _outcome(name, family="injection", slice_name="vibe-py", vuln="model_entailed", fixed="none", reason=""):  # type: ignore[no-untyped-def]
    from openultrasast.model.calibrate import PairOutcome

    return PairOutcome(pair=name, family=family, slice=slice_name, vuln_rung=vuln, fixed_rung=fixed, reason=reason)


def test_a_pair_the_model_splits_is_covered() -> None:
    from openultrasast.model.calibrate import calibrate

    report = calibrate([_outcome("a")])
    assert report.covered == ("a",)
    assert report.gaps == ()


def test_a_pair_the_model_cannot_split_is_a_named_gap_not_a_miss() -> None:
    """Req 9.2: the reason travels with the gap, because a deterministic model fails the same way every time."""
    from openultrasast.model.calibrate import calibrate

    report = calibrate([_outcome("b", vuln="none", fixed="none", reason="sink_not_in_table")])
    assert report.gaps and report.gaps[0].pair == "b"
    assert report.gaps[0].reason == "sink_not_in_table"
    assert report.covered == ()


def test_flagging_both_sides_equally_is_a_gap_not_a_success() -> None:
    """The model saw something on the fix too, so it distinguished nothing — that is the whole metric."""
    from openultrasast.model.calibrate import calibrate

    report = calibrate([_outcome("c", vuln="model_entailed", fixed="model_entailed")])
    assert report.covered == ()
    assert report.gaps[0].reason, "an unsplit pair must carry a reason even when none was supplied"


def test_gaps_are_grouped_by_family_with_their_reasons() -> None:
    from openultrasast.model.calibrate import calibrate

    report = calibrate([
        _outcome("a", family="path", vuln="none", reason="sink_not_in_table"),
        _outcome("b", family="path", vuln="none", reason="sink_not_in_table"),
        _outcome("c", family="injection", vuln="none", reason="source_unmodelled"),
        _outcome("d", family="injection"),
    ])
    by_family = report.gaps_by_family()
    assert set(by_family) == {"path", "injection"}
    assert by_family["path"]["pairs"] == 2
    assert by_family["path"]["reasons"] == {"sink_not_in_table": 2}
    assert by_family["injection"]["pairs"] == 1


def test_the_report_is_per_slice_and_names_the_deciding_one() -> None:
    """Req 9.3/11.1: the real-world slice decides; a development slice must not stand in for the corpus."""
    from openultrasast.model.calibrate import calibrate

    report = calibrate([
        _outcome("a", slice_name="vibe-py"),
        _outcome("b", slice_name="vfc-js", vuln="none", reason="sink_not_in_table"),
    ])
    assert set(report.per_slice) == {"vibe-py", "vfc-js"}
    assert report.per_slice["vibe-py"]["covered"] == 1
    assert report.per_slice["vfc-js"]["gaps"] == 1


def test_the_report_refuses_a_bare_aggregate() -> None:
    from openultrasast.model.calibrate import calibrate

    text = calibrate([_outcome("a"), _outcome("b", slice_name="vfc-js", vuln="none")]).to_markdown()
    assert "vibe-py" in text and "vfc-js" in text, "no headline without its per-slice rows"
    assert "coverage" in text.lower()


def test_a_cve_recipe_yields_the_parent_and_fix_commits() -> None:
    """Req 9.4: the harvest seam. The fix diff is the oracle; nothing is hand-labelled."""
    from openultrasast.model.calibrate import harvest_recipe

    recipe = harvest_recipe({"repo": "org/proj", "fix_commit": "abc123", "relpath": "app.py", "function": "run"})
    assert recipe.repo == "org/proj"
    assert recipe.fix_commit == "abc123"
    assert recipe.parent_ref == "abc123^", "the vulnerable side is the fix commit's parent, by construction"
    assert recipe.relpath == "app.py" and recipe.function == "run"
