"""learning-harness task 1.3: additive corpus fields and hygiene at load (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_vendored

IDENTICAL_TWINS = {
    "dsvw-dsvw-do-get",
    "python-insecure-app-main-try-hack-me",
    "pythonssti-main-read-root",
    "vampi-books-get-by-title",
    "vulnpy-deserialization-do-pickle-load",
}
VENDORED_PER_SLICE = {"local": 3, "github": 6, "sast": 11, "vibe-py": 35, "vfc-js": 17, "vfc": 176, "agent-vfc": 29}


def test_identical_twins_are_unscorable_and_no_row_is_dropped() -> None:
    cases = load_pair_catalog(DEFAULT_CATALOG)
    per_slice: dict[str, int] = {}
    for case in select_vendored(cases):
        per_slice[case.slice] = per_slice.get(case.slice, 0) + 1
    assert per_slice == VENDORED_PER_SLICE  # nothing dropped by the new accounting
    twins = {case.name for case in cases if case.unscorable == "identical_twin"}
    assert twins == IDENTICAL_TWINS
    assert all(case.unscorable is None for case in cases if case.name not in IDENTICAL_TWINS and not case.known_limit)


def test_a_declared_known_limit_wins_over_a_computed_reason(tmp_path: Path) -> None:
    from openultrasast.pairs import _load_catalog_file

    (tmp_path / "v.py").write_text("# provenance: x\n\ndef f():\n    return 1\n")
    (tmp_path / "f.py").write_text("# provenance: y\n\ndef f():\n    return 1\n")
    head = (
        '[[pair]]\nname = "t"\nslice = "sast"\nvuln = "v.py"\nfixed = "f.py"\nrelpath = "app.py"\n{extra}\n'
        '[[pair.expected]]\ncwe = "CWE-95"\nclass = "x"\npath = "app.py"\nsink = "eval"\nmechanism = "other"\n'
    )
    (tmp_path / "plain.toml").write_text(head.format(extra=""))
    (case,) = _load_catalog_file(tmp_path / "plain.toml")
    assert case.unscorable == "identical_twin"  # the provenance headers differ, the bodies do not
    (tmp_path / "limited.toml").write_text(head.format(extra='known_limit = "java hash"'))
    (limited,) = _load_catalog_file(tmp_path / "limited.toml")
    assert limited.unscorable == "known_limit:java hash"


def test_expected_rows_carry_an_opaque_family_label(tmp_path: Path) -> None:
    from openultrasast.pairs import _load_catalog_file

    (tmp_path / "v.py").write_text("x = 1\n")
    (tmp_path / "f.py").write_text("x = 2\n")
    row = (
        '[[pair]]\nname = "t"\nslice = "sast"\nvuln = "v.py"\nfixed = "f.py"\nrelpath = "app.py"\n\n'
        '[[pair.expected]]\ncwe = "CWE-95"\nclass = "x"\npath = "app.py"\nsink = "eval"\nmechanism = "other"\nfamily = "{family}"\n'
    )
    (tmp_path / "c.toml").write_text(row.format(family="injection"))
    (case,) = _load_catalog_file(tmp_path / "c.toml")
    assert case.expected[0].family == "injection"
    # the corpus stores the label; the classifier owns the taxonomy, so a fabricated id is not rejected here
    (tmp_path / "d.toml").write_text(row.format(family="not_a_family"))
    (other,) = _load_catalog_file(tmp_path / "d.toml")
    assert other.expected[0].family == "not_a_family"


def test_duplicate_bodies_across_pairs_are_reported_before_any_split() -> None:
    from openultrasast.pairs import duplicate_groups

    groups = duplicate_groups(select_vendored(load_pair_catalog(DEFAULT_CATALOG)))
    assert all(len(names) > 1 for names in groups)
    assert all(len(set(names)) == len(names) for names in groups)
    report = Path("benchmarks/measurements/2026-09-06-corpus-hygiene.json")
    assert report.is_file(), "the hygiene report is committed beside the numbers it explains"
    payload = json.loads(report.read_text())
    assert payload["duplicate_groups"] == [list(names) for names in groups]
    assert set(payload["identical_twins"]) == IDENTICAL_TWINS


def test_split_by_repository_keeps_declared_splits_and_reports_straddles() -> None:
    from openultrasast.pairs import split_by_repository

    cases = select_vendored(load_pair_catalog(DEFAULT_CATALOG))
    assigned, report = split_by_repository(cases)
    declared = {case.name: case.split for case in cases if case.split_declared}
    assert {case.name: case.split for case in assigned if case.name in declared} == declared  # never re-splits a declared row
    assert {name for name, _ in report.assigned} == {case.name for case in cases if not case.split_declared}
    assert report.straddling, "repositories that sit in both splits are a corpus defect worth naming"
    payload = json.loads(Path("benchmarks/measurements/2026-09-06-corpus-hygiene.json").read_text())
    assert payload["straddling"] == [[repo, list(names)] for repo, names in report.straddling]
    assert payload["undeclared_split"] == [list(item) for item in report.assigned]


def test_split_by_repository_assigns_undeclared_rows_by_repository_and_date(tmp_path: Path) -> None:
    from openultrasast.pairs import split_by_repository

    def case(name: str, repo: str, date: str = "") -> PairCase:
        (tmp_path / f"{name}.py").write_text(f"# {name}\n")
        return PairCase(
            name=name,
            slice="sast",
            language="python",
            origin="test",
            vuln_file=tmp_path / f"{name}.py",
            fixed_file=tmp_path / f"{name}.py",
            relpath="app.py",
            expected=(),
            min_recall=1.0,
            fix_policy="silent",
            repo=repo,
            split="",
            split_declared=False,
            fix_date=date,
        )

    cases = [case("a", "one", "2024-01-01"), case("b", "one", "2026-01-01"), case("c", "two", "2025-01-01"), case("d", "two", "2025-06-01")]
    assigned, report = split_by_repository(cases, holdout_fraction=0.5)
    by_name = {item.name: item.split for item in assigned}
    assert by_name["a"] == by_name["b"] and by_name["c"] == by_name["d"]  # a repository never straddles
    assert {by_name["a"], by_name["c"]} == {"train", "holdout"}
    assert by_name["a"] == "train"  # oldest repository trains, newest is held out
    assert dict(report.assigned) == by_name and report.straddling == () and report.undated == 0


def test_pair_signals_can_be_filtered_to_one_split() -> None:
    from openultrasast.pairs import PairOutcome, build_pair_signals

    def outcome(name: str, split: str) -> PairOutcome:
        return PairOutcome(
            name=name,
            slice="sast",
            language="python",
            origin="t",
            detected_vuln=False,
            silent_fix=True,
            pair_correct=False,
            vuln_matched=0,
            vuln_expected=1,
            vuln_findings=0,
            fix_findings=0,
            fix_leaks=0,
            recall=0.0,
            misses=("r:app.py:CWE-95",),
            leaks=(),
            split=split,
        )

    outcomes = [outcome("train-one", "train"), outcome("holdout-one", "holdout")]
    assert {signal["pair"] for signal in build_pair_signals(outcomes)} == {"train-one", "holdout-one"}
    assert {signal["pair"] for signal in build_pair_signals(outcomes, split="train")} == {"train-one"}
