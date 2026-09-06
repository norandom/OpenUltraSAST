"""A unit fixture may not be easier than the corpus it claims to cover (learning-harness 4.2, Req 10.3, 10.4).

Two things a corpus number cannot survive: a byte-identical pair counted as a detector result, and a fixture that
passes because the world it describes is simpler than the one the detector meets. The first is excluded by name;
the second is measured on three axes the corpus actually varies on, and the comparison is recorded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_obligation_operations import APP  # noqa: E402

from openultrasast.learning.difficulty import DifficultyVector, difficulty_of, hardest, strictly_easier  # noqa: E402
from openultrasast.pairs import DEFAULT_CATALOG, load_pair_catalog, select_vendored  # noqa: E402

TWINS = {
    "dsvw-dsvw-do-get",
    "python-insecure-app-main-try-hack-me",
    "pythonssti-main-read-root",
    "vampi-books-get-by-title",
    "vulnpy-deserialization-do-pickle-load",
}
# The rows the shared obligations fixture claims to cover: the vibe-py absence pairs.
COVERED = ("vampi-books-get-by-title", "vampi-users-update-password", "threatbyte-api-v1-get", "threatbyte-api-v1-delete")
FIXTURE_HANDLERS = ("guarded", "constrained", "constrained_too", "leaky", "from_spec")
REPORT = Path("benchmarks/measurements/2026-09-06-fixture-difficulty.json")


# --- identical twins ---------------------------------------------------------


def test_every_identical_twin_declares_the_limit_rather_than_only_hashing_to_it() -> None:
    """A content hash is evidence; the catalog row is the maintainer standing behind it.

    A re-harvest that changes one byte would otherwise turn a known-unscorable row back into a scored one with no
    review, and the number would move for a reason nobody chose."""
    cases = {case.name: case for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG))}
    for name in sorted(TWINS):
        assert cases[name].known_limit == "identical_twin", f"{name} is a twin by content but says nothing in the catalog"
        assert cases[name].unscorable == "identical_twin", "the declared limit and the computed one must be one reason, not two"


def test_the_twins_leave_every_denominator_with_their_reason_listed() -> None:
    from openultrasast.learning.families import load_families
    from openultrasast.learning.scoring import PairFamilyScore, aggregate

    cases = [case for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG)) if case.name in TWINS]
    scores = [
        PairFamilyScore(
            pair=case.name, family="injection", slice=case.slice, runs=(), outcome="unscorable", unscorable_reason=case.unscorable
        )
        for case in cases
    ]
    metrics = aggregate(scores, taxonomy=load_families())["injection"]
    assert metrics.scorable == 0
    assert metrics.unscorable == {"identical_twin": len(TWINS)}


# --- the difficulty check ----------------------------------------------------


def _corpus_vectors() -> list[DifficultyVector]:
    cases = {case.name: case for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG))}
    vectors = []
    for name in COVERED:
        case = cases[name]
        function = next(row.function for row in case.expected if row.function)
        context = [vuln.read_text() for _relpath, vuln, _fixed in case.context_files]
        vectors.append(difficulty_of(case.vuln_file.read_text(), function, context=context))
    return vectors


def test_the_shared_obligations_fixture_is_not_easier_than_the_rows_it_covers() -> None:
    """The check Req 10.4 asks for, on the fixture every obligations test shares."""
    fixture = [difficulty_of(APP, name) for name in FIXTURE_HANDLERS]
    corpus = _corpus_vectors()
    assert not strictly_easier(fixture, corpus), (
        f"the fixture reaches {hardest(fixture)} where the corpus reaches {hardest(corpus)} "
        "(binding hops, registration distance, guard distance)"
    )


def test_the_check_catches_a_fixture_that_is_easier_on_one_axis(tmp_path: Path) -> None:
    """Mutation of the check itself: drop the corpus-shaped handler and it has to fail."""
    without = [difficulty_of(APP, name) for name in FIXTURE_HANDLERS if name != "from_spec"]
    assert strictly_easier(without, _corpus_vectors())
    assert hardest(without)[1] == 0, "every remaining handler carries its route decorator; nothing is registered elsewhere"


def test_the_verdict_is_recorded_beside_the_numbers_it_explains() -> None:
    assert REPORT.is_file(), "the fixture-difficulty verdict is committed, not recomputed from memory"
    payload = json.loads(REPORT.read_text())
    fixture = [difficulty_of(APP, name) for name in FIXTURE_HANDLERS]
    corpus = _corpus_vectors()
    assert payload["fixture"] == [row.to_dict() for row in fixture]
    assert payload["corpus"] == [row.to_dict() for row in corpus]
    assert payload["strictly_easier"] is False and payload["verdict"] == "fixture_matches_corpus"
    assert payload["axes"] == ["binding_hops", "registration_distance", "guard_distance"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("@app.route('/x')\ndef h():\n    return Book.query.filter_by(user_id=request.user.id).first()\n", (0, 0, 2)),
        ("@app.route('/x')\n@login_required\ndef h():\n    return 1\n", (0, 0, 0)),
        ("def h():\n    u = current_user.id\n    v = u\n    return v\n", (2, 2, 1)),
        ("app.add_url_rule('/x', view_func=h)\n\n\ndef h():\n    return 1\n", (0, 1, 2)),
    ],
)
def test_each_axis_is_read_off_the_code(source: str, expected: tuple[int, int, int]) -> None:
    assert difficulty_of(source, "h").axes() == expected
