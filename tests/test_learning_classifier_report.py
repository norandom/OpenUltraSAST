"""learning-harness task 2.2: the classifier reports on itself and queues disagreements (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.learning.families import load_families
from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_vendored


def _case(tmp_path: Path, name: str, *, cwe: str, mechanism: str = "other", family: str | None = None, tier: str = "reviewed") -> PairCase:
    (tmp_path / f"{name}.py").write_text(f"# {name}\nx = 1\n")
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}.py",
        fixed_file=tmp_path / f"{name}.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(cwe=cwe, vulnerability_class="x", path="app.py", evidence="", function="f", mechanism=mechanism, family=family),
        ),
        min_recall=1.0,
        fix_policy="silent",
        review_tier=tier,
        reviewer="m" if tier == "reviewed" else "",
    )


def test_the_report_covers_the_whole_corpus_and_names_the_unknowns(tmp_path: Path) -> None:
    from openultrasast.learning.classify import measure_classifier

    taxonomy = load_families()
    cases = select_vendored(load_pair_catalog(DEFAULT_CATALOG))
    report = measure_classifier(cases, taxonomy, client=None)
    assert report.taxonomy_version == taxonomy.version
    assert report.classified == len(cases)
    assert sum(report.per_tier.values()) == len(cases) and set(report.per_tier) <= {"static", "model", "none"}
    assert report.per_family["memory"] >= 150  # the vfc rows land in one family instead of reading `other`
    assert report.per_family["access_control"] >= 10 and report.per_family["injection"] >= 40
    assert report.unknown == 2 and report.per_tier["static"] == len(cases) - 2  # tier one places all but two rows
    payload = report.to_dict()
    json.dumps(payload)
    # Task 4.1 declared `family` on the ten absence rows; only the four at a reference tier (`seeded`) count as labels
    # a maintainer stands behind, and the six `title`-tier agent rows do not. Agreement over four rows of one family is
    # not yet a measurement of the classifier, so the number is recorded, not celebrated.
    assert payload["labeled"] == 4 and payload["agreement"] == 1.0
    assert set(report.confusion) == {"access_control"}


def test_agreement_uses_the_first_answer_and_the_oracle_uses_any_of_them(tmp_path: Path) -> None:
    from openultrasast.learning.classify import measure_classifier

    taxonomy = load_families()
    cases = [
        _case(tmp_path, "hit", cwe="CWE-89", family="injection"),  # tier one answers injection: agreement and oracle
        _case(tmp_path, "miss", cwe="CWE-89", family="access_control"),  # answers injection: neither
    ]
    report = measure_classifier(cases, taxonomy, client=None)
    assert report.labeled == 2
    assert report.agreement == 0.5 and report.oracle_router == 0.5
    assert abs(report.random_router - 1 / 9) < 1e-9  # a uniform pick over the nine real families
    assert report.confusion["injection"]["injection"] == 1 and report.confusion["access_control"]["injection"] == 1


def test_every_disagreement_is_queued_once_with_both_answers_and_the_tier(tmp_path: Path) -> None:
    from openultrasast.learning.classify import measure_classifier, write_review_queue

    taxonomy = load_families()
    cases = [_case(tmp_path, "miss", cwe="CWE-89", family="access_control"), _case(tmp_path, "hit", cwe="CWE-89", family="injection")]
    report = measure_classifier(cases, taxonomy, client=None)
    assert [entry.pair for entry in report.queue] == ["miss"]
    entry = report.queue[0]
    assert entry.label == "access_control" and entry.classified == ("injection",) and entry.tier == "static"
    queue_path = tmp_path / "review-queue.jsonl"
    write_review_queue(queue_path, report.queue)
    write_review_queue(queue_path, report.queue)  # a second measurement must not duplicate the row
    rows = [json.loads(line) for line in queue_path.read_text().splitlines() if line.strip()]
    assert [row["pair"] for row in rows] == ["miss"]
    assert rows[0]["label"] == "access_control" and rows[0]["classified"] == ["injection"] and rows[0]["tier"] == "static"


def test_measuring_never_writes_a_label(tmp_path: Path) -> None:
    from openultrasast.learning.classify import measure_classifier

    taxonomy = load_families()
    case = _case(tmp_path, "miss", cwe="CWE-89", family="access_control")
    measure_classifier([case], taxonomy, client=None)
    assert case.expected[0].family == "access_control"  # the classifier proposes; the maintainer decides


def test_only_reviewed_and_seeded_rows_count_towards_agreement(tmp_path: Path) -> None:
    from openultrasast.learning.classify import measure_classifier

    taxonomy = load_families()
    cases = [
        _case(tmp_path, "trusted", cwe="CWE-89", family="access_control", tier="reviewed"),
        _case(tmp_path, "untrusted", cwe="CWE-89", family="access_control", tier="title"),
    ]
    report = measure_classifier(cases, taxonomy, client=None)
    assert report.labeled == 1 and report.classified == 2  # an unreviewed label is not a reference answer
    assert [entry.pair for entry in report.queue] == ["trusted"]


def test_the_report_says_when_hierarchical_credit_could_not_apply(tmp_path: Path) -> None:
    """Req 2.6: the shipped taxonomy is flat, so partial credit is inert and every figure must say so."""
    from openultrasast.learning.classify import measure_classifier

    taxonomy = load_families()
    report = measure_classifier([_case(tmp_path, "a", cwe="CWE-89", family="injection")], taxonomy, client=None)
    assert report.hierarchical_credit is False
    assert report.to_dict()["hierarchical_credit"] is False
