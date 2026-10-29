"""Task 10.5: aggregate multiple path judgments in the opt-in abstract mode.

Req 3.10 chains stay independent; Reqs 4.1-4.5 findings only for unguarded;
Req 11.5: unguarded if any complete path is unguarded, discharged only for a
complete all-discharged enumeration, indeterminate otherwise.
"""

from openultrasast.semantic.obligations.abstract_domain import (
    Completeness,
    PairJudgment,
    PathJudgment,
    WitnessMatch,
)
from openultrasast.semantic.obligations.judgment import aggregate_judgments


def _match(evidence: str) -> WitnessMatch:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation

    return WitnessMatch(
        relation=EvidenceRelation.MUST,
        resource_relation=EvidenceRelation.MUST,
        authority_relation=EvidenceRelation.MUST,
        evidence=(evidence,),
    )


def _judgment(
    judgment: PairJudgment,
    *,
    missing: tuple[str, ...] = (),
    is_complete: bool = True,
    reasons: tuple[str, ...] = (),
    evidence: tuple[str, ...] = (),
) -> PathJudgment:
    completeness = Completeness(is_complete=is_complete, reasons=reasons)
    return PathJudgment(
        judgment=judgment,
        missing=missing,
        completeness=completeness,
        matches=tuple(_match(item) for item in evidence),
    )


def test_any_complete_unguarded_path_makes_the_aggregate_unguarded() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(PairJudgment.UNGUARDED, missing=("path_guard",)),
        )
    )
    assert aggregate.judgment is PairJudgment.UNGUARDED
    assert aggregate.missing == ("path_guard",)


def test_unguarded_on_an_incomplete_path_does_not_decide() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(
                PairJudgment.UNGUARDED,
                missing=("path_guard",),
                is_complete=False,
                reasons=("resolution:no_candidate",),
            ),
        )
    )
    assert aggregate.judgment is PairJudgment.INDETERMINATE


def test_complete_all_discharged_enumeration_is_discharged() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(PairJudgment.DISCHARGED),
        )
    )
    assert aggregate.judgment is PairJudgment.DISCHARGED
    assert aggregate.missing == ()


def test_discharged_with_one_incomplete_path_is_indeterminate() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(
                PairJudgment.DISCHARGED,
                is_complete=False,
                reasons=("summaries:depth_cutoff",),
            ),
        )
    )
    assert aggregate.judgment is PairJudgment.INDETERMINATE


def test_discharged_and_indeterminate_mix_is_indeterminate() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(PairJudgment.INDETERMINATE),
        )
    )
    assert aggregate.judgment is PairJudgment.INDETERMINATE


def test_empty_enumeration_is_indeterminate() -> None:
    aggregate = aggregate_judgments(())
    assert aggregate.judgment is PairJudgment.INDETERMINATE
    assert aggregate.missing == ()


def test_missing_kinds_union_across_complete_unguarded_paths() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.UNGUARDED, missing=("path_guard",)),
            _judgment(
                PairJudgment.UNGUARDED,
                missing=("ownership_check", "path_guard"),
            ),
        )
    )
    assert aggregate.judgment is PairJudgment.UNGUARDED
    assert aggregate.missing == ("ownership_check", "path_guard")


def test_result_completeness_joins_input_reasons() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.DISCHARGED),
            _judgment(
                PairJudgment.INDETERMINATE,
                is_complete=False,
                reasons=("summaries:depth_cutoff",),
            ),
        )
    )
    assert aggregate.judgment is PairJudgment.INDETERMINATE
    assert aggregate.completeness.is_complete is False
    assert "summaries:depth_cutoff" in aggregate.completeness.reasons


def test_matches_from_every_path_are_carried_deduplicated() -> None:
    aggregate = aggregate_judgments(
        (
            _judgment(PairJudgment.UNGUARDED, missing=("path_guard",), evidence=("w:1",)),
            _judgment(PairJudgment.DISCHARGED, evidence=("w:1", "w:2")),
        )
    )
    assert tuple(match.evidence for match in aggregate.matches) == (("w:1",), ("w:2",))


def test_aggregation_is_deterministic() -> None:
    judgments = (
        _judgment(PairJudgment.UNGUARDED, missing=("path_guard",)),
        _judgment(PairJudgment.DISCHARGED),
    )
    assert aggregate_judgments(judgments) == aggregate_judgments(judgments)
