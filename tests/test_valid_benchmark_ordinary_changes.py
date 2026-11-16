"""Deterministic ordinary-change selection and contamination lifecycle tests."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import lifecycle as _lifecycle_module  # noqa: E402, F401
from benchmarks.valid import lifecycle_projection as lifecycle_projection_module  # noqa: E402
from benchmarks.valid import ordinary_changes as ordinary  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
    CanonicalEcosystem,
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import (  # noqa: E402
    EvidenceRef,
    FixSiteRequest,
    LicenseEvidence,
    PackageEcosystemEvidence,
    SourceEvidence,
    build_fix_site_candidate,
)
from benchmarks.valid.ground_truth_review import (  # noqa: E402
    GroundTruthAttestationV1,
    VerifiedScope,
    review_ground_truth,
)
from benchmarks.valid.lifecycle import (  # noqa: E402
    PopulationLifecycleProjectionV1,
    PopulationLifecycleState,
    decode_lifecycle_event,
)
from benchmarks.valid.reservation_identity import build_network_identity  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

PARENT = "a" * 40
FIXED = "b" * 40
SECOND_FIXED = "c" * 40
ECOSYSTEM_POLICY = content_digest({"policy": "ecosystem-v1"})
GROUND_TRUTH_POLICY = content_digest({"policy": "ground-truth-v1"})
DRAW_POLICY = content_digest({"policy": "ordinary-first-parent-v1", "required": 20})
SOURCE = content_digest({"source": "fixture-first-parent-history"})
CONTAMINATION_POLICY = content_digest({"policy": "contamination-review-v1"})


class _FixReader:
    def __init__(self, fixed: str, parent: str) -> None:
        self.fixed = fixed
        self.parent = parent

    def parents(self, revision: str) -> tuple[str, ...]:
        return (self.parent,) if revision == self.fixed else ()

    def blob(self, revision: str, path: str) -> str | None:
        if path != "src/app.py":
            return None
        return {
            self.parent: 'def handle():\n    return "before"\n',
            self.fixed: f'def handle():\n    return "{self.fixed[:1]}"\n',
        }.get(revision)


class _History:
    def __init__(
        self,
        count: int,
        *,
        merge_at: int | None = None,
        unreadable_at: int | None = None,
        fixed_parents: dict[str, str] | None = None,
    ) -> None:
        tips = [PARENT, *(_revision(index) for index in range(1, count))]
        root = _revision(count)
        self.parents_by_tip: dict[str, tuple[str, ...]] = {}
        for index, tip in enumerate(tips):
            parent = tips[index + 1] if index + 1 < len(tips) else root
            parents = (parent, "f" * 40) if merge_at == index else (parent,)
            self.parents_by_tip[tip] = parents
        self.unreadable = tips[unreadable_at] if unreadable_at is not None else None
        self.fixed_parents = fixed_parents or {FIXED: PARENT, SECOND_FIXED: PARENT}

    def parents(self, revision: str) -> tuple[str, ...]:
        if revision in self.fixed_parents:
            return (self.fixed_parents[revision],)
        return self.parents_by_tip.get(revision, ())

    def change_bytes(self, revision: str) -> bytes | None:
        if revision == self.unreadable:
            return None
        return f"change:{revision}".encode()


def _revision(index: int) -> str:
    return f"{index + 1:040x}"


def _positive(*, fixed: str = FIXED, parent: str = PARENT) -> ordinary.ReviewedPositiveInput:
    network = build_network_identity("https://github.com/example/application")
    candidate = build_fix_site_candidate(
        _FixReader(fixed, parent),
        FixSiteRequest(
            repository=network,
            vulnerable_parent=parent,
            fixed_revision=fixed,
            path="src/app.py",
            function="handle",
            observed_language="python",
            package_evidence=PackageEcosystemEvidence(
                "python",
                EvidenceRef("pyproject.toml", content_digest({"manifest": "python"}), 17),
            ),
            license_evidence=LicenseEvidence(
                "Apache-2.0",
                EvidenceRef("LICENSE", content_digest({"license": "Apache-2.0"}), 11),
            ),
            source_evidence=SourceEvidence(
                "security_advisory",
                f"fixture://advisory/{fixed[:1]}",
                content_digest({"advisory": fixed}),
            ),
            change_inputs_digest=content_digest({"parent": parent, "fixed": fixed}),
        ),
    )
    ecosystem = review_repository_ecosystem(
        candidate,
        EcosystemReviewAttestationV1(
            candidate.candidate_digest,
            candidate.source_evidence.evidence_digest,
            "ecosystem-producer@example.invalid",
            "ecosystem-reviewer@example.invalid",
            True,
            ECOSYSTEM_POLICY,
            True,
            EcosystemReviewDecision.PYTHON,
        ),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )
    ground_truth = review_ground_truth(
        candidate,
        ecosystem,
        GroundTruthAttestationV1(
            candidate.candidate_digest,
            ecosystem.review_digest,
            "truth-producer@example.invalid",
            "truth-reviewer@example.invalid",
            True,
            GROUND_TRUTH_POLICY,
            True,
            True,
            True,
            True,
            (VerifiedScope("injection", CanonicalEcosystem.PYTHON),),
        ),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return ordinary.ReviewedPositiveInput(candidate, ecosystem, ground_truth)


def _draw(
    positives: tuple[ordinary.ReviewedPositiveInput, ...] = (),
    *,
    history: _History | None = None,
    reviews: tuple[ordinary.OrdinaryContaminationReviewV1, ...] = (),
    required: int = 20,
) -> ordinary.OrdinarySelectionV1:
    values = tuple(positives) or (_positive(),)
    source = ordinary.OrdinaryHistorySource(
        history or _History(21, merge_at=3),
        values[0].candidate.canonical_repository,
        values[0].candidate.network_identity_digest,
        SOURCE,
    )
    return ordinary.draw_ordinary_selection(
        values,
        history_by_network={values[0].candidate.network_identity_digest: source},
        contamination_reviews=reviews,
        required_per_positive=required,
        policy_digest=DRAW_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _contamination(tip: str, timing: ordinary.ContaminationTiming) -> ordinary.OrdinaryContaminationReviewV1:
    return ordinary.reviewed_contamination(
        network_identity_digest=_positive().candidate.network_identity_digest,
        tip_revision=tip,
        timing=timing,
        evidence_digest=content_digest({"contamination": tip}),
        producer_identity="contamination-producer@example.invalid",
        reviewer_identity="contamination-reviewer@example.invalid",
        conflict_disclosed=True,
        policy_digest=CONTAMINATION_POLICY,
    )


def _active_lifecycle(population: str, freeze: str) -> PopulationLifecycleProjectionV1:
    draft = PopulationLifecycleProjectionV1(
        PopulationLifecycleState.REPLACEMENT_COMPLETE,
        content_digest({"withdrawal": 1}),
        population,
        freeze,
        content_digest({"head": 1}),
        (content_digest({"root": 1}), content_digest({"head": 1})),
        (),
        True,
        "",
    )
    return replace(
        draft,
        projection_digest=content_digest(lifecycle_projection_module._projection_value(draft, include_digest=False)),
    )


def test_draws_twenty_first_parent_pushes_deterministically_and_excludes_fix() -> None:
    first = _draw()
    second = _draw()

    assert ordinary.ordinary_selection_bytes(first) == ordinary.ordinary_selection_bytes(second)
    assert len(first.pushes) == len(first.assignments) == 20
    assert all(push.tip_revision != FIXED for push in first.pushes)
    merge_tip = _revision(3)
    merge = next(push for push in first.pushes if push.tip_revision == merge_tip)
    assert merge.base_revision == _revision(4)


def test_nineteen_eligible_pushes_are_insufficient() -> None:
    with pytest.raises(ordinary.OrdinarySelectionError, match="19 of 20"):
        _draw(history=_History(19))


def test_shared_underlying_pushes_are_stored_once_but_assigned_per_positive() -> None:
    selection = _draw((_positive(), _positive(fixed=SECOND_FIXED)))

    assert len(selection.positive_change_digests) == 2
    assert len(selection.pushes) == 20
    assert len(selection.assignments) == 40


def test_every_accepted_fix_is_excluded_from_linear_same_network_draws() -> None:
    positives = (_positive(), _positive(fixed=SECOND_FIXED, parent=FIXED))
    history = _History(21, fixed_parents={FIXED: PARENT, SECOND_FIXED: FIXED})

    selection = _draw(positives, history=history)

    tips = {push.tip_revision for push in selection.pushes}
    pushes_by_digest = {push.push_digest: push for push in selection.pushes}
    assigned_tips = {pushes_by_digest[item.push_digest].tip_revision for item in selection.assignments}
    assert FIXED not in tips
    assert SECOND_FIXED not in tips
    assert not ({FIXED, SECOND_FIXED} & assigned_tips)
    assert {item.fixed_revision for item in selection.fix_exclusions} == {FIXED, SECOND_FIXED}
    assert len(selection.pushes) == 20
    assert len(selection.assignments) == 40
    source = ordinary.OrdinaryHistorySource(
        history,
        positives[0].candidate.canonical_repository,
        positives[0].candidate.network_identity_digest,
        SOURCE,
    )
    assert ordinary.validate_ordinary_selection(
        selection,
        positives,
        history_by_network={positives[0].candidate.network_identity_digest: source},
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    changed_fix = replace(
        selection.fix_exclusions[0],
        ground_truth_review_digest=content_digest({"review": "substituted"}),
    )
    forged = replace(selection, fix_exclusions=tuple(sorted((changed_fix, *selection.fix_exclusions[1:]))))
    with pytest.raises(ordinary.OrdinarySelectionError, match="provenance"):
        ordinary.ordinary_selection_bytes(forged)


def test_reviewed_pre_freeze_contamination_is_excluded_with_reason() -> None:
    review = _contamination(PARENT, ordinary.ContaminationTiming.PRE_FREEZE)
    selection = _draw(history=_History(21), reviews=(review,))

    assert len(selection.pushes) == 20
    assert selection.exclusions == (
        ordinary.OrdinaryExclusionV1(
            review.network_identity_digest,
            review.tip_revision,
            ordinary.OrdinaryExclusionReason.REVIEWED_SECURITY_DEFECT,
            review.review_digest,
        ),
    )
    assert all(push.tip_revision != PARENT for push in selection.pushes)


def test_post_freeze_contamination_cannot_rewrite_draw_and_emits_retirement() -> None:
    selection = _draw()
    review = _contamination(selection.pushes[0].tip_revision, ordinary.ContaminationTiming.POST_FREEZE)
    before = ordinary.ordinary_selection_bytes(selection)
    lifecycle = _active_lifecycle(content_digest({"population": 1}), content_digest({"freeze": 1}))

    event = decode_lifecycle_event(ordinary.post_freeze_contamination_retirement(selection, review, lifecycle))

    assert event.reason_code == "contaminated_negative"
    assert (event.population_digest, event.freeze_digest) == (lifecycle.population_digest, lifecycle.freeze_digest)
    assert ordinary.ordinary_selection_bytes(selection) == before
    with pytest.raises(ordinary.OrdinarySelectionError, match="post-freeze"):
        _draw(reviews=(review,))


def test_assignment_ecosystem_substitution_is_refused() -> None:
    selection = _draw()
    forged_assignment = replace(selection.assignments[0], ecosystem=CanonicalEcosystem.JAVASCRIPT)
    forged = replace(selection, assignments=(forged_assignment, *selection.assignments[1:]))

    with pytest.raises(ordinary.OrdinarySelectionError, match="crosses repository or ecosystem"):
        ordinary.ordinary_selection_bytes(forged)


@pytest.mark.parametrize("history,message", ((_History(20, unreadable_at=2), "unreadable"),))
def test_unreadable_ordinary_change_refuses_clean_draw(history: _History, message: str) -> None:
    with pytest.raises(ordinary.OrdinarySelectionError, match=message):
        _draw(history=history)


def test_empty_ordinary_change_refuses_clean_draw() -> None:
    class EmptyHistory(_History):
        def change_bytes(self, revision: str) -> bytes | None:
            return b"" if revision == PARENT else super().change_bytes(revision)

    with pytest.raises(ordinary.OrdinarySelectionError, match="empty"):
        _draw(history=EmptyHistory(20))


def test_source_policy_and_order_are_identity_bearing() -> None:
    selection = _draw()
    reversed_pushes = replace(selection, pushes=tuple(reversed(selection.pushes)))
    changed_policy = replace(selection, policy_digest=content_digest({"policy": "changed"}))

    with pytest.raises(ordinary.OrdinarySelectionError, match="canonical"):
        ordinary.ordinary_selection_bytes(reversed_pushes)
    with pytest.raises(ordinary.OrdinarySelectionError, match="digest"):
        ordinary.ordinary_selection_bytes(changed_policy)


def test_selection_must_reproduce_from_exact_history_and_review_inputs() -> None:
    positive = _positive()
    history = _History(21)
    source = ordinary.OrdinaryHistorySource(
        history, positive.candidate.canonical_repository, positive.candidate.network_identity_digest, SOURCE
    )
    selection = _draw((positive,), history=history)

    assert ordinary.validate_ordinary_selection(
        selection,
        (positive,),
        history_by_network={positive.candidate.network_identity_digest: source},
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    changed_source = ordinary.OrdinaryHistorySource(
        history,
        positive.candidate.canonical_repository,
        positive.candidate.network_identity_digest,
        content_digest({"source": "changed"}),
    )
    with pytest.raises(ordinary.OrdinarySelectionError, match="reproduce"):
        ordinary.validate_ordinary_selection(
            selection,
            (positive,),
            history_by_network={positive.candidate.network_identity_digest: changed_source},
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_unrelated_contamination_review_cannot_disappear_from_selection() -> None:
    review = _contamination("e" * 40, ordinary.ContaminationTiming.PRE_FREEZE)

    with pytest.raises(ordinary.OrdinarySelectionError, match="does not identify"):
        _draw(reviews=(review,))


def test_history_source_cannot_cross_repository_identity() -> None:
    positive = _positive()
    source = ordinary.OrdinaryHistorySource(
        _History(20),
        "https://github.com/other/application",
        positive.candidate.network_identity_digest,
        SOURCE,
    )

    with pytest.raises(ordinary.OrdinarySelectionError, match="crosses repository"):
        ordinary.draw_ordinary_selection(
            (positive,),
            history_by_network={positive.candidate.network_identity_digest: source},
            policy_digest=DRAW_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_contamination_requires_independent_disclosed_exact_review() -> None:
    with pytest.raises(ordinary.OrdinarySelectionError, match="independent"):
        ordinary.reviewed_contamination(
            network_identity_digest=_positive().candidate.network_identity_digest,
            tip_revision=PARENT,
            timing=ordinary.ContaminationTiming.PRE_FREEZE,
            evidence_digest=content_digest({"contamination": PARENT}),
            producer_identity="same@example.invalid",
            reviewer_identity="same@example.invalid",
            conflict_disclosed=True,
            policy_digest=CONTAMINATION_POLICY,
        )

    review = _contamination(PARENT, ordinary.ContaminationTiming.PRE_FREEZE)
    with pytest.raises(ordinary.OrdinarySelectionError, match="digest"):
        ordinary.contamination_review_bytes(replace(review, evidence_digest=content_digest({"changed": 1})))
