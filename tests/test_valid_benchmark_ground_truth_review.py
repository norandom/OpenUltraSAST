"""Independent positive ground-truth and exact-scope review contracts."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import ground_truth_review as ground_truth_module  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
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
    GroundTruthExclusionReason,
    GroundTruthReviewError,
    GroundTruthStatus,
    VerifiedScope,
    ground_truth_review_bytes,
    project_accepted_ground_truth,
    review_ground_truth,
)
from benchmarks.valid.reservation_identity import build_network_identity  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

PARENT = "a" * 40
FIXED = "b" * 40
ECOSYSTEM_POLICY = content_digest({"policy": "ecosystem-v1"})
GROUND_TRUTH_POLICY = content_digest({"policy": "ground-truth-v1"})


class _Reader:
    def parents(self, revision: str) -> tuple[str, ...]:
        return (PARENT,) if revision == FIXED else ()

    def blob(self, revision: str, path: str) -> str | None:
        if path != "src/app.py":
            return None
        return {
            PARENT: 'def handle():\n    return "before"\n',
            FIXED: 'def handle():\n    return "after"\n',
        }.get(revision)


def _candidate(*, network=None):
    request = FixSiteRequest(
        repository=network or build_network_identity("https://github.com/example/application"),
        vulnerable_parent=PARENT,
        fixed_revision=FIXED,
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
        source_evidence=SourceEvidence("security_advisory", "fixture://advisory/1", content_digest({"advisory": 1})),
        change_inputs_digest=content_digest({"parent": PARENT, "fixed": FIXED}),
    )
    return build_fix_site_candidate(_Reader(), request)


def _ecosystem(candidate):
    attestation = EcosystemReviewAttestationV1(
        candidate.candidate_digest,
        candidate.source_evidence.evidence_digest,
        "ecosystem-producer@example.invalid",
        "ecosystem-reviewer@example.invalid",
        True,
        ECOSYSTEM_POLICY,
        True,
        EcosystemReviewDecision.PYTHON,
    )
    return review_repository_ecosystem(candidate, attestation, expected_policy_digest=ECOSYSTEM_POLICY)


def _attestation(candidate, ecosystem, **changes):
    values = {
        "candidate_digest": candidate.candidate_digest,
        "ecosystem_review_digest": ecosystem.review_digest,
        "producer_identity": "ground-truth-producer@example.invalid",
        "reviewer_identity": "ground-truth-reviewer@example.invalid",
        "conflict_disclosed": True,
        "policy_digest": GROUND_TRUTH_POLICY,
        "policy_satisfied": True,
        "defect_present": True,
        "fix_addresses": True,
        "in_repository_reachable": True,
        "verified_scopes": (
            VerifiedScope("injection", "python"),
            VerifiedScope("authorization", "python"),
        ),
        "model_assistance_digest": content_digest({"model-assistance": "non-authoritative"}),
    }
    values.update(changes)
    return GroundTruthAttestationV1(**values)


def _review(candidate=None, **changes):
    candidate = candidate or _candidate()
    ecosystem = _ecosystem(candidate)
    review = review_ground_truth(
        candidate,
        ecosystem,
        _attestation(candidate, ecosystem, **changes),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return candidate, ecosystem, review


def _encoded(candidate, ecosystem, review):
    return ground_truth_review_bytes(
        review,
        candidate=candidate,
        ecosystem_review=ecosystem,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _rehash(review):
    draft = replace(review, review_digest="")
    return replace(
        draft,
        review_digest=content_digest(ground_truth_module._review_value(draft, include_digest=False)),
    )


def test_accepts_explicit_human_judgments_and_sorted_exact_scopes_once() -> None:
    candidate, ecosystem, review = _review()

    assert review.status is GroundTruthStatus.ACCEPTED
    assert tuple(scope.vulnerability_family for scope in review.verified_scopes) == ("authorization", "injection")
    assert len({review.change_identity_digest}) == 1
    assert review.model_assistance_digest is not None
    assert _encoded(candidate, ecosystem, review)
    projection = project_accepted_ground_truth(
        (review,),
        candidates_by_digest={candidate.candidate_digest: candidate},
        ecosystem_reviews_by_digest={ecosystem.review_digest: ecosystem},
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    assert len(projection) == 1
    assert len(projection[0].verified_scopes) == 2


@pytest.mark.parametrize(
    "changes,reason",
    (
        ({"defect_present": None}, GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT),
        ({"fix_addresses": False}, GroundTruthExclusionReason.JUDGMENT_REJECTED),
        (
            {"in_repository_reachable": None, "model_assistance_digest": content_digest({"model": "agrees"})},
            GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT,
        ),
        ({"reviewer_identity": "ground-truth-producer@example.invalid"}, GroundTruthExclusionReason.SELF_REVIEW),
        ({"conflict_disclosed": False}, GroundTruthExclusionReason.CONFLICT_DISCLOSURE_MISSING),
        ({"policy_satisfied": False}, GroundTruthExclusionReason.POLICY_UNSATISFIED),
        ({"verified_scopes": ()}, GroundTruthExclusionReason.MISSING_SCOPE),
        ({"verified_scopes": (VerifiedScope("injection", "javascript"),)}, GroundTruthExclusionReason.SCOPE_SUBSTITUTION),
    ),
)
def test_missing_rejected_model_only_policy_and_scope_failures_are_excluded(changes, reason) -> None:
    _, _, review = _review(**changes)

    assert review.status is GroundTruthStatus.EXCLUDED
    assert review.exclusion_reason is reason
    assert review.verified_scopes == ()


@pytest.mark.parametrize("field", ("candidate_digest", "ecosystem_review_digest", "policy_digest"))
def test_stale_authority_roots_are_refused(field: str) -> None:
    candidate = _candidate()
    ecosystem = _ecosystem(candidate)
    changes = {field: "0" * 64}
    with pytest.raises(GroundTruthReviewError, match="candidate|ecosystem|policy"):
        review_ground_truth(
            candidate,
            ecosystem,
            _attestation(candidate, ecosystem, **changes),
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_scope_family_is_canonical_evidence_not_detector_vocabulary() -> None:
    _, _, review = _review(verified_scopes=(VerifiedScope("Custom_Family", "python"),))
    assert review.status is GroundTruthStatus.ACCEPTED
    assert review.verified_scopes[0].vulnerability_family == "custom_family"


def test_rehashed_root_or_outcome_substitution_is_refused() -> None:
    candidate, ecosystem, review = _review()
    forged = _rehash(
        replace(
            review,
            candidate_digest="0" * 64,
            status=GroundTruthStatus.EXCLUDED,
            verified_scopes=(),
            exclusion_reason=GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT,
        )
    )
    with pytest.raises(GroundTruthReviewError, match="candidate|outcome|authority"):
        _encoded(candidate, ecosystem, forged)


def test_projection_refuses_scope_substitution_and_deduplicates_equal_review() -> None:
    candidate, ecosystem, review = _review()
    forged = _rehash(replace(review, verified_scopes=(VerifiedScope("injection", "javascript"),)))
    kwargs = {
        "candidates_by_digest": {candidate.candidate_digest: candidate},
        "ecosystem_reviews_by_digest": {ecosystem.review_digest: ecosystem},
        "expected_ecosystem_policy_digest": ECOSYSTEM_POLICY,
        "expected_ground_truth_policy_digest": GROUND_TRUTH_POLICY,
    }
    with pytest.raises(GroundTruthReviewError, match="scope|outcome"):
        project_accepted_ground_truth((forged,), **kwargs)
    assert len(project_accepted_ground_truth((review, review), **kwargs)) == 1


def test_conflicting_reviews_for_one_change_identity_fail_closed() -> None:
    candidate, ecosystem, review = _review()
    conflicting = review_ground_truth(
        candidate,
        ecosystem,
        _attestation(candidate, ecosystem, verified_scopes=(VerifiedScope("injection", "python"),)),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    with pytest.raises(GroundTruthReviewError, match="conflicting"):
        project_accepted_ground_truth(
            (review, conflicting),
            candidates_by_digest={candidate.candidate_digest: candidate},
            ecosystem_reviews_by_digest={ecosystem.review_digest: ecosystem},
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_projection_revalidates_complete_ecosystem_review_authority() -> None:
    canonical = "https://github.com/example/application"
    candidate = _candidate(network=build_network_identity(canonical))
    conflicting_candidate = _candidate(network=build_network_identity(canonical, aliases=("https://github.com/example/former",)))
    ecosystem = _ecosystem(candidate)
    conflicting_ecosystem = _ecosystem(conflicting_candidate)
    review = review_ground_truth(
        candidate,
        ecosystem,
        _attestation(candidate, ecosystem),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )

    with pytest.raises(GroundTruthReviewError, match="network|identity"):
        project_accepted_ground_truth(
            (review,),
            candidates_by_digest={
                candidate.candidate_digest: candidate,
                conflicting_candidate.candidate_digest: conflicting_candidate,
            },
            ecosystem_reviews_by_digest={
                ecosystem.review_digest: ecosystem,
                conflicting_ecosystem.review_digest: conflicting_ecosystem,
            },
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )
