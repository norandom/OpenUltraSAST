"""Independent canonical ecosystem review for fix-site candidates."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import ecosystem_review as ecosystem_review_module
from benchmarks.valid import fix_site_catalog as fix_site_catalog_module
from benchmarks.valid.ecosystem_review import (
    CanonicalEcosystem,
    EcosystemInsufficientReason,
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    EcosystemReviewError,
    EcosystemReviewStatus,
    project_accepted_ecosystems,
    repository_ecosystem_review_bytes,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import (
    EvidenceRef,
    FixSiteRequest,
    LicenseEvidence,
    PackageEcosystemEvidence,
    SourceEvidence,
    build_fix_site_candidate,
)
from benchmarks.valid.reservation_identity import build_network_identity
from openultrasast.core.canonical import content_digest

PARENT = "a" * 40
FIXED = "b" * 40
POLICY = content_digest({"policy": "independent-ecosystem-review-v1"})


class _Reader:
    def __init__(self, path: str, before: str, after: str) -> None:
        self._path = path
        self._sources = {PARENT: before, FIXED: after}

    def parents(self, revision: str) -> tuple[str, ...]:
        return (PARENT,) if revision == FIXED else ()

    def blob(self, revision: str, path: str) -> str | None:
        return self._sources.get(revision) if path == self._path else None


def _candidate(language: str = "python", package_hint: str | None = None, repository=None):
    if language == "python":
        path = "src/app.py"
        before = 'def handle():\n    return "before"\n'
        after = 'def handle():\n    return "after"\n'
    else:
        suffix = "ts" if language == "typescript" else "js"
        path = f"src/app.{suffix}"
        before = 'function handle() {\n  return "before";\n}\n'
        after = 'function handle() {\n  return "after";\n}\n'
    hint = package_hint or ("python" if language == "python" else "javascript")
    manifest_path = "pyproject.toml" if hint == "python" else "package.json"
    request = FixSiteRequest(
        repository=repository or build_network_identity("https://github.com/example/application"),
        vulnerable_parent=PARENT,
        fixed_revision=FIXED,
        path=path,
        function="handle",
        observed_language=language,
        package_evidence=PackageEcosystemEvidence(
            hint,
            EvidenceRef(manifest_path, content_digest({"manifest": hint}), 17),
        ),
        license_evidence=LicenseEvidence(
            "Apache-2.0",
            EvidenceRef("LICENSE", content_digest({"license": "Apache-2.0"}), 11),
        ),
        source_evidence=SourceEvidence(
            "security_advisory",
            "fixture://advisory/1",
            content_digest({"advisory": 1}),
        ),
        change_inputs_digest=content_digest({"parent": PARENT, "fixed": FIXED}),
    )
    return build_fix_site_candidate(_Reader(path, before, after), request)


def _attestation(candidate, decision: EcosystemReviewDecision, **changes: object) -> EcosystemReviewAttestationV1:
    values: dict[str, object] = {
        "candidate_digest": candidate.candidate_digest,
        "source_evidence_digest": candidate.source_evidence.evidence_digest,
        "producer_identity": "producer@example.invalid",
        "reviewer_identity": "reviewer@example.invalid",
        "conflict_disclosed": True,
        "policy_digest": POLICY,
        "policy_satisfied": True,
        "decision": decision,
    }
    values.update(changes)
    return EcosystemReviewAttestationV1(**values)  # type: ignore[arg-type]


def _rehash(review):
    draft = replace(review, review_digest="")
    return replace(
        draft,
        review_digest=content_digest(ecosystem_review_module._review_value(draft, include_digest=False)),
    )


def _rehash_candidate(candidate, **changes):
    draft = replace(candidate, provenance_digest="", candidate_digest="", **changes)
    provenance = content_digest(fix_site_catalog_module._provenance_value(draft))
    reviewed = replace(draft, provenance_digest=provenance)
    return replace(
        reviewed,
        candidate_digest=content_digest(fix_site_catalog_module._candidate_value(reviewed, include_digest=False)),
    )


def _encoded(review, candidate) -> bytes:
    return repository_ecosystem_review_bytes(
        review,
        candidate=candidate,
        expected_policy_digest=POLICY,
    )


def _project(reviews, *candidates):
    return project_accepted_ecosystems(
        reviews,
        candidates_by_digest={candidate.candidate_digest: candidate for candidate in candidates},
        expected_policy_digest=POLICY,
    )


@pytest.mark.parametrize(
    "language,decision,ecosystem",
    (
        ("python", EcosystemReviewDecision.PYTHON, CanonicalEcosystem.PYTHON),
        ("javascript", EcosystemReviewDecision.JAVASCRIPT, CanonicalEcosystem.JAVASCRIPT),
        ("typescript", EcosystemReviewDecision.JAVASCRIPT, CanonicalEcosystem.JAVASCRIPT),
    ),
)
def test_review_accepts_only_canonical_ecosystems(language, decision, ecosystem) -> None:
    candidate = _candidate(language)
    review = review_repository_ecosystem(candidate, _attestation(candidate, decision), expected_policy_digest=POLICY)

    assert review.status is EcosystemReviewStatus.ACCEPTED
    assert review.ecosystem is ecosystem
    assert review.insufficient_reason is None
    assert _encoded(review, candidate)


@pytest.mark.parametrize(
    "decision,reason",
    (
        (EcosystemReviewDecision.UNRESOLVED, EcosystemInsufficientReason.UNRESOLVED),
        (EcosystemReviewDecision.CONFLICTING, EcosystemInsufficientReason.CONFLICTING),
        (EcosystemReviewDecision.POLYGLOT_AMBIGUITY, EcosystemInsufficientReason.POLYGLOT_AMBIGUITY),
    ),
)
def test_bounded_review_decisions_remain_insufficient(decision, reason) -> None:
    candidate = _candidate()
    review = review_repository_ecosystem(candidate, _attestation(candidate, decision), expected_policy_digest=POLICY)

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.ecosystem is None
    assert review.insufficient_reason is reason


def test_conflicting_candidate_evidence_cannot_be_accepted() -> None:
    candidate = _candidate("python", package_hint="javascript")
    review = review_repository_ecosystem(
        candidate,
        _attestation(candidate, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.insufficient_reason is EcosystemInsufficientReason.CONFLICTING


@pytest.mark.parametrize(
    "changes,reason",
    (
        ({"reviewer_identity": "producer@example.invalid"}, EcosystemInsufficientReason.SELF_REVIEW),
        ({"conflict_disclosed": False}, EcosystemInsufficientReason.CONFLICT_DISCLOSURE_MISSING),
        ({"policy_satisfied": False}, EcosystemInsufficientReason.POLICY_UNSATISFIED),
    ),
)
def test_review_policy_failures_are_non_admissible(changes, reason) -> None:
    candidate = _candidate()
    review = review_repository_ecosystem(
        candidate,
        _attestation(candidate, EcosystemReviewDecision.PYTHON, **changes),
        expected_policy_digest=POLICY,
    )

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.ecosystem is None
    assert review.insufficient_reason is reason


@pytest.mark.parametrize(
    "changes,message",
    (
        ({"candidate_digest": "0" * 64}, "candidate"),
        ({"source_evidence_digest": "1" * 64}, "source evidence"),
        ({"policy_digest": "2" * 64}, "policy"),
    ),
)
def test_stale_review_evidence_is_refused(changes, message) -> None:
    candidate = _candidate()
    with pytest.raises(EcosystemReviewError, match=message):
        review_repository_ecosystem(
            candidate,
            _attestation(candidate, EcosystemReviewDecision.PYTHON, **changes),
            expected_policy_digest=POLICY,
        )


def test_review_bytes_are_deterministic_and_tamper_evident() -> None:
    candidate = _candidate("typescript")
    review = review_repository_ecosystem(
        candidate,
        _attestation(candidate, EcosystemReviewDecision.JAVASCRIPT),
        expected_policy_digest=POLICY,
    )

    assert _encoded(review, candidate) == _encoded(review, candidate)
    with pytest.raises(EcosystemReviewError, match="digest"):
        _encoded(replace(review, review_digest="0" * 64), candidate)


def test_repository_cannot_have_two_accepted_canonical_ecosystems() -> None:
    python_candidate = _candidate("python")
    javascript_candidate = _candidate("javascript")
    python_review = review_repository_ecosystem(
        python_candidate,
        _attestation(python_candidate, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    javascript_review = review_repository_ecosystem(
        javascript_candidate,
        _attestation(javascript_candidate, EcosystemReviewDecision.JAVASCRIPT),
        expected_policy_digest=POLICY,
    )

    with pytest.raises(EcosystemReviewError, match="conflicting accepted"):
        _project((python_review, javascript_review), python_candidate, javascript_candidate)


def test_rehashed_candidate_source_and_package_substitution_is_refused() -> None:
    candidate = _candidate()
    review = review_repository_ecosystem(
        candidate,
        _attestation(candidate, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    forged = _rehash(
        replace(
            review,
            candidate_digest="0" * 64,
            source_evidence_digest="1" * 64,
            package_evidence_digest="2" * 64,
        )
    )

    with pytest.raises(EcosystemReviewError, match="candidate|evidence"):
        _encoded(forged, candidate)


def test_projection_refuses_rehashed_candidate_identity_substitution() -> None:
    candidate = _candidate()
    review = review_repository_ecosystem(
        candidate,
        _attestation(candidate, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    forged = _rehash(replace(review, candidate_digest="0" * 64))

    with pytest.raises(EcosystemReviewError, match="candidate|evidence"):
        _project((forged,), candidate)


@pytest.mark.parametrize("mutation", ("self_review_reason", "accepted_outcome"))
def test_rehashed_outcome_substitution_is_rederived_and_refused(mutation: str) -> None:
    candidate = _candidate()
    if mutation == "self_review_reason":
        review = review_repository_ecosystem(
            candidate,
            _attestation(
                candidate,
                EcosystemReviewDecision.PYTHON,
                reviewer_identity="producer@example.invalid",
            ),
            expected_policy_digest=POLICY,
        )
        forged = _rehash(replace(review, insufficient_reason=EcosystemInsufficientReason.UNRESOLVED))
    else:
        review = review_repository_ecosystem(
            candidate,
            _attestation(candidate, EcosystemReviewDecision.PYTHON),
            expected_policy_digest=POLICY,
        )
        forged = _rehash(
            replace(
                review,
                status=EcosystemReviewStatus.INSUFFICIENT,
                ecosystem=None,
                insufficient_reason=EcosystemInsufficientReason.UNRESOLVED,
            )
        )

    with pytest.raises(EcosystemReviewError, match="outcome|review"):
        _encoded(forged, candidate)


@pytest.mark.parametrize("second_language", ("python", "javascript"))
def test_same_repository_cannot_resolve_to_different_networks(second_language: str) -> None:
    canonical = "https://github.com/example/application"
    first_network = build_network_identity(canonical)
    second_network = build_network_identity(canonical, aliases=("https://github.com/example/former",))
    first = _candidate("python", repository=first_network)
    second = _candidate(second_language, repository=second_network)
    first_review = review_repository_ecosystem(
        first,
        _attestation(first, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    second_decision = EcosystemReviewDecision.PYTHON if second_language == "python" else EcosystemReviewDecision.JAVASCRIPT
    second_review = review_repository_ecosystem(
        second,
        _attestation(second, second_decision),
        expected_policy_digest=POLICY,
    )

    with pytest.raises(EcosystemReviewError, match="identity|network"):
        _project((first_review, second_review), first, second)


def test_same_network_cannot_resolve_to_different_canonical_repositories() -> None:
    first = _candidate()
    second = _rehash_candidate(first, canonical_repository="https://github.com/other/application")
    first_review = review_repository_ecosystem(
        first,
        _attestation(first, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    second_review = review_repository_ecosystem(
        second,
        _attestation(second, EcosystemReviewDecision.UNRESOLVED),
        expected_policy_digest=POLICY,
    )

    with pytest.raises(EcosystemReviewError, match="identity|network"):
        _project((first_review, second_review), first, second)


def test_insufficient_review_cannot_hide_repository_network_conflict() -> None:
    canonical = "https://github.com/example/application"
    first = _candidate(repository=build_network_identity(canonical))
    second = _candidate(repository=build_network_identity(canonical, redirects=("https://github.com/example/redirect",)))
    accepted = review_repository_ecosystem(
        first,
        _attestation(first, EcosystemReviewDecision.PYTHON),
        expected_policy_digest=POLICY,
    )
    insufficient = review_repository_ecosystem(
        second,
        _attestation(second, EcosystemReviewDecision.UNRESOLVED),
        expected_policy_digest=POLICY,
    )

    with pytest.raises(EcosystemReviewError, match="identity|network"):
        _project((accepted, insufficient), first, second)
