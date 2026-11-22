"""Attestation-fixture apparatus for bounded Python cohort ingestion tests.

External review records are supplied as untrusted canonical bytes built with the
same independently reviewed attestation convention as the committed review
authority tests: distinct producer and reviewer identities, real policy and
conflict-disclosure machinery, and digest-bound evidence. Nothing here fabricates
reviewer judgment; every mutation deliberately weakens one attestation so the
ingestion boundary has to record the closed exclusion itself.
"""

from __future__ import annotations

import io
from dataclasses import replace
from typing import Any

from benchmarks.valid.catalog import candidate_request
from benchmarks.valid.cohort_ingestion import EXTERNAL_REVIEW_RECORD_SCHEMA
from benchmarks.valid.ecosystem_review import (
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    RepositoryEcosystemReviewV1,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import (
    EvidenceRef,
    FixSiteCandidateV1,
    LicenseEvidence,
    PackageEcosystemEvidence,
    build_fix_site_candidate,
)
from benchmarks.valid.ground_truth_review import GroundTruthAttestationV1, GroundTruthReviewV1, VerifiedScope, review_ground_truth
from benchmarks.valid.reservation import RepositoryIdentityResolver, ReservationAuthority
from benchmarks.valid.reservation_identity import build_network_identity
from benchmarks.valid.sourcing_queue import (
    ReviewQueueEntryV1,
    SourcingQueueStateV1,
    family_evidence,
    reachability_evidence,
    sourcing_candidate_request,
    sourcing_queue_policy,
)
from benchmarks.valid.sourcing_queue_build import build_sourcing_queue
from openultrasast.core.canonical import bytes_digest, canonical_bytes, content_digest

ECOSYSTEM_POLICY = content_digest({"policy": "ecosystem-review-fixture-v1"})
GROUND_TRUTH_POLICY = content_digest({"policy": "ground-truth-review-fixture-v1"})
ENUMERATION_ACTOR = "cohort-sourcing-operator@example.invalid"
ENUMERATION_REVIEWER = "cohort-enumeration-reviewer@example.invalid"
ECOSYSTEM_PRODUCER = "ecosystem-producer@example.invalid"
ECOSYSTEM_REVIEWER = "ecosystem-reviewer@example.invalid"
PYTHON_COUNT = 12

_APPS: dict[str, dict[str, Any]] = {}
for _index in range(PYTHON_COUNT):
    _family = "injection" if _index % 2 == 0 else "path_traversal"
    _apps_key = f"py-{_index:02d}"
    _APPS[_apps_key] = {
        "url": f"https://github.com/fixture/cohort-{_apps_key}",
        "repo": f"fixture/cohort-{_apps_key}",
        "path": "app.py",
        "function": f"handler_{_index:02d}",
        "language": "python",
        "hint": "python",
        "family": _family,
        "cwe": "CWE-94" if _family == "injection" else "CWE-22",
        "vulnerable": f"def handler_{_index:02d}(query):\n    return eval(query)\n",
        "fixed": f"def handler_{_index:02d}(query):\n    return str(query)\n",
    }
_APPS["js-00"] = {
    "url": "https://github.com/fixture/cohort-js-00",
    "repo": "fixture/cohort-js-00",
    "path": "lib/index.js",
    "function": "sanitize",
    "language": "javascript",
    "hint": "javascript",
    "family": "injection",
    "cwe": "CWE-94",
    "vulnerable": "function sanitize(input) {\n  return eval(input);\n}\n",
    "fixed": "function sanitize(input) {\n  return String(input);\n}\n",
}
_APPS["js-01"] = {
    "url": "https://github.com/fixture/cohort-js-01",
    "repo": "fixture/cohort-js-01",
    "path": "src/validate.js",
    "function": "validate",
    "language": "javascript",
    "hint": "javascript",
    "family": "output_encoding",
    "cwe": "CWE-79",
    "vulnerable": "function validate(input) {\n  return eval(input);\n}\n",
    "fixed": "function validate(input) {\n  return String(input);\n}\n",
}
_REVISIONS = {name: (f"{5000 + index * 2:040x}", f"{5001 + index * 2:040x}") for index, name in enumerate(sorted(_APPS))}
READ_POLICY = bytes_digest(b"cohort-ingestion-read-policy-fixture")


class FakeReader:
    """FixSiteReader over pinned synthetic snapshots, both sides nonzero."""

    def __init__(self) -> None:
        self._blobs: dict[tuple[str, str], str] = {}
        self._parents: dict[str, tuple[str, ...]] = {}
        for name, app in _APPS.items():
            parent, fix = _REVISIONS[name]
            self._blobs[(parent, app["path"])] = app["vulnerable"]
            self._blobs[(fix, app["path"])] = app["fixed"]
            self._parents[fix] = (parent,)

    def parents(self, revision: str) -> tuple[str, ...]:
        return self._parents.get(revision, ())

    def blob(self, revision: str, path: str) -> str | None:
        return self._blobs.get((revision, path))


class _Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if kwargs.get("IfNoneMatch") != "*":
            raise AssertionError("conditional create was not requested")
        if key in self.objects:
            raise _ProviderConflict
        body = kwargs["Body"]
        assert isinstance(body, bytes)
        self.objects[key] = body
        return {"ETag": "opaque-storage-token"}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if key not in self.objects:
            raise _ProviderMissing
        return {"Body": io.BytesIO(self.objects[key]), "ContentLength": len(self.objects[key])}


class _ProviderConflict(Exception):
    response = {"Error": {"Code": "ConditionalRequestConflict", "Message": "provider-secret"}}


class _ProviderMissing(Exception):
    response = {"Error": {"Code": "NoSuchKey", "Message": "provider-secret"}}


def _settings():
    from benchmarks.valid.store_configuration import StorePurpose, StoreSettings

    return StoreSettings(
        StorePurpose.DURABLE,
        "https://store.internal.invalid:9000",
        "valid-benchmark-durable",
        "ACCESS-SECRET",
        "SECRET-SECRET",
        "eu-test-1",
        "SESSION-SECRET",
    )


def _read_authority():
    from benchmarks.valid.artifact_repository import ArtifactActorRole, artifact_read_authority

    return artifact_read_authority(ArtifactActorRole.OPERATOR, (), READ_POLICY, expected_access_policy_digest=READ_POLICY)


def case_for(name: str, **changes: Any) -> dict[str, Any]:
    app = _APPS[name]
    parent, fix = _REVISIONS[name]
    case = {
        "id": f"{name}-case",
        "repo": app["repo"],
        "url": app["url"],
        "advisory": f"GHSA-cohort-{name}",
        "cwe": app["cwe"],
        "family": app["family"],
        "language": app["language"],
        "commit": fix,
        "parent": parent,
        "path": app["path"],
        "function": app["function"],
        "advisory_text": f"Cohort fixture advisory for {name} describing the defect.",
    }
    case.update(changes)
    return case


def request_for(name: str, **changes: Any):
    app = _APPS[name]
    case_changes = {key: value for key, value in changes.items() if key != "advisory_text"}
    advisory_text = changes.get("advisory_text", f"Cohort fixture advisory for {name} describing the defect.")
    return sourcing_candidate_request(
        case_for(name, advisory_text=advisory_text, **case_changes),
        family=family_evidence(
            vulnerability_family=app["family"],
            cwe=app["cwe"],
            advisory_locator=f"GHSA-cohort-{name}",
            advisory_text=advisory_text,
        ),
        reachability=reachability_evidence(entry_point=f"route:/run/{name}", evidence=f"route:/run/{name}"),
        package_evidence=PackageEcosystemEvidence(app["hint"], EvidenceRef("requirements.txt", content_digest({"manifest": name}), 27)),
        license_evidence=LicenseEvidence("MIT", EvidenceRef("LICENSE", content_digest({"license": name}), 21)),
    )


def resolver() -> RepositoryIdentityResolver:
    return RepositoryIdentityResolver(build_network_identity(app["url"]) for app in _APPS.values())


def authority(resolver_: RepositoryIdentityResolver, legacy: tuple = ()) -> ReservationAuthority:
    return ReservationAuthority(resolver_, legacy_sources=tuple(legacy))


def python_cohort_state(
    requests: list | None = None,
    *,
    resolver_: RepositoryIdentityResolver | None = None,
    authority_: ReservationAuthority | None = None,
    per_ecosystem_cap: int = 20,
) -> tuple[SourcingQueueStateV1, RepositoryIdentityResolver]:
    resolved = resolver_ or resolver()
    state = build_sourcing_queue(
        requests or [request_for(f"py-{index:02d}") for index in range(PYTHON_COUNT)] + [request_for("js-00")],
        reader=FakeReader(),
        resolver=resolved,
        authority=authority_ or authority(resolved),
        policy=sourcing_queue_policy(per_ecosystem_cap=per_ecosystem_cap, required_families=2),
        enumeration_actor=ENUMERATION_ACTOR,
        enumeration_reviewer=ENUMERATION_REVIEWER,
    )
    return state, resolved


def candidates_for(requests: list, resolver_: RepositoryIdentityResolver) -> dict[str, FixSiteCandidateV1]:
    result: dict[str, FixSiteCandidateV1] = {}
    for request in requests:
        fix_request = candidate_request(
            request.case,
            resolver=resolver_,
            package_evidence=request.package_evidence,
            license_evidence=request.license_evidence,
        )
        candidate = build_fix_site_candidate(FakeReader(), fix_request)
        result[candidate.candidate_digest] = candidate
    return result


def python_entries(state: SourcingQueueStateV1) -> list[ReviewQueueEntryV1]:
    return [*state.python_queue.entries]


def _eco_value(att: EcosystemReviewAttestationV1) -> dict[str, Any]:
    return {
        "candidate_digest": att.candidate_digest,
        "source_evidence_digest": att.source_evidence_digest,
        "producer_identity": att.producer_identity,
        "reviewer_identity": att.reviewer_identity,
        "conflict_disclosed": att.conflict_disclosed,
        "policy_digest": att.policy_digest,
        "policy_satisfied": att.policy_satisfied,
        "decision": att.decision.value,
    }


def _gt_value(att: GroundTruthAttestationV1) -> dict[str, Any]:
    return {
        "candidate_digest": att.candidate_digest,
        "ecosystem_review_digest": att.ecosystem_review_digest,
        "producer_identity": att.producer_identity,
        "reviewer_identity": att.reviewer_identity,
        "conflict_disclosed": att.conflict_disclosed,
        "policy_digest": att.policy_digest,
        "policy_satisfied": att.policy_satisfied,
        "defect_present": att.defect_present,
        "fix_addresses": att.fix_addresses,
        "in_repository_reachable": att.in_repository_reachable,
        "verified_scopes": tuple(
            {"vulnerability_family": scope.vulnerability_family, "ecosystem": scope.ecosystem.value} for scope in att.verified_scopes
        ),
        "model_assistance_digest": att.model_assistance_digest,
    }


def reviewed_record(
    entry: ReviewQueueEntryV1,
    candidate: FixSiteCandidateV1,
    *,
    eco_changes: dict[str, Any] | None = None,
    gt_changes: dict[str, Any] | None = None,
    entry_digest: str | None = None,
    record_extra: dict[str, Any] | None = None,
    derive_review: bool = True,
) -> tuple[bytes, GroundTruthReviewV1 | None]:
    """Build one external review record and the review the authorities derive from it."""
    locator = entry.family.advisory_locator
    eco = replace(
        EcosystemReviewAttestationV1(
            candidate_digest=candidate.candidate_digest,
            source_evidence_digest=candidate.source_evidence.evidence_digest,
            producer_identity=ECOSYSTEM_PRODUCER,
            reviewer_identity=ECOSYSTEM_REVIEWER,
            conflict_disclosed=True,
            policy_digest=ECOSYSTEM_POLICY,
            policy_satisfied=True,
            decision=EcosystemReviewDecision.PYTHON,
        ),
        **(eco_changes or {}),
    )
    ecosystem = review_repository_ecosystem(candidate, eco, expected_policy_digest=ECOSYSTEM_POLICY)
    ground_truth = replace(
        GroundTruthAttestationV1(
            candidate_digest=candidate.candidate_digest,
            ecosystem_review_digest=ecosystem.review_digest,
            producer_identity=f"producer-{locator}@example.invalid",
            reviewer_identity=f"reviewer-{locator}@example.invalid",
            conflict_disclosed=True,
            policy_digest=GROUND_TRUTH_POLICY,
            policy_satisfied=True,
            defect_present=True,
            fix_addresses=True,
            in_repository_reachable=True,
            verified_scopes=(VerifiedScope(entry.family.vulnerability_family, "python"),),
            model_assistance_digest=None,
        ),
        **(gt_changes or {}),
    )
    review = None
    if derive_review:
        review = review_ground_truth(
            candidate,
            ecosystem,
            ground_truth,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )
    payload: dict[str, Any] = {
        "schema_version": EXTERNAL_REVIEW_RECORD_SCHEMA,
        "queue_entry_digest": entry_digest or entry.entry_digest,
        "ecosystem_attestation": _eco_value(eco),
        "ground_truth_attestation": _gt_value(ground_truth),
    }
    payload.update(record_extra or {})
    return canonical_bytes(payload), review


def model_only_assistance_digest() -> str:
    from benchmarks.valid import verify

    record = {
        "id": "model-only-fixture",
        "vulnerable_pre_fix": True,
        "fix_addresses_it": True,
        "reachable_in_repo": True,
        "entry_point": "route:/run/model-only",
        "confidence": 0.91,
        "model": "stub",
        "advisory_cited": True,
    }
    return verify.model_assistance_digest(record)


__all__ = [
    "ECOSYSTEM_POLICY",
    "ECOSYSTEM_PRODUCER",
    "ECOSYSTEM_REVIEWER",
    "ENUMERATION_ACTOR",
    "ENUMERATION_REVIEWER",
    "GROUND_TRUTH_POLICY",
    "FakeReader",
    "PYTHON_COUNT",
    "READ_POLICY",
    "RepositoryEcosystemReviewV1",
    "authority",
    "candidates_for",
    "case_for",
    "model_only_assistance_digest",
    "python_cohort_state",
    "python_entries",
    "request_for",
    "resolver",
    "reviewed_record",
]
