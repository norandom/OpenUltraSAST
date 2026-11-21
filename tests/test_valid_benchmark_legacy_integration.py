"""Legacy catalog, verification, and assembly routed through the new authorities (task 9.1)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.unseen import extract, replay  # noqa: E402
from benchmarks.valid import assemble, catalog, verify  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
    CanonicalEcosystem,
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import (  # noqa: E402
    EvidenceRef,
    LicenseEvidence,
    PackageEcosystemEvidence,
    build_fix_site_candidate,
)
from benchmarks.valid.ground_truth_review import (  # noqa: E402
    GroundTruthExclusionReason,
    GroundTruthStatus,
    VerifiedScope,
    review_ground_truth,
)
from benchmarks.valid.historical_authorization import (  # noqa: E402
    HISTORICAL_REVIEW_SCHEMA,
    PINNED_HISTORICAL_DIGESTS,
    HistoricalAuthorizationError,
    accept_reviewed_withdrawal,
    authorize_historical_path,
    build_withdrawal_candidate,
    pinned_historical_inventory,
    require_current_qualification,
)
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    OrdinaryDrawAssignmentV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    OrdinarySelectionV1,
    ReviewedPositiveInput,
    _fix_exclusion_value,
    _push_value,
    _selection_value,
)
from benchmarks.valid.population_freeze import (  # noqa: E402
    PopulationClass,
    PopulationClassificationReason,
    PopulationFreezeError,
    population_freeze_bytes,
)
from benchmarks.valid.population_freeze_contract import accept_population_freeze  # noqa: E402
from benchmarks.valid.reservation import (  # noqa: E402
    RepositoryIdentityResolver,
    ReservationAuthority,
    legacy_reservation_source,
)
from benchmarks.valid.reservation_identity import build_network_identity  # noqa: E402
from openultrasast.core.canonical import bytes_digest, canonical_bytes, content_digest  # noqa: E402
from openultrasast.tool_hunter import ChatResponse  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PILOT_POOL = ROOT / "benchmarks/valid/pilot/pool-valid.toml"
PILOT_FREEZE = ROOT / "benchmarks/valid/pilot/freeze-valid.json"
TRAIN_CATALOG = ROOT / "benchmarks/valid/train/catalog.toml"
ECOSYSTEM_POLICY = content_digest({"policy": "ecosystem-review-fixture"})
GROUND_TRUTH_POLICY = content_digest({"policy": "ground-truth-review-fixture"})
FREEZE_POLICY = content_digest({"policy": "population-freeze-fixture"})
DRAW_POLICY = content_digest({"policy": "ordinary-first-parent-fixture", "required": 20})
PROVENANCE = content_digest({"source": "legacy-integration-fixture"})
PACKAGE_EVIDENCE = PackageEcosystemEvidence("python", EvidenceRef("requirements.txt", content_digest({"manifest": 1}), 27))
LICENSE_EVIDENCE = LicenseEvidence("MIT", EvidenceRef("LICENSE", content_digest({"license": 1}), 21))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def pair(tmp_path):
    commit_count = 0

    def runner(argv, **kwargs):
        nonlocal commit_count
        assert not {"fetch", "clone", "pull", "push", "blame"} & set(argv)
        assert not any(arg.startswith("-L") for arg in argv)
        if "commit" in argv:
            timestamp = f"@{1600000000 + commit_count * 86400} +0000"
            kwargs["env"] = {**os.environ, "GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp}
            commit_count += 1
        return subprocess.run(argv, **kwargs)

    git = extract.Git(tmp_path, runner=runner)
    git.run("init", "-q")
    git.run("config", "user.name", "Fixture")
    git.run("config", "user.email", "fixture@example.invalid")
    pre = 'from flask import request\n@app.route("/run")\ndef handler():\n    return eval(request.args["code"])\n'
    post = pre.replace('eval(request.args["code"])', 'int(request.args["code"])')
    commits = []
    for text in (pre, post):
        (tmp_path / "app.py").write_text(text)
        git.run("add", "app.py")
        git.run("commit", "-qm", "fixture")
        commits.append(git.run("rev-parse", "HEAD").strip())
    source = dict(
        repository="fixture/app",
        url="https://github.com/fixture/app",
        parent=commits[0],
        fix=commits[1],
        advisory="GHSA-fixture",
        cwe="CWE-94",
        family="injection",
        advisory_text="Request code is evaluated.",
    )
    (case,) = catalog.build_cases(git, source)
    return git, case


class Stub:
    def __init__(self, **changes):
        self.calls = []
        self.answer = dict(
            vulnerable_pre_fix=True,
            fix_addresses_it=True,
            reachable_in_repo=True,
            entry_point="Flask route /run using request.args",
            confidence=0.86,
            advisory_cited=True,
            **changes,
        )

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        return ChatResponse(content=json.dumps(self.answer))


def ordinary_rows(n=90):
    return [
        dict(
            head=f"{i + 10:040x}",
            parents=[f"{i + 9:040x}"],
            timestamp=i,
            author="Fixture",
            message="ordinary edit",
            files=[dict(path="other.py", added=1, removed=1, head_lines=[[2, 2]], functions=["other"], generated=False)],
        )
        for i in range(n)
    ]


def accepted(case, **changes):
    record = dict(
        id=case["id"],
        vulnerable_pre_fix=True,
        fix_addresses_it=True,
        reachable_in_repo=True,
        entry_point="Flask route /run",
        confidence=0.86,
        model="stub",
        advisory_cited=True,
        human_spot_check=dict(decision="accept", reviewer="AB", date="2026-10-12"),
        verdict="accepted",
    )
    record.update(changes)
    return record


def human_judgment(**changes):
    values = {
        "producer_identity": "ground-truth-producer@example.invalid",
        "reviewer_identity": "ground-truth-reviewer@example.invalid",
        "conflict_disclosed": True,
        "policy_digest": GROUND_TRUTH_POLICY,
        "policy_satisfied": True,
        "defect_present": True,
        "fix_addresses": True,
        "in_repository_reachable": True,
        "verified_scopes": (VerifiedScope("injection", "python"),),
    }
    values.update(changes)
    return values


def _resolver(*networks):
    return RepositoryIdentityResolver(networks or (build_network_identity("https://github.com/fixture/app"),))


def _candidate(git, case, resolver):
    request = catalog.candidate_request(case, resolver=resolver, package_evidence=PACKAGE_EVIDENCE, license_evidence=LICENSE_EVIDENCE)
    return build_fix_site_candidate(git, request)


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


def _reviewed_positive(git, case, record, *, resolver, human=None):
    candidate = _candidate(git, case, resolver)
    ecosystem = _ecosystem(candidate)
    attestation = verify.review_attestation(
        record,
        candidate_digest=candidate.candidate_digest,
        ecosystem_review_digest=ecosystem.review_digest,
        human_judgment=human or human_judgment(),
    )
    review = review_ground_truth(
        candidate,
        ecosystem,
        attestation,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return ReviewedPositiveInput(candidate, ecosystem, review)


def _selection(positive):
    network = positive.candidate.network_identity_digest
    repository = positive.candidate.canonical_repository
    pushes = []
    for index in range(20):
        draft = OrdinaryPushV1(
            repository,
            network,
            CanonicalEcosystem.PYTHON,
            f"{9000 + index * 2:040x}",
            f"{9001 + index * 2:040x}",
            8,
            content_digest({"change": index}),
            content_digest({"history": network}),
            "",
        )
        pushes.append(replace(draft, push_digest=content_digest(_push_value(draft, include_digest=False))))
    change = positive.ground_truth_review.change_identity_digest
    fix_exclusion = OrdinaryFixExclusionV1(
        network,
        positive.candidate.fixed.revision,
        change,
        positive.ground_truth_review.review_digest,
    )
    assignments = tuple(OrdinaryDrawAssignmentV1(change, push.network_identity_digest, push.ecosystem, push.push_digest) for push in pushes)
    provenance = content_digest(
        {
            "history_sources": ((repository, network, pushes[0].history_source_digest),),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in (fix_exclusion,)),
            "policy_digest": DRAW_POLICY,
        }
    )
    selection = OrdinarySelectionV1(
        20,
        DRAW_POLICY,
        (change,),
        (fix_exclusion,),
        tuple(sorted(pushes, key=lambda item: item.push_digest)),
        tuple(sorted(assignments)),
        (),
        provenance,
        "",
    )
    return replace(selection, selection_digest=content_digest(_selection_value(selection, include_digest=False)))


def _replacement_arguments(positive, *, authority, census):
    return dict(
        ordinary_selection=_selection(positive),
        reservation_census=census,
        reservation_authority=authority,
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def test_model_assistance_is_separate_and_never_an_accepted_label(pair):
    git, case = pair
    record = verify.spot_check(verify.verify_case(git, case, client=Stub()), "accept", "AB", "2026-10-12")
    assert record["verdict"] == "accepted"

    assistance = verify.model_assistance(record)
    assert assistance["authoritative"] is False
    assert set(assistance["checks"]) == {*verify.CHECKS, "advisory_cited"}
    assert "human_spot_check" not in assistance and "verdict" not in assistance

    candidate = _candidate(git, case, _resolver())
    ecosystem = _ecosystem(candidate)
    attestation = verify.review_attestation(
        record,
        candidate_digest=candidate.candidate_digest,
        ecosystem_review_digest=ecosystem.review_digest,
        human_judgment=human_judgment(defect_present=None, fix_addresses=None, in_repository_reachable=None),
    )
    assert attestation.model_assistance_digest == verify.model_assistance_digest(record)
    review = review_ground_truth(
        candidate,
        ecosystem,
        attestation,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    assert review.status is GroundTruthStatus.EXCLUDED
    assert review.exclusion_reason is GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT
    assert review.model_assistance_digest == verify.model_assistance_digest(record)


def test_legacy_record_and_spot_check_shapes_cannot_supply_the_human_judgment(pair):
    git, case = pair
    record = verify.spot_check(verify.verify_case(git, case, client=Stub()), "accept", "AB", "2026-10-12")
    candidate = _candidate(git, case, _resolver())
    ecosystem = _ecosystem(candidate)
    keywords = dict(candidate_digest=candidate.candidate_digest, ecosystem_review_digest=ecosystem.review_digest)

    for legacy_shape in (None, record, record["human_spot_check"], accepted(case) | {"decision": "accept"}):
        with pytest.raises(ValueError, match="human judgment"):
            verify.review_attestation(record, human_judgment=legacy_shape, **keywords)


def test_only_the_human_judgment_decides_acceptance(pair):
    git, case = pair
    disagreeing = Stub()
    for key in verify.CHECKS:
        disagreeing.answer[key] = False
    record = verify.spot_check(verify.verify_case(git, case, client=disagreeing), "reject", "AB", "2026-10-12")
    assert record["verdict"] == "rejected"

    positive = _reviewed_positive(git, case, record, resolver=_resolver())
    assert positive.ground_truth_review.status is GroundTruthStatus.ACCEPTED
    assert positive.ground_truth_review.verified_scopes == (VerifiedScope("injection", "python"),)

    rejected = _reviewed_positive(
        git,
        case,
        record,
        resolver=_resolver(),
        human=human_judgment(defect_present=False),
    )
    assert rejected.ground_truth_review.status is GroundTruthStatus.EXCLUDED
    assert rejected.ground_truth_review.exclusion_reason is GroundTruthExclusionReason.JUDGMENT_REJECTED

    self_reviewed = _reviewed_positive(
        git,
        case,
        record,
        resolver=_resolver(),
        human=human_judgment(reviewer_identity="ground-truth-producer@example.invalid"),
    )
    assert self_reviewed.ground_truth_review.status is GroundTruthStatus.EXCLUDED
    assert self_reviewed.ground_truth_review.exclusion_reason is GroundTruthExclusionReason.SELF_REVIEW


def test_catalog_routes_identity_language_license_and_source_evidence(pair):
    git, case = pair
    resolver = _resolver(build_network_identity("https://github.com/fixture/app", aliases=("https://github.com/fixture-mirror/app",)))

    request = catalog.candidate_request(case, resolver=resolver, package_evidence=PACKAGE_EVIDENCE, license_evidence=LICENSE_EVIDENCE)
    assert request.repository.canonical_repository == "https://github.com/fixture/app"
    candidate = build_fix_site_candidate(git, request)

    identity = resolver.resolve(case["url"])
    assert candidate.canonical_repository == identity.canonical_repository
    assert candidate.network_identity_digest == identity.network_identity_digest
    assert resolver.resolve("https://github.com/FIXTURE-MIRROR/app.git").network_identity_digest == identity.network_identity_digest
    assert candidate.observed_language == case["language"] == "python"
    assert candidate.license_evidence.expression == "MIT"
    assert candidate.package_evidence.ecosystem_hint == "python"
    assert candidate.source_evidence.source_kind == "security_advisory"
    assert candidate.source_evidence.source_locator == case["advisory"]
    assert candidate.source_evidence.evidence_digest == bytes_digest(case["advisory_text"].encode("utf-8"))
    assert candidate.vulnerable.content_digest != candidate.fixed.content_digest
    assert "eval(" in candidate.vulnerable.content and "int(" in candidate.fixed.content


def test_legacy_assembly_is_development_only_and_refused_as_admission_root(pair, tmp_path, monkeypatch):
    git, case = pair
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows())
    record = assemble.freeze(
        tmp_path / "pool",
        cases=[case],
        verifications=[accepted(case)],
        repos={case["repo"]: git},
        used=set(),
        seed=7,
    )

    assert assemble.LEGACY_FREEZE_ADMISSION_CLASS == "legacy_development_only"
    assert record["admission_class"] == assemble.LEGACY_FREEZE_ADMISSION_CLASS
    assert record["admission_class"] not in {item.value for item in PopulationClass}
    # The exact validator the V3 admission preflight freeze gate calls refuses the legacy record.
    with pytest.raises((AttributeError, TypeError, PopulationFreezeError)):
        population_freeze_bytes(record)
    with pytest.raises((AttributeError, TypeError, PopulationFreezeError)):
        population_freeze_bytes(json.loads((tmp_path / "pool/freeze-valid.json").read_text()))
    # The development workflow itself stays usable: the legacy pool still replays.
    loaded = replay.load_slice(tmp_path / "pool/pool-valid.toml", 1)
    assert loaded and loaded[0]["case_id"] == case["id"]


def test_replacement_freeze_delegates_to_the_population_and_artifact_authorities(pair):
    git, case = pair
    record = verify.verify_case(git, case, client=Stub())
    positive = _reviewed_positive(git, case, record, resolver=_resolver())
    authority = ReservationAuthority(_resolver())
    census = authority.current_census()

    freeze = assemble.replacement_freeze((positive,), **_replacement_arguments(positive, authority=authority, census=census))

    assert freeze.positive_count == 1
    assert freeze.population_class is PopulationClass.INSUFFICIENT
    assert PopulationClassificationReason.BELOW_MINIMUM_POSITIVES in freeze.classification_reasons
    assert freeze.population_class is not PopulationClass.ADMISSION
    assert freeze.reservation_census_digest == census.census_digest
    content = accept_population_freeze(freeze)
    assert content == population_freeze_bytes(freeze) and len(content) > 0
    # New identities must never be historical pilot identities (requirement 4.9).
    with pytest.raises(PopulationFreezeError, match="historical identity"):
        assemble.replacement_freeze(
            (positive,),
            forbidden_historical_identities=(freeze.population_digest, freeze.freeze_digest),
            **_replacement_arguments(positive, authority=authority, census=census),
        )


def test_withdrawn_pilot_identities_are_refused_as_replacement_inputs(pair):
    git, case = pair
    pilot_repositories = sorted(row["repository"] for row in tomllib.loads(PILOT_POOL.read_text())["repository"])
    assert len(pilot_repositories) == 12
    pilot = pilot_repositories[0]
    owner, name = pilot.split("/")
    pilot_url = f"https://github.com/{pilot}"
    network = build_network_identity(pilot_url, aliases=(f"https://github.com/{owner}-mirror/{name}",))
    resolver = _resolver(network)
    legacy = legacy_reservation_source(resolver, repository=pilot_url, source_digest=content_digest({"pilot": pilot}))
    authority = ReservationAuthority(resolver, legacy_sources=(legacy,))
    census = authority.current_census()

    assert authority.is_reserved(pilot_url, census)
    assert authority.is_reserved(f"https://github.com/{owner}-mirror/{name}", census)
    assert not authority.is_reserved("https://github.com/fixture/app", census)

    pilot_source = dict(
        repository=pilot,
        url=pilot_url,
        parent=case["parent"],
        fix=case["commit"],
        advisory="GHSA-pilot",
        cwe="CWE-94",
        family="injection",
        advisory_text="Historical pilot defect.",
    )
    (pilot_case,) = catalog.build_cases(git, pilot_source)
    record = verify.verify_case(git, pilot_case, client=Stub())
    positive = _reviewed_positive(git, pilot_case, record, resolver=resolver)

    with pytest.raises(PopulationFreezeError, match="permanently reserved"):
        assemble.replacement_freeze((positive,), **_replacement_arguments(positive, authority=authority, census=census))

    # The withdrawn pilot itself stays auditable exactly, but never as current qualification.
    inventory = pinned_historical_inventory(ROOT)
    withdrawal_candidate = build_withdrawal_candidate(inventory)
    review = {
        "schema_version": HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": withdrawal_candidate.candidate_digest,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "custodian",
        "reviewer_identity": "historical-reviewer",
        "conflict_disclosed": True,
        "policy_digest": content_digest({"policy": "historical-review-fixture"}),
    }
    review["review_digest"] = content_digest(review)
    withdrawal = accept_reviewed_withdrawal(withdrawal_candidate, canonical_bytes(review))
    with pytest.raises(HistoricalAuthorizationError, match="non-admissible"):
        require_current_qualification(withdrawal)
    pool_digest = PINNED_HISTORICAL_DIGESTS["benchmarks/valid/pilot/pool-valid.toml"]
    audited = authorize_historical_path(ROOT, "benchmarks/valid/pilot/pool-valid.toml", pool_digest, withdrawal)
    assert hashlib.sha256(audited).hexdigest() == pool_digest


def test_historical_pilot_and_train_readers_remain_byte_identical_and_usable():
    for relative in ("benchmarks/valid/pilot/pool-valid.toml", "benchmarks/valid/pilot/freeze-valid.json"):
        content = (ROOT / relative).read_bytes()
        assert content and hashlib.sha256(content).hexdigest() == PINNED_HISTORICAL_DIGESTS[relative]

    rows = replay.load_slice(PILOT_POOL, 1)
    assert rows and sum(1 for row in rows if row["kind"] == "vulnerability") >= 1
    freeze = json.loads(PILOT_FREEZE.read_text())
    assert freeze["freeze_digest"] and freeze["negative_ratio"] == 20

    train_cases = tomllib.loads(TRAIN_CATALOG.read_text())["case"]
    assert train_cases and all(row["language"] and row["cwe"] and row["repo"] for row in train_cases[:50])
