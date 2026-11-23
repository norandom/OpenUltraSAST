"""Bounded label-blind sourcing and review queues for the replacement population."""

from __future__ import annotations

import io
import itertools
import json
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import sourcing_queue_store, verify  # noqa: E402
from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.fix_site_catalog import EvidenceRef, LicenseEvidence, PackageEcosystemEvidence  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import ArtifactKind, ArtifactReference, validate_artifact  # noqa: E402
from benchmarks.valid.reservation import (  # noqa: E402
    RepositoryIdentityResolver,
    ReservationAuthority,
    legacy_reservation_source,
)
from benchmarks.valid.reservation_identity import build_network_identity  # noqa: E402
from benchmarks.valid.sourcing_queue import (  # noqa: E402
    QueueEntryStatus,
    SourcingQueueError,
    SourcingQueueReason,
    family_evidence,
    pending_queue_identities,
    queue_state_bytes,
    reachability_evidence,
    reviewer_evidence_package_bytes,
    reviewer_evidence_payload,
    sourcing_candidate_request,
    sourcing_queue_policy,
)
from benchmarks.valid.sourcing_queue_build import build_sourcing_queue  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose, StoreSettings  # noqa: E402
from openultrasast.core.canonical import bytes_digest, content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PILOT_POOL = ROOT / "benchmarks/valid/pilot/pool-valid.toml"
READ_POLICY = bytes_digest(b"sourcing-queue-read-policy-fixture")
ENUMERATION_ACTOR = "sourcing-operator@example.invalid"
ENUMERATION_REVIEWER = "enumeration-reviewer@example.invalid"
DEFAULT_ADVISORY = "Advisory text describing the defect."

PYTHON_VULNERABLE = 'from flask import request\n\n\n@app.route("/run")\ndef handler():\n    return eval(request.args["code"])\n'
PYTHON_FIXED = 'from flask import request\n\n\n@app.route("/run")\ndef handler():\n    return int(request.args["code"])\n'
SECOND_VULNERABLE = "def load(query):\n    return eval(query)\n"
SECOND_FIXED = "def load(query):\n    return str(query)\n"
JS_VULNERABLE = "function sanitize(input) {\n  return eval(input);\n}\n"
JS_FIXED = "function sanitize(input) {\n  return String(input);\n}\n"
TS_VULNERABLE = "export function validate(input: string): string {\n  return eval(input);\n}\n"
TS_FIXED = "export function validate(input: string): string {\n  return String(input);\n}\n"

APPS = {
    "py-app": {
        "url": "https://github.com/fixture/py-app",
        "path": "app.py",
        "function": "handler",
        "language": "python",
        "hint": "python",
        "manifest": "requirements.txt",
        "vulnerable": PYTHON_VULNERABLE,
        "fixed": PYTHON_FIXED,
    },
    "py-two": {
        "url": "https://github.com/fixture/py-two",
        "path": "service.py",
        "function": "load",
        "language": "python",
        "hint": "python",
        "manifest": "requirements.txt",
        "vulnerable": SECOND_VULNERABLE,
        "fixed": SECOND_FIXED,
    },
    "py-three": {
        "url": "https://github.com/fixture/py-three",
        "path": "worker.py",
        "function": "load",
        "language": "python",
        "hint": "python",
        "manifest": "requirements.txt",
        "vulnerable": SECOND_VULNERABLE,
        "fixed": SECOND_FIXED,
    },
    "js-app": {
        "url": "https://github.com/fixture/js-app",
        "path": "lib/index.js",
        "function": "sanitize",
        "language": "javascript",
        "hint": "javascript",
        "manifest": "package.json",
        "vulnerable": JS_VULNERABLE,
        "fixed": JS_FIXED,
    },
    "ts-app": {
        "url": "https://github.com/fixture/ts-app",
        "path": "src/validate.ts",
        "function": "validate",
        "language": "typescript",
        "hint": "javascript",
        "manifest": "package.json",
        "vulnerable": TS_VULNERABLE,
        "fixed": TS_FIXED,
    },
}
_REVISIONS = {name: (f"{2000 + index * 2:040x}", f"{2001 + index * 2:040x}") for index, name in enumerate(sorted(APPS))}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    from benchmarks.unseen import extract

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)


class FakeReader:
    """FixSiteReader over pinned synthetic snapshots, both sides nonzero."""

    def __init__(self) -> None:
        self._blobs: dict[tuple[str, str], str] = {}
        self._parents: dict[str, tuple[str, ...]] = {}
        for name, app in APPS.items():
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


def _settings() -> StoreSettings:
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
    return artifact_read_authority(ArtifactActorRole.OPERATOR, (), READ_POLICY, expected_access_policy_digest=READ_POLICY)


def _case(name, **changes):
    app = APPS[name]
    parent, fix = _REVISIONS[name]
    case = {
        "id": f"{name}-case",
        "repo": app["url"].removeprefix("https://github.com/"),
        "url": app["url"],
        "advisory": "GHSA-fixture",
        "cwe": "CWE-94",
        "family": "injection",
        "language": app["language"],
        "commit": fix,
        "parent": parent,
        "path": app["path"],
        "function": app["function"],
        "advisory_text": DEFAULT_ADVISORY,
    }
    case.update(changes)
    return case


def _request(name, **changes):
    app = APPS[name]
    family = changes.pop("family", "injection")
    cwe = changes.pop("cwe", "CWE-94")
    entry_point = changes.pop("entry_point", "Flask route /run")
    advisory_text = changes.pop("advisory_text", DEFAULT_ADVISORY)
    family_advisory_text = changes.pop("family_advisory_text", advisory_text)
    model_digest = changes.pop("model_assistance_digest", None)
    return sourcing_candidate_request(
        _case(name, advisory_text=advisory_text, **changes),
        family=family_evidence(
            vulnerability_family=family,
            cwe=cwe,
            advisory_locator="GHSA-fixture",
            advisory_text=family_advisory_text,
        ),
        reachability=reachability_evidence(entry_point=entry_point, evidence=f"route:{entry_point}"),
        package_evidence=PackageEcosystemEvidence(
            app["hint"], EvidenceRef(app["manifest"], content_digest({"manifest": app["manifest"]}), 27)
        ),
        license_evidence=LicenseEvidence("MIT", EvidenceRef("LICENSE", content_digest({"license": 1}), 21)),
        model_assistance_digest=model_digest,
    )


def _resolver():
    return RepositoryIdentityResolver(build_network_identity(app["url"]) for app in APPS.values())


def _authority(resolver, legacy=()):
    return ReservationAuthority(resolver, legacy_sources=tuple(legacy))


def _policy(per_ecosystem_cap=4, required_families=2):
    return sourcing_queue_policy(per_ecosystem_cap=per_ecosystem_cap, required_families=required_families)


def _build(requests, *, resolver=None, authority=None, policy=None):
    resolver = resolver or _resolver()
    return build_sourcing_queue(
        requests,
        reader=FakeReader(),
        resolver=resolver,
        authority=authority or _authority(resolver),
        policy=policy or _policy(),
        enumeration_actor=ENUMERATION_ACTOR,
        enumeration_reviewer=ENUMERATION_REVIEWER,
    )


def _two_family_requests():
    return [
        _request("py-app"),
        _request("js-app", family="output_encoding", cwe="CWE-79", entry_point="HTTP response header write"),
    ]


def _all_entries(state):
    return [*state.python_queue.entries, *state.javascript_queue.entries]


def test_two_ecosystem_queues_with_two_families_and_nonzero_evidence():
    state = _build([*_two_family_requests(), _request("ts-app", entry_point="CLI argument validation")])

    assert state.python_queue.ecosystem == "python"
    assert state.javascript_queue.ecosystem == "javascript"
    assert sorted(entry.observed_language for entry in state.javascript_queue.entries) == ["javascript", "typescript"]
    assert {entry.canonical_ecosystem for entry in _all_entries(state)} == {"python", "javascript"}
    families = {entry.family.vulnerability_family for entry in _all_entries(state)}
    assert families == {"injection", "output_encoding"}

    for entry in _all_entries(state):
        assert entry.entry_status is QueueEntryStatus.PENDING_EXTERNAL_REVIEW
        assert entry.reachability.entry_point.strip()
        assert len(entry.reachability.evidence_digest) == 64
        assert entry.family.advisory_locator.strip()
        assert entry.fix_site.vulnerable_byte_length > 0
        assert entry.fix_site.fixed_byte_length > 0
        assert len(entry.fix_site.vulnerable_snapshot_digest) == 64
        assert len(entry.fix_site.fixed_snapshot_digest) == 64
        assert entry.fix_site.vulnerable_revision != entry.fix_site.fixed_revision

    py = state.python_queue.entries[0]
    assert py.fix_site.path == "app.py" and py.fix_site.function == "handler"


def test_sourcing_is_label_blind():
    clean = _build(_two_family_requests())

    labeled = []
    for request in _two_family_requests():
        case = dict(request.case)
        case["label_check"] = "confirmed"
        case["verdict"] = "accepted"
        case["label"] = True
        case["human_spot_check"] = {"decision": "accept", "reviewer": "AB"}
        labeled.append(
            sourcing_candidate_request(
                case,
                family=request.family,
                reachability=request.reachability,
                package_evidence=request.package_evidence,
                license_evidence=request.license_evidence,
                model_assistance_digest=request.model_assistance_digest,
            )
        )
    labeled_state = _build(labeled)

    assert labeled_state == clean
    assert pending_queue_identities(labeled_state) == pending_queue_identities(clean)
    assert queue_state_bytes(labeled_state) == queue_state_bytes(clean)

    for content in (queue_state_bytes(clean), reviewer_evidence_package_bytes(clean.python_queue.entries[0])):
        for forbidden in (b"label_check", b"verdict", b"accepted", b"confirmed", b"label", b"human_spot"):
            assert forbidden not in content


def test_complete_pilot_census_is_excluded_before_review():
    pilot_repositories = sorted(row["repository"] for row in tomllib.loads(PILOT_POOL.read_text())["repository"])
    assert len(pilot_repositories) == 12

    networks = []
    for index, repository in enumerate(pilot_repositories):
        owner, name = repository.split("/")
        aliases = (f"https://github.com/{owner}-mirror/{name}",) if index == 0 else ()
        networks.append(build_network_identity(f"https://github.com/{repository}", aliases=aliases))
    networks.append(build_network_identity(APPS["py-app"]["url"]))
    networks.append(build_network_identity(APPS["js-app"]["url"]))
    resolver = RepositoryIdentityResolver(networks)
    legacy = tuple(
        legacy_reservation_source(
            resolver, repository=f"https://github.com/{repository}", source_digest=content_digest({"pilot": repository})
        )
        for repository in pilot_repositories
    )
    authority = _authority(resolver, legacy=legacy)
    census = authority.current_census()
    assert len(census.reserved_network_digests) == 12

    owner, name = pilot_repositories[0].split("/")
    canonical_pilot = _request("py-app", url=f"https://github.com/{pilot_repositories[0]}", repo=pilot_repositories[0])
    alias_pilot = _request(
        "js-app",
        url=f"https://github.com/{owner}-mirror/{name}",
        repo=f"{owner}-mirror/{name}",
        family="output_encoding",
        cwe="CWE-79",
    )
    state = _build(
        [
            canonical_pilot,
            alias_pilot,
            _request("py-app"),
            _request("js-app", family="output_encoding", cwe="CWE-79"),
        ],
        resolver=resolver,
        authority=authority,
    )

    reserved_exclusions = [item for item in state.exclusions if item.reason is SourcingQueueReason.RESERVED_REPOSITORY]
    assert len(reserved_exclusions) == 2
    assert {item.repository for item in reserved_exclusions} == {f"https://github.com/{pilot_repositories[0]}"}
    queued_repositories = {entry.canonical_repository for entry in _all_entries(state)}
    assert queued_repositories.isdisjoint(f"https://github.com/{repository}" for repository in pilot_repositories)
    identities = pending_queue_identities(state)
    assert identities and all(identity.startswith(("python:", "javascript:")) for identity in identities)
    assert authority.current_census().reserved_network_digests == census.reserved_network_digests


def test_bounded_queues_enforce_caps_deterministically():
    requests = [_request(name) for name in ("py-app", "py-two", "py-three")]
    requests.append(_request("js-app", family="output_encoding", cwe="CWE-79"))
    state = _build(requests, policy=_policy(per_ecosystem_cap=2))
    assert len(state.python_queue.entries) == 2
    cap_exclusions = [item for item in state.exclusions if item.reason is SourcingQueueReason.QUEUE_CAP_EXCEEDED]
    assert len(cap_exclusions) == 1

    reversed_state = _build(list(reversed(requests)), policy=_policy(per_ecosystem_cap=2))
    assert reversed_state.state_digest == state.state_digest
    assert pending_queue_identities(reversed_state) == pending_queue_identities(state)
    assert reversed_state.exclusions == state.exclusions


class _TwinPathReader(FakeReader):
    """The py-app revisions also carry a second fix site under a different path."""

    def __init__(self) -> None:
        super().__init__()
        parent, fix = _REVISIONS["py-app"]
        self._blobs[(parent, "twin.py")] = SECOND_VULNERABLE
        self._blobs[(fix, "twin.py")] = SECOND_FIXED


class _TwinFunctionReader(FakeReader):
    """app.py at the py-app revisions carries a second function the fix changes."""

    def __init__(self) -> None:
        super().__init__()
        parent, fix = _REVISIONS["py-app"]
        self._blobs[(parent, "app.py")] = PYTHON_VULNERABLE + "\n\n" + SECOND_VULNERABLE
        self._blobs[(fix, "app.py")] = PYTHON_FIXED + "\n\n" + SECOND_FIXED


class _SameFunctionReader(FakeReader):
    """The py-two revisions also carry the same function under a different path."""

    def __init__(self) -> None:
        super().__init__()
        parent, fix = _REVISIONS["py-two"]
        self._blobs[(parent, "worker.py")] = SECOND_VULNERABLE
        self._blobs[(fix, "worker.py")] = SECOND_FIXED


def _build_with_reader(reader, requests, policy):
    resolver = _resolver()
    return build_sourcing_queue(
        requests,
        reader=reader,
        resolver=resolver,
        authority=_authority(resolver),
        policy=policy,
        enumeration_actor=ENUMERATION_ACTOR,
        enumeration_reviewer=ENUMERATION_REVIEWER,
    )


@pytest.mark.parametrize(
    "reader_type, name, changes, differing",
    (
        (_TwinPathReader, "py-app", {"path": "twin.py", "function": "load"}, ("path", "function")),
        (_TwinFunctionReader, "py-app", {"function": "load"}, ("function",)),
        (_SameFunctionReader, "py-two", {"path": "worker.py"}, ("path",)),
    ),
    ids=("path-and-function", "function-only", "path-only"),
)
def test_fix_site_scalars_break_otherwise_tied_candidates_under_a_cap(reader_type, name, changes, differing):
    first = _request(name)
    second = _request(name, **changes)
    requests = [first, second, _request("js-app", family="output_encoding", cwe="CWE-79")]
    policy = _policy(per_ecosystem_cap=1)
    assert (first.family, first.reachability, first.package_evidence, first.license_evidence) == (
        second.family,
        second.reachability,
        second.package_evidence,
        second.license_evidence,
    )
    assert (first.case["url"], first.model_assistance_digest) == (second.case["url"], second.model_assistance_digest)
    sites = tuple((request.case["path"], request.case["function"]) for request in (first, second))
    for element, index in (("path", 0), ("function", 1)):
        assert (sites[0][index] != sites[1][index]) is (element in differing)
    assert sites[0] < sites[1]

    digests = set()
    for order in itertools.permutations(requests):
        state = _build_with_reader(reader_type(), list(order), policy)
        (queued,) = state.python_queue.entries
        assert (queued.fix_site.path, queued.fix_site.function) == sites[0]
        digests.add((state.state_digest, pending_queue_identities(state)))

    assert len(digests) == 1
    state = _build_with_reader(reader_type(), requests, policy)
    (capped,) = [item for item in state.exclusions if item.reason is SourcingQueueReason.QUEUE_CAP_EXCEEDED]
    assert capped.candidate_digest != state.python_queue.entries[0].candidate_digest
    assert len(state.javascript_queue.entries) == 1


def test_durable_resume_reproduces_pending_identities():
    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    state = _build([*_two_family_requests(), _request("ts-app", entry_point="CLI argument validation")])

    reference = sourcing_queue_store.persist_sourcing_queue(store, state)
    assert sourcing_queue_store.persist_sourcing_queue(store, state) == reference

    restarted = S3ArtifactRepository(_settings(), client)
    resumed = sourcing_queue_store.resume_sourcing_queue(
        restarted, reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == state
    assert pending_queue_identities(resumed) == pending_queue_identities(state)


def test_exclusions_are_closed_and_enumeration_is_not_influence():
    resolver = _resolver()
    authority = _authority(resolver)
    census_before = authority.current_census()

    requests = [
        _request("py-app"),
        _request("js-app", family="output_encoding", cwe="CWE-79"),
        _request("py-two", url="https://github.com/unresolved/app", repo="unresolved/app"),
        _request("py-two", language="java", path="src/App.java"),
        _request("py-two"),
        _request("py-two"),
        _request("py-three", advisory_text="", family_advisory_text=DEFAULT_ADVISORY),
        _request("py-three", path="missing.py"),
        _request("py-app", advisory_text="Case-side advisory text.", family_advisory_text=DEFAULT_ADVISORY),
    ]
    state = _build(requests, resolver=resolver, authority=authority)

    reasons = {item.reason for item in state.exclusions}
    assert reasons == {
        SourcingQueueReason.UNRESOLVED_REPOSITORY,
        SourcingQueueReason.UNSUPPORTED_ECOSYSTEM,
        SourcingQueueReason.DUPLICATE_CANDIDATE,
        SourcingQueueReason.EVIDENCE_EMPTY,
        SourcingQueueReason.EVIDENCE_MISMATCH,
    }
    assert len(state.python_queue.entries) == 2
    assert len(state.javascript_queue.entries) == 1

    census_after = authority.current_census()
    assert census_after.reserved_network_digests == census_before.reserved_network_digests == ()
    assert not authority.is_reserved(APPS["py-app"]["url"], census_after)
    assert not authority.is_reserved(APPS["js-app"]["url"], census_after)

    decoded = sourcing_queue_store.decode_queue_state(queue_state_bytes(state))
    assert decoded == state
    assert pending_queue_identities(decoded) == pending_queue_identities(state)


def test_empty_evidence_inputs_are_refused_closed():
    with pytest.raises(SourcingQueueError) as empty_reachability:
        reachability_evidence(entry_point="  ", evidence="route:/run")
    assert empty_reachability.value.reason is SourcingQueueReason.EVIDENCE_EMPTY
    with pytest.raises(SourcingQueueError) as empty_family:
        family_evidence(vulnerability_family="injection", cwe="CWE-94", advisory_locator=" ", advisory_text="Advisory text.")
    assert empty_family.value.reason is SourcingQueueReason.EVIDENCE_EMPTY
    with pytest.raises(SourcingQueueError) as bad_family:
        family_evidence(vulnerability_family="Injection!", cwe="CWE-94", advisory_locator="GHSA-fixture", advisory_text="Advisory text.")
    assert bad_family.value.reason is SourcingQueueReason.EVIDENCE_EMPTY
    with pytest.raises(SourcingQueueError) as bad_cwe:
        family_evidence(vulnerability_family="injection", cwe="94", advisory_locator="GHSA-fixture", advisory_text="Advisory text.")
    assert bad_cwe.value.reason is SourcingQueueReason.EVIDENCE_EMPTY
    with pytest.raises(ValueError, match="families"):
        sourcing_queue_policy(per_ecosystem_cap=2, required_families=1)


def test_insufficient_families_is_a_closed_refusal():
    with pytest.raises(SourcingQueueError) as error:
        _build([_request("py-app"), _request("ts-app", entry_point="CLI argument validation")])
    assert error.value.reason is SourcingQueueReason.INSUFFICIENT_FAMILIES
    assert "families" in str(error.value)


def test_reviewer_evidence_package_is_canonical_and_model_assistance_stays_non_authoritative():
    record = {
        "id": "fixture",
        "vulnerable_pre_fix": True,
        "fix_addresses_it": True,
        "reachable_in_repo": True,
        "entry_point": "Flask route /run",
        "confidence": 0.86,
        "model": "stub",
        "advisory_cited": True,
    }
    assistance = verify.model_assistance(record)
    assert assistance["authoritative"] is False
    assert assistance["schema_version"] == "openultrasast.valid-detection-benchmark.model-assistance.v1"

    state = _build([_request("py-app", model_assistance_digest=verify.model_assistance_digest(record)), _two_family_requests()[1]])
    entry = state.python_queue.entries[0]
    package = reviewer_evidence_package_bytes(entry)
    payload = json.loads(package)

    assert len(QueueEntryStatus) == 1
    assert payload["entry_status"] == "pending_external_review"
    assert payload["model_assistance"] == {
        "schema_version": "openultrasast.valid-detection-benchmark.model-assistance.v1",
        "digest": verify.model_assistance_digest(record),
        "authoritative": False,
    }
    assert payload["queue_entry_digest"] == entry.entry_digest
    assert payload["fix_site"]["vulnerable_snapshot_digest"] == entry.fix_site.vulnerable_snapshot_digest
    for forbidden in (b"verdict", b"accepted", b"label", b"decision"):
        assert forbidden not in package

    bare = _build(_two_family_requests())
    assert json.loads(reviewer_evidence_package_bytes(bare.python_queue.entries[0]))["model_assistance"] is None
    assert reviewer_evidence_payload(entry)["family"]["vulnerability_family"] == "injection"


def test_evidence_packages_publish_and_reread_from_durable_store():
    store = S3ArtifactRepository(_settings(), _Client())
    state = _build([*_two_family_requests(), _request("ts-app", entry_point="CLI argument validation")])
    entries = _all_entries(state)

    references = sourcing_queue_store.publish_reviewer_evidence_packages(store, state)
    assert len(references) == len(entries)
    assert all(isinstance(item, ArtifactReference) and item.artifact_kind is ArtifactKind.REVIEW for item in references)

    for reference, entry in zip(references, entries, strict=True):
        accepted = store.get(
            reference, expected_kind=ArtifactKind.REVIEW, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
        )
        validate_artifact(accepted.content, reference=reference)
        assert accepted.artifact.payload == reviewer_evidence_payload(entry)


def test_queue_state_decode_refuses_hostile_bytes():
    state = _build(_two_family_requests())
    decode = sourcing_queue_store.decode_queue_state

    with pytest.raises(SourcingQueueError):
        decode(b"")
    with pytest.raises(SourcingQueueError):
        decode(b"not json at all")
    with pytest.raises(SourcingQueueError):
        decode(b'{"schema_version": "openultrasast.valid-detection-benchmark.sourcing-queue.v1"}')
    with pytest.raises(SourcingQueueError):
        decode(b'{"schema_version":"openultrasast.valid-detection-benchmark.sourcing-queue.v1","x":NaN}')
    with pytest.raises(SourcingQueueError):
        decode(b'{"schema_version":"openultrasast.valid-detection-benchmark.sourcing-queue.v1","x":1e999}')
    with pytest.raises(SourcingQueueError):
        decode(b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}")

    tampered = json.loads(queue_state_bytes(state))
    tampered["state_digest"] = "0" * 64
    tampered_bytes = json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(SourcingQueueError):
        decode(tampered_bytes)

    truncated = json.loads(queue_state_bytes(state))
    truncated["python_queue"]["cap"] = 99
    truncated_bytes = json.dumps(truncated, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(SourcingQueueError):
        decode(truncated_bytes)


def test_fix_derived_locations_come_from_the_security_fix_pair_only():
    state = _build(_two_family_requests())
    entry = state.python_queue.entries[0]
    parent, fix = _REVISIONS["py-app"]

    assert entry.fix_site.vulnerable_revision == parent
    assert entry.fix_site.fixed_revision == fix
    assert entry.fix_site.vulnerable_snapshot_digest != entry.fix_site.fixed_snapshot_digest
    assert entry.candidate_digest != entry.entry_digest
