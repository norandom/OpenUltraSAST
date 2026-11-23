"""Ordinary-change population draws over the closed replacement positive set."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    COMBINED_JAVASCRIPT_NAMES,
    COMBINED_PYTHON_NAMES,
    ECOSYSTEM_POLICY,
    ENUMERATION_ACTOR,
    ENUMERATION_REVIEWER,
    FOURTH_JAVASCRIPT_NAMES,
    GROUND_TRUTH_POLICY,
    READ_POLICY,
    THIRD_PYTHON_NAMES,
    FakeReader,
    _Client,
    _read_authority,
    _settings,
    authority,
    candidate_for,
    case_for,
    ingested_replacement_ledger,
    replacement_cohort_state,
    request_for,
    resolver,
    reviewed_record,
)

from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.catalog import candidate_request  # noqa: E402
from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    CohortBatchStatus,
    ingest_javascript_cohort_batch,
    ingest_python_cohort_batch,
)
from benchmarks.valid.cohort_selection import (  # noqa: E402
    ingest_fourth_cohort_batch,
    ingest_third_cohort_batch,
    select_fourth_cohort_batch,
    select_third_cohort_batch,
)
from benchmarks.valid.fix_site_catalog import build_fix_site_candidate  # noqa: E402
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    ContaminationTiming,
    OrdinaryExclusionReason,
    reviewed_contamination,
)
from benchmarks.valid.ordinary_draw import (  # noqa: E402
    MINIMUM_ORDINARY_PER_POSITIVE,
    OrdinaryDrawError,
    OrdinaryDrawReason,
    OrdinaryDrawRule,
    OrdinaryPopulationHistorySource,
    draw_ordinary_population,
)
from benchmarks.valid.ordinary_draw_contract import (  # noqa: E402
    ORDINARY_POPULATION_DRAW_SCHEMA,
    OrdinaryDrawStateError,
    OrdinaryDrawStateReason,
    ordinary_population_draw,
    ordinary_population_draw_bytes,
)
from benchmarks.valid.ordinary_draw_store import (  # noqa: E402
    decode_ordinary_population_draw,
    persist_ordinary_population_draw,
    resume_ordinary_population_draw,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    validate_artifact,
)
from benchmarks.valid.reservation import ReservationAuthority, legacy_reservation_source  # noqa: E402
from benchmarks.valid.sourcing_queue import sourcing_queue_policy  # noqa: E402
from benchmarks.valid.sourcing_queue_build import build_sourcing_queue  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

LEAN_PYTHON = tuple(f"py-{index:02d}" for index in range(10))
LEAN_JAVASCRIPT = tuple(f"js-{index:02d}" for index in range(10))
LEAN_THIRD_PYTHON = tuple(f"py3-{index:02d}" for index in range(10))
LEAN_THIRD_JAVASCRIPT = tuple(f"js3-{index:02d}" for index in range(10))
LEAN_NAMES = (*LEAN_PYTHON, *LEAN_JAVASCRIPT, *LEAN_THIRD_PYTHON, *LEAN_THIRD_JAVASCRIPT)
CLOSED_PYTHON_NAMES = (*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES)
CLOSED_JAVASCRIPT_NAMES = (*COMBINED_JAVASCRIPT_NAMES, *FOURTH_JAVASCRIPT_NAMES)
FULL_NAMES = (*CLOSED_PYTHON_NAMES, *CLOSED_JAVASCRIPT_NAMES)
ORDINARY_DEPTH = 26
DRAW_POLICY = content_digest({"policy": "ordinary-population-draw-v1", "required_per_positive": MINIMUM_ORDINARY_PER_POSITIVE})
SOURCE = content_digest({"source": "fixture-ordinary-first-parent-histories"})
CONTAMINATION_POLICY = content_digest({"policy": "contamination-review-v1"})
SECOND_PARENT = f"{0xF50000:040x}"
SECOND_FIX = f"{0xF50001:040x}"


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


class OrdinaryFixtureHistory:
    """Synthetic first-parent ordinary histories below each fixture vulnerable parent."""

    def __init__(self, names, *, depth=ORDINARY_DEPTH, inserted=None, contents=None):
        self._parents: dict[str, tuple[str, ...]] = {}
        self._changes: dict[str, bytes] = {}
        self._repositories: dict[str, bytes] = {}
        for index, name in enumerate(sorted(names)):
            row = case_for(name)
            parent = row["parent"]
            self._repositories[row["url"]] = f"repository-manifest:{name}".encode()
            prefix = [parent, *(inserted or {}).get(name, ())]
            chain = [*prefix] + [f"{0xF00000 + index * (depth + 8) + step:040x}" for step in range(depth)]
            self._parents[row["commit"]] = (parent,)
            for position, revision in enumerate(chain):
                following = chain[position + 1] if position + 1 < len(chain) else ""
                self._parents[revision] = (following,) if following else ()
                content: bytes | None
                if revision in (contents or {}):
                    content = contents[revision]
                elif revision == parent:
                    content = f"snapshot:{name}:vulnerable".encode()
                elif revision in prefix[1:]:
                    content = None
                else:
                    content = f"ordinary:{name}:{position}".encode()
                if content is not None:
                    self._changes[revision] = content

    def parents(self, revision: str) -> tuple[str, ...]:
        return self._parents.get(revision, ())

    def change_bytes(self, revision: str) -> bytes | None:
        return self._changes.get(revision)

    def repository_bytes(self, canonical_repository: str) -> bytes | None:
        return self._repositories.get(canonical_repository)


class LabelLadenReader:
    """History reader carrying released label and detector-observation markers."""

    def __init__(self, inner: OrdinaryFixtureHistory) -> None:
        self._inner = inner
        self.released_admission_labels = b"released-label-marker"
        self.detector_observations = b"detector-observation-marker"

    def parents(self, revision: str) -> tuple[str, ...]:
        return self._inner.parents(revision)

    def change_bytes(self, revision: str) -> bytes | None:
        return self._inner.change_bytes(revision)

    def repository_bytes(self, canonical_repository: str) -> bytes | None:
        return self._inner.repository_bytes(canonical_repository)


class SharedRepoReader(FakeReader):
    """Fixture reader extended with a second reviewed change inside repo py-00."""

    def __init__(self) -> None:
        super().__init__()
        self._blobs[(SECOND_PARENT, "app/second.py")] = "def helper(query):\n    return eval(query)\n"
        self._blobs[(SECOND_FIX, "app/second.py")] = "def helper(query):\n    return str(query)\n"
        self._parents[SECOND_FIX] = (SECOND_PARENT,)


def _second_change_request():
    return request_for(
        "py-00",
        path="app/second.py",
        function="helper",
        advisory="GHSA-cohort-py-00-second",
        commit=SECOND_FIX,
        parent=SECOND_PARENT,
    )


def _candidate(request, resolved, reader=None):
    fix_request = candidate_request(
        request.case,
        resolver=resolved,
        package_evidence=request.package_evidence,
        license_evidence=request.license_evidence,
    )
    return build_fix_site_candidate(reader or FakeReader(), fix_request)


def _lean_state():
    return replacement_cohort_state(
        python_names=(*LEAN_PYTHON, *LEAN_THIRD_PYTHON),
        javascript_names=(*LEAN_JAVASCRIPT, *LEAN_THIRD_JAVASCRIPT),
    )


def _batch_for(state, resolved, names, ecosystem, extra_requests=()):
    queue = state.python_queue if ecosystem == "python" else state.javascript_queue
    candidates = {}
    for name in names:
        candidate = candidate_for(name, resolved)
        candidates[candidate.candidate_digest] = candidate
    for request in extra_requests:
        candidate = _candidate(request, resolved, SharedRepoReader())
        candidates[candidate.candidate_digest] = candidate
    by_candidate = {entry.candidate_digest: entry for entry in queue.entries}
    records = [reviewed_record(by_candidate[digest], candidates[digest], ecosystem=ecosystem)[0] for digest in candidates]
    ingest = ingest_python_cohort_batch if ecosystem == "python" else ingest_javascript_cohort_batch
    return (
        ingest(
            records,
            state=state,
            candidates_by_digest=candidates,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        ),
        candidates,
    )


def _lean_batches(state, resolved):
    rounds = (
        ("python", LEAN_PYTHON),
        ("javascript", LEAN_JAVASCRIPT),
        ("python", LEAN_THIRD_PYTHON),
        ("javascript", LEAN_THIRD_JAVASCRIPT),
    )
    return tuple(_batch_for(state, resolved, names, ecosystem)[0] for ecosystem, names in rounds)


def _draw(
    batches,
    resolved,
    history,
    *,
    names=LEAN_NAMES,
    reviews=(),
    excluded_reviews=(),
    census=None,
    required=MINIMUM_ORDINARY_PER_POSITIVE,
    extra_candidates=(),
    reader=None,
):
    candidates = {}
    for name in names:
        candidate = candidate_for(name, resolved)
        candidates[candidate.candidate_digest] = candidate
    for candidate in extra_candidates:
        candidates[candidate.candidate_digest] = candidate
    sources = {}
    for candidate in candidates.values():
        history_reader = reader if reader is not None else history
        sources[candidate.network_identity_digest] = OrdinaryPopulationHistorySource(
            history_reader,
            candidate.canonical_repository,
            candidate.network_identity_digest,
            SOURCE,
        )
    return draw_ordinary_population(
        batches,
        candidates_by_digest=candidates,
        history_by_network=sources,
        contamination_reviews=reviews,
        excluded_reviews=excluded_reviews,
        reservation_census=census if census is not None else authority(resolved).current_census(),
        required_per_positive=required,
        policy_digest=DRAW_POLICY,
    )


def _contamination(name: str, tip: str, timing=ContaminationTiming.PRE_FREEZE):
    return reviewed_contamination(
        network_identity_digest=candidate_for(name, resolver()).network_identity_digest,
        tip_revision=tip,
        timing=timing,
        evidence_digest=content_digest({"contamination": tip}),
        producer_identity="contamination-producer@example.invalid",
        reviewer_identity="contamination-reviewer@example.invalid",
        conflict_disclosed=True,
        policy_digest=CONTAMINATION_POLICY,
    )


def _excluded_review(name: str, resolved):
    candidate = candidate_for(name, resolved)
    state, _ = _lean_state()
    queue = state.python_queue if case_for(name)["repo"].startswith("fixture/cohort-py") else state.javascript_queue
    entry = next(item for item in queue.entries if item.candidate_digest == candidate.candidate_digest)
    return reviewed_record(entry, candidate, gt_changes={"defect_present": False})[1]


def _fields(draw):
    return dict(
        required_per_positive=draw.required_per_positive,
        policy_digest=draw.policy_digest,
        closure_digest=draw.closure_digest,
        reservation_census_digest=draw.reservation_census_digest,
        positive_change_digests=draw.positive_change_digests,
        per_positive_counts=draw.per_positive_counts,
        repository_receipts=draw.repository_receipts,
        fix_exclusions=draw.fix_exclusions,
        pushes=draw.pushes,
        assignments=draw.assignments,
        exclusions=draw.exclusions,
        provenance=draw.provenance,
    )


def _full_closed_batches():
    state, resolved = replacement_cohort_state(
        python_names=CLOSED_PYTHON_NAMES,
        javascript_names=CLOSED_JAVASCRIPT_NAMES,
    )
    candidates = {name: candidate_for(name, resolved) for name in FULL_NAMES}
    by_digest = {candidate.candidate_digest: candidate for candidate in candidates.values()}
    ledger = ingested_replacement_ledger(state, resolved)
    third_selection = select_third_cohort_batch(
        state=state,
        accepted_batches=ledger,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    third_entries = [entry for entry in state.python_queue.entries if entry.entry_digest in set(third_selection.selected_entries)]
    third = ingest_third_cohort_batch(
        [reviewed_record(entry, by_digest[entry.candidate_digest])[0] for entry in third_entries],
        selection=third_selection,
        state=state,
        candidates_by_digest=by_digest,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    ledger = (*ledger, third)
    fourth_selection = select_fourth_cohort_batch(
        state=state,
        accepted_batches=ledger,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    fourth_entries = [entry for entry in state.javascript_queue.entries if entry.entry_digest in set(fourth_selection.selected_entries)]
    fourth = ingest_fourth_cohort_batch(
        [reviewed_record(entry, by_digest[entry.candidate_digest], ecosystem="javascript")[0] for entry in fourth_entries],
        selection=fourth_selection,
        state=state,
        candidates_by_digest=by_digest,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return (*ledger, fourth), resolved


def test_every_accepted_positive_draws_twenty_eligible_pushes():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    assert all(batch.status is CohortBatchStatus.ACCEPTED for batch in batches)
    history = OrdinaryFixtureHistory(LEAN_NAMES)
    draw = _draw(batches, resolved, history)

    assert len(draw.per_positive_counts) == 40
    assert all(count == MINIMUM_ORDINARY_PER_POSITIVE for _, count in draw.per_positive_counts)
    assert len(draw.assignments) == 40 * MINIMUM_ORDINARY_PER_POSITIVE
    assert len(draw.pushes) == 40 * MINIMUM_ORDINARY_PER_POSITIVE
    assert len(set(draw.pushes)) == len(draw.pushes)
    assert all(push.change_byte_length > 0 for push in draw.pushes)
    assert all(receipt.byte_length > 0 for receipt in draw.repository_receipts)
    assert len(draw.repository_receipts) == 40

    eligible = {
        (row.network_identity_digest, row.tip_revision)
        for row in draw.provenance
        if row.rule is OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY
    }
    for push in draw.pushes:
        row = next(
            item
            for item in draw.provenance
            if item.rule is OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY
            and (item.network_identity_digest, item.tip_revision) == (push.network_identity_digest, push.tip_revision)
        )
        assert row.evidence_digest == push.push_digest
    assert eligible == {(push.network_identity_digest, push.tip_revision) for push in draw.pushes}

    ecosystems = {
        candidate_for(name, resolved).network_identity_digest: ("python" if name.startswith(("py-", "py3-")) else "javascript")
        for name in LEAN_NAMES
    }
    assert all(push.ecosystem.value == ecosystems[push.network_identity_digest] for push in draw.pushes)
    assert decode_ordinary_population_draw(ordinary_population_draw_bytes(draw)) == draw


def test_draw_is_deterministic_and_permutation_invariant():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)
    first = _draw(batches, resolved, history)
    second = _draw(tuple(reversed(batches)), resolved, history)

    assert ordinary_population_draw_bytes(first) == ordinary_population_draw_bytes(second)
    assert first.draw_digest == second.draw_digest
    assert first.provenance_digest == second.provenance_digest


def test_draw_is_label_blind_and_detector_blind(monkeypatch):
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    plain = _draw(batches, resolved, OrdinaryFixtureHistory(LEAN_NAMES))
    monkeypatch.setenv("VALID_BENCHMARK_ADMISSION_LABELS", "released-label-marker")
    monkeypatch.setenv("VALID_BENCHMARK_DETECTOR_OBSERVATIONS", "detector-observation-marker")
    laden = _draw(batches, resolved, OrdinaryFixtureHistory(LEAN_NAMES), reader=LabelLadenReader(OrdinaryFixtureHistory(LEAN_NAMES)))

    assert ordinary_population_draw_bytes(plain) == ordinary_population_draw_bytes(laden)
    value = json.loads(ordinary_population_draw_bytes(plain))
    assert set(value) == {
        "schema_version",
        "required_per_positive",
        "policy_digest",
        "closure_digest",
        "reservation_census_digest",
        "positive_change_digests",
        "per_positive_counts",
        "repository_receipts",
        "fix_exclusions",
        "pushes",
        "assignments",
        "exclusions",
        "provenance",
        "provenance_digest",
        "draw_digest",
    }
    assert value["schema_version"] == ORDINARY_POPULATION_DRAW_SCHEMA
    assert not any("label" in key or "observation" in key for key in value)


def test_draw_excludes_contaminated_and_reviewed_excluded_changes():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)
    py_parent = case_for("py-00")["parent"]
    js_parent = case_for("js-00")["parent"]
    excluded_review = _excluded_review("js-00", resolved)
    assert excluded_review.status.value == "excluded"

    draw = _draw(
        batches,
        resolved,
        history,
        reviews=(_contamination("py-00", py_parent),),
        excluded_reviews=(excluded_review,),
    )

    py_network = candidate_for("py-00", resolved).network_identity_digest
    js_network = candidate_for("js-00", resolved).network_identity_digest
    assert all((push.network_identity_digest, push.tip_revision) != (py_network, py_parent) for push in draw.pushes)
    assert all((push.network_identity_digest, push.tip_revision) != (js_network, js_parent) for push in draw.pushes)
    assert len(draw.exclusions) == 1
    assert draw.exclusions[0].reason is OrdinaryExclusionReason.REVIEWED_SECURITY_DEFECT
    rules = {(row.network_identity_digest, row.tip_revision, row.rule) for row in draw.provenance}
    assert (py_network, py_parent, OrdinaryDrawRule.EXCLUDED_REVIEWED_CONTAMINATION) in rules
    assert (js_network, js_parent, OrdinaryDrawRule.EXCLUDED_REVIEWED_CHANGE) in rules
    for row in draw.provenance:
        if row.rule is OrdinaryDrawRule.EXCLUDED_REVIEWED_CHANGE:
            assert row.evidence_digest == excluded_review.review_digest
    counts = dict(draw.per_positive_counts)
    assert all(count >= MINIMUM_ORDINARY_PER_POSITIVE for count in counts.values())


def test_draw_refuses_unapplied_and_post_freeze_exclusion_evidence():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, history, reviews=(_contamination("py-00", "e" * 40),))
    assert error.value.reason is OrdinaryDrawReason.CONFLICTING_EXCLUSION_EVIDENCE

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(
            batches,
            resolved,
            history,
            reviews=(_contamination("py-00", case_for("py-00")["parent"], ContaminationTiming.POST_FREEZE),),
        )
    assert error.value.reason is OrdinaryDrawReason.POST_FREEZE_CONTAMINATION


def test_shared_repository_pushes_are_drawn_once_and_fixes_are_excluded_mid_walk():
    resolved = resolver()
    requests = [request_for(name) for name in (*LEAN_PYTHON, *LEAN_JAVASCRIPT, *LEAN_THIRD_PYTHON, *LEAN_THIRD_JAVASCRIPT)]
    requests.append(_second_change_request())
    state = build_sourcing_queue(
        requests,
        reader=SharedRepoReader(),
        resolver=resolved,
        authority=authority(resolved),
        policy=sourcing_queue_policy(per_ecosystem_cap=25, required_families=2),
        enumeration_actor=ENUMERATION_ACTOR,
        enumeration_reviewer=ENUMERATION_REVIEWER,
    )
    python_batch, python_candidates = _batch_for(state, resolved, LEAN_PYTHON, "python", extra_requests=(_second_change_request(),))
    other = (
        _batch_for(state, resolved, LEAN_JAVASCRIPT, "javascript")[0],
        _batch_for(state, resolved, LEAN_THIRD_PYTHON, "python")[0],
        _batch_for(state, resolved, LEAN_THIRD_JAVASCRIPT, "javascript")[0],
    )
    batches = (python_batch, *other)
    assert len(batches) == 4

    history = OrdinaryFixtureHistory(
        (*LEAN_PYTHON, *LEAN_JAVASCRIPT, *LEAN_THIRD_PYTHON, *LEAN_THIRD_JAVASCRIPT),
        inserted={"py-00": (SECOND_FIX, SECOND_PARENT)},
        contents={SECOND_PARENT: b"snapshot:py-00:second-vulnerable"},
    )
    draw = _draw(batches, resolved, history, extra_candidates=python_candidates.values())

    assert len(draw.per_positive_counts) == 41
    assert all(count == MINIMUM_ORDINARY_PER_POSITIVE for _, count in draw.per_positive_counts)
    assert len(draw.assignments) == 41 * MINIMUM_ORDINARY_PER_POSITIVE
    assert len(draw.pushes) == 39 * MINIMUM_ORDINARY_PER_POSITIVE + MINIMUM_ORDINARY_PER_POSITIVE + 1
    py_network = candidate_for("py-00", resolved).network_identity_digest
    shared = [push for push in draw.pushes if push.network_identity_digest == py_network]
    assert len(shared) == MINIMUM_ORDINARY_PER_POSITIVE + 1
    assert all(push.tip_revision != SECOND_FIX for push in draw.pushes)
    second_digest = next(candidate.candidate_digest for candidate in python_candidates.values() if candidate.fixed.revision == SECOND_FIX)
    second_positive = next(positive for positive in python_batch.accepted_positives if positive.candidate_digest == second_digest)
    fix_rows = [row for row in draw.provenance if row.rule is OrdinaryDrawRule.EXCLUDED_ACCEPTED_FIX]
    assert any(row.tip_revision == SECOND_FIX and row.network_identity_digest == py_network for row in fix_rows)
    assert any(row.evidence_digest == second_positive.ground_truth_review_digest for row in fix_rows)


def test_draw_refuses_insufficient_histories_closed():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, OrdinaryFixtureHistory(LEAN_NAMES, depth=18))
    assert error.value.reason is OrdinaryDrawReason.INSUFFICIENT_HISTORY
    assert "18 of 20" in str(error.value)

    class ShallowHistory(OrdinaryFixtureHistory):
        def __init__(self) -> None:
            super().__init__(LEAN_NAMES)
            fixes = {case_for(name)["commit"] for name in LEAN_NAMES}
            self._parents = {revision: edges for revision, edges in self._parents.items() if revision in fixes}

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, ShallowHistory())
    assert error.value.reason is OrdinaryDrawReason.INSUFFICIENT_HISTORY
    assert "0 of 20" in str(error.value)


def test_draw_proves_repositories_and_changes_readable_and_nonzero():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    py_repo = case_for("py-00")["url"]
    py_parent = case_for("py-00")["parent"]

    missing = OrdinaryFixtureHistory(LEAN_NAMES)
    del missing._repositories[py_repo]
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, missing)
    assert error.value.reason is OrdinaryDrawReason.REPOSITORY_UNREADABLE

    empty = OrdinaryFixtureHistory(LEAN_NAMES)
    empty._repositories[py_repo] = b""
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, empty)
    assert error.value.reason is OrdinaryDrawReason.REPOSITORY_UNREADABLE

    unreadable = OrdinaryFixtureHistory(LEAN_NAMES)
    del unreadable._changes[py_parent]
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, unreadable)
    assert error.value.reason is OrdinaryDrawReason.HISTORY_UNREADABLE

    zero = OrdinaryFixtureHistory(LEAN_NAMES)
    zero._changes[py_parent] = b""
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, zero)
    assert error.value.reason is OrdinaryDrawReason.HISTORY_UNREADABLE

    unbound = OrdinaryFixtureHistory(LEAN_NAMES)
    unbound._parents[case_for("py-00")["commit"]] = ("d" * 40,)
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, unbound)
    assert error.value.reason is OrdinaryDrawReason.HISTORY_UNBOUND


def test_draw_refuses_reserved_repositories_and_unclosed_sets():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    history = OrdinaryFixtureHistory(LEAN_NAMES)

    legacy = legacy_reservation_source(
        resolved,
        repository=case_for("py-00")["url"],
        source_digest=content_digest({"legacy-pilot": "py-00"}),
    )
    reserved_census = ReservationAuthority(resolved, legacy_sources=(legacy,)).current_census()
    assert candidate_for("py-00", resolved).network_identity_digest in reserved_census.reserved_network_digests
    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, history, census=reserved_census)
    assert error.value.reason is OrdinaryDrawReason.RESERVED_REPOSITORY

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches[:2], resolved, history)
    assert error.value.reason is OrdinaryDrawReason.POSITIVE_SET_NOT_CLOSED

    candidates = {name: candidate_for(name, resolved) for name in LEAN_NAMES}
    sources = {
        candidate.network_identity_digest: OrdinaryPopulationHistorySource(
            history,
            candidate.canonical_repository,
            candidate.network_identity_digest,
            SOURCE,
        )
        for candidate in candidates.values()
    }
    del candidates["py3-00"]
    with pytest.raises(OrdinaryDrawError) as error:
        draw_ordinary_population(
            batches,
            candidates_by_digest={candidate.candidate_digest: candidate for candidate in candidates.values()},
            history_by_network=sources,
            reservation_census=authority(resolved).current_census(),
            required_per_positive=MINIMUM_ORDINARY_PER_POSITIVE,
            policy_digest=DRAW_POLICY,
        )
    assert error.value.reason is OrdinaryDrawReason.CANDIDATE_MISSING

    with pytest.raises(OrdinaryDrawError) as error:
        _draw(batches, resolved, history, required=19)
    assert error.value.reason is OrdinaryDrawReason.INVALID_REQUEST


def test_draw_assembler_fails_closed_on_impossible_combinations():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    draw = _draw(batches, resolved, OrdinaryFixtureHistory(LEAN_NAMES))
    based = _fields(draw)

    assert ordinary_population_draw(**based).draw_digest == draw.draw_digest
    short_counts = (*based["per_positive_counts"][:-1], (based["per_positive_counts"][-1][0], 19))
    duplicate_pushes = (*based["pushes"], based["pushes"][0])
    mutations = (
        {"per_positive_counts": short_counts},
        {"pushes": based["pushes"][:-1]},
        {"pushes": duplicate_pushes},
        {"repository_receipts": (replace(based["repository_receipts"][0], byte_length=0), *based["repository_receipts"][1:])},
        {"provenance": tuple(row for row in based["provenance"] if row.rule is not OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY)},
        {"reservation_census_digest": "z" * 64},
        {"positive_change_digests": based["positive_change_digests"][:-1]},
        {"assignments": based["assignments"][:-1]},
    )
    for changes in mutations:
        with pytest.raises(OrdinaryDrawStateError) as error:
            ordinary_population_draw(**{**based, **changes})
        assert error.value.reason is OrdinaryDrawStateReason.STATE_MISMATCH

    forged_rows = tuple(replace(row, rule="forged_rule") for row in draw.provenance)
    with pytest.raises(OrdinaryDrawStateError) as error:
        replace(draw, provenance=forged_rows)
    assert error.value.reason is OrdinaryDrawStateReason.STATE_MISMATCH

    malformed_fix = (replace(based["fix_exclusions"][0], fixed_revision="not-a-revision"), *based["fix_exclusions"][1:])
    with pytest.raises(OrdinaryDrawStateError) as error:
        ordinary_population_draw(**{**based, "fix_exclusions": malformed_fix})
    assert error.value.reason is OrdinaryDrawStateReason.STATE_MISMATCH


def test_draw_decode_is_hostile_and_persists_durably():
    state, resolved = _lean_state()
    batches = _lean_batches(state, resolved)
    draw = _draw(batches, resolved, OrdinaryFixtureHistory(LEAN_NAMES))
    content = ordinary_population_draw_bytes(draw)
    assert content and decode_ordinary_population_draw(content) == draw

    good = json.loads(content)
    spaced = json.dumps(good, sort_keys=True, indent=1).encode("utf-8")
    wrong_schema = json.dumps({**good, "schema_version": "other.v1"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered = json.dumps({**good, "required_per_positive": 19}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    for bad in (
        b"",
        b"not json at all",
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}",
        spaced,
        wrong_schema,
        tampered,
    ):
        with pytest.raises(OrdinaryDrawStateError):
            decode_ordinary_population_draw(bad)

    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    reference = persist_ordinary_population_draw(store, draw)
    assert persist_ordinary_population_draw(store, draw) == reference
    accepted = store.get(
        reference, expected_kind=ArtifactKind.POPULATION, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    validate_artifact(accepted.content, reference=reference)
    assert reference.access_class is ArtifactAccessClass.OPERATOR_SAFE

    resumed = resume_ordinary_population_draw(
        S3ArtifactRepository(_settings(), client), reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == draw
    assert ordinary_population_draw_bytes(resumed) == content


def test_full_closed_set_draw_reproduces_from_durable_evidence_after_restart():
    batches, resolved = _full_closed_batches()
    assert len(batches) == 4
    history = OrdinaryFixtureHistory(FULL_NAMES)
    draw = _draw(batches, resolved, history, names=FULL_NAMES)

    assert len(draw.per_positive_counts) == 48
    assert all(count >= MINIMUM_ORDINARY_PER_POSITIVE for _, count in draw.per_positive_counts)
    assert len(draw.assignments) == 48 * MINIMUM_ORDINARY_PER_POSITIVE

    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    reference = persist_ordinary_population_draw(store, draw)
    restarted = resume_ordinary_population_draw(
        S3ArtifactRepository(_settings(), client), reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert restarted == draw
    content = ordinary_population_draw_bytes(draw)
    assert ordinary_population_draw_bytes(restarted) == content
    assert decode_ordinary_population_draw(content) == restarted
