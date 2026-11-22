"""Outcome-blind selection of the third bounded cohort batch over pending queues."""

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
    GROUND_TRUTH_POLICY,
    READ_POLICY,
    SINGLE_FAMILY_JAVASCRIPT_NAMES,
    SINGLE_FAMILY_PYTHON_NAMES,
    THIRD_JAVASCRIPT_NAMES,
    THIRD_PYTHON_NAMES,
    _Client,
    _read_authority,
    _settings,
    authority,
    ingested_replacement_ledger,
    replacement_cohort_state,
    resolver,
)

from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.cohort_selection import (  # noqa: E402
    COHORT_BATCH_CAP,
    CohortSelectionReason,
    CohortSelectionStateError,
    CohortSelectionStateReason,
    CohortSelectionStatus,
    cohort_selection,
    cohort_selection_bytes,
    select_third_cohort_batch,
)
from benchmarks.valid.cohort_selection_store import (  # noqa: E402
    decode_cohort_selection,
    persist_cohort_selection,
    resume_cohort_selection,
)
from benchmarks.valid.replacement_artifact_contract import ArtifactAccessClass, ArtifactKind, validate_artifact  # noqa: E402
from benchmarks.valid.reservation import legacy_reservation_source  # noqa: E402
from benchmarks.valid.sourcing_queue import ecosystem_review_queue, sourcing_queue_policy, sourcing_queue_state  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

THIRD_PYTHON_FAMILIES = {"deserialization", "ssrf"}


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


def _select(state, ledger, *, eco=ECOSYSTEM_POLICY, gt=GROUND_TRUTH_POLICY):
    return select_third_cohort_batch(
        state=state,
        accepted_batches=ledger,
        expected_ecosystem_policy_digest=eco,
        expected_ground_truth_policy_digest=gt,
    )


def _prepared():
    state, resolved = replacement_cohort_state()
    ledger = ingested_replacement_ledger(state, resolved)
    return state, resolved, ledger


def test_selection_balances_family_coverage_across_both_ecosystems():
    state, resolved, ledger = _prepared()
    assert {batch.ecosystem for batch in ledger} == {"python", "javascript"}

    selection = _select(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "python"
    assert selection.reason is CohortSelectionReason.BALANCED_PROGRESS_SELECTED
    expected = sorted(
        entry.entry_digest for entry in state.python_queue.entries if entry.family.vulnerability_family in THIRD_PYTHON_FAMILIES
    )
    assert selection.selected_entries == tuple(expected)
    assert selection.targeted_families == ("deserialization", "ssrf")
    assert selection.accepted_families == ("injection", "output_encoding", "path_traversal")
    assert dict(selection.accepted_by_ecosystem) == {"javascript": 12, "python": 12}
    assert selection.census_digest == state.census_digest
    assert selection.queue_digest == state.python_queue.queue_digest
    assert selection.prior_batch_digests == tuple(sorted(batch.batch_digest for batch in ledger))
    assert decode_cohort_selection(cohort_selection_bytes(selection)) == selection


def test_selection_targets_a_missing_ecosystem_to_preserve_both():
    state, resolved = replacement_cohort_state()
    ledger = ingested_replacement_ledger(state, resolved, javascript_names=())

    selection = _select(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "javascript"
    assert selection.reason is CohortSelectionReason.MISSING_ECOSYSTEM_SELECTED
    assert dict(selection.accepted_by_ecosystem) == {"python": 12}
    pending = sorted(state.javascript_queue.entries, key=lambda entry: entry.entry_digest)
    assert selection.selected_entries == tuple(entry.entry_digest for entry in pending[:COHORT_BATCH_CAP])
    assert selection.targeted_families == tuple(
        sorted({entry.family.vulnerability_family for entry in pending[:COHORT_BATCH_CAP]})
    )


def test_selection_targets_the_second_vulnerability_family_gap():
    state, resolved = replacement_cohort_state(
        python_names=("py-01", "py-03", *SINGLE_FAMILY_PYTHON_NAMES, *THIRD_PYTHON_NAMES),
        javascript_names=("js-01", *SINGLE_FAMILY_JAVASCRIPT_NAMES, *THIRD_JAVASCRIPT_NAMES),
    )
    ledger = ingested_replacement_ledger(
        state,
        resolved,
        python_names=("py-01", "py-03", *SINGLE_FAMILY_PYTHON_NAMES),
        javascript_names=("js-01", *SINGLE_FAMILY_JAVASCRIPT_NAMES),
        weakened_python=2,
        weakened_javascript=1,
    )
    ledger_families = {
        scope.vulnerability_family
        for batch in ledger
        for item in batch.accepted_positives
        for scope in item.verified_scopes
    }
    assert ledger_families == {"injection"}

    selection = _select(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.reason is CohortSelectionReason.FAMILY_GAP_SELECTED
    assert selection.ecosystem == "javascript"
    assert selection.targeted_families == ("deserialization", "output_encoding", "prototype_pollution", "ssrf")
    js_batch = next(batch for batch in ledger if batch.ecosystem == "javascript")
    pending = set(js_batch.pending_entries)
    assert set(selection.selected_entries) == pending
    typescript = [entry for entry in state.javascript_queue.entries if entry.observed_language == "typescript"]
    assert typescript and all(entry.entry_digest in pending for entry in typescript)
    assert all(entry.canonical_ecosystem == "javascript" for entry in typescript)


def test_selection_ignores_how_many_reviews_passed():
    state, resolved = replacement_cohort_state()
    full = ingested_replacement_ledger(state, resolved)
    thinned = ingested_replacement_ledger(state, resolved, weakened_python=2)
    assert len(thinned[0].accepted_positives) < len(full[0].accepted_positives)

    chosen = _select(state, full)
    other = _select(state, thinned)

    assert (chosen.status, chosen.reason, chosen.ecosystem) == (other.status, other.reason, other.ecosystem)
    assert chosen.selected_entries == other.selected_entries
    assert chosen.targeted_families == other.targeted_families
    assert chosen.selection_digest != other.selection_digest


def test_selection_refuses_a_reweighted_policy_after_judgments():
    state, resolved, ledger = _prepared()

    changed = _select(state, ledger, eco=content_digest({"policy": "reweighted-after-outcomes"}))
    frozen = _select(state, ledger)

    assert changed.status is CohortSelectionStatus.REFUSED
    assert changed.reason is CohortSelectionReason.POLICY_MISMATCH
    assert changed.selected_entries == () and changed.targeted_families == ()
    assert frozen.status is CohortSelectionStatus.SELECTED


def test_selection_refuses_a_stale_reservation_census():
    state, resolved, ledger = _prepared()
    reserved = legacy_reservation_source(
        resolved, repository="https://github.com/fixture/cohort-pyinj-00", source_digest="c" * 64
    )
    stale_state, _ = replacement_cohort_state(authority_=authority(resolver(), legacy=(reserved,)))
    assert stale_state.census_digest != state.census_digest
    assert [entry.entry_digest for entry in stale_state.python_queue.entries] == [
        entry.entry_digest for entry in state.python_queue.entries
    ]

    selection = _select(stale_state, ledger)

    assert selection.status is CohortSelectionStatus.REFUSED
    assert selection.reason is CohortSelectionReason.CENSUS_MISMATCH
    assert selection.census_digest == stale_state.census_digest
    assert decode_cohort_selection(cohort_selection_bytes(selection)) == selection


def test_selection_without_pending_entries_refuses_closed():
    state, _, ledger = _prepared()
    policy = sourcing_queue_policy(per_ecosystem_cap=1)
    empty = sourcing_queue_state(
        python_queue=ecosystem_review_queue("python", cap=1, policy_digest=policy.policy_digest, entries=()),
        javascript_queue=ecosystem_review_queue("javascript", cap=1, policy_digest=policy.policy_digest, entries=()),
        exclusions=(),
        census_digest=state.census_digest,
        policy_digest=policy.policy_digest,
    )

    selection = _select(empty, ledger)

    assert selection.status is CohortSelectionStatus.REFUSED
    assert selection.reason is CohortSelectionReason.NO_PENDING_ENTRIES
    assert selection.ecosystem is None and selection.queue_digest is None
    assert decode_cohort_selection(cohort_selection_bytes(selection)) == selection


def test_selection_is_deterministic_across_permutations():
    forward, resolved = replacement_cohort_state()
    backward, _ = replacement_cohort_state(
        python_names=tuple(reversed((*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES))),
        javascript_names=tuple(reversed((*COMBINED_JAVASCRIPT_NAMES, *THIRD_JAVASCRIPT_NAMES))),
    )
    assert forward.state_digest == backward.state_digest
    ledger = ingested_replacement_ledger(forward, resolved)

    assert _select(forward, ledger) == _select(backward, ledger)


def test_selection_caps_at_twenty_preferring_family_gaps():
    state, resolved = replacement_cohort_state(
        python_names=(*COMBINED_PYTHON_NAMES, *THIRD_PYTHON_NAMES, *SINGLE_FAMILY_PYTHON_NAMES),
    )
    ledger = ingested_replacement_ledger(state, resolved)

    selection = _select(state, ledger)

    assert selection.status is CohortSelectionStatus.SELECTED
    assert selection.ecosystem == "python"
    assert len(selection.selected_entries) == COHORT_BATCH_CAP
    gap_entries = {
        entry.entry_digest
        for entry in state.python_queue.entries
        if entry.family.vulnerability_family in {"deserialization", "ssrf"}
    }
    assert gap_entries <= set(selection.selected_entries)
    python_batch = next(batch for batch in ledger if batch.ecosystem == "python")
    unselected = [
        entry
        for entry in state.python_queue.entries
        if entry.entry_digest in set(python_batch.pending_entries)
        and entry.entry_digest not in set(selection.selected_entries)
    ]
    assert len(unselected) == 4
    assert {entry.family.vulnerability_family for entry in unselected} == {"injection"}


def test_selection_decodes_hostile_bytes_and_persists_durably():
    state, resolved, ledger = _prepared()
    selection = _select(state, ledger)
    content = cohort_selection_bytes(selection)
    assert content and decode_cohort_selection(content) == selection

    good = json.loads(content)
    spaced = json.dumps(good, sort_keys=True, indent=1).encode("utf-8")
    wrong_schema = json.dumps({**good, "schema_version": "other.v1"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered = json.dumps({**good, "reason": "no_pending_entries"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
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
        with pytest.raises(CohortSelectionStateError):
            decode_cohort_selection(bad)

    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    reference = persist_cohort_selection(store, selection)
    assert persist_cohort_selection(store, selection) == reference
    accepted = store.get(
        reference, expected_kind=ArtifactKind.POPULATION, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    validate_artifact(accepted.content, reference=reference)
    assert reference.access_class is ArtifactAccessClass.OPERATOR_SAFE

    resumed = resume_cohort_selection(
        S3ArtifactRepository(_settings(), client), reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == selection
    assert cohort_selection_bytes(resumed) == content


def test_malformed_ledgers_and_states_fail_closed():
    state, _, ledger = _prepared()
    forged_census = replace(ledger[0], census_digest="z" * 64)
    wrong_ecosystem = replace(ledger[0], ecosystem="typescript")
    for bad in (None, {"ecosystem": "python"}, forged_census, wrong_ecosystem):
        with pytest.raises(CohortSelectionStateError) as error:
            _select(state, (bad,))
        assert error.value.reason is CohortSelectionStateReason.STATE_MISMATCH

    with pytest.raises(CohortSelectionStateError):
        _select({"python_queue": ()}, ledger)


def test_selection_module_and_outputs_avoid_out_of_scope_machinery():
    root = Path(__file__).resolve().parents[1]
    for name in ("benchmarks/valid/cohort_selection.py", "benchmarks/valid/cohort_selection_store.py"):
        source = (root / name).read_bytes()
        for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
            assert forbidden not in source, f"{name} references out-of-scope machinery: {forbidden!r}"

    state, resolved, ledger = _prepared()
    content = cohort_selection_bytes(_select(state, ledger))
    for forbidden in (b"admission", b"detector", b"observation", b"label", b"verdict", b"score"):
        assert forbidden not in content

    stale = (root / "benchmarks/valid/cohort_ingestion.py").read_bytes()
    assert b"pending Python review queue entry" not in stale


def test_refused_selections_never_carry_entries_or_families():
    state, resolved, ledger = _prepared()
    refused = _select(state, ledger, gt=content_digest({"policy": "changed"}))
    rebuilt = cohort_selection(
        ecosystem=refused.ecosystem,
        selected_entries=refused.selected_entries,
        targeted_families=refused.targeted_families,
        queue_digest=refused.queue_digest,
        census_digest=refused.census_digest,
        ecosystem_policy_digest=refused.ecosystem_policy_digest,
        ground_truth_policy_digest=refused.ground_truth_policy_digest,
        prior_batch_digests=refused.prior_batch_digests,
        accepted_families=refused.accepted_families,
        accepted_by_ecosystem=dict(refused.accepted_by_ecosystem),
        status=refused.status,
        reason=refused.reason,
    )
    assert rebuilt == refused
    with pytest.raises(CohortSelectionStateError):
        cohort_selection(
            ecosystem=None,
            selected_entries=(),
            targeted_families=(),
            queue_digest=None,
            census_digest=refused.census_digest,
            ecosystem_policy_digest=refused.ecosystem_policy_digest,
            ground_truth_policy_digest=refused.ground_truth_policy_digest,
            prior_batch_digests=refused.prior_batch_digests,
            accepted_families=refused.accepted_families,
            accepted_by_ecosystem=dict(refused.accepted_by_ecosystem),
            status=CohortSelectionStatus.SELECTED,
            reason=refused.reason,
        )
