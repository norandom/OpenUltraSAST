"""Exact historical withdrawal inventory and audit authorization contracts."""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIGEST = content_digest({"policy": "historical-exact-file-review-v1"})


def _review_bytes(default_subject_digest: str, **updates: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": default_subject_digest,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "benchmark-custodian",
        "reviewer_identity": "independent-reviewer",
        "conflict_disclosed": True,
        "policy_digest": POLICY_DIGEST,
    }
    value.update(updates)
    value["review_digest"] = content_digest(value)
    return canonical_json_bytes(value)


def _reviewed(root: Path = ROOT) -> historical.HistoricalWithdrawalV1:
    inventory = historical.pinned_historical_inventory(root)
    candidate = historical.build_withdrawal_candidate(inventory)
    return historical.accept_reviewed_withdrawal(candidate, _review_bytes(candidate.candidate_digest))


def _copy_history(destination: Path) -> None:
    for relative in historical.PINNED_HISTORICAL_DIGESTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def test_pinned_inventory_reuses_exact_frozen_surface_and_reads_nonzero_bytes() -> None:
    before = {relative: (ROOT / relative).read_bytes() for relative in historical.PINNED_HISTORICAL_DIGESTS}
    inventory = historical.pinned_historical_inventory(ROOT)

    assert tuple(entry.path for entry in inventory.entries) == tuple(sorted(historical.PINNED_HISTORICAL_DIGESTS))
    assert all(entry.byte_length > 0 for entry in inventory.entries)
    assert all(sha256(before[entry.path]).hexdigest() == entry.content_digest for entry in inventory.entries)
    assert historical.inventory_bytes(inventory) == historical.inventory_bytes(historical.pinned_historical_inventory(ROOT))
    assert {relative: (ROOT / relative).read_bytes() for relative in before} == before


def test_reviewed_withdrawal_is_non_admissible_and_replacement_pending() -> None:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)
    withdrawal = historical.accept_reviewed_withdrawal(candidate, _review_bytes(candidate.candidate_digest))

    assert withdrawal.pilot_date == "2026-10-12"
    assert withdrawal.status is historical.HistoricalStatus.WITHDRAWN_NON_ADMISSIBLE
    assert withdrawal.replacement_status is historical.ReplacementStatus.PENDING
    assert withdrawal.reason is historical.WithdrawalReason.PERMANENT_RESERVATION_OVERLAP
    assert withdrawal.inventory_digest == inventory.inventory_digest
    with pytest.raises(historical.HistoricalAuthorizationError, match="non-admissible"):
        historical.require_current_qualification(withdrawal)


@pytest.mark.parametrize(
    "updates,message",
    (
        ({"reviewer_identity": "benchmark-custodian"}, "independent"),
        ({"conflict_disclosed": False}, "disclosure"),
        ({"subject_digest": "0" * 64}, "subject"),
        ({"decision": "approve_everything"}, "decision"),
        ({"policy_digest": "short"}, "policy"),
    ),
)
def test_review_evidence_must_be_independent_exact_and_policy_bound(updates: dict[str, object], message: str) -> None:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)

    with pytest.raises(historical.HistoricalAuthorizationError, match=message):
        historical.accept_reviewed_withdrawal(candidate, _review_bytes(candidate.candidate_digest, **updates))


def test_exact_path_and_digest_authorize_unchanged_audit_bytes() -> None:
    withdrawal = _reviewed()
    path = "benchmarks/valid/pilot/freeze-valid.json"
    digest = historical.PINNED_HISTORICAL_DIGESTS[path]

    authorized = historical.authorize_historical_path(ROOT, path, digest, withdrawal)

    assert authorized == (ROOT / path).read_bytes()
    assert sha256(authorized).hexdigest() == digest


@pytest.mark.parametrize(
    "path",
    (
        ".",
        "benchmarks/valid/pilot",
        "benchmarks/valid/pilot/*",
        "benchmarks/valid/pilot/*.json",
        "benchmarks/valid/pilot/../pilot/freeze-valid.json",
        "/benchmarks/valid/pilot/freeze-valid.json",
        "valid/pilot",
    ),
)
def test_broad_noncanonical_and_directory_authorizations_are_refused(path: str) -> None:
    withdrawal = _reviewed()
    with pytest.raises(historical.HistoricalAuthorizationError, match="path|authorized"):
        historical.authorize_historical_path(ROOT, path, "0" * 64, withdrawal)


def test_changed_relocated_and_symlinked_bytes_are_refused(tmp_path: Path) -> None:
    _copy_history(tmp_path)
    withdrawal = _reviewed(tmp_path)
    relative = "benchmarks/valid/pilot/freeze-valid.json"
    digest = historical.PINNED_HISTORICAL_DIGESTS[relative]
    original = tmp_path / relative

    original.write_bytes(original.read_bytes() + b"\n")
    with pytest.raises(historical.HistoricalAuthorizationError, match="digest|length"):
        historical.authorize_historical_path(tmp_path, relative, digest, withdrawal)

    shutil.copyfile(ROOT / relative, original)
    relocated = "benchmarks/valid/pilot/relocated-freeze.json"
    shutil.copyfile(original, tmp_path / relocated)
    with pytest.raises(historical.HistoricalAuthorizationError, match="authorized"):
        historical.authorize_historical_path(tmp_path, relocated, digest, withdrawal)

    original.unlink()
    original.symlink_to(ROOT / relative)
    with pytest.raises(historical.HistoricalAuthorizationError, match="regular file"):
        historical.authorize_historical_path(tmp_path, relative, digest, withdrawal)


def test_inventory_or_review_tampering_cannot_reproduce_authority() -> None:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)
    withdrawal = historical.accept_reviewed_withdrawal(candidate, _review_bytes(candidate.candidate_digest))

    changed_entry = replace(inventory.entries[0], byte_length=inventory.entries[0].byte_length + 1)
    changed_inventory = replace(inventory, entries=(changed_entry, *inventory.entries[1:]))
    with pytest.raises(historical.HistoricalAuthorizationError, match="inventory"):
        historical.inventory_bytes(changed_inventory)

    decoded = json.loads(_review_bytes(candidate.candidate_digest))
    decoded["producer_identity"] = "different-producer"
    with pytest.raises(historical.HistoricalAuthorizationError, match="review digest"):
        historical.accept_reviewed_withdrawal(candidate, canonical_json_bytes(decoded))
    assert withdrawal.withdrawal_digest


def test_noncanonical_and_duplicate_review_bytes_are_refused() -> None:
    candidate = historical.build_withdrawal_candidate(historical.pinned_historical_inventory(ROOT))
    pretty = json.dumps(json.loads(_review_bytes(candidate.candidate_digest)), indent=2).encode()
    duplicate = b'{"schema_version":"x","schema_version":"x"}'

    with pytest.raises(historical.HistoricalAuthorizationError, match="canonical"):
        historical.accept_reviewed_withdrawal(candidate, pretty)
    with pytest.raises(historical.HistoricalAuthorizationError, match="duplicate"):
        historical.accept_reviewed_withdrawal(candidate, duplicate)
