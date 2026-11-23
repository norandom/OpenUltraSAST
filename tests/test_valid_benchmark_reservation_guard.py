"""Production-backed permanent-reservation guard integration."""

from __future__ import annotations

import shutil
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid import lifecycle, reservation, reservation_guard  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POLICY = content_digest({"policy": "guard-review-v1"})
POPULATION = content_digest({"population": "replacement"})
FREEZE = content_digest({"freeze": "replacement"})


def _network(canonical: str, *, alias: str | None = None, fork: str | None = None):
    return reservation.build_network_identity(
        canonical,
        aliases=(alias,) if alias else (),
        forks=(fork,) if fork else (),
    )


def _authority(tmp_path: Path):
    reserved = _network(
        "https://github.com/acme/reserved",
        alias="https://github.com/acme/old-reserved",
        fork="https://github.com/fork/reserved",
    )
    fresh = _network("https://github.com/fresh/project")
    resolver = reservation.RepositoryIdentityResolver((reserved, fresh))
    source_path = "benchmarks/reservations/source.txt"
    target = tmp_path / source_path
    target.parent.mkdir(parents=True)
    target.write_text("https://github.com/acme/reserved\n")
    source_digest = sha256(target.read_bytes()).hexdigest()
    legacy = reservation.legacy_reservation_source(
        resolver,
        repository=reserved.canonical_repository,
        source_digest=source_digest,
    )
    authority = reservation.ReservationAuthority(resolver, legacy_sources=(legacy,))
    census = authority.project_census(())
    source = reservation_guard.exact_reservation_source(tmp_path, source_path, (legacy.legacy_source_digest,))
    return authority, census, source


def _historical_review(subject: str) -> bytes:
    value: dict[str, object] = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": subject,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "custodian",
        "reviewer_identity": "reviewer",
        "conflict_disclosed": True,
        "policy_digest": POLICY,
    }
    value["review_digest"] = content_digest(value)
    return canonical_json_bytes(value)


def _copy_history(destination: Path) -> historical.HistoricalWithdrawalV1:
    for relative in historical.PINNED_HISTORICAL_DIGESTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    inventory = historical.pinned_historical_inventory(destination)
    candidate = historical.build_withdrawal_candidate(inventory)
    return historical.accept_reviewed_withdrawal(candidate, _historical_review(candidate.candidate_digest))


def _active_lifecycle(withdrawal: historical.HistoricalWithdrawalV1):
    root = lifecycle.withdrawn_event(withdrawal)
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        producer_identity="producer",
        reviewer_identity="reviewer",
        conflict_disclosed=True,
        policy_digest=POLICY,
    )
    return lifecycle.BaselineLifecycleAuthority().project((root, replacement))


def _scan_roots(root: Path) -> None:
    for name in ("benchmarks", "src", "tests", "plane"):
        (root / name).mkdir(exist_ok=True)


def _clean_report(tmp_path, authority, census, source, withdrawal):
    return reservation_guard.scan_permanent_reservations(
        tmp_path,
        scan_roots=("benchmarks", "src", "tests", "plane"),
        authority=authority,
        census=census,
        reservation_sources=(source,),
        historical_withdrawal=withdrawal,
    )


def _partial_src_report(report: reservation_guard.ReservationGuardReportV1, path: Path) -> reservation_guard.ReservationGuardReportV1:
    content = path.read_bytes()
    receipt = content_digest(
        {
            "files": (
                {
                    "path": path.parent.name + "/" + path.name,
                    "byte_length": len(content),
                    "content_digest": sha256(content).hexdigest(),
                },
            )
        }
    )
    draft = replace(
        report,
        files_read=1,
        bytes_read=len(content),
        scan_roots=("src",),
        input_receipt_digest=receipt,
        violations=(),
        report_digest="",
    )
    value = {
        "schema_version": reservation_guard.GUARD_REPORT_SCHEMA,
        "files_read": draft.files_read,
        "bytes_read": draft.bytes_read,
        "reserved_network_count": draft.reserved_network_count,
        "census_digest": draft.census_digest,
        "scan_roots": draft.scan_roots,
        "input_receipt_digest": draft.input_receipt_digest,
        "reservation_source_digests": draft.reservation_source_digests,
        "historical_withdrawal_digest": draft.historical_withdrawal_digest,
        "violations": (),
    }
    return replace(draft, report_digest=content_digest(value))


def test_exact_source_is_allowed_but_alias_and_fork_leaks_are_all_reported(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    leak = tmp_path / "src/leak.txt"
    leak.write_text("github.com/acme/old-reserved\ngithub.com/fork/reserved\n")

    report = reservation_guard.scan_permanent_reservations(
        tmp_path,
        scan_roots=("benchmarks", "src", "tests", "plane"),
        authority=authority,
        census=census,
        reservation_sources=(source,),
    )

    assert report.files_read == 2
    assert report.bytes_read > 0
    assert report.reserved_network_count == 1
    assert tuple(item.path for item in report.violations) == ("src/leak.txt", "src/leak.txt")
    assert {item.repository for item in report.violations} == {
        "https://github.com/acme/old-reserved",
        "https://github.com/fork/reserved",
    }
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=2"):
        reservation_guard.require_clean_guard(report)


def test_changed_source_bytes_and_empty_or_unreadable_inputs_fail_loudly(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    (tmp_path / source.path).write_text("github.com/acme/reserved\nchanged\n")
    with pytest.raises(reservation_guard.ReservationGuardError, match="source bytes changed"):
        reservation_guard.scan_permanent_reservations(
            tmp_path,
            scan_roots=("benchmarks", "src", "tests", "plane"),
            authority=authority,
            census=census,
            reservation_sources=(source,),
        )
    with pytest.raises(reservation_guard.ReservationGuardError, match="scan"):
        reservation_guard.scan_permanent_reservations(
            tmp_path,
            scan_roots=("missing",),
            authority=authority,
            census=census,
            reservation_sources=(),
        )


def test_exact_source_authority_is_scoped_to_its_bound_network(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    first = _network("https://github.com/acme/first")
    second = _network("https://github.com/acme/second")
    resolver = reservation.RepositoryIdentityResolver((first, second))
    path = "benchmarks/reservations/source.txt"
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_text("github.com/acme/first, github.com/acme/second.\n")
    source_digest = sha256(target.read_bytes()).hexdigest()
    first_legacy = reservation.legacy_reservation_source(resolver, repository=first.canonical_repository, source_digest=source_digest)
    second_legacy = reservation.legacy_reservation_source(
        resolver,
        repository=second.canonical_repository,
        source_digest=content_digest({"other": "source"}),
    )
    authority = reservation.ReservationAuthority(resolver, legacy_sources=(first_legacy, second_legacy))
    census = authority.project_census(())
    source = reservation_guard.exact_reservation_source(tmp_path, path, (first_legacy.legacy_source_digest,))

    report = reservation_guard.scan_permanent_reservations(
        tmp_path,
        scan_roots=("benchmarks", "src", "tests", "plane"),
        authority=authority,
        census=census,
        reservation_sources=(source,),
    )

    assert tuple(item.repository for item in report.violations) == ("https://github.com/acme/second",)


def test_only_reviewed_exact_historical_files_are_allowed(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    historical_path = tmp_path / "benchmarks/valid/pilot/pool-valid.toml"
    historical_path.write_bytes(historical_path.read_bytes() + b"\n# github.com/acme/reserved\n")
    with pytest.raises(reservation_guard.ReservationGuardError, match="historical|digest"):
        reservation_guard.scan_permanent_reservations(
            tmp_path,
            scan_roots=("benchmarks", "src", "tests", "plane"),
            authority=authority,
            census=census,
            reservation_sources=(source,),
            historical_withdrawal=withdrawal,
        )


def test_unchanged_reviewed_historical_file_is_exactly_allowed(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    report = reservation_guard.scan_permanent_reservations(
        tmp_path,
        scan_roots=("benchmarks", "src", "tests", "plane"),
        authority=authority,
        census=census,
        reservation_sources=(source,),
        historical_withdrawal=withdrawal,
    )
    reservation_guard.require_clean_guard(report)
    assert report.scan_roots == ("benchmarks", "plane", "src", "tests")
    assert report.input_receipt_digest and report.reservation_source_digests
    assert report.historical_withdrawal_digest == withdrawal.withdrawal_digest
    assert b"github.com/acme/reserved" not in reservation_guard.guard_report_bytes(report)


@pytest.mark.parametrize(
    "repository",
    (
        "https://github.com/acme/reserved",
        "https://github.com/acme/old-reserved",
        "https://github.com/fork/reserved",
    ),
)
def test_replacement_rejects_reserved_canonical_alias_and_fork(tmp_path: Path, repository: str) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    projection = _active_lifecycle(withdrawal)
    report = _clean_report(tmp_path, authority, census, source, withdrawal)
    with pytest.raises(reservation_guard.ReservationGuardError, match="permanent reservation"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=(repository,),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )


def test_replacement_accepts_resolved_fresh_identity_and_exact_historical_audit(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    projection = _active_lifecycle(withdrawal)
    report = _clean_report(tmp_path, authority, census, source, withdrawal)
    path = "benchmarks/valid/pilot/freeze-valid.json"
    accepted = reservation_guard.validate_replacement_population(
        tmp_path,
        repositories=("https://github.com/fresh/project",),
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        lifecycle=projection,
        guard_report=report,
        authority=authority,
        census=census,
        historical_withdrawal=withdrawal,
        reservation_sources=(source,),
        historical_requests=((path, historical.PINNED_HISTORICAL_DIGESTS[path]),),
    )
    assert accepted.network_identity_digests
    assert accepted.historical_paths == (path,)
    assert accepted.acceptance_digest

    (tmp_path / "src/leak.txt").write_text("github.com/acme/reserved\n")
    with pytest.raises(reservation_guard.ReservationGuardError, match="stale|changed"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/fresh/project",),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )
    dirty = _clean_report(tmp_path, authority, census, source, withdrawal)
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/fresh/project",),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=dirty,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )


def test_replacement_refuses_unresolved_identity_wrong_lifecycle_and_broad_history(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    projection = _active_lifecycle(withdrawal)
    report = _clean_report(tmp_path, authority, census, source, withdrawal)
    with pytest.raises(reservation_guard.ReservationGuardError, match="unresolved"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/unknown/project",),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )
    with pytest.raises(reservation_guard.ReservationGuardError, match="identity"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/fresh/project",),
            population_digest="0" * 64,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )
    with pytest.raises(reservation_guard.ReservationGuardError, match="historical"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/fresh/project",),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
            historical_requests=(("benchmarks/valid/pilot", "0" * 64),),
        )


def test_partial_scope_report_and_replacement_acceptance_are_refused(tmp_path: Path) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    withdrawal = _copy_history(tmp_path)
    projection = _active_lifecycle(withdrawal)
    clean = tmp_path / "src/clean.txt"
    clean.write_text("clean-ok")
    report = _clean_report(tmp_path, authority, census, source, withdrawal)
    partial = _partial_src_report(report, clean)
    (tmp_path / "tests/leak.txt").write_text("github.com/acme/reserved\n")

    with pytest.raises(reservation_guard.ReservationGuardError, match="scope"):
        reservation_guard.guard_report_bytes(partial)
    with pytest.raises(reservation_guard.ReservationGuardError, match="scope"):
        reservation_guard.validate_replacement_population(
            tmp_path,
            repositories=("https://github.com/fresh/project",),
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            lifecycle=projection,
            guard_report=partial,
            authority=authority,
            census=census,
            historical_withdrawal=withdrawal,
            reservation_sources=(source,),
        )


@pytest.mark.parametrize("suffix", (".Git", ".gIT", ".GIT"))
def test_mixed_case_git_suffix_reference_is_still_a_reserved_violation(tmp_path: Path, suffix: str) -> None:
    _scan_roots(tmp_path)
    authority, census, source = _authority(tmp_path)
    (tmp_path / "src/leak.txt").write_text(f"see https://GITHUB.com/ACME/Reserved{suffix} for details\n")

    report = reservation_guard.scan_permanent_reservations(
        tmp_path,
        scan_roots=("benchmarks", "src", "tests", "plane"),
        authority=authority,
        census=census,
        reservation_sources=(source,),
    )

    assert report.files_read == 2 and report.bytes_read > 0 and report.reserved_network_count == 1
    assert tuple((item.path, item.repository) for item in report.violations) == (("src/leak.txt", "https://github.com/ACME/Reserved"),)
    reserved = authority.resolve_repository("https://github.com/acme/reserved")
    assert report.violations[0].network_identity_digest == reserved.network_identity_digest
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
        reservation_guard.require_clean_guard(report)
