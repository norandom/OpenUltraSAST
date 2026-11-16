"""Production permanent-reservation guard over exact reviewed authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath

from benchmarks.valid.historical_authorization import (
    HistoricalAuthorizationError,
    HistoricalWithdrawalV1,
    authorize_historical_path,
    withdrawal_bytes,
)
from benchmarks.valid.lifecycle import PopulationLifecycleProjectionV1, PopulationLifecycleState
from benchmarks.valid.lifecycle_projection import projection_bytes
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from benchmarks.valid.reservation import (
    ReservationAuthority,
    ReservationCensusV1,
    ReservationError,
    census_bytes,
)
from benchmarks.valid.reservation_guard_sources import PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS
from openultrasast.core.canonical import JsonValue, content_digest

GUARD_REPORT_SCHEMA = "openultrasast.valid-detection-benchmark.reservation-guard.v1"
REPLACEMENT_ACCEPTANCE_SCHEMA = "openultrasast.valid-detection-benchmark.reservation-acceptance.v1"
PRODUCTION_GUARD_SCAN_ROOTS = ("benchmarks", "plane", "src", "tests")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REPOSITORY = re.compile(
    rb"github\.com/([A-Za-z0-9_.-]*[A-Za-z0-9_-]/[A-Za-z0-9_.-]*[A-Za-z0-9_-])(?:\.git)?"
    rb"(?=[./?\#\s\"'<>),;:\]\}]|$)",
    re.IGNORECASE,
)
_SKIPPED_SUFFIXES = frozenset({".bin", ".gz", ".pyc"})


class ReservationGuardError(ValueError):
    """The permanent-reservation guard could not establish a clean result."""


@dataclass(frozen=True)
class ExactReservationSourceV1:
    path: str
    byte_length: int
    content_digest: str
    legacy_source_digests: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ForbiddenReservationReferenceV1:
    path: str
    repository: str
    network_identity_digest: str


@dataclass(frozen=True)
class ReservationGuardReportV1:
    files_read: int
    bytes_read: int
    reserved_network_count: int
    census_digest: str
    scan_roots: tuple[str, ...]
    input_receipt_digest: str
    reservation_source_digests: tuple[str, ...]
    historical_withdrawal_digest: str | None
    violations: tuple[ForbiddenReservationReferenceV1, ...]
    report_digest: str


@dataclass(frozen=True)
class ReplacementReservationAcceptanceV1:
    population_digest: str
    freeze_digest: str
    census_digest: str
    guard_report_digest: str
    lifecycle_projection_digest: str
    network_identity_digests: tuple[str, ...]
    historical_paths: tuple[str, ...]
    acceptance_digest: str


def _path(value: str) -> str:
    candidate = PurePosixPath(value)
    if not value or candidate.is_absolute() or str(candidate) != value or ".." in candidate.parts:
        raise ReservationGuardError("guard path must be canonical repository-relative POSIX")
    return value


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReservationGuardError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _read(root: Path, relative: str) -> bytes:
    path = _path(relative)
    resolved_root = root.resolve()
    target = root / path
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(resolved_root):
        raise ReservationGuardError("guard input must resolve to a regular repository file")
    try:
        content = target.read_bytes()
    except OSError as error:
        raise ReservationGuardError("guard input is unreadable") from error
    return content


def exact_reservation_source(
    root: Path,
    relative_path: str,
    legacy_source_digests: tuple[str, ...],
) -> ExactReservationSourceV1:
    """Bind one exact source file to census-carried legacy authorities."""
    content = _read(root, relative_path)
    if not content:
        raise ReservationGuardError("reservation source read zero bytes")
    digests = tuple(sorted(set(legacy_source_digests)))
    if not digests:
        raise ReservationGuardError("reservation source lacks legacy authorities")
    for digest in digests:
        _digest(digest, "legacy source digest")
    return ExactReservationSourceV1(relative_path, len(content), sha256(content).hexdigest(), digests)


def _validate_sources(
    root: Path,
    authority: ReservationAuthority,
    census: ReservationCensusV1,
    sources: tuple[ExactReservationSourceV1, ...],
) -> tuple[dict[str, frozenset[str]], tuple[str, ...]]:
    allowed: dict[str, frozenset[str]] = {}
    identities: list[str] = []
    for source in sources:
        path = _path(source.path)
        if path in allowed:
            raise ReservationGuardError("reservation source path is duplicated")
        content = _read(root, path)
        if not content or len(content) != source.byte_length or sha256(content).hexdigest() != source.content_digest:
            raise ReservationGuardError("reservation source bytes changed")
        if not source.legacy_source_digests or not set(source.legacy_source_digests) <= set(census.legacy_source_digests):
            raise ReservationGuardError("reservation source is not bound to the census")
        try:
            networks = frozenset(authority.legacy_source_network_digest(digest) for digest in source.legacy_source_digests)
        except ReservationError as error:
            raise ReservationGuardError("reservation source identity is not accepted") from error
        allowed[path] = networks
        identities.append(
            content_digest(
                {
                    "path": path,
                    "byte_length": source.byte_length,
                    "content_digest": source.content_digest,
                    "legacy_source_digests": source.legacy_source_digests,
                }
            )
        )
    return allowed, tuple(sorted(identities))


def _historical_paths(root: Path, withdrawal: HistoricalWithdrawalV1 | None) -> tuple[frozenset[str], str | None]:
    if withdrawal is None:
        return frozenset(), None
    withdrawal_bytes(withdrawal)
    allowed: set[str] = set()
    for entry in withdrawal.candidate.entries:
        try:
            authorize_historical_path(root, entry.path, entry.content_digest, withdrawal)
        except HistoricalAuthorizationError as error:
            raise ReservationGuardError("reviewed historical path or digest changed") from error
        allowed.add(entry.path)
    return frozenset(allowed), withdrawal.withdrawal_digest


def _repository_matches(content: bytes) -> tuple[str, ...]:
    values = {match.group(1).decode("ascii").removesuffix(".git") for match in _REPOSITORY.finditer(content)}
    return tuple(sorted(f"https://github.com/{value}" for value in values))


def _scan_scope(roots: tuple[str, ...]) -> tuple[str, ...]:
    canonical = tuple(sorted({_path(root) for root in roots}))
    if canonical != PRODUCTION_GUARD_SCAN_ROOTS:
        raise ReservationGuardError("production guard scan scope is incomplete or unsupported")
    return PRODUCTION_GUARD_SCAN_ROOTS


def _scan_files(root: Path, roots: tuple[str, ...]) -> tuple[tuple[str, bytes], ...]:
    collected: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for relative_root in roots:
        base = root / _path(relative_root)
        if base.is_symlink() or not base.is_dir():
            raise ReservationGuardError("guard scan root is unreadable or not a directory")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise ReservationGuardError("guard scan contains a symlink")
            if not path.is_file() or path.suffix in _SKIPPED_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if relative in seen:
                raise ReservationGuardError("guard scan roots overlap")
            seen.add(relative)
            collected.append((relative, _read(root, relative)))
    if not collected or sum(len(content) for _, content in collected) <= 0:
        raise ReservationGuardError("guard scan read zero repository bytes")
    return tuple(collected)


def _input_receipt_digest(files: tuple[tuple[str, bytes], ...]) -> str:
    receipts: tuple[JsonValue, ...] = tuple(
        {"path": path, "byte_length": len(content), "content_digest": sha256(content).hexdigest()}
        for path, content in sorted(files, key=lambda item: item[0])
    )
    return content_digest({"files": receipts})


def _report_value(report: ReservationGuardReportV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": GUARD_REPORT_SCHEMA,
        "files_read": report.files_read,
        "bytes_read": report.bytes_read,
        "reserved_network_count": report.reserved_network_count,
        "census_digest": report.census_digest,
        "scan_roots": report.scan_roots,
        "input_receipt_digest": report.input_receipt_digest,
        "reservation_source_digests": report.reservation_source_digests,
        "historical_withdrawal_digest": report.historical_withdrawal_digest,
        "violations": tuple(
            {
                "path": item.path,
                "repository": item.repository,
                "network_identity_digest": item.network_identity_digest,
            }
            for item in report.violations
        ),
    }
    if include_digest:
        value["report_digest"] = report.report_digest
    return value


def guard_report_bytes(report: ReservationGuardReportV1) -> bytes:
    if report.files_read <= 0 or report.bytes_read <= 0 or report.reserved_network_count <= 0:
        raise ReservationGuardError("guard report lacks nonzero instrument proof")
    _digest(report.census_digest, "guard census digest")
    if report.scan_roots != _scan_scope(report.scan_roots):
        raise ReservationGuardError("guard scan roots are not canonical")
    _digest(report.input_receipt_digest, "guard input receipt digest")
    if report.reservation_source_digests != tuple(sorted(set(report.reservation_source_digests))):
        raise ReservationGuardError("guard source identities are not canonical")
    for digest in report.reservation_source_digests:
        _digest(digest, "guard source identity")
    if report.historical_withdrawal_digest is not None:
        _digest(report.historical_withdrawal_digest, "guard historical withdrawal digest")
    if report.violations != tuple(sorted(set(report.violations))):
        raise ReservationGuardError("guard violations are not canonical")
    if report.report_digest != content_digest(_report_value(report, include_digest=False)):
        raise ReservationGuardError("guard report digest does not match")
    return canonical_json_bytes(_report_value(report, include_digest=True))


def scan_permanent_reservations(
    root: Path,
    *,
    scan_roots: tuple[str, ...],
    authority: ReservationAuthority,
    census: ReservationCensusV1,
    reservation_sources: tuple[ExactReservationSourceV1, ...] = (),
    historical_withdrawal: HistoricalWithdrawalV1 | None = None,
) -> ReservationGuardReportV1:
    """Report every reserved reference outside exact authority-bearing files."""
    census_content = census_bytes(census)
    if not census_content or not census.reserved_network_digests:
        raise ReservationGuardError("guard reservation census is empty")
    roots = _scan_scope(scan_roots)
    source_networks, source_digests = _validate_sources(root, authority, census, reservation_sources)
    historical_paths, historical_digest = _historical_paths(root, historical_withdrawal)
    files = _scan_files(root, roots)
    violations: set[ForbiddenReservationReferenceV1] = set()
    for path, content in files:
        for repository in _repository_matches(content):
            if authority.is_reserved(repository, census):
                network = authority.resolve_repository(repository)
                if path in historical_paths or network.network_identity_digest in source_networks.get(path, frozenset()):
                    continue
                violations.add(ForbiddenReservationReferenceV1(path, repository, network.network_identity_digest))
    draft = ReservationGuardReportV1(
        files_read=len(files),
        bytes_read=sum(len(content) for _, content in files),
        reserved_network_count=len(census.reserved_network_digests),
        census_digest=census.census_digest,
        scan_roots=roots,
        input_receipt_digest=_input_receipt_digest(files),
        reservation_source_digests=source_digests,
        historical_withdrawal_digest=historical_digest,
        violations=tuple(sorted(violations)),
        report_digest="",
    )
    report = ReservationGuardReportV1(**{**vars(draft), "report_digest": content_digest(_report_value(draft, include_digest=False))})
    guard_report_bytes(report)
    return report


def require_clean_guard(report: ReservationGuardReportV1) -> None:
    guard_report_bytes(report)
    if report.violations:
        raise ReservationGuardError(f"permanent reservation references forbidden: count={len(report.violations)}")


def _acceptance_value(value: ReplacementReservationAcceptanceV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": REPLACEMENT_ACCEPTANCE_SCHEMA,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "census_digest": value.census_digest,
        "guard_report_digest": value.guard_report_digest,
        "lifecycle_projection_digest": value.lifecycle_projection_digest,
        "network_identity_digests": value.network_identity_digests,
        "historical_paths": value.historical_paths,
    }
    if include_digest:
        result["acceptance_digest"] = value.acceptance_digest
    return result


def _replacement_networks(repositories: tuple[str, ...], authority: ReservationAuthority, census: ReservationCensusV1) -> tuple[str, ...]:
    if not repositories:
        raise ReservationGuardError("replacement repository census is empty")
    networks: set[str] = set()
    for repository in repositories:
        try:
            network = authority.resolve_repository(repository)
        except ReservationError as error:
            raise ReservationGuardError("replacement repository identity is unresolved") from error
        if network.network_identity_digest in census.reserved_network_digests:
            raise ReservationGuardError("replacement repository resolves to permanent reservation")
        networks.add(network.network_identity_digest)
    return tuple(sorted(networks))


def _replacement_history(
    root: Path,
    withdrawal: HistoricalWithdrawalV1,
    requests: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    paths: set[str] = set()
    for path, digest in requests:
        try:
            authorize_historical_path(root, path, digest, withdrawal)
        except HistoricalAuthorizationError as error:
            raise ReservationGuardError("replacement historical reference is not exactly authorized") from error
        paths.add(_path(path))
    return tuple(sorted(paths))


def _require_current_report(
    root: Path,
    report: ReservationGuardReportV1,
    authority: ReservationAuthority,
    census: ReservationCensusV1,
    sources: tuple[ExactReservationSourceV1, ...],
    withdrawal: HistoricalWithdrawalV1,
) -> None:
    current = scan_permanent_reservations(
        root,
        scan_roots=PRODUCTION_GUARD_SCAN_ROOTS,
        authority=authority,
        census=census,
        reservation_sources=sources,
        historical_withdrawal=withdrawal,
    )
    if current != report:
        raise ReservationGuardError("replacement guard report is stale or the scanned authority changed")
    require_clean_guard(current)


def validate_replacement_population(
    root: Path,
    *,
    repositories: tuple[str, ...],
    population_digest: str,
    freeze_digest: str,
    lifecycle: PopulationLifecycleProjectionV1,
    guard_report: ReservationGuardReportV1,
    authority: ReservationAuthority,
    census: ReservationCensusV1,
    historical_withdrawal: HistoricalWithdrawalV1,
    reservation_sources: tuple[ExactReservationSourceV1, ...] = (),
    historical_requests: tuple[tuple[str, str], ...] = (),
) -> ReplacementReservationAcceptanceV1:
    """Accept only one resolved, unreserved, lifecycle-eligible replacement."""
    census_bytes(census)
    require_clean_guard(guard_report)
    if guard_report.census_digest != census.census_digest:
        raise ReservationGuardError("replacement guard report does not bind the census")
    if guard_report.reserved_network_count != len(census.reserved_network_digests):
        raise ReservationGuardError("replacement guard report census count does not match")
    _require_current_report(root, guard_report, authority, census, reservation_sources, historical_withdrawal)
    projection_bytes(lifecycle)
    population = _digest(population_digest, "population digest")
    freeze = _digest(freeze_digest, "freeze digest")
    if lifecycle.state is not PopulationLifecycleState.REPLACEMENT_COMPLETE or not lifecycle.admission_eligible:
        raise ReservationGuardError("replacement lifecycle is not admission eligible")
    if (lifecycle.population_digest, lifecycle.freeze_digest) != (population, freeze):
        raise ReservationGuardError("replacement lifecycle identity does not match")
    networks = _replacement_networks(repositories, authority, census)
    paths = _replacement_history(root, historical_withdrawal, historical_requests)
    draft = ReplacementReservationAcceptanceV1(
        population,
        freeze,
        census.census_digest,
        guard_report.report_digest,
        lifecycle.projection_digest,
        networks,
        paths,
        "",
    )
    return ReplacementReservationAcceptanceV1(
        **{**vars(draft), "acceptance_digest": content_digest(_acceptance_value(draft, include_digest=False))}
    )


__all__ = [
    "PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS",
    "PRODUCTION_GUARD_SCAN_ROOTS",
    "ExactReservationSourceV1",
    "ForbiddenReservationReferenceV1",
    "ReplacementReservationAcceptanceV1",
    "ReservationGuardError",
    "ReservationGuardReportV1",
    "exact_reservation_source",
    "guard_report_bytes",
    "require_clean_guard",
    "scan_permanent_reservations",
    "validate_replacement_population",
]
