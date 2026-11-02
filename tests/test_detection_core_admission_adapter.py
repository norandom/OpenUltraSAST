"""Benchmark-owned guarded admission integration for detection-core Task 9.6."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Lock

import pytest
from test_core_admission_metrics import _setup

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid.admission_run import V2AdmissionRunInput, run_v2_admission
from benchmarks.valid.admission_scoring import score_v2_admission
from benchmarks.valid.population_custody import (
    AdmissionSpendAuthority,
    GuardedCustodyError,
    GuardedPopulationCustodian,
    ReleaseReview,
)
from openultrasast.core.admission_case import AdmissionCaseResult, derive_admission_case_result_digest
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.admission_spend import AdmissionPreparation, authorize_admission
from openultrasast.core.canonical import content_digest
from openultrasast.core.custody import LineagePurpose, PopulationCustodyLog, PopulationStatus
from openultrasast.core.factpack import IndependenceAttestation, derive_independence_attestation_digest


class SimulatedCrash(RuntimeError):
    pass


class _Store:
    def __init__(self, initial: PopulationCustodyLog, *, fail_before_append: bool = False) -> None:
        self.log = initial
        self.fail_before_append = fail_before_append
        self.lock = Lock()

    def current_log(self, population_digest: str) -> PopulationCustodyLog:
        if population_digest != self.log.population_digest:
            raise LookupError("population not found")
        return self.log

    def compare_and_swap(self, expected_log_digest: str, replacement: PopulationCustodyLog) -> bool:
        with self.lock:
            if self.fail_before_append:
                raise SimulatedCrash("before durable append")
            if self.log.log_digest != expected_log_digest:
                return False
            self.log = replacement
            return True


def _custodian(setup: object, store: _Store) -> GuardedPopulationCustodian:
    population = setup.manifest.identity.population_digest  # type: ignore[attr-defined]
    current = setup.custody.current_log(population)  # type: ignore[attr-defined]
    return GuardedPopulationCustodian(
        population,
        current.custodian_identity,
        setup.context.evidence.custody_policy,  # type: ignore[attr-defined]
        store,
        setup.custody,  # type: ignore[attr-defined]
    )


def _label_file(tmp_path: Path) -> Path:
    path = tmp_path / "labels.json"
    path.write_bytes(b'{"labels":["vulnerable","fixed","ordinary"]}')
    assert path.stat().st_size > 0
    return path


def _reviewer(setup: object) -> ReleaseReview:
    def review(payload: str, producer: str) -> IndependenceAttestation:
        draft = IndependenceAttestation(
            payload,
            producer,
            setup.manifest.review.reviewer_identity,  # type: ignore[attr-defined]
            setup.manifest.review.conflict_disclosure,  # type: ignore[attr-defined]
            "0" * 64,
        )
        return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))

    return review


def _authority(setup: object) -> AdmissionSpendAuthority:
    return AdmissionSpendAuthority(
        setup.manifest,  # type: ignore[attr-defined]
        setup.denominator,  # type: ignore[attr-defined]
        setup.readiness,  # type: ignore[attr-defined]
        setup.context,  # type: ignore[attr-defined]
        setup.resolver,  # type: ignore[attr-defined]
    )


def _request(setup: object, custodian: GuardedPopulationCustodian, path: Path) -> V2AdmissionRunInput:
    def analyze(labels: bytes) -> tuple[AdmissionCaseResult, ...]:
        assert labels == path.read_bytes()
        return setup.cases  # type: ignore[attr-defined,no-any-return]

    return V2AdmissionRunInput(
        _authority(setup),
        custodian,
        path.read_bytes,
        analyze,
        _reviewer(setup),
    )


def _prepare(setup: object, custodian: GuardedPopulationCustodian) -> AdmissionPreparation:
    authority = _authority(setup)
    return authorize_admission(
        authority.manifest,
        authority.denominator,
        authority.readiness,
        authority.context,
        custodian,
        authority.resolver,
    )


def test_synthetic_admission_runs_end_to_end_after_nonzero_label_read(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)

    replay = run_v2_admission(_request(setup, custodian, _label_file(tmp_path)))

    assert replay.report.decision in (AdmissionDecision.GO, AdmissionDecision.NO_GO)
    assert replay.label_release_receipt.status is PopulationStatus.SPENT
    assert replay.case_release.review.producer_identity == custodian.custodian_identity
    assert replay.case_release.review.reviewer_identity != custodian.custodian_identity
    assert store.log.status is PopulationStatus.SPENT


def test_crash_before_append_releases_no_labels_and_preserves_available(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population), fail_before_append=True)
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)
    reads = 0

    def labels() -> bytes:
        nonlocal reads
        reads += 1
        return _label_file(tmp_path).read_bytes()

    with pytest.raises(SimulatedCrash, match="before durable append"):
        custodian.spend_and_release_labels(_authority(setup), preparation, labels)
    assert reads == 0
    assert store.log.status is PopulationStatus.AVAILABLE


@pytest.mark.parametrize("mutation", ("preparation", "authorization", "purpose", "influenced"))
def test_invalid_preparation_never_spends_or_releases_labels(mutation: str) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)
    if mutation == "preparation":
        changed = replace(preparation, preparation_digest="0" * 64)
    elif mutation == "authorization":
        authorization = replace(preparation.authorization, authorization_digest="0" * 64)
        changed = replace(preparation, authorization=authorization)
    elif mutation == "purpose":
        request = replace(preparation.label_release_request, purpose=LineagePurpose.PROMOTION)
        changed = replace(preparation, label_release_request=request)
    else:
        request = replace(preparation.label_release_request, influenced_artifact_digest=content_digest("substituted"))
        changed = replace(preparation, label_release_request=request)
    reads = 0

    def labels() -> bytes:
        nonlocal reads
        reads += 1
        return b"escaped-labels"

    with pytest.raises(GuardedCustodyError):
        custodian.spend_and_release_labels(_authority(setup), changed, labels)
    assert reads == 0
    assert store.log.status is PopulationStatus.AVAILABLE


def test_crash_after_append_leaves_population_spent(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)

    def crash() -> bytes:
        _label_file(tmp_path).read_bytes()
        raise SimulatedCrash("after durable append")

    with pytest.raises(SimulatedCrash, match="after durable append"):
        custodian.spend_and_release_labels(_authority(setup), preparation, crash)
    assert store.log.status is PopulationStatus.SPENT
    assert store.log.receipt_count > 0


def test_concurrent_preparations_release_labels_to_one_cas_winner(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)
    path = _label_file(tmp_path)
    reads = 0
    lock = Lock()

    def labels() -> bytes:
        nonlocal reads
        with lock:
            reads += 1
        return path.read_bytes()

    def attempt() -> object:
        try:
            return custodian.spend_and_release_labels(_authority(setup), preparation, labels)
        except GuardedCustodyError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: attempt(), range(2)))
    assert sum(not isinstance(item, GuardedCustodyError) for item in results) == 1
    assert reads == 1
    assert store.log.status is PopulationStatus.SPENT


def test_swapped_operational_payload_is_refused_before_metrics(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)
    authority = _authority(setup)
    guarded = custodian.spend_and_release_labels(authority, preparation, _label_file(tmp_path).read_bytes)
    release = custodian.release_cases(
        authority,
        preparation,
        guarded.receipt,
        setup.cases,
        _reviewer(setup),
    )
    changed = replace(setup.cases[0], total_reply_ms=setup.cases[0].total_reply_ms + 1)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))

    with pytest.raises(ValueError, match="release|binding|case"):
        score_v2_admission(
            setup.manifest,
            setup.denominator,
            setup.readiness,
            preparation,
            guarded.receipt,
            release,
            (changed, *setup.cases[1:]),
            setup.context,
            custodian,
            setup.resolver,
        )


def test_case_release_requires_an_independent_attestation(tmp_path: Path) -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)
    authority = _authority(setup)
    guarded = custodian.spend_and_release_labels(authority, preparation, _label_file(tmp_path).read_bytes)

    def self_review(payload: str, producer: str) -> IndependenceAttestation:
        draft = IndependenceAttestation(payload, producer, producer, setup.manifest.review.conflict_disclosure, "0" * 64)
        return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))

    with pytest.raises(ValueError, match="independent"):
        custodian.release_cases(
            authority,
            preparation,
            guarded.receipt,
            setup.cases,
            self_review,
        )


def test_zero_byte_label_input_fails_after_monotonic_spend() -> None:
    setup = _setup()
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    preparation = _prepare(setup, custodian)

    with pytest.raises(GuardedCustodyError, match="zero-byte"):
        custodian.spend_and_release_labels(_authority(setup), preparation, lambda: b"")
    assert store.log.status is PopulationStatus.SPENT
