"""Append-only population custody contracts (Req 12.2, 13.1, 13.4)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import detection_core_fixtures as fixtures
import pytest

from openultrasast.core import canonical, provenance


def _request(
    log: provenance.PopulationCustodyLog,
    *,
    labels_accessed: bool = False,
    purpose: provenance.LineagePurpose | None = None,
) -> provenance.PopulationUseRequest:
    return provenance.PopulationUseRequest(
        population_digest=log.population_digest,
        arm_id="arm-v2",
        purpose=purpose or provenance.LineagePurpose.SEMANTIC_FACT,
        labels_accessed=labels_accessed,
        influenced_artifact_digest=canonical.content_digest("artifact"),
        expected_log_digest=log.log_digest,
    )


def test_empty_log_and_policy_have_deterministic_identities() -> None:
    first, policy, _ = fixtures.custody_contract()
    second, _, _ = fixtures.custody_contract()
    assert first == second
    assert first.receipts == ()
    assert first.receipt_count == 0
    assert first.head_receipt_digest is None
    assert first.status is provenance.PopulationStatus.AVAILABLE
    provenance.validate_population_custody_log(first, policy)


def test_record_derives_cas_sequence_predecessor_and_receipt_identity() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    receipt = provenance.record_population_use(_request(prior), prior, custodian, policy)
    assert receipt.sequence == 1
    assert receipt.predecessor_digest is None
    assert receipt.prior_status is provenance.PopulationStatus.AVAILABLE
    assert receipt.status is provenance.PopulationStatus.AVAILABLE
    assert receipt.request_digest == provenance.derive_population_use_request_digest(receipt.request)
    assert receipt.receipt_digest == provenance.derive_population_use_receipt_digest(receipt)


def test_append_constructs_and_validates_a_contiguous_complete_chain() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    first = provenance.record_population_use(_request(prior), prior, custodian, policy)
    one = provenance.append_population_use(prior, first, policy)
    second = provenance.record_population_use(_request(one), one, custodian, policy)
    complete = provenance.append_population_use(one, second, policy)
    provenance.validate_population_custody_log(complete, policy)
    assert complete.receipt_count == 2
    assert complete.head_receipt_digest == second.receipt_digest
    assert second.predecessor_digest == first.receipt_digest


def test_compare_and_swap_refuses_an_old_log_head() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    stale = _request(prior)
    first = provenance.record_population_use(stale, prior, custodian, policy)
    current = provenance.append_population_use(prior, first, policy)
    with pytest.raises(provenance.PopulationCustodyError, match="expected log"):
        provenance.record_population_use(stale, current, custodian, policy)


def test_label_access_spends_population_and_status_is_monotonic() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    spent_receipt = provenance.record_population_use(_request(prior, labels_accessed=True), prior, custodian, policy)
    spent = provenance.append_population_use(prior, spent_receipt, policy)
    later = provenance.record_population_use(_request(spent), spent, custodian, policy)
    complete = provenance.append_population_use(spent, later, policy)
    assert spent_receipt.status is provenance.PopulationStatus.SPENT
    assert later.prior_status is provenance.PopulationStatus.SPENT
    assert later.status is provenance.PopulationStatus.SPENT
    assert complete.status is provenance.PopulationStatus.SPENT


def test_broken_or_omitted_receipts_are_refused() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    first = provenance.record_population_use(_request(prior), prior, custodian, policy)
    one = provenance.append_population_use(prior, first, policy)
    second = provenance.record_population_use(_request(one), one, custodian, policy)
    complete = provenance.append_population_use(one, second, policy)
    broken = replace(second, predecessor_digest=None)
    with pytest.raises(provenance.PopulationCustodyError, match="predecessor"):
        provenance.validate_population_custody_log(replace(complete, receipts=(first, broken)), policy)
    with pytest.raises(provenance.PopulationCustodyError, match="sequence"):
        provenance.validate_population_custody_log(
            replace(complete, receipts=(second,), receipt_count=1, head_receipt_digest=second.receipt_digest), policy
        )


def test_log_metadata_and_receipt_identities_are_rederived() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    receipt = provenance.record_population_use(_request(prior), prior, custodian, policy)
    current = provenance.append_population_use(prior, receipt, policy)
    for changed, message in (
        (replace(current, receipt_count=2), "count"),
        (replace(current, head_receipt_digest=None), "head"),
        (replace(current, log_digest="0" * 64), "log digest"),
        (replace(current, status=provenance.PopulationStatus.SPENT), "status"),
    ):
        with pytest.raises(provenance.PopulationCustodyError, match=message):
            provenance.validate_population_custody_log(changed, policy)
    with pytest.raises(provenance.PopulationCustodyError, match="receipt digest"):
        provenance.validate_population_custody_log(replace(current, receipts=(replace(receipt, receipt_digest="0" * 64),)), policy)


def test_unreviewed_custodian_and_tampered_policy_are_refused() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    with pytest.raises(provenance.PopulationCustodyError, match="reviewed"):
        provenance.record_population_use(_request(prior), prior, canonical.content_digest("other"), policy)
    with pytest.raises(provenance.PopulationCustodyError, match="policy"):
        provenance.record_population_use(_request(prior), prior, custodian, replace(policy, policy_digest="0" * 64))


def test_reviewed_custodian_cannot_take_over_an_existing_log() -> None:
    prior, _, custodian = fixtures.custody_contract()
    other = canonical.content_digest("other-reviewed-custodian")
    reviewed = (custodian, other)
    policy = provenance.PopulationCustodyPolicy(
        reviewed,
        provenance.derive_population_custody_policy_digest(reviewed),
    )
    with pytest.raises(provenance.PopulationCustodyError, match="does not match log"):
        provenance.record_population_use(_request(prior), prior, other, policy)


def test_receipt_reasons_are_derived_from_the_status_transition() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    receipt = provenance.record_population_use(_request(prior), prior, custodian, policy)
    tampered = replace(receipt, reasons=("labels_accessed",), receipt_digest="0" * 64)
    tampered = replace(tampered, receipt_digest=provenance.derive_population_use_receipt_digest(tampered))
    with pytest.raises(provenance.PopulationCustodyError, match="reasons"):
        provenance.append_population_use(prior, tampered, policy)


def test_current_log_check_refuses_an_old_but_internally_valid_prefix() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    port = fixtures.InMemoryPopulationCustody(prior, policy)
    port.append(_request(prior), custodian)
    provenance.validate_population_custody_log(port.current_log(prior.population_digest), policy, current=port)
    with pytest.raises(provenance.PopulationCustodyError, match="current complete log"):
        provenance.validate_population_custody_log(prior, policy, current=port)


def test_current_log_check_validates_the_ports_complete_chain() -> None:
    prior, policy, _ = fixtures.custody_contract()

    class InvalidPort:
        def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
            assert population_digest == prior.population_digest
            return replace(prior, log_digest="0" * 64)

    with pytest.raises(provenance.PopulationCustodyError, match="log digest"):
        provenance.validate_population_custody_log(prior, policy, current=InvalidPort())


def test_concurrent_requests_have_exactly_one_cas_successor() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    port = fixtures.InMemoryPopulationCustody(prior, policy)
    left = _request(prior, labels_accessed=True, purpose=provenance.LineagePurpose.ADMISSION_LABEL_OPEN)
    right = replace(left, arm_id="other-arm")

    def attempt(
        request: provenance.PopulationUseRequest,
    ) -> provenance.PopulationUseReceipt | provenance.PopulationCustodyError:
        try:
            return port.append(request, custodian)
        except provenance.PopulationCustodyError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(attempt, (left, right)))
    winners = tuple(result for result in results if isinstance(result, provenance.PopulationUseReceipt))
    failures = tuple(result for result in results if isinstance(result, provenance.PopulationCustodyError))
    assert len(winners) == len(failures) == 1
    assert "expected log" in str(failures[0])
    current = port.current_log(prior.population_digest)
    assert current.receipts == winners
    assert current.status is provenance.PopulationStatus.SPENT


def test_fixture_cannot_restore_a_spent_population() -> None:
    prior, policy, custodian = fixtures.custody_contract()
    port = fixtures.InMemoryPopulationCustody(prior, policy)
    port.append(_request(prior, labels_accessed=True), custodian)
    spent = port.current_log(prior.population_digest)
    port.append(_request(spent), custodian)
    current = port.current_log(prior.population_digest)
    assert current.status is provenance.PopulationStatus.SPENT
    restored = replace(current, status=provenance.PopulationStatus.AVAILABLE)
    with pytest.raises(provenance.PopulationCustodyError, match="status"):
        provenance.validate_population_custody_log(restored, policy)


@pytest.mark.parametrize("field", ["population_digest", "expected_log_digest"])
def test_request_digest_fields_are_runtime_validated(field: str) -> None:
    prior, _, _ = fixtures.custody_contract()
    with pytest.raises(canonical.DigestFormatError):
        if field == "population_digest":
            replace(_request(prior), population_digest="short")
        else:
            replace(_request(prior), expected_log_digest="short")
