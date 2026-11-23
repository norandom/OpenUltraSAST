"""Task 8.3 admission spend: custody commit before label release and review."""

from __future__ import annotations

import base64
import copy
import json
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_admission_execution import (  # noqa: E402
    _admission_review,
    _case,
    _Env,
)
from test_valid_benchmark_admission_replay import _core_context, _mint_bridge_products  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    CUSTODIAN,
    _attestation,
    _Client,
    _digest,
    _policy,
    _settings,
)

from benchmarks.valid import admission_spend as spend  # noqa: E402
from benchmarks.valid.admission_replay import bridge_core_authorization  # noqa: E402
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendReason,
    AdmissionSpendRequestV1,
    GroundTruthLabelV1,
    commit_spend_and_release,
    decode_sealed_labels,
    join_released_cases,
    label_open_request,
    release_review_subject,
)
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import validate_artifact  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    LineagePurpose,
    PopulationStatus,
    PopulationUseRequest,
    append_population_use,
    record_population_use,
)
from openultrasast.core.evaluation_admission import validate_shared_spend  # noqa: E402
from openultrasast.core.evaluation_spend import EvaluationSharedSpendError, EvaluationSpendBindingV3  # noqa: E402

LABEL_MARKER = b"confidential-ground-truth-judgment"


class _LabelSource:
    """Custodian-bound label loader counting reads and proving spend ordering."""

    def __init__(self, payload: bytes, custody, population: str) -> None:
        self.payload = payload
        self.custody = custody
        self.population = population
        self.reads = 0

    def __call__(self) -> bytes:
        self.reads += 1
        head = self.custody.current_log(self.population)
        assert head.status is PopulationStatus.SPENT, "labels opened before committed spend"
        return self.payload


class _RacedCustody:
    """Loses the CAS exactly once: a rival commits a successor first."""

    def __init__(self, inner, population: str, custodian: str, policy) -> None:
        self._inner = inner
        self._population = population
        self._custodian = custodian
        self._policy = policy
        self._raced = False

    def current_log(self, population_digest: str):
        return self._inner.current_log(population_digest)

    def compare_and_swap(self, expected_log_digest: str, replacement) -> bool:
        if not self._raced:
            self._raced = True
            prior = self._inner.current_log(self._population)
            rival = PopulationUseRequest(self._population, "rival-arm", LineagePurpose.ADMISSION_LABEL_OPEN, True, None, prior.log_digest)
            receipt = record_population_use(rival, prior, self._custodian, self._policy)
            assert self._inner.compare_and_swap(prior.log_digest, append_population_use(prior, receipt, self._policy))
        return self._inner.compare_and_swap(expected_log_digest, replacement)


class _CountingCustody:
    """Pass-through custody port counting head reads and compare-and-swap calls."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.reads = 0
        self.swaps = 0

    def current_log(self, population_digest: str):
        self.reads += 1
        return self._inner.current_log(population_digest)

    def compare_and_swap(self, expected_log_digest: str, replacement) -> bool:
        self.swaps += 1
        return self._inner.compare_and_swap(expected_log_digest, replacement)


class _BrokenHeadWriteClient(_Client):
    """Fails every write against the custody head key; reads delegate."""

    def __init__(self, inner: _Client, key: str) -> None:
        super().__init__()
        self._inner = inner
        self._key = key

    def put_object(self, **kwargs: object) -> dict[str, object]:
        if str(kwargs.get("Key")) == self._key:
            raise RuntimeError("provider unavailable")
        return self._inner.put_object(**kwargs)

    def get_object(self, **kwargs: object) -> dict[str, object]:
        return self._inner.get_object(**kwargs)

    def __iter__(self):
        return iter(tuple(self._inner))

    def body(self, key: str) -> bytes:
        return self._inner.body(key)


def _scope_census(freeze) -> tuple[tuple[str, str, int], ...]:
    return tuple((row.vulnerability_family, row.ecosystem.value, row.count) for row in sorted(freeze.scope_census))


def _label_bytes(freeze, *, drop: int = 0, zero: bool = False) -> bytes:
    if zero:
        return b""
    scopes: list[tuple[str, str]] = []
    for family, ecosystem, count in _scope_census(freeze):
        scopes.extend([(family, ecosystem)] * count)
    positives = freeze.positive_change_digests
    assert len(scopes) == len(positives)
    rows = []
    for index, (positive, scope) in enumerate(zip(positives, scopes, strict=True)):
        family, ecosystem = scope
        label = canonical.canonical_bytes(
            {
                "schema_version": spend.GROUND_TRUTH_LABEL_SCHEMA,
                "role": "vulnerable" if index % 2 == 0 else "fixed",
                "pair_id_digest": _digest(f"pair-{index // 2}"),
                "family_id": family,
                "ecosystem": ecosystem,
            }
        )
        judgment = b'{"judgment":"defect-present"}' + LABEL_MARKER
        rows.append(
            {
                "change_digest": positive,
                "label_digest": canonical.bytes_digest(label),
                "judgment_digest": canonical.bytes_digest(judgment),
                "label_base64": base64.b64encode(label).decode("ascii"),
                "judgment_base64": base64.b64encode(judgment).decode("ascii"),
            }
        )
    if drop:
        rows = rows[:-drop]
    return canonical.canonical_bytes(
        {
            "schema_version": spend.SEALED_LABEL_OBJECT_SCHEMA,
            "records": tuple(sorted(rows, key=lambda row: row["change_digest"])),
        }
    )


def _nan_label_bytes(freeze) -> bytes:
    """Digest-consistent sealed object whose first label embeds a bare NaN."""
    document = json.loads(_label_bytes(freeze))
    record = document["records"][0]
    truth = json.loads(base64.b64decode(record["label_base64"]))
    truth["pair_id_digest"] = float("nan")
    poisoned = json.dumps(truth, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["label_base64"] = base64.b64encode(poisoned).decode("ascii")
    record["label_digest"] = canonical.bytes_digest(poisoned)
    return canonical.canonical_bytes({**document, "records": tuple(document["records"])})


def _outer_splice(raw: bytes, suffix: bytes) -> bytes:
    assert raw.endswith(b"}")
    return raw[:-1] + b"," + suffix + b"}"


def _replaced_label_bytes(freeze, poisoned: bytes) -> bytes:
    """Digest-consistent sealed object whose first label is arbitrary bytes."""
    document = json.loads(_label_bytes(freeze))
    record = document["records"][0]
    record["label_base64"] = base64.b64encode(poisoned).decode("ascii")
    record["label_digest"] = canonical.bytes_digest(poisoned)
    return canonical.canonical_bytes({**document, "records": tuple(document["records"])})


def _numeric_role_label_bytes(freeze) -> bytes:
    truth = json.loads(base64.b64decode(json.loads(_label_bytes(freeze))["records"][0]["label_base64"]))
    truth["role"] = 7
    return _replaced_label_bytes(freeze, canonical.canonical_bytes(truth))


class _SpendEnv(_Env):
    def __init__(self, case, *, labels: bytes | None = None, custody=None) -> None:
        super().__init__(case)
        self.population = case.freeze.population_digest
        if custody is not None:
            self.custody = custody
        payload = _label_bytes(case.freeze) if labels is None else labels
        self.loader = _LabelSource(payload, self.custody, self.population)
        self.product = self.execute(review=_admission_review(case))
        assert self.product.admission_manifest is not None
        assert self.product.spend_authorization is not None and self.product.spend_authorization.may_spend
        assert self.loader.reads == 0
        self.disclosure, self.resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="release-disclosures")

    def broken_head_custody(self) -> S3DurableCustodyStore:
        head_key = f"custody/{self.population}/head.json"
        broken = _BrokenHeadWriteClient(self.durable, head_key)
        return S3DurableCustodyStore(
            _settings(StorePurpose.DURABLE),
            broken,
            self.custody_policy,
            self.case.report,
            self.case.transient_identity,
            self.case.transient_profile,
        )

    def spend_request(self, **overrides: object) -> AdmissionSpendRequestV1:
        value: dict[str, object] = {
            "execution": self.product,
            "custody": self.custody,
            "repository": self.repository,
            "custodian_access_policy_digest": ACCESS_POLICY,
            "custody_policy": self.custody_policy,
            "custodian_identity": CUSTODIAN,
            "population_digest": self.population,
            "positive_change_digests": self.case.freeze.positive_change_digests,
            "scope_census": _scope_census(self.case.freeze),
            "load_labels": self.loader,
            "review": self.review(),
            "review_policy": _policy(),
            "resolver": self.resolver,
        }
        value.update(overrides)
        return AdmissionSpendRequestV1(**value)

    def planned_receipt_digest(self) -> str:
        prior = self.custody.current_log(self.population)
        manifest = self.product.admission_manifest
        assert manifest is not None
        request = label_open_request(self.population, manifest.manifest_digest, prior.log_digest)
        return record_population_use(request, prior, CUSTODIAN, self.custody_policy).receipt_digest

    def review(self, subject: str | None = None) -> object:
        manifest = self.product.admission_manifest
        assert manifest is not None
        if subject is None:
            try:
                cases = join_released_cases(
                    self.product,
                    self.repository,
                    ACCESS_POLICY,
                    decode_sealed_labels(self.loader.payload),
                    self.case.freeze.positive_change_digests,
                    _scope_census(self.case.freeze),
                )
                subject = release_review_subject(manifest.manifest_digest, self.planned_receipt_digest(), cases, self.loader.payload)
            except spend.AdmissionSpendError:
                subject = _digest("underivable-release-subject")
        return _attestation(subject, _digest("release-producer"), self.disclosure)

    def sealed_workflow_payloads(self) -> list[tuple[str, object]]:
        rows = []
        for key in self.durable:
            if key.startswith("workflows/custodian_sealed/"):
                rows.append((key, validate_artifact(self.durable.body(key)).payload.get("schema_version")))
        return rows


def _assert_refusal(environment: _SpendEnv, product, reason: AdmissionSpendReason, *, reads: int, committed: bool) -> None:
    assert product.refusal_reason is reason
    assert environment.loader.reads == reads
    assert product.released_cases == ()
    assert product.review_reference is None
    assert product.release_digest == ""
    assert product.labels_spent is committed
    assert bool(product.custody_receipt_digest) is committed


def test_committed_spend_rereads_exact_successor_before_any_label_byte_opens() -> None:
    case = _case()
    environment = _SpendEnv(case)
    assert environment.loader.reads == 0

    product = commit_spend_and_release(environment.spend_request())

    assert product.refusal_reason is None
    assert environment.loader.reads == 1
    assert product.labels_spent is True
    assert product.label_bytes_read == len(environment.loader.payload) > 0
    assert product.label_bytes_digest == canonical.bytes_digest(environment.loader.payload)
    head = environment.custody.current_log(environment.population)
    assert head.status is PopulationStatus.SPENT
    assert head.receipt_count == 1
    assert product.custody_receipt_digest == head.receipts[-1].receipt_digest
    assert head.receipts[-1].request.purpose is LineagePurpose.ADMISSION_LABEL_OPEN
    assert head.receipts[-1].request.labels_accessed is True
    assert product.released_cases
    assert product.review_reference is not None
    assert product.release_digest


def test_released_cases_bind_scope_role_pair_result_inputs_observation_and_manifest() -> None:
    case = _case()
    environment = _SpendEnv(case)
    manifest = environment.product.admission_manifest
    assert manifest is not None
    positives = frozenset(case.freeze.positive_change_digests)

    product = commit_spend_and_release(environment.spend_request())

    labels = {row.change_digest: row for row in decode_sealed_labels(environment.loader.payload)}
    slots = {row.slot_digest: row for row in environment.product.sealed_observations}
    seen_inputs: set[str] = set()
    for row in product.released_cases:
        assert row.manifest_digest == manifest.manifest_digest
        assert row.observation_slot_digest in slots
        sealed = slots[row.observation_slot_digest]
        assert row.arm_id == sealed.arm_id
        assert row.input_identity_digest == sealed.input_identity_digest
        assert row.observation_digest == sealed.observation_digest
        seen_inputs.add(row.case_input_digest)
        if row.case_input_digest in positives:
            label = labels[row.case_input_digest]
            assert row.role is label.role
            assert row.pair_id_digest == label.pair_id_digest
            assert (row.family_id, row.ecosystem) == (label.family_id, label.ecosystem)
            assert row.label_digest == label.label_digest
            assert row.judgment_digest == label.judgment_digest
        else:
            assert row.role.value == "ordinary"
            assert row.pair_id_digest is None and row.family_id == "" and row.ecosystem == ""
            assert row.label_digest == "0" * 64 and row.judgment_digest == "0" * 64
        assert row.result_digest and row.read_receipt_digest
    assert seen_inputs == set(case.manifest.input_digests)


def test_failed_custody_cas_makes_zero_label_reads() -> None:
    case = _case()
    base = _SpendEnv(case)
    raced = _RacedCustody(base.custody, base.population, CUSTODIAN, base.custody_policy)
    environment = _SpendEnv(case, custody=raced)

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_CONFLICT, reads=0, committed=False)
    head = environment.custody.current_log(environment.population)
    assert head.status is PopulationStatus.SPENT
    assert head.receipts[-1].request.arm_id == "rival-arm"


def test_ambiguous_custody_write_makes_zero_label_reads() -> None:
    case = _case()
    environment = _SpendEnv(case)
    custody = environment.broken_head_custody()
    environment.custody = custody
    environment.loader.custody = custody

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_UNREADABLE, reads=0, committed=False)
    assert custody.current_log(environment.population).status is PopulationStatus.AVAILABLE
    assert custody.current_log(environment.population).receipt_count == 0


def test_moved_custody_head_refuses_before_any_label_read() -> None:
    case = _case()
    environment = _SpendEnv(case)
    prior = environment.custody.current_log(environment.population)
    rival = PopulationUseRequest(environment.population, "rival-arm", LineagePurpose.ADMISSION_LABEL_OPEN, True, None, prior.log_digest)
    receipt = record_population_use(rival, prior, CUSTODIAN, environment.custody_policy)
    assert environment.custody.compare_and_swap(prior.log_digest, append_population_use(prior, receipt, environment.custody_policy))

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE, reads=0, committed=False)


def test_unauthorized_execution_product_never_spends_or_reads_labels() -> None:
    case = _case()
    environment = _SpendEnv(case)
    refusal_product = replace(environment.product, admission_manifest=None)

    product = commit_spend_and_release(environment.spend_request(execution=refusal_product))

    _assert_refusal(environment, product, AdmissionSpendReason.AUTHORIZATION_REFUSED, reads=0, committed=False)
    assert environment.custody.current_log(environment.population).status is PopulationStatus.AVAILABLE


def test_zero_label_bytes_refused_after_committed_spend() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=b"")

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)
    assert product.label_bytes_read == 0
    head = environment.custody.current_log(environment.population)
    assert product.custody_receipt_digest == head.receipts[-1].receipt_digest


def test_malformed_label_object_refused_after_committed_spend() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=b'{"schema_version":"unknown","records":[]}')

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_missing_label_record_breaks_the_ground_truth_join() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=_label_bytes(case.freeze, drop=1))

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.JOIN_INCOMPLETE, reads=1, committed=True)


def test_non_finite_label_constant_is_refused_closed_after_committed_spend() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=_nan_label_bytes(case.freeze))

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_outer_numeric_overflow_in_extra_key_is_refused_closed() -> None:
    case = _case()
    poisoned = _outer_splice(_label_bytes(case.freeze), b'"poison":1e999')

    environment = _SpendEnv(case, labels=poisoned)
    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_deeply_nested_label_bytes_are_refused_closed() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=_replaced_label_bytes(case.freeze, b"[" * 200000))

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_deeply_nested_outer_extra_key_is_refused_closed() -> None:
    case = _case()
    poisoned = _outer_splice(_label_bytes(case.freeze), b'"poison":' + b"[" * 200000 + b"]")

    environment = _SpendEnv(case, labels=poisoned)
    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_non_canonical_label_role_value_is_refused_closed() -> None:
    case = _case()
    environment = _SpendEnv(case, labels=_numeric_role_label_bytes(case.freeze))

    product = commit_spend_and_release(environment.spend_request())

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)


def test_adversarial_label_decode_battery_is_fully_closed() -> None:
    case = _case()
    base = _label_bytes(case.freeze)
    schema = spend.SEALED_LABEL_OBJECT_SCHEMA.encode()
    battery = (
        b"",
        b"not-json",
        b"\xff\xfe{}",
        b"[]",
        b'{"schema_version":"unknown"}',
        base.replace(b'"label_digest"', b'"label-digest"', 1),
        _outer_splice(base, b'"poison":NaN'),
        _outer_splice(base, b'"poison":Infinity'),
        _outer_splice(base, b'"poison":-Infinity'),
        _outer_splice(base, b'"poison":1e999'),
        _outer_splice(base, b'"poison":-1e999'),
        _outer_splice(base, b'"poison":' + b"9" * 5000),
        _outer_splice(base, b'"poison":' + b"[" * 200000 + b"]"),
        _outer_splice(base, b'"poison":' + b'{"deep":' * 2000),
        _outer_splice(base, b'"records":5'),
        _outer_splice(base, b'"schema_version":' + schema),
        _nan_label_bytes(case.freeze),
        _numeric_role_label_bytes(case.freeze),
        _replaced_label_bytes(case.freeze, b"[" * 200000),
        _replaced_label_bytes(case.freeze, b'{"role":"vulnerable"}'),
        _replaced_label_bytes(case.freeze, b'{"na\\u0000":1}'),
    )
    for raw in battery:
        with pytest.raises(spend.AdmissionSpendError):
            decode_sealed_labels(raw)


@pytest.mark.parametrize("mode", ["missing", "self", "stale"])
def test_missing_self_or_stale_release_review_is_refused(mode: str) -> None:
    case = _case()
    environment = _SpendEnv(case)
    review = environment.review()
    if mode == "missing":
        review = None
    elif mode == "self":
        review = _attestation(review.subject_digest, review.reviewer_identity, environment.disclosure)
    else:
        review = _attestation(_digest("wrong-subject"), _digest("release-producer"), environment.disclosure)

    product = commit_spend_and_release(environment.spend_request(review=review))

    _assert_refusal(environment, product, AdmissionSpendReason.REVIEW_REQUIRED, reads=1, committed=True)


def test_reviewed_release_is_sealed_and_carries_no_label_bytes() -> None:
    case = _case()
    environment = _SpendEnv(case)
    assert environment.adapter.calls, "arms executed label-blind before the spend"

    product = commit_spend_and_release(environment.spend_request())

    release_rows = [row for row in environment.sealed_workflow_payloads() if row[1] == spend.CASE_RELEASE_DOCUMENT_SCHEMA]
    assert len(release_rows) == 1
    release_key = release_rows[0][0]
    release_bytes = environment.durable.body(release_key)
    assert LABEL_MARKER not in release_bytes
    assert b"label_base64" not in release_bytes
    assert b"judgment_base64" not in release_bytes
    accepted = validate_artifact(release_bytes)
    assert accepted.access_class.value == "custodian_sealed"
    assert accepted.payload["custody_receipt_digest"] == product.custody_receipt_digest
    assert accepted.payload["release_digest"] == product.release_digest
    assert accepted.payload["label_bytes_read"] == product.label_bytes_read
    assert accepted.payload["case_digests"] == tuple(row.case_digest for row in product.released_cases)
    review_value = accepted.payload["review"]
    assert review_value["producer_identity"] != review_value["reviewer_identity"]


def test_only_release_bound_to_committed_receipt_reaches_scoring() -> None:
    case = _case()
    environment = _SpendEnv(case)

    first = commit_spend_and_release(environment.spend_request())
    second = commit_spend_and_release(environment.spend_request())

    assert first.refusal_reason is None
    assert second.refusal_reason is AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE
    assert environment.loader.reads == 1
    release_rows = [row for row in environment.sealed_workflow_payloads() if row[1] == spend.CASE_RELEASE_DOCUMENT_SCHEMA]
    assert len(release_rows) == 1


def test_decode_sealed_labels_is_strict_and_closed() -> None:
    case = _case()
    raw = _label_bytes(case.freeze)

    labels = decode_sealed_labels(raw)

    assert labels == tuple(sorted(labels, key=lambda row: row.change_digest))
    assert all(type(row) is GroundTruthLabelV1 for row in labels)
    assert len(labels) == len(case.freeze.positive_change_digests)
    with pytest.raises(spend.AdmissionSpendError):
        decode_sealed_labels(b"not-json")
    with pytest.raises(spend.AdmissionSpendError):
        decode_sealed_labels(raw.replace(spend.SEALED_LABEL_OBJECT_SCHEMA.encode(), b"unknown-schema"))
    with pytest.raises(spend.AdmissionSpendError):
        decode_sealed_labels(raw.replace(b'"label_digest"', b'"label-digest"', 1))


@lru_cache(maxsize=1)
def _core_bridge():
    """The committed 8.5 bridge: a real core preparation minted over a fresh available head of the 8.3 case.

    The bridge products are minted fresh (never the replay suite's cached store, which its own
    spend test leaves spent) so the preparation never depends on test ordering.
    """
    return bridge_core_authorization(_mint_bridge_products()[-1])


class _MovedHeadCustody:
    """Serve an available head a rival moved with one label-blind use after the execution was authorized.

    The durable store accepts only the available-to-spent transition, so this core-valid head is
    served through the custody port the spend accepts while the backing store stays untouched.
    """

    def __init__(self, store, head) -> None:
        self._store = store
        self._head = head
        self.swaps = 0

    def current_log(self, population_digest: str):
        return self._head

    def compare_and_swap(self, expected_log_digest: str, replacement) -> bool:
        self.swaps += 1
        return self._store.compare_and_swap(expected_log_digest, replacement)


def _preparation_review(environment: _SpendEnv, preparation) -> object:
    """External post-spend review over the subject the preparation-rooted receipt will produce."""
    manifest = environment.product.admission_manifest
    prior = environment.custody.current_log(environment.population)
    receipt = record_population_use(preparation.label_release_request, prior, CUSTODIAN, environment.custody_policy)
    cases = join_released_cases(
        environment.product,
        environment.repository,
        ACCESS_POLICY,
        decode_sealed_labels(environment.loader.payload),
        environment.case.freeze.positive_change_digests,
        _scope_census(environment.case.freeze),
    )
    subject = release_review_subject(manifest.manifest_digest, receipt.receipt_digest, cases, environment.loader.payload)
    return _attestation(subject, _digest("release-producer"), environment.disclosure)


def _rival_spend(environment: _SpendEnv) -> None:
    """Commit a rival label-open receipt first so the authorized head is no longer available."""
    prior = environment.custody.current_log(environment.population)
    rival = PopulationUseRequest(environment.population, "rival-arm", LineagePurpose.ADMISSION_LABEL_OPEN, True, None, prior.log_digest)
    receipt = record_population_use(rival, prior, CUSTODIAN, environment.custody_policy)
    assert environment.custody.compare_and_swap(prior.log_digest, append_population_use(prior, receipt, environment.custody_policy))


def _spent_through(path: str, preparation) -> tuple[_SpendEnv, object, object]:
    """Spend one fresh available head through one minting path; return the environment, release, receipt."""
    environment = _SpendEnv(_case())
    head = environment.custody.current_log(environment.population)
    assert head.status is PopulationStatus.AVAILABLE
    assert head.log_digest == preparation.authority.custody_log_digest
    if path == "legacy":
        product = commit_spend_and_release(environment.spend_request())
    else:
        review = _preparation_review(environment, preparation)
        product = spend.commit_preparation_spend_and_release(environment.spend_request(review=review), preparation)
    assert product.refusal_reason is None
    assert environment.loader.reads == 1
    assert product.labels_spent is True
    assert product.review_reference is not None and product.released_cases
    receipt = environment.custody.current_log(environment.population).receipts[-1]
    assert product.custody_receipt_digest == receipt.receipt_digest
    return environment, product, receipt


def _core_check(custody, receipt, bridge):
    """The same core check for both sides: the binding it returned or the refusal it raised."""
    try:
        return validate_shared_spend(bridge.admission_manifest, bridge.preparation, receipt, _core_context()[0], custody)
    except EvaluationSharedSpendError as error:
        return error


def test_preparation_spend_receipt_binds_in_core_where_the_legacy_label_open_receipt_is_refused() -> None:
    """One byte-identical available head per minting path (a population spends once); the same core check binds one."""
    bridge = _core_bridge()
    preparation = bridge.preparation

    legacy_environment, legacy, legacy_receipt = _spent_through("legacy", preparation)
    environment, product, receipt = _spent_through("preparation", preparation)

    assert legacy_environment.product.admission_manifest == environment.product.admission_manifest
    assert legacy.released_cases == product.released_cases
    assert legacy.label_bytes_digest == product.label_bytes_digest == canonical.bytes_digest(environment.loader.payload)
    assert receipt.request == preparation.label_release_request
    assert legacy_receipt.request.arm_id == spend.LABEL_OPEN_ARM_ID
    assert legacy_receipt.request.influenced_artifact_digest == environment.product.admission_manifest.manifest_digest
    assert legacy_receipt.request != preparation.label_release_request
    sealed = [row for row in environment.sealed_workflow_payloads() if row[1] == spend.CASE_RELEASE_DOCUMENT_SCHEMA]
    assert len(sealed) == 1

    bound = _core_check(environment.custody, receipt, bridge)

    assert type(bound) is EvaluationSpendBindingV3
    assert bound.receipt_digest == receipt.receipt_digest == product.custody_receipt_digest
    assert bound.preparation_digest == preparation.preparation_digest

    refused = _core_check(legacy_environment.custody, legacy_receipt, bridge)

    assert type(refused) is EvaluationSharedSpendError
    assert str(refused) == "shared-spend receipt does not match the preparation"


def test_preparation_spend_refuses_a_head_a_rival_already_spent_before_any_write() -> None:
    preparation = _core_bridge().preparation
    environment = _SpendEnv(_case())
    _rival_spend(environment)
    moved = environment.custody.current_log(environment.population)
    assert moved.status is PopulationStatus.SPENT

    product = spend.commit_preparation_spend_and_release(environment.spend_request(), preparation)

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE, reads=0, committed=False)
    assert environment.custody.current_log(environment.population) == moved


def test_preparation_spend_refuses_a_moved_but_available_head_before_any_write() -> None:
    preparation = _core_bridge().preparation
    environment = _SpendEnv(_case())
    prior = environment.custody.current_log(environment.population)
    blind = PopulationUseRequest(environment.population, "rival-arm", LineagePurpose.ADMISSION_LABEL_OPEN, False, None, prior.log_digest)
    receipt = record_population_use(blind, prior, CUSTODIAN, environment.custody_policy)
    moved = append_population_use(prior, receipt, environment.custody_policy)
    assert moved.status is PopulationStatus.AVAILABLE
    assert moved.log_digest != preparation.label_release_request.expected_log_digest
    custody = _MovedHeadCustody(environment.custody, moved)

    product = spend.commit_preparation_spend_and_release(environment.spend_request(custody=custody), preparation)

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE, reads=0, committed=False)
    assert custody.swaps == 0
    assert environment.custody.current_log(environment.population) == prior


def test_preparation_spend_loses_the_custody_compare_and_swap_closed() -> None:
    preparation = _core_bridge().preparation
    base = _SpendEnv(_case())
    raced = _RacedCustody(base.custody, base.population, CUSTODIAN, base.custody_policy)
    environment = _SpendEnv(_case(), custody=raced)

    product = spend.commit_preparation_spend_and_release(environment.spend_request(), preparation)

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_CONFLICT, reads=0, committed=False)
    head = environment.custody.current_log(environment.population)
    assert head.status is PopulationStatus.SPENT
    assert head.receipts[-1].request.arm_id == "rival-arm"


@pytest.mark.parametrize("labels", [b"", b"not-json"], ids=["empty", "malformed"])
def test_preparation_spend_with_unreadable_labels_keeps_the_committed_spend_closed(labels: bytes) -> None:
    preparation = _core_bridge().preparation
    environment = _SpendEnv(_case(), labels=labels)

    product = spend.commit_preparation_spend_and_release(environment.spend_request(), preparation)

    _assert_refusal(environment, product, AdmissionSpendReason.LABELS_UNREADABLE, reads=1, committed=True)
    head = environment.custody.current_log(environment.population)
    assert head.status is PopulationStatus.SPENT
    assert head.receipts[-1].request == preparation.label_release_request
    assert product.custody_receipt_digest == head.receipts[-1].receipt_digest


def test_preparation_spend_refuses_a_value_that_is_not_the_core_preparation_before_any_write() -> None:
    environment = _SpendEnv(_case())
    manifest = environment.product.admission_manifest
    prior = environment.custody.current_log(environment.population)
    not_a_preparation = label_open_request(environment.population, manifest.manifest_digest, prior.log_digest)

    with pytest.raises(spend.AdmissionSpendError) as raised:
        spend.commit_preparation_spend_and_release(environment.spend_request(), not_a_preparation)

    assert raised.value.reason is AdmissionSpendReason.INVALID_REQUEST
    assert environment.custody.current_log(environment.population) == prior
    assert environment.loader.reads == 0


def test_legacy_spend_refuses_a_forged_custody_log_digest_only_after_the_head_check() -> None:
    """The label-open request is minted from the head the custody check accepted, never before it."""
    environment = _SpendEnv(_case())
    custody = _CountingCustody(environment.custody)
    forged = copy.copy(environment.product.admission_manifest)
    object.__setattr__(forged, "custody_log_digest", "not-a-digest")
    prior = environment.custody.current_log(environment.population)

    product = commit_spend_and_release(
        environment.spend_request(execution=replace(environment.product, admission_manifest=forged), custody=custody)
    )

    _assert_refusal(environment, product, AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE, reads=0, committed=False)
    assert custody.reads == 1
    assert custody.swaps == 0
    assert environment.custody.current_log(environment.population) == prior
