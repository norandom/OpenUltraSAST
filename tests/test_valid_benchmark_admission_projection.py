"""Task 8.4 exact-scope projection and matching differential-proof promotion."""

from __future__ import annotations

import base64
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_admission_execution import (  # noqa: E402
    ORDINARY_PUSHES,
    _admission_review,
    _capability_report,
    _capture,
    _case,
    _cases,
    _configuration,
    _Env,
    _freeze,
    _material_manifest,
    _push_value,
    _reviewed_manifest,
    _selection,
    _selection_value,
    _union_rule,
    execution,
)
from test_valid_benchmark_admission_spend import _LabelSource, _scope_census  # noqa: E402
from test_valid_benchmark_arm_registry import _registration  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    CUSTODIAN,
    _attestation,
    _digest,
    _policy,
    _settings,
)

from benchmarks.valid import admission_projection as projection  # noqa: E402
from benchmarks.valid import admission_spend as spend  # noqa: E402
from benchmarks.valid import arm_contract as registry  # noqa: E402
from benchmarks.valid.admission_execution import initial_attempt_event_payload_digest  # noqa: E402
from benchmarks.valid.admission_orchestrator import (  # noqa: E402
    AdmissionExecutionBindingV1,
    admission_census_payload_digest,
    admission_manifest_payload_digest,
    compose_plan_manifest,
    compose_population_census,
)
from benchmarks.valid.admission_projection import (  # noqa: E402
    AdmissionProjectionError,
    AdmissionProjectionReason,
    LabelBlindProofCandidateV1,
    ProjectionRequestV1,
    ProofDisposition,
    ProofPromotionRequestV1,
    VerificationBasis,
    exact_scope_projection_bytes,
    project_exact_scopes,
    promote_proof_candidate,
    proof_promotion_bytes,
)
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendReason,
    AdmissionSpendReleaseV1,
    commit_spend_and_release,
)
from benchmarks.valid.arm_combination import CombinationRuleKindV1, CombinationRuleRegistrationV1  # noqa: E402
from benchmarks.valid.ecosystem_review import CanonicalEcosystem  # noqa: E402
from benchmarks.valid.isolated_execution_bundle import build_component_execution_bundles  # noqa: E402
from benchmarks.valid.isolated_execution_contract import ExecutionAdapterKind  # noqa: E402
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1, ordinary_selection_bytes  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose, store_namespace_identity  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import empty_population_custody_log, record_population_use  # noqa: E402
from openultrasast.core.evaluation_measurement import (  # noqa: E402
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    Comparator,
    DenominatorPolicyV3,
    IntervalMethod,
    IntervalPrecisionRuleV3,
    MetricId,
    ScopedThresholdV3,
    ScopeKey,
    ScopeSufficiencyRuleV3,
    Statistic,
    standard_scoped_metric_rules,
)
from openultrasast.core.evaluation_plan import EcosystemOrdinaryCensusV3  # noqa: E402
from openultrasast.core.proof import (  # noqa: E402
    DIFFERENTIAL_PROOF_SCHEMA,
    ControlBinding,
    DifferentialProofRecord,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofTrustPolicy,
    ProofVerificationReceipt,
    derive_producer_identity_digest,
)
from openultrasast.core.semantics import SourceLocation  # noqa: E402


def _judgment(index: int) -> bytes:
    return canonical.canonical_bytes(
        {
            "schema_version": projection.GROUND_TRUTH_JUDGMENT_SCHEMA,
            "path": f"src/vulnerable_{index}.py",
            "line": index + 1,
            "column": None,
            "symbol": f"handler_{index}",
        }
    )


def _anchor(index: int) -> SourceLocation:
    return SourceLocation(f"src/vulnerable_{index}.py", index + 1, None, f"handler_{index}")


def _located_label_bytes(freeze, *, swap: bool = False, poison: int | None = None) -> bytes:
    """Sealed labels whose judgments carry the reviewed vulnerable location."""
    scopes: list[tuple[str, str]] = []
    for family, ecosystem, count in _scope_census(freeze):
        scopes.extend([(family, ecosystem)] * count)
    positives = freeze.positive_change_digests
    assert len(scopes) == len(positives)
    rows = []
    for index, (positive, scope) in enumerate(zip(positives, scopes, strict=True)):
        family, ecosystem = scope
        role = "vulnerable" if index % 2 == 0 else "fixed"
        pair = index // 2
        if swap and index == 40:
            family, role, pair = "injection", "vulnerable", 21
        if swap and index == 41:
            family, ecosystem, role, pair = "output_encoding", "python", "fixed", 21
        if swap and index == 42:
            role, pair = "vulnerable", 20
        if swap and index == 43:
            family, role, pair = "injection", "fixed", 20
        label = canonical.canonical_bytes(
            {
                "schema_version": spend.GROUND_TRUTH_LABEL_SCHEMA,
                "role": role,
                "pair_id_digest": _digest(f"pair-{pair}"),
                "family_id": family,
                "ecosystem": ecosystem,
            }
        )
        judgment = _judgment(index)
        if poison == index:
            judgment = b'{"column":NaN,"line":1,"path":"p.py","schema_version":"x","symbol":null}'
        rows.append(
            {
                "change_digest": positive,
                "label_digest": canonical.bytes_digest(label),
                "judgment_digest": canonical.bytes_digest(judgment),
                "label_base64": base64.b64encode(label).decode("ascii"),
                "judgment_base64": base64.b64encode(judgment).decode("ascii"),
            }
        )
    return canonical.canonical_bytes(
        {"schema_version": spend.SEALED_LABEL_OBJECT_SCHEMA, "records": tuple(sorted(rows, key=lambda row: row["change_digest"]))}
    )


class _RunEnv(_Env):
    """Execute, spend, and release against one case with explicit labels."""

    def __init__(self, case, *, labels: bytes, review) -> None:
        super().__init__(case)
        self.population = case.freeze.population_digest
        self.loader = _LabelSource(labels, self.custody, self.population)
        self.product = self.execute(review=review)
        assert self.product.admission_manifest is not None
        assert self.product.spend_authorization is not None and self.product.spend_authorization.may_spend
        assert self.loader.reads == 0
        self.disclosure, self.resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="release-disclosures")
        self.release = commit_spend_and_release(self.spend_request())
        assert self.release.refusal_reason is None

    def spend_request(self, **overrides: object) -> object:
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
        return spend.AdmissionSpendRequestV1(**value)

    def planned_receipt_digest(self) -> str:
        prior = self.custody.current_log(self.population)
        manifest = self.product.admission_manifest
        assert manifest is not None
        request = spend.label_open_request(self.population, manifest.manifest_digest, prior.log_digest)
        return record_population_use(request, prior, CUSTODIAN, self.custody_policy).receipt_digest

    def review(self, subject: str | None = None) -> object:
        manifest = self.product.admission_manifest
        assert manifest is not None
        if subject is None:
            try:
                cases = spend.join_released_cases(
                    self.product,
                    self.repository,
                    ACCESS_POLICY,
                    spend.decode_sealed_labels(self.loader.payload),
                    self.case.freeze.positive_change_digests,
                    _scope_census(self.case.freeze),
                )
                subject = spend.release_review_subject(manifest.manifest_digest, self.planned_receipt_digest(), cases, self.loader.payload)
            except spend.AdmissionSpendError:
                subject = _digest("underivable-release-subject")
        return _attestation(subject, _digest("release-producer"), self.disclosure)


@lru_cache(maxsize=1)
def _located_env() -> _RunEnv:
    case = _case()
    return _RunEnv(case, labels=_located_label_bytes(case.freeze), review=_admission_review(case))


@lru_cache(maxsize=1)
def _swap_env() -> _RunEnv:
    case = _case()
    return _RunEnv(case, labels=_located_label_bytes(case.freeze, swap=True), review=_admission_review(case))


@lru_cache(maxsize=1)
def _poison_env() -> _RunEnv:
    case = _case()
    return _RunEnv(case, labels=_located_label_bytes(case.freeze, poison=2), review=_admission_review(case))


def _relaxed_rules(arm_id: str, scopes: tuple[tuple[str, str], ...]):
    thresholds, policies, sufficiency = [], [], []
    for family, ecosystem in scopes:
        key = ArmScopeKey(arm_id, ScopeKey(family, ecosystem))
        thresholds.extend(
            ScopedThresholdV3(
                key,
                metric_id,
                Statistic.PER_100 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else Statistic.RATE,
                Comparator.AT_MOST
                if metric_id in {MetricId.FIXED_FALSE_ALARM_RATE, MetricId.ORDINARY_FALSE_ALARMS_PER_100}
                else Comparator.AT_LEAST,
                0.5,
                "",
            )
            for metric_id in MetricId
        )
        policies.append(DenominatorPolicyV3(key, standard_scoped_metric_rules(key), IntervalMethod.WILSON_95, ""))
        precision = tuple(
            IntervalPrecisionRuleV3(metric_id, 30.0 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else 0.99, 2, "")
            for metric_id in MetricId
        )
        sufficiency.append(ScopeSufficiencyRuleV3(key, 2, 2, precision, ""))
    return tuple(thresholds), tuple(policies), tuple(sufficiency)


def _relaxed_configuration(arm_id: str, scopes: tuple[tuple[str, str], ...]) -> ArmConfigurationV3:
    thresholds, policies, sufficiency = _relaxed_rules(arm_id, scopes)
    return ArmConfigurationV3(
        arm_id,
        ArmKindV3.COMPONENT,
        tuple(sorted(ScopeKey(family, ecosystem) for family, ecosystem in scopes)),
        policies,
        thresholds,
        sufficiency,
        _digest("judgment-vocabulary"),
        "analyzer@sha256:abc",
        _digest("facts"),
        _digest(f"relaxed-{arm_id}"),
        _digest("budget"),
        "container@sha256:def",
        _digest("outcome-mapping"),
        CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        None,
        "",
    )


@lru_cache(maxsize=1)
def _two_scope_case():
    from test_valid_benchmark_admission_execution import _ExecCase  # noqa: E402

    class TwoScope(_ExecCase):
        def __init__(self) -> None:
            self.freeze = _freeze()
            self.selection = _selection(self.freeze)
            self.material = _material_manifest(self.freeze)
            self.manifest, self.manifest_review, self.disclosure, self.resolver = _reviewed_manifest(
                self.freeze, self.selection, self.material
            )
            self.ordinary_census = (EcosystemOrdinaryCensusV3("python", ORDINARY_PUSHES),)
            two = (("injection", "python"), ("output_encoding", "python"))
            self.plan = registry.register_evaluation_plan(
                registrations=(
                    _registration(
                        registry.ArmRole.COMBINED,
                        replace(
                            _configuration("arm-combined", (("injection", "python"),), combined=True),
                            combination_rule=_union_rule(),
                            configuration_identity_digest="",
                        ),
                    ),
                    _registration(registry.ArmRole.EXPERIMENTAL, _relaxed_configuration("arm-experimental", two)),
                    _registration(registry.ArmRole.SHIPPED, _relaxed_configuration("arm-shipped", two)),
                ),
                population_digest=self.manifest.population_digest,
                freeze_digest=self.manifest.freeze_digest,
                input_set_digest=self.manifest.input_set_digest,
                input_identity_digests=self.manifest.input_digests,
            )
            self.cases = _cases(self.manifest, self.selection, self.material)
            self.budgets = tuple(
                execution.ArmExecutionBudgetV1(
                    row.arm_id,
                    row.configuration.registered_budget_digest,
                    120,
                    512 * 1024 * 1024,
                    1024 * 1024 * 1024,
                    4 * 1024 * 1024,
                    "",
                )
                for row in self.plan.registrations
                if row.configuration.kind is ArmKindV3.COMPONENT
            )
            self.bundles = build_component_execution_bundles(
                self.plan,
                self.manifest,
                self.selection,
                self.material,
                self.cases,
                self.budgets,
                adapter_kind=ExecutionAdapterKind.LOCAL,
                output_namespace_digest=_digest("observation-output-namespace"),
            )
            self.bindings = tuple(
                AdmissionExecutionBindingV1(
                    bundle.arm.arm_id,
                    bundle.bundle_digest,
                    bundle.budget.budget_digest,
                    bundle.environment.environment_digest,
                    bundle.output_destination.destination_digest,
                )
                for bundle in self.bundles
            )
            self.durable_identity = store_namespace_identity(_settings(StorePurpose.DURABLE))
            self.transient_identity = store_namespace_identity(_settings(StorePurpose.TRANSIENT))
            self.report, self.transient_profile = _capability_report(self.durable_identity, self.transient_identity)
            self.custody_log_digest = empty_population_custody_log(self.freeze.population_digest, CUSTODIAN).log_digest
            self.census_review = _attestation(
                admission_census_payload_digest(self.plan, self.manifest, self.ordinary_census, self.manifest_review),
                _digest("census-producer"),
                self.disclosure,
            )
            self.census = compose_population_census(self.plan, self.manifest, self.ordinary_census, self.census_review)
            self.plan_review = _attestation(
                admission_manifest_payload_digest(
                    self.plan, self.census, (self.report.report_digest,), self.custody_log_digest, self.manifest_review
                ),
                _digest("plan-producer"),
                self.disclosure,
            )
            self.plan_manifest = compose_plan_manifest(
                self.plan, self.census, (self.report.report_digest,), self.custody_log_digest, self.plan_review
            )
            self.attempt_status_ref = stored_artifact(b'{"status":"sealed"}', artifact_id="attempt-status")[0]
            combined_configuration = next(
                row.configuration for row in self.plan.registrations if row.configuration.kind is ArmKindV3.COMBINED
            )
            assert combined_configuration.combination_rule is not None
            self.combination_registrations = (
                CombinationRuleRegistrationV1(
                    "arm-combined", CombinationRuleKindV1.UNION, combined_configuration.combination_rule.rule_digest, ""
                ),
            )
            self.attempt_subject = initial_attempt_event_payload_digest(self.plan_manifest, self.attempt_status_ref)
            self.attempt_review = _attestation(self.attempt_subject, _digest("attempt-producer"), self.disclosure)
            self.default_factory = _capture(self.plan)

    return TwoScope()


@lru_cache(maxsize=1)
def _two_scope_admission_review(case):
    harvest = _Env(case)
    subject = harvest.execute().manifest_subject_digest
    return _attestation(subject, _digest("admission-producer"), case.disclosure)


@lru_cache(maxsize=1)
def _two_scope_env() -> _RunEnv:
    case = _two_scope_case()
    return _RunEnv(case, labels=_located_label_bytes(case.freeze, swap=True), review=_two_scope_admission_review(case))


def _positives() -> tuple[str, ...]:
    return _case().freeze.positive_change_digests


def _case_digest(environment: _RunEnv, arm_id: str, case_input: str) -> str:
    for row in environment.release.released_cases:
        if row.arm_id == arm_id and row.case_input_digest == case_input:
            return row.case_digest
    raise AssertionError("released case not found")


def _projection(environment: _RunEnv):
    return project_exact_scopes(ProjectionRequestV1(environment.release, environment.product, environment.case.selection))


def _proof_material(flagged: str, control: str, *, outcome: ProofOutcome = ProofOutcome.DEMONSTRATED, safe_observed: bool = False):
    producer = ProofProducerIdentity("proof-producer", "verifier-7", _digest("sandbox"), _digest("oracle"), _digest("proof-review"))
    producer_digest = derive_producer_identity_digest(producer)
    affected = ProofSideResult(flagged, True, _digest("affected-observation"), 1, "")
    safe = ProofSideResult(control, safe_observed, _digest("safe-observation"), 1, "")
    control_manifest, _ = stored_artifact(b'{"control":"manifest"}', artifact_id="control-manifest")
    witness, _ = stored_artifact(b'{"witness":"bytes"}', artifact_id="proof-witness")
    attestation, _ = stored_artifact(b'{"attested":true}', artifact_id="proof-attestation")
    reviewer = _digest("control-reviewer")
    binding = ControlBinding(flagged, control, control_manifest, reviewer, "")
    record = DifferentialProofRecord(DIFFERENTIAL_PROOF_SCHEMA, producer, affected, safe, binding, witness, outcome, "")
    receipt = ProofVerificationReceipt(
        producer_digest, record.record_digest, affected.result_digest, safe.result_digest, witness.content_digest, attestation, ""
    )
    trust = ProofTrustPolicy((producer_digest,), (reviewer,), ("trusted-store",), 512, "")
    return record, receipt, trust


def _candidate(record, receipt, **overrides: object) -> LabelBlindProofCandidateV1:
    value: dict[str, object] = {
        "arm_id": "arm-experimental",
        "family_claim": "injection",
        "ecosystem_claim": "python",
        "packet_digest": _digest("packet-pair-1"),
        "anchor": _anchor(2),
        "flagged_input_digest": _positives()[2],
        "control_input_digest": _positives()[3],
        "record_digest": record.record_digest,
        "receipt_digest": receipt.receipt_digest,
        "candidate_digest": "",
    }
    value.update(overrides)
    return LabelBlindProofCandidateV1(**value)


def _promotion(
    environment: _RunEnv,
    candidate,
    record,
    receipt,
    trust,
    *,
    basis=VerificationBasis.EXECUTION_DIFFERENTIAL,
    label_bytes=None,
):
    return promote_proof_candidate(
        ProofPromotionRequestV1(
            environment.release,
            environment.product,
            environment.case.selection,
            environment.loader.payload if label_bytes is None else label_bytes,
            candidate,
            record,
            receipt,
            basis,
            trust,
        )
    )


def _refusal(environment, callable_value, reason: AdmissionProjectionReason) -> None:
    with pytest.raises(AdmissionProjectionError) as report:
        callable_value()
    assert report.value.reason is reason


def test_ordinary_pushes_project_once_per_claimed_family_in_reviewed_ecosystem() -> None:
    product = _projection(_two_scope_env())
    rows = {(row.arm_id, row.family_id, row.ecosystem): row for row in product.scopes}
    assert set(rows) == {
        ("arm-combined", "injection", "python"),
        ("arm-experimental", "injection", "python"),
        ("arm-experimental", "output_encoding", "python"),
        ("arm-shipped", "injection", "python"),
        ("arm-shipped", "output_encoding", "python"),
    }
    for _key, row in rows.items():
        assert row.ordinary_push_count == ORDINARY_PUSHES
        assert len(set(row.ordinary_case_digests)) == ORDINARY_PUSHES
        assert row.scope_digest
    experimental = {key: rows[key] for key in rows if key[0] == "arm-experimental"}
    shared = {row.ordinary_case_digests for row in experimental.values()}
    assert len(shared) == 1


def test_whole_coverage_deduplicates_by_change_input_identity() -> None:
    environment = _located_env()
    product = _projection(environment)
    whole = product.whole_coverage
    assert whole.change_input_digests == tuple(sorted(environment.case.manifest.input_digests))
    assert whole.change_input_count == len(whole.change_input_digests) == 44 + ORDINARY_PUSHES
    assert len(environment.release.released_cases) == 3 * (44 + ORDINARY_PUSHES)


def test_multi_scope_positive_counts_once_in_whole_and_once_per_verified_scope() -> None:
    environment = _two_scope_env()
    product = _projection(environment)
    rows = {(row.family_id, row.ecosystem): row for row in product.scopes if row.arm_id == "arm-experimental"}
    injection, encoding = rows[("injection", "python")], rows[("output_encoding", "python")]
    positives = environment.case.freeze.positive_change_digests
    assert _case_digest(environment, "arm-experimental", positives[40]) in injection.vulnerable_case_digests
    assert _case_digest(environment, "arm-experimental", positives[43]) in injection.fixed_case_digests
    assert _case_digest(environment, "arm-experimental", positives[41]) in encoding.fixed_case_digests
    assert _case_digest(environment, "arm-experimental", positives[42]) in encoding.vulnerable_case_digests
    assert _case_digest(environment, "arm-experimental", positives[41]) not in injection.fixed_case_digests
    assert _case_digest(environment, "arm-experimental", positives[40]) not in encoding.vulnerable_case_digests
    assert injection.vulnerable_count == 20 and injection.fixed_count == 20
    assert encoding.vulnerable_count == 1 and encoding.fixed_count == 1
    whole = product.whole_coverage.change_input_digests
    for digest in (positives[40], positives[41], positives[42], positives[43]):
        assert whole.count(digest) == 1


def test_unverified_scope_grants_no_credit_beyond_whole_coverage() -> None:
    environment = _swap_env()
    product = _projection(environment)
    assert {row.family_id for row in product.scopes} == {"injection"}
    positives = environment.case.freeze.positive_change_digests
    for digest in (positives[40], positives[41], positives[42], positives[43]):
        assert digest in product.whole_coverage.change_input_digests
    injection = next(row for row in product.scopes if row.arm_id == "arm-shipped")
    assert _case_digest(environment, "arm-shipped", positives[43]) in injection.fixed_case_digests
    assert _case_digest(environment, "arm-shipped", positives[41]) not in injection.fixed_case_digests


def test_cross_ecosystem_selection_is_refused() -> None:
    environment = _located_env()
    selection = environment.case.selection
    first = selection.pushes[0]
    draft = replace(first, ecosystem=CanonicalEcosystem.JAVASCRIPT)
    pushed = replace(draft, push_digest=canonical.content_digest(_push_value(draft, include_digest=False)))
    pushes = tuple(sorted((*selection.pushes[1:], pushed), key=lambda item: item.push_digest))
    assignments = tuple(
        sorted(
            replace(item, ecosystem=CanonicalEcosystem.JAVASCRIPT, push_digest=pushed.push_digest)
            if item.push_digest == first.push_digest
            else item
            for item in selection.assignments
        )
    )
    draft_selection = OrdinarySelectionV1(
        selection.required_per_positive,
        selection.policy_digest,
        selection.positive_change_digests,
        selection.fix_exclusions,
        pushes,
        assignments,
        selection.exclusions,
        selection.provenance_digest,
        "",
    )
    tampered = replace(draft_selection, selection_digest=canonical.content_digest(_selection_value(draft_selection, include_digest=False)))
    ordinary_selection_bytes(tampered)
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(environment.release, environment.product, tampered)),
        AdmissionProjectionReason.ECOSYSTEM_CROSSED,
    )


def test_fabricated_release_counts_are_refused_by_census_rebinding() -> None:
    environment = _located_env()
    release = environment.release
    flagged = _positives()[2]
    dropped_labeled = AdmissionSpendReleaseV1(
        None,
        release.custody_receipt_digest,
        True,
        release.label_bytes_read,
        release.label_bytes_digest,
        tuple(row for row in release.released_cases if row.case_input_digest != flagged),
        release.review_reference,
        release.release_digest,
    )
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(dropped_labeled, environment.product, environment.case.selection)),
        AdmissionProjectionReason.CENSUS_MISMATCH,
    )
    ordinary_input = environment.case.selection.pushes[0].push_digest
    dropped_ordinary = AdmissionSpendReleaseV1(
        None,
        release.custody_receipt_digest,
        True,
        release.label_bytes_read,
        release.label_bytes_digest,
        tuple(row for row in release.released_cases if row.case_input_digest != ordinary_input),
        release.review_reference,
        release.release_digest,
    )
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(dropped_ordinary, environment.product, environment.case.selection)),
        AdmissionProjectionReason.CENSUS_MISMATCH,
    )


def _forged_release(environment: _RunEnv, original, *, marker: str) -> AdmissionSpendReleaseV1:
    release = environment.release
    forged = replace(original, result_digest=_digest(marker), case_digest="")
    return AdmissionSpendReleaseV1(
        None,
        release.custody_receipt_digest,
        True,
        release.label_bytes_read,
        release.label_bytes_digest,
        (*release.released_cases, forged),
        release.review_reference,
        release.release_digest,
    )


def test_duplicated_ordinary_row_with_fresh_case_digest_is_refused() -> None:
    environment = _located_env()
    push = environment.case.selection.pushes[0].push_digest
    original = next(row for row in environment.release.released_cases if row.arm_id == "arm-shipped" and row.case_input_digest == push)
    forged = _forged_release(environment, original, marker="forged-ordinary-result")
    assert forged.released_cases[-1].case_digest != original.case_digest
    assert forged.release_digest == environment.release.release_digest
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(forged, environment.product, environment.case.selection)),
        AdmissionProjectionReason.CENSUS_MISMATCH,
    )


def test_duplicated_vulnerable_row_is_refused() -> None:
    environment = _located_env()
    original = next(
        row for row in environment.release.released_cases if row.arm_id == "arm-shipped" and row.case_input_digest == _positives()[2]
    )
    forged = _forged_release(environment, original, marker="forged-vulnerable-result")
    assert forged.released_cases[-1].case_digest != original.case_digest
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(forged, environment.product, environment.case.selection)),
        AdmissionProjectionReason.CENSUS_MISMATCH,
    )


def test_projection_replays_exactly() -> None:
    environment = _two_scope_env()
    first = _projection(environment)
    second = _projection(environment)
    assert first == second
    assert exact_scope_projection_bytes(first) == exact_scope_projection_bytes(second)
    assert first.projection_digest == second.projection_digest
    assert canonical_json_bytes({"digest": first.projection_digest})


def test_invalid_or_unbound_requests_are_refused() -> None:
    environment = _located_env()
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1({}, environment.product, environment.case.selection)),
        AdmissionProjectionReason.INVALID_REQUEST,
    )
    refused = AdmissionSpendReleaseV1(AdmissionSpendReason.CUSTODY_CONFLICT, "", False, 0, "", (), None, "")
    _refusal(
        environment,
        lambda: project_exact_scopes(ProjectionRequestV1(refused, environment.product, environment.case.selection)),
        AdmissionProjectionReason.RELEASE_UNBOUND,
    )


def test_absent_proof_is_not_demonstrated() -> None:
    environment = _located_env()
    record, receipt, trust = _proof_material(_positives()[2], _positives()[3])
    missing = _promotion(environment, None, None, None, trust)
    assert missing.disposition is ProofDisposition.NOT_DEMONSTRATED
    assert missing.attachment is None
    partial = _promotion(environment, None, record, receipt, trust)
    assert partial.disposition is ProofDisposition.NOT_DEMONSTRATED and partial.attachment is None


def test_inconclusive_or_failed_proof_is_not_demonstrated() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    for outcome in (ProofOutcome.INCONCLUSIVE, ProofOutcome.FAILED):
        record, receipt, trust = _proof_material(flagged, control, outcome=outcome)
        product = _promotion(environment, _candidate(record, receipt), record, receipt, trust)
        assert product.disposition is ProofDisposition.NOT_DEMONSTRATED
        assert product.attachment is None
    record, receipt, trust = _proof_material(flagged, control, safe_observed=True)
    product = _promotion(environment, _candidate(record, receipt), record, receipt, trust)
    assert product.disposition is ProofDisposition.NOT_DEMONSTRATED and product.attachment is None


def test_matching_differential_proof_is_promoted_and_replays() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(flagged, control)
    candidate = _candidate(record, receipt)
    product = _promotion(environment, candidate, record, receipt, trust)
    assert product.disposition is ProofDisposition.DEMONSTRATED
    assert product.attachment is not None
    assert product.attachment.location == _anchor(2)
    assert product.attachment.family_id == "injection"
    assert product.attachment.packet_digest == candidate.packet_digest
    assert product.attachment.proof.record_digest == record.record_digest
    assert product.attachment.verification.receipt_digest == receipt.receipt_digest
    repeat = _promotion(environment, candidate, record, receipt, trust)
    assert repeat == product
    assert proof_promotion_bytes(repeat) == proof_promotion_bytes(product)


def test_swapped_roles_are_refused() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(control, flagged)
    candidate = _candidate(record, receipt, flagged_input_digest=control, control_input_digest=flagged)
    _refusal(environment, lambda: _promotion(environment, candidate, record, receipt, trust), AdmissionProjectionReason.PROOF_MISMATCH)


def test_unrelated_inputs_and_pairs_are_refused() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    other_pair = _positives()[5]
    record, receipt, trust = _proof_material(flagged, other_pair)
    candidate = _candidate(record, receipt, control_input_digest=other_pair)
    _refusal(environment, lambda: _promotion(environment, candidate, record, receipt, trust), AdmissionProjectionReason.PROOF_MISMATCH)
    ordinary = environment.case.selection.pushes[0].push_digest
    wrong_flagged, wrong_receipt, wrong_trust = _proof_material(ordinary, control)
    ordinary_candidate = _candidate(wrong_flagged, wrong_receipt, flagged_input_digest=ordinary)
    _refusal(
        environment,
        lambda: _promotion(environment, ordinary_candidate, wrong_flagged, wrong_receipt, wrong_trust),
        AdmissionProjectionReason.PROOF_MISMATCH,
    )


def test_cross_family_and_location_evidence_is_refused() -> None:
    environment = _two_scope_env()
    flagged, control = environment.case.freeze.positive_change_digests[2:4]
    record, receipt, trust = _proof_material(flagged, control)
    cross_family = _candidate(record, receipt, family_claim="output_encoding")
    _refusal(environment, lambda: _promotion(environment, cross_family, record, receipt, trust), AdmissionProjectionReason.PROOF_MISMATCH)
    cross_location = _candidate(record, receipt, anchor=SourceLocation("src/other.py", 99, None, "other"))
    _refusal(environment, lambda: _promotion(environment, cross_location, record, receipt, trust), AdmissionProjectionReason.PROOF_MISMATCH)


def test_unclaimed_scope_or_arm_is_refused() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(flagged, control)
    unclaimed = _candidate(record, receipt, family_claim="output_encoding")
    _refusal(environment, lambda: _promotion(environment, unclaimed, record, receipt, trust), AdmissionProjectionReason.SCOPE_UNVERIFIED)
    ghost = _candidate(record, receipt, arm_id="arm-ghost")
    _refusal(environment, lambda: _promotion(environment, ghost, record, receipt, trust), AdmissionProjectionReason.SCOPE_UNVERIFIED)


def test_scanner_only_and_model_only_evidence_is_refused() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(flagged, control)
    candidate = _candidate(record, receipt)
    for basis in (VerificationBasis.SCANNER_VERIFICATION, VerificationBasis.MODEL_AGREEMENT):
        _refusal(
            environment,
            lambda basis=basis: _promotion(environment, candidate, record, receipt, trust, basis=basis),
            AdmissionProjectionReason.PROOF_UNTRUSTED,
        )


def test_untrusted_producer_or_mismatched_receipt_is_refused() -> None:
    environment = _located_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(flagged, control)
    unreviewed = ProofTrustPolicy((_digest("someone-else"),), trust.reviewed_control_reviewer_digests, ("trusted-store",), 512, "")
    _refusal(
        environment,
        lambda: _promotion(environment, _candidate(record, receipt), record, receipt, unreviewed),
        AdmissionProjectionReason.PROOF_UNTRUSTED,
    )
    mismatched = ProofVerificationReceipt(
        receipt.producer_identity_digest,
        _digest("other-record"),
        receipt.affected_result_digest,
        receipt.safe_result_digest,
        receipt.witness_content_digest,
        receipt.attestation,
        "",
    )
    _refusal(
        environment,
        lambda: _promotion(environment, _candidate(record, mismatched), record, mismatched, trust),
        AdmissionProjectionReason.PROOF_UNTRUSTED,
    )
    swapped = _candidate(record, receipt, record_digest=_digest("unrelated-record"))
    _refusal(environment, lambda: _promotion(environment, swapped, record, receipt, trust), AdmissionProjectionReason.PROOF_MISMATCH)


def test_hostile_judgment_and_unbound_labels_are_refused() -> None:
    environment = _poison_env()
    flagged, control = _positives()[2], _positives()[3]
    record, receipt, trust = _proof_material(flagged, control)
    candidate = _candidate(record, receipt)
    _refusal(environment, lambda: _promotion(environment, candidate, record, receipt, trust), AdmissionProjectionReason.JUDGMENT_UNREADABLE)
    located = _located_env()
    other = _located_label_bytes(located.case.freeze, poison=5)
    _refusal(
        located,
        lambda: _promotion(located, candidate, record, receipt, trust, label_bytes=other),
        AdmissionProjectionReason.RELEASE_UNBOUND,
    )
