"""Task 8.1 admission orchestrator preflight, insufficiency, retry authority."""

from __future__ import annotations

import io
import sys
import threading
from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import product
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402

from benchmarks.valid import (
    admission_orchestrator,  # noqa: E402
    lifecycle,  # noqa: E402
)
from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid.admission_orchestrator import (  # noqa: E402
    PREFLIGHT_WITNESS_SCHEMA,
    AdmissionExecutionBindingV1,
    AdmissionOrchestrator,
    AdmissionOrchestratorError,
    AdmissionPreflightReason,
    AdmissionRunRequestV1,
)
from benchmarks.valid.arm_contract import (  # noqa: E402
    ArmLifecycleState,
    ArmRegistrationV1,
    ArmRole,
    register_evaluation_plan,
)
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.custody_probe_contract import (  # noqa: E402
    MANDATORY_PROBE_RESULTS,
    RETENTION_PROBE_STATE_SCHEMA,
    ProbeResultName,
    ProbeResultReason,
    RetentionProbeState,
    build_capability_report,
    failed_result,
    passed_result,
)
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.ecosystem_review import CanonicalEcosystem  # noqa: E402
from benchmarks.valid.population_freeze_contract import (  # noqa: E402
    PopulationClass,
    PopulationClassificationReason,
    PopulationFreezeV3,
    PopulationScopeCountV1,
    _freeze_value,
    _population_value,
)
from benchmarks.valid.population_label_blind import review_label_blind_population_manifest  # noqa: E402
from benchmarks.valid.population_label_blind_contract import (  # noqa: E402
    LabelBlindPopulationDraftV3,
    _draft_value,
)
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes, validate_artifact  # noqa: E402
from benchmarks.valid.store_configuration import (  # noqa: E402
    StorePurpose,
    StoreSettings,
    default_retention_profiles,
    store_namespace_identity,
)
from benchmarks.valid.workflow_journal import (  # noqa: E402
    S3WorkflowJournal,
    WorkflowJournalError,
    WorkflowJournalReason,
    require_selected_authority,
)
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowStatus,
    decode_workflow_outcome,
    workflow_outcome_bytes,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    PopulationCustodyPolicy,
    PopulationStatus,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
)
from openultrasast.core.evaluation_feasibility import FeasibilityStatusV3  # noqa: E402
from openultrasast.core.evaluation_measurement import (  # noqa: E402
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    CombinationDecisionRowV3,
    CombinationOperatorV3,
    CombinationRuleV3,
    Comparator,
    DenominatorPolicyV3,
    IntervalMethod,
    IntervalPrecisionRuleV3,
    MetricId,
    NeutralOutcome,
    ProofCandidatePolicyV3,
    ScopedThresholdV3,
    ScopeKey,
    ScopeSufficiencyRuleV3,
    Statistic,
    standard_scoped_metric_rules,
)
from openultrasast.core.evaluation_plan import (  # noqa: E402
    EcosystemOrdinaryCensusV3,
    derive_evaluation_input_set_digest,
)
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

ROOT = Path(__file__).resolve().parents[1]
REVIEWER = canonical.content_digest("admission-reviewer")
CUSTODIAN = canonical.content_digest("custodian-identity")
POLICY = canonical.content_digest({"policy": "baseline-lifecycle-review-v1"})
WORKFLOW = canonical.content_digest("workflow-8-1")
ACCESS_POLICY = canonical.content_digest("custodian-access-policy")


class _ProviderError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code, "Message": "provider password=/private/path"}}
        super().__init__("provider secret")


class _Version:
    def __init__(self, version_id: str, body: bytes, etag: str) -> None:
        self.version_id = version_id
        self.body = body
        self.etag = etag


class _Client:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.versions: dict[str, list[_Version]] = {}
        self.next_version = 1

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        with self.lock:
            versions = self.versions.setdefault(key, [])
            current = versions[-1] if versions else None
            if kwargs.get("IfNoneMatch") == "*" and current is not None:
                raise _ProviderError("PreconditionFailed")
            expected = kwargs.get("IfMatch")
            if expected is not None and (current is None or current.etag != expected):
                raise _ProviderError("PreconditionFailed")
            body = kwargs["Body"]
            assert isinstance(body, bytes) and body
            version_id = f"version-{self.next_version}"
            self.next_version += 1
            etag = sha256(body + version_id.encode()).hexdigest()
            versions.append(_Version(version_id, body, etag))
            return {"ETag": etag, "VersionId": version_id}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        with self.lock:
            key = str(kwargs["Key"])
            versions = self.versions.get(key, [])
            if not versions:
                raise _ProviderError("NoSuchKey")
            version = versions[-1]
            return {
                "Body": io.BytesIO(version.body),
                "ContentLength": len(version.body),
                "VersionId": version.version_id,
                "ETag": version.etag,
            }

    def __iter__(self):
        with self.lock:
            return iter(tuple(self.versions))

    def body(self, key: str) -> bytes:
        response = self.get_object(Bucket="unused", Key=key)
        source = response["Body"]
        assert hasattr(source, "read")
        return source.read()


class _SpyExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, registration: object, bundle: object) -> object:
        self.calls.append(str(getattr(registration, "arm_id", "unknown")))
        raise AssertionError("preflight must never call an arm adapter")


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _settings(purpose: StorePurpose) -> StoreSettings:
    return StoreSettings(
        purpose,
        f"https://{purpose.value}.invalid:9000",
        f"valid-{purpose.value}",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _policy(reviewer: str = REVIEWER) -> ReviewIndependencePolicy:
    digest = derive_review_independence_policy_digest((reviewer,), (), ("trusted-store",), 4096)
    return ReviewIndependencePolicy((reviewer,), (), ("trusted-store",), 4096, digest)


def _attestation(subject: str, producer: str, disclosure: canonical.ContentRef) -> IndependenceAttestation:
    draft = IndependenceAttestation(subject, producer, REVIEWER, disclosure, "0" * 64)
    return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))


def _lifecycle(population: str, freeze: str, *, active: bool = True) -> lifecycle.BaselineLifecycleAuthority:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)
    review = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": candidate.candidate_digest,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "custodian",
        "reviewer_identity": "historical-reviewer",
        "conflict_disclosed": True,
        "policy_digest": POLICY,
    }
    review["review_digest"] = canonical.content_digest(review)
    withdrawn = historical.accept_reviewed_withdrawal(candidate, canonical.canonical_bytes(review))
    root = lifecycle.withdrawn_event(withdrawn)
    authority = lifecycle.BaselineLifecycleAuthority()
    authority.append(root)
    if active:
        authority.append(
            lifecycle.reviewed_replacement_event(
                predecessor_digest=lifecycle.decode_lifecycle_event(root).event_digest,
                historical_withdrawal_digest=lifecycle.decode_lifecycle_event(root).historical_withdrawal_digest,
                population_digest=population,
                freeze_digest=freeze,
                producer_identity="lifecycle-producer",
                reviewer_identity="lifecycle-reviewer",
                conflict_disclosed=True,
                policy_digest=POLICY,
            )
        )
    return authority


def _freeze(*, pilot: bool = False) -> PopulationFreezeV3:
    counts = (20, 10, 9) if pilot else (40, 2, 2)
    scope_census = (
        PopulationScopeCountV1("injection", CanonicalEcosystem.JAVASCRIPT, counts[1]),
        PopulationScopeCountV1("injection", CanonicalEcosystem.PYTHON, counts[0]),
        PopulationScopeCountV1("output_encoding", CanonicalEcosystem.PYTHON, counts[2]),
    )
    positive_count = sum(row.count for row in scope_census)
    positives = tuple(sorted(_digest(f"positive-{index}") for index in range(positive_count)))
    ecosystem_reviews = tuple(sorted(_digest(f"eco-{index}") for index in range(positive_count)))
    ground_truth_reviews = tuple(sorted(_digest(f"truth-{index}") for index in range(positive_count)))
    selection = canonical.content_digest(
        {
            "accepted_changes": positives,
            "scope_census": tuple(
                (row.vulnerability_family, row.ecosystem.value, row.count) for row in scope_census
            ),
        }
    )
    reviews = canonical.content_digest(
        {"ecosystem_reviews": ecosystem_reviews, "ground_truth_reviews": ground_truth_reviews}
    )
    draft = PopulationFreezeV3(
        PopulationClass.DEVELOPMENT_PILOT if pilot else PopulationClass.ADMISSION,
        (PopulationClassificationReason.BELOW_MINIMUM_POSITIVES,) if pilot else (),
        positive_count,
        (CanonicalEcosystem.JAVASCRIPT, CanonicalEcosystem.PYTHON),
        ("injection", "output_encoding"),
        scope_census,
        (),
        positives,
        selection,
        ecosystem_reviews,
        ground_truth_reviews,
        reviews,
        _digest("ordinary-selection"),
        _digest("reservation-census"),
        (("review_excluded", 1),),
        _digest("source-provenance"),
        _digest("ecosystem-policy"),
        _digest("ground-truth-policy"),
        _digest("freeze-policy"),
        "0" * 64,
        "0" * 64,
    )
    bound = replace(draft, population_digest=canonical.content_digest(_population_value(draft)))
    return replace(bound, freeze_digest=canonical.content_digest(_freeze_value(bound, include_digest=False)))


def _label_blind_manifest(freeze: PopulationFreezeV3, ordinary: int):
    inputs = tuple(sorted({*freeze.positive_change_digests, *(_digest(f"ordinary-{i}") for i in range(ordinary))}))
    draft = LabelBlindPopulationDraftV3(
        freeze.population_digest,
        freeze.freeze_digest,
        freeze.reservation_census_digest,
        freeze.review_set_digest,
        freeze.ordinary_selection_digest,
        _digest("public-manifest"),
        _digest("material-artifacts"),
        freeze.scope_census,
        inputs,
        freeze.positive_count,
        len(inputs),
        derive_evaluation_input_set_digest(inputs),
        "",
    )
    draft = replace(draft, draft_digest=canonical.content_digest(_draft_value(draft, include_digest=False)))
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="admission-disclosures")
    review = _attestation(draft.draft_digest, _digest("manifest-producer"), disclosure)
    manifest = review_label_blind_population_manifest(draft, review, _policy(), resolver)
    return manifest, review, disclosure, resolver


def _thresholds_and_rules(arm_id: str, scopes: tuple[tuple[str, str], ...], minimum_ordinary: int):
    thresholds = []
    policies = []
    sufficiency = []
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
            IntervalPrecisionRuleV3(
                metric_id,
                30.0 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else 0.25,
                4,
                "",
            )
            for metric_id in MetricId
        )
        sufficiency.append(ScopeSufficiencyRuleV3(key, 4, minimum_ordinary, precision, ""))
    return tuple(thresholds), tuple(policies), tuple(sufficiency)


def _configuration(arm_id: str, scopes: tuple[tuple[str, str], ...], *, combined: bool = False,
                   minimum_ordinary: int = 8, label: str = "configuration") -> ArmConfigurationV3:
    thresholds, policies, sufficiency = _thresholds_and_rules(arm_id, scopes, minimum_ordinary)
    rule = None
    if combined:
        arm_ids = ("arm-experimental", "arm-shipped")
        rows = tuple(
            CombinationDecisionRowV3(
                outcomes,
                NeutralOutcome.VIOLATION if NeutralOutcome.VIOLATION in outcomes else outcomes[0],
                "",
            )
            for outcomes in product(tuple(NeutralOutcome), repeat=len(arm_ids))
        )
        rule = CombinationRuleV3(arm_id, arm_ids, CombinationOperatorV3.DECLARATIVE_TABLE, rows,
                                 ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY, "")
    return ArmConfigurationV3(
        arm_id,
        ArmKindV3.COMBINED if combined else ArmKindV3.COMPONENT,
        tuple(sorted(ScopeKey(family, ecosystem) for family, ecosystem in scopes)),
        policies,
        thresholds,
        sufficiency,
        _digest("judgment-vocabulary"),
        "analyzer@sha256:abc",
        _digest("facts"),
        _digest(label),
        _digest("budget"),
        "container@sha256:def",
        _digest("outcome-mapping"),
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE if combined else CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        rule,
        "",
    )


@dataclass
class _Case:
    freeze: PopulationFreezeV3
    manifest: object
    plan: object
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...]
    census_review: IndependenceAttestation
    plan_review: IndependenceAttestation
    policy: ReviewIndependencePolicy
    resolver: object
    disclosure: canonical.ContentRef
    report: object
    durable_identity: str
    transient_identity: str
    transient_profile: object
    custody_log_digest: str
    bindings: tuple[AdmissionExecutionBindingV1, ...]

    def request(self, **overrides: object) -> AdmissionRunRequestV1:
        value: dict[str, object] = {
            "population_digest": self.freeze.population_digest,
            "freeze_digest": self.freeze.freeze_digest,
            "freeze": self.freeze,
            "manifest": self.manifest,
            "plan": self.plan,
            "current_registrations": self.plan.registrations,
            "ordinary_census": self.ordinary_census,
            "census_review": self.census_review,
            "plan_review": self.plan_review,
            "review_policy": self.policy,
            "resolver": self.resolver,
            "capability_report": self.report,
            "expected_durable_store_identity": self.durable_identity,
            "expected_transient_store_identity": self.transient_identity,
            "transient_retention_profile": self.transient_profile,
            "execution_bindings": self.bindings,
            "workflow_digest": WORKFLOW,
            "attempt_id": "attempt-1",
            "lease_owner_id": "owner-a",
            "heartbeat_at": "2026-11-21T09:00:00Z",
            "lease_expires_at": "2026-11-21T09:30:00Z",
            "recorded_runtime_ms": 250,
        }
        value.update(overrides)
        return AdmissionRunRequestV1(**value)


def _capability_report(durable_identity: str, transient_identity: str, *, failed: bool = False):
    profiles = default_retention_profiles(current_expiry_days=7, noncurrent_expiry_days=7)
    profile = profiles[StorePurpose.TRANSIENT]
    state = RetentionProbeState(
        RETENTION_PROBE_STATE_SCHEMA,
        _digest("probe-input"),
        512,
        1763000000,
        durable_identity,
        transient_identity,
        "valid-transient",
        "probe/current",
        "version-1",
        1764000000,
        "probe/noncurrent",
        "version-2",
        "version-3",
        1765000000,
        "",
    )
    state = replace(state, state_digest=canonical.bytes_digest(canonical.canonical_bytes({
        "schema_version": RETENTION_PROBE_STATE_SCHEMA,
        "input_digest": state.input_digest,
        "input_bytes_read": state.input_bytes_read,
        "started_at_epoch": state.started_at_epoch,
        "durable_store_identity": state.durable_store_identity,
        "transient_store_identity": state.transient_store_identity,
        "transient_bucket": state.transient_bucket,
        "current_key": state.current_key,
        "current_version_id": state.current_version_id,
        "current_deadline_epoch": state.current_deadline_epoch,
        "noncurrent_key": state.noncurrent_key,
        "noncurrent_version_id": state.noncurrent_version_id,
        "successor_version_id": state.successor_version_id,
        "noncurrent_deadline_epoch": state.noncurrent_deadline_epoch,
    })))
    results = tuple(
        failed_result(ProbeResultName.CONDITIONAL_CREATE, ProbeResultReason.CONDITIONAL_CREATE_UNSUPPORTED)
        if failed and name is ProbeResultName.CONDITIONAL_CREATE
        else passed_result(name)
        for name in MANDATORY_PROBE_RESULTS
    )
    return build_capability_report(_digest("probe-input"), 512, profile, state, results), profile


class _Environment:
    def __init__(self, case: _Case, *, lifecycle_active: bool = True) -> None:
        population = case.freeze.population_digest
        self.durable = _Client()
        self.transient = _Client()
        durable_settings = _settings(StorePurpose.DURABLE)
        self.repository = S3ArtifactRepository(durable_settings, self.durable)
        report = case.report
        custody_policy = PopulationCustodyPolicy(
            (CUSTODIAN,), derive_population_custody_policy_digest((CUSTODIAN,))
        )
        self.custody = S3DurableCustodyStore(
            durable_settings,
            self.durable,
            custody_policy,
            report,
            case.transient_identity,
            case.transient_profile,
        )
        assert self.custody.initialize(empty_population_custody_log(population, CUSTODIAN))
        self.journal = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), self.transient)
        self.spy = _SpyExecutor()
        self.orchestrator = AdmissionOrchestrator(
            _lifecycle(population, case.freeze.freeze_digest, active=lifecycle_active),
            self.repository,
            self.custody,
            self.journal,
            self.spy,
            ACCESS_POLICY,
        )

    def preflight(self, request: AdmissionRunRequestV1):
        return self.orchestrator.preflight(request)


def _case(*, ordinary: int = 12, pilot: bool = False, small_scope_claimed: bool = False) -> _Case:
    freeze = _freeze(pilot=pilot)
    manifest, manifest_review, disclosure, resolver = _label_blind_manifest(freeze, ordinary)
    ordinary_census = (EcosystemOrdinaryCensusV3("python", ordinary),)
    shipped_scopes = (
        (("injection", "python"), ("output_encoding", "python"))
        if small_scope_claimed
        else (("injection", "python"),)
    )
    registrations = (
        ArmRegistrationV1(
            ArmRole.COMBINED,
            ArmLifecycleState.ACTIVE,
            None,
            _configuration("arm-combined", (("injection", "python"),), combined=True),
            "",
        ),
        ArmRegistrationV1(
            ArmRole.EXPERIMENTAL, ArmLifecycleState.ACTIVE, None, _configuration("arm-experimental", (("injection", "python"),)), ""
        ),
        ArmRegistrationV1(ArmRole.SHIPPED, ArmLifecycleState.ACTIVE, None, _configuration("arm-shipped", shipped_scopes), ""),
    )
    plan = register_evaluation_plan(
        registrations=registrations,
        population_digest=freeze.population_digest,
        freeze_digest=freeze.freeze_digest,
        input_set_digest=manifest.input_set_digest,
        input_identity_digests=manifest.input_digests,
    )
    durable_identity = store_namespace_identity(_settings(StorePurpose.DURABLE))
    transient_identity = store_namespace_identity(_settings(StorePurpose.TRANSIENT))
    report, transient_profile = _capability_report(durable_identity, transient_identity)
    census_payload = admission_orchestrator.admission_census_payload_digest(
        plan, manifest, ordinary_census, manifest_review
    )
    census_review = _attestation(census_payload, _digest("census-producer"), disclosure)
    census = admission_orchestrator.compose_population_census(plan, manifest, ordinary_census, census_review)
    custody_log = empty_population_custody_log(freeze.population_digest, CUSTODIAN)
    manifest_payload = admission_orchestrator.admission_manifest_payload_digest(
        plan,
        census,
        (report.report_digest,),
        custody_log.log_digest,
        manifest_review,
    )
    plan_review = _attestation(manifest_payload, _digest("plan-producer"), disclosure)
    bindings = tuple(
        AdmissionExecutionBindingV1(
            arm_id,
            _digest(f"bundle-{arm_id}"),
            _digest(f"budget-{arm_id}"),
            _digest(f"environment-{arm_id}"),
            _digest(f"destination-{arm_id}"),
        )
        for arm_id in ("arm-experimental", "arm-shipped")
    )
    return _Case(
        freeze,
        manifest,
        plan,
        ordinary_census,
        census_review,
        plan_review,
        _policy(),
        resolver,
        disclosure,
        report,
        durable_identity,
        transient_identity,
        transient_profile,
        custody_log.log_digest,
        bindings,
    )


def _refusal(case: _Case, reason: AdmissionPreflightReason, **overrides: object) -> None:
    environment = _Environment(case)
    with pytest.raises(AdmissionOrchestratorError) as report:
        environment.preflight(case.request(**overrides))
    assert report.value.reason is reason
    assert not any(key.startswith("workflow/") for key in environment.transient)
    assert not any(key.startswith("workflows/") for key in environment.durable)
    assert environment.spy.calls == []


def test_preflight_refuses_pending_lifecycle_without_any_authority_or_head() -> None:
    case = _case()
    environment = _Environment(case, lifecycle_active=False)
    with pytest.raises(AdmissionOrchestratorError) as report:
        environment.preflight(case.request())
    assert report.value.reason is AdmissionPreflightReason.LIFECYCLE_NOT_ADMISSIBLE
    assert not any(key.startswith("workflow/") for key in environment.transient)
    assert not any(key.startswith("workflows/") for key in environment.durable)
    assert environment.spy.calls == []


def test_preflight_refuses_failed_capability_report() -> None:
    case = _case()
    durable = store_namespace_identity(_settings(StorePurpose.DURABLE))
    transient = store_namespace_identity(_settings(StorePurpose.TRANSIENT))
    failed_report, _ = _capability_report(durable, transient, failed=True)
    _refusal(case, AdmissionPreflightReason.STORE_CAPABILITY_FAILED, capability_report=failed_report)


def test_preflight_refuses_non_admission_freeze_class() -> None:
    _refusal(_case(pilot=True), AdmissionPreflightReason.FREEZE_NOT_ADMISSION_CLASS)


def test_preflight_refuses_unresolved_label_blind_manifest() -> None:
    case = _case()
    corrupted = replace(case.manifest, review_digest=_digest("wrong-review"))
    _refusal(case, AdmissionPreflightReason.MANIFEST_UNRESOLVED, manifest=corrupted)


def test_preflight_refuses_manifest_bound_to_other_population() -> None:
    case = _case()
    _refusal(
        case,
        AdmissionPreflightReason.MANIFEST_UNRESOLVED,
        manifest=replace(case.manifest, population_digest=_digest("other-population")),
    )


def test_preflight_refuses_stale_arm_identity() -> None:
    case = _case()
    stale = tuple(
        ArmRegistrationV1(
            row.role,
            row.lifecycle_state,
            row.strategy_decision_authority,
            replace(row.configuration, registered_budget_digest=_digest("changed-budget"), configuration_identity_digest=""),
            "",
        )
        if row.arm_id == "arm-shipped"
        else row
        for row in case.plan.registrations
    )
    _refusal(case, AdmissionPreflightReason.ARM_IDENTITY_STALE, current_registrations=stale)


def test_preflight_refuses_missing_current_arm_registration() -> None:
    case = _case()
    _refusal(
        case,
        AdmissionPreflightReason.ARM_IDENTITY_STALE,
        current_registrations=tuple(row for row in case.plan.registrations if row.arm_id != "arm-shipped"),
    )


def test_preflight_refuses_unaligned_execution_bindings() -> None:
    case = _case()
    _refusal(
        case,
        AdmissionPreflightReason.INVALID_REQUEST,
        execution_bindings=case.bindings[:1],
    )


def test_insufficient_scope_persists_witnesses_without_authority_head_or_spend() -> None:
    case = _case(ordinary=2)
    environment = _Environment(case)
    preflight = environment.preflight(case.request())

    outcome = preflight.insufficient_outcome
    assert outcome is not None
    assert outcome.status is WorkflowStatus.INSUFFICIENT
    assert workflow_outcome_bytes(outcome)
    assert decode_workflow_outcome(workflow_outcome_bytes(outcome)) == outcome
    assert preflight.retry_authority is None and preflight.workflow_head is None
    assert preflight.feasibility.may_spend is False
    assert [(row.arm_id, row.family_id, row.ecosystem) for row in preflight.scope_witnesses] == [
        ("arm-combined", "injection", "python"),
        ("arm-experimental", "injection", "python"),
        ("arm-shipped", "injection", "python"),
    ]
    assert all("interval_precision" in row.reasons and "minimum_size" in row.reasons for row in preflight.scope_witnesses)

    operator_keys = [key for key in environment.durable if key.startswith("workflows/operator_safe/")]
    assert len(operator_keys) == 2
    payloads = {}
    for key in operator_keys:
        artifact = validate_artifact(environment.durable.body(key))
        payloads[artifact.payload["schema_version"]] = artifact.payload
    outcome_payload = payloads.get("openultrasast.valid-detection-benchmark.workflow-outcome.v1")
    assert outcome_payload is not None
    assert canonical_json_bytes(outcome_payload) == workflow_outcome_bytes(outcome)
    witness = payloads.get(PREFLIGHT_WITNESS_SCHEMA)
    assert witness is not None
    assert witness["failed_gates"] == ("preflight_feasibility",)
    assert witness["scope_witnesses"][0]["reasons"] == ("interval_precision", "minimum_size")
    assert not any(key.startswith("workflows/custodian_sealed/") for key in environment.durable)
    assert not any(key.startswith("workflow/") for key in environment.transient)
    log = environment.custody.current_log(case.freeze.population_digest)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0
    assert environment.spy.calls == []


def test_whole_population_never_substitutes_for_an_insufficient_scope() -> None:
    case = _case(small_scope_claimed=True)
    environment = _Environment(case)
    preflight = environment.preflight(case.request())

    assert preflight.feasibility.may_spend is False
    insufficient = {(row.arm_id, row.family_id, row.ecosystem) for row in preflight.scope_witnesses}
    assert insufficient == {("arm-shipped", "output_encoding", "python")}
    assert all("minimum_size" in row.reasons for row in preflight.scope_witnesses)
    feasible_rows = [
        row
        for row in preflight.feasibility.rows
        if (row.key.arm_id, row.key.scope.family_id, row.key.scope.ecosystem)
        == ("arm-shipped", "injection", "python")
    ]
    assert feasible_rows
    assert all(row.status is FeasibilityStatusV3.FEASIBLE for row in feasible_rows)
    assert preflight.retry_authority is None and preflight.workflow_head is None
    assert preflight.insufficient_outcome is not None
    assert not any(key.startswith("workflows/custodian_sealed/") for key in environment.durable)
    assert not any(key.startswith("workflow/") for key in environment.transient)
    assert environment.custody.current_log(case.freeze.population_digest).status is PopulationStatus.AVAILABLE


def test_feasible_preflight_persists_and_selects_sealed_retry_authority() -> None:
    case = _case()
    environment = _Environment(case)
    preflight = environment.preflight(case.request())

    assert preflight.insufficient_outcome is None
    assert preflight.scope_witnesses == ()
    assert preflight.feasibility.may_spend is True
    authority = preflight.retry_authority
    reference = preflight.retry_authority_reference
    assert authority is not None and reference is not None
    assert reference.artifact_kind.value == "workflow"
    assert reference.access_class.value == "custodian_sealed"
    assert authority.authority_digest != reference.content_digest

    sealed = [key for key in environment.durable if key.startswith("workflows/custodian_sealed/")]
    assert sealed == [f"workflows/custodian_sealed/{reference.content_digest}.json"]
    artifact = validate_artifact(environment.durable.body(sealed[0]), reference=reference)
    assert artifact.payload["authority_digest"] == authority.authority_digest

    head = preflight.workflow_head
    assert head is not None
    assert environment.journal.current_head(WORKFLOW) == head
    assert head.sequence == 0
    assert head.retry_authority_ref == reference
    assert head.retry_authority_digest == reference.content_digest
    assert require_selected_authority(head, reference, reference.content_digest) == reference
    with pytest.raises(WorkflowJournalError) as substituted:
        require_selected_authority(head, reference, authority.authority_digest)
    assert substituted.value.reason is WorkflowJournalReason.AUTHORITY_SUBSTITUTED

    status = environment.journal.rebuild_status(WORKFLOW, "2026-11-21T09:05:00Z")
    assert status.counts.planned_arms == 3
    assert status.counts.planned_inputs == len(case.manifest.input_digests)
    assert status.phase is not None and status.phase.value == "preflight"
    assert preflight.expected_observation_slots == case.plan.declaration.expected_observation_slots
    assert preflight.input_set_digest == case.manifest.input_set_digest
    assert environment.custody.current_log(case.freeze.population_digest).status is PopulationStatus.AVAILABLE
    assert environment.spy.calls == []


def test_retry_authority_binds_every_ordered_identity() -> None:
    case = _case()
    preflight = _Environment(case).preflight(case.request())
    authority = preflight.retry_authority
    assert authority is not None

    assert authority.population_digest == case.freeze.population_digest
    assert authority.freeze_digest == case.freeze.freeze_digest
    assert authority.plan_digest == case.plan.plan_digest
    assert authority.ordered_arm_ids == ("arm-shipped", "arm-experimental", "arm-combined")
    assert authority.ordered_bundle_digests == (_digest("bundle-arm-experimental"), _digest("bundle-arm-shipped"))
    assert authority.ordered_budget_digests == (_digest("budget-arm-experimental"), _digest("budget-arm-shipped"))
    assert authority.ordered_environment_digests == (
        _digest("environment-arm-experimental"),
        _digest("environment-arm-shipped"),
    )
    assert authority.ordered_destination_digests == (
        _digest("destination-arm-experimental"),
        _digest("destination-arm-shipped"),
    )
    assert authority.ordered_checkpoint_slot_digests == tuple(
        slot.slot_digest for slot in case.plan.declaration.expected_observation_slots
    )
    assert authority.ordered_input_set_digests == (case.manifest.input_set_digest, case.manifest.input_set_digest)
    assert len(authority.admission_identity_digest) == 64


def test_preflight_is_deterministic_across_identical_runs() -> None:
    case = _case()
    first = _Environment(case).preflight(case.request())
    second = _Environment(case).preflight(case.request())
    assert first.retry_authority == second.retry_authority
    assert first.retry_authority_reference == second.retry_authority_reference
    assert first.workflow_head == second.workflow_head


def test_duplicate_head_selection_is_refused_and_original_head_preserved() -> None:
    case = _case()
    environment = _Environment(case)
    first = environment.preflight(case.request())
    with pytest.raises(AdmissionOrchestratorError) as report:
        environment.preflight(case.request())
    assert report.value.reason is AdmissionPreflightReason.WORKFLOW_HEAD_EXISTS
    assert environment.journal.current_head(WORKFLOW) == first.workflow_head


def test_dict_shaped_freeze_is_refused_closed_without_writes() -> None:
    case = _case()
    environment = _Environment(case)
    durable_before = tuple(environment.durable)
    transient_before = tuple(environment.transient)

    with pytest.raises(AdmissionOrchestratorError) as report:
        environment.preflight(case.request(freeze={"population_class": "admission"}))

    assert report.value.reason is AdmissionPreflightReason.INVALID_REQUEST
    hollow = object.__new__(PopulationFreezeV3)
    with pytest.raises(AdmissionOrchestratorError) as report:
        environment.preflight(case.request(freeze=hollow))

    assert report.value.reason is AdmissionPreflightReason.FREEZE_NOT_ADMISSION_CLASS
    assert tuple(environment.durable) == durable_before
    assert tuple(environment.transient) == transient_before
    assert environment.spy.calls == []
