"""Task 8.2 admission execution: seal every planned observation before spend."""

from __future__ import annotations

import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest
from detection_core_fixtures import stored_artifact

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_arm_registry import _registration  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    CUSTODIAN,
    _attestation,
    _capability_report,
    _Client,
    _configuration,
    _digest,
    _freeze,
    _lifecycle,
    _policy,
    _settings,
    _SpyExecutor,
)

from benchmarks.valid import admission_execution  # noqa: E402
from benchmarks.valid import arm_contract as registry  # noqa: E402
from benchmarks.valid import isolated_execution as execution  # noqa: E402
from benchmarks.valid import observation_checkpoint as checkpoint  # noqa: E402
from benchmarks.valid import observation_receipt as receipt  # noqa: E402
from benchmarks.valid.admission_execution import (  # noqa: E402
    AdmissionExecutionReason,
    AdmissionExecutionRequestV1,
    execute_planned_observations,
    initial_attempt_event_payload_digest,
    reauthorize_before_spend,
)
from benchmarks.valid.admission_orchestrator import (  # noqa: E402
    AdmissionExecutionBindingV1,
    AdmissionOrchestrator,
    AdmissionRunRequestV1,
    admission_census_payload_digest,
    admission_manifest_payload_digest,
    compose_plan_manifest,
    compose_population_census,
)
from benchmarks.valid.arm_combination import (  # noqa: E402
    CombinationRuleKindV1,
    CombinationRuleRegistrationV1,
    ComponentObservationV1,
    combine_observations,
    register_combination_plan,
)
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.isolated_execution_bundle import build_component_execution_bundles  # noqa: E402
from benchmarks.valid.isolated_execution_contract import ExecutionAdapterKind  # noqa: E402
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    OrdinaryDrawAssignmentV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    OrdinarySelectionV1,
    _fix_exclusion_value,
    _push_value,
    _selection_value,
)
from benchmarks.valid.population_label_blind import review_label_blind_population_manifest  # noqa: E402
from benchmarks.valid.population_label_blind_contract import (  # noqa: E402
    LabelBlindPopulationDraftV3,
    _draft_value,
)
from benchmarks.valid.population_material_contract import (  # noqa: E402
    LicenseClass,
    OpaquePrivateMaterialRefV1,
    PublicPopulationMaterialManifestV1,
    PublicSourceRecordV1,
    _manifest_value,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
    validate_artifact,
)
from benchmarks.valid.store_configuration import (  # noqa: E402
    StorePurpose,
    default_retention_profiles,
    store_namespace_identity,
)
from benchmarks.valid.workflow_journal import S3WorkflowJournal  # noqa: E402
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowStatus,
    decode_workflow_outcome,
    workflow_outcome_bytes,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    LineagePurpose,
    PopulationCustodyPolicy,
    PopulationStatus,
    PopulationUseRequest,
    append_population_use,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
    record_population_use,
)
from openultrasast.core.evaluation_authority import (  # noqa: E402
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionV3  # noqa: E402
from openultrasast.core.evaluation_measurement import (  # noqa: E402
    ArmKindV3,
    CaseOutcomeProjectionPolicyV3,
)
from openultrasast.core.evaluation_observation import (  # noqa: E402
    ArmObservationSetV3,
    ObservationCaseRefV3,
    decode_arm_observation_set,
)
from openultrasast.core.evaluation_plan import (  # noqa: E402
    EcosystemOrdinaryCensusV3,  # noqa: E402
    derive_evaluation_input_set_digest,
)
from openultrasast.core.evidence import NeutralOutcome  # noqa: E402

WORKFLOW = _digest("workflow-8-2")
RETENTION = _digest("observation-retention")
NAMESPACE = _digest("observation-output-namespace")
ORDINARY_PUSHES = 20
UNANIMOUS = CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE
DECLARATIVE = CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE


def _pushes() -> tuple[OrdinaryPushV1, ...]:
    network = _digest("ordinary-network")
    rows = []
    for index in range(ORDINARY_PUSHES):
        draft = OrdinaryPushV1(
            "https://example.invalid/app.git",
            network,
            "python",
            f"{index:040x}",
            f"{index + 1:040x}",
            64,
            _digest(f"ordinary-change-{index}"),
            _digest("ordinary-history"),
            "",
        )
        rows.append(replace(draft, push_digest=canonical.content_digest(_push_value(draft, include_digest=False))))
    return tuple(sorted(rows, key=lambda item: item.push_digest))


def _selection(freeze) -> OrdinarySelectionV1:
    pushes = _pushes()
    network = pushes[0].network_identity_digest
    positives = freeze.positive_change_digests
    assignments = tuple(
        sorted(
            OrdinaryDrawAssignmentV1(positive, network, pushes[0].ecosystem, push.push_digest)
            for positive in positives
            for push in pushes
        )
    )
    fix_exclusions = tuple(
        sorted(
            OrdinaryFixExclusionV1(network, f"{7000 + index:040x}", positive, freeze.ground_truth_review_digests[index])
            for index, positive in enumerate(positives)
        )
    )
    policy = _digest("ordinary-policy")
    provenance = canonical.content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in pushes})
            ),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in fix_exclusions),
            "policy_digest": policy,
        }
    )
    draft = OrdinarySelectionV1(ORDINARY_PUSHES, policy, positives, fix_exclusions, pushes, assignments, (), provenance, "")
    return replace(draft, selection_digest=canonical.content_digest(_selection_value(draft, include_digest=False)))


def _material_manifest(freeze) -> PublicPopulationMaterialManifestV1:
    positives = freeze.positive_change_digests
    public = tuple(
        sorted(
            PublicSourceRecordV1(change, LicenseClass.PERMISSIVE, "MIT", _digest(f"public-{index}"), 128, _digest(f"object-{index}"))
            for index, change in enumerate(positives[:25])
        )
    )
    private = tuple(
        sorted(
            OpaquePrivateMaterialRefV1(change, LicenseClass.NON_PERMISSIVE, _digest(f"private-{index}"), 96)
            for index, change in enumerate(positives[25:])
        )
    )
    draft = PublicPopulationMaterialManifestV1(
        freeze.population_digest,
        freeze.freeze_digest,
        positives,
        public,
        private,
        _digest("private-object"),
        _digest("sealed-labels"),
        ((LicenseClass.NON_PERMISSIVE, len(private)), (LicenseClass.PERMISSIVE, 25)),
        ((_digest("review-excluded"), 1),),
        len(public),
        len(private),
        _digest("partition-policy"),
        "",
    )
    return replace(draft, manifest_digest=canonical.content_digest(_manifest_value(draft, include_digest=False)))


def _reviewed_manifest(freeze, selection, material):
    inputs = tuple(sorted({*freeze.positive_change_digests, *(push.push_digest for push in selection.pushes)}))
    draft = LabelBlindPopulationDraftV3(
        freeze.population_digest,
        freeze.freeze_digest,
        freeze.reservation_census_digest,
        freeze.review_set_digest,
        selection.selection_digest,
        material.manifest_digest,
        _digest("material-artifacts"),
        freeze.scope_census,
        inputs,
        freeze.positive_count,
        len(inputs),
        derive_evaluation_input_set_digest(inputs),
        "",
    )
    draft = replace(draft, draft_digest=canonical.content_digest(_draft_value(draft, include_digest=False)))
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="execution-disclosures")
    review = _attestation(draft.draft_digest, _digest("manifest-producer"), disclosure)
    manifest = review_label_blind_population_manifest(draft, review, _policy(), resolver)
    return manifest, review, disclosure, resolver


def _cases(manifest, selection, material) -> tuple[execution.LabelBlindCaseInputV1, ...]:
    public = {row.change_digest: row for row in material.public_sources}
    private = {row.change_digest: row for row in material.private_refs}
    pushes = {row.push_digest: row for row in selection.pushes}
    rows = []
    for item in manifest.input_digests:
        if item in public:
            source, access, provenance, length = (
                public[item].source_digest,
                ArtifactAccessClass.PUBLIC,
                public[item].object_digest,
                public[item].byte_length,
            )
        elif item in private:
            source, access, provenance, length = (
                private[item].source_digest,
                ArtifactAccessClass.PRIVATE,
                material.private_object_digest,
                private[item].byte_length,
            )
        else:
            push = pushes[item]
            source, access, provenance, length, change = (
                push.change_content_digest,
                ArtifactAccessClass.PRIVATE,
                push.history_source_digest,
                push.change_byte_length,
                push.change_content_digest,
            )
        if item in public or item in private:
            change = item
        rows.append(
            execution.LabelBlindCaseInputV1(
                item,
                change,
                ArtifactReference(ArtifactKind.POPULATION, source, length, provenance, access),
                "",
            )
        )
    return tuple(rows)


def _read_rows(bundle, status=receipt.InputReadStatus.COMPLETED):
    count = bundle.case_inputs[0].code_reference.byte_length
    return tuple(
        receipt.InputReadReceiptV1(
            row.input_identity_digest,
            row.code_reference.byte_length,
            row.code_reference.byte_length if status is receipt.InputReadStatus.COMPLETED else count - 1,
            status,
            "",
        )
        for row in bundle.case_inputs
    )


def _stage_rows(status=receipt.StageExecutionStatus.COMPLETED):
    return tuple(
        receipt.StageExecutionReceiptV1(
            stage,
            status,
            _digest(f"stage-{stage.value}") if status is receipt.StageExecutionStatus.COMPLETED else "",
            "",
        )
        for stage in receipt.RequiredExecutionStage
    )


def _case_ref(bundle, slot):
    policy = UNANIMOUS if bundle.arm.configuration_kind is ArmKindV3.COMPONENT else DECLARATIVE
    projection = CaseOutcomeProjectionV3(
        slot.input_identity_digest, policy, (_digest(f"record-{bundle.arm.arm_id}"),), NeutralOutcome.SATISFIED, ""
    )
    return ObservationCaseRefV3(
        _digest(f"case-{bundle.arm.arm_id}-{slot.input_identity_digest}"),
        slot.input_identity_digest,
        _digest(f"push-{slot.input_identity_digest}"),
        _digest(f"result-{bundle.arm.arm_id}-{slot.input_identity_digest}"),
        projection,
        None,
    )


def _observations(plan, bundle, slots=None):
    rows = (
        tuple(slot for slot in plan.declaration.expected_observation_slots if slot.arm_id == bundle.arm.arm_id)
        if slots is None
        else slots
    )
    reads, stages = _read_rows(bundle), _stage_rows()
    return tuple(
        ArmObservationSetV3(
            slot.slot_digest,
            slot.arm_id,
            slot.input_identity_digest,
            slot.execution_identity,
            bundle.arm.registered_budget_digest,
            bundle.arm.configuration_identity_digest,
            receipt.input_read_evidence_digest(reads),
            receipt.stage_execution_evidence_digest(stages),
            (_case_ref(bundle, slot),),
            "",
        )
        for slot in rows
    )


def _capture(plan):
    def factory(bundle):
        reads, stages = _read_rows(bundle), _stage_rows()
        observations = _observations(plan, bundle)
        output = checkpoint.component_observation_output_bytes(observations)
        outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=9)
        return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), observations)

    return factory


def _cross_arm_factory(plan):
    def factory(bundle):
        other = "arm-shipped" if bundle.arm.arm_id == "arm-experimental" else "arm-experimental"
        slots = tuple(slot for slot in plan.declaration.expected_observation_slots if slot.arm_id == other)
        reads, stages = _read_rows(bundle), _stage_rows()
        observations = _observations(plan, bundle, slots=slots)
        output = checkpoint.component_observation_output_bytes(observations)
        outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=9)
        return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), observations)

    return factory


def _partial_factory(plan):
    def factory(bundle):
        reads = _read_rows(bundle, receipt.InputReadStatus.PARTIAL)
        stages = _stage_rows()
        observations = _observations(plan, bundle)
        output = checkpoint.component_observation_output_bytes(observations)
        outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=9)
        return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), observations)

    return factory


def _boom(bundle):
    raise AssertionError("completed arms must never be rerun under the same plan")


class _Adapter:
    def __init__(self, factory) -> None:
        self.factory = factory
        self.calls: list[object] = []

    def execute(self, bundle):
        self.calls.append(bundle)
        return self.factory(bundle)


def _union_rule():
    from itertools import product

    from openultrasast.core.evaluation_measurement import (
        CombinationDecisionRowV3,
        CombinationOperatorV3,
        CombinationRuleV3,
        ProofCandidatePolicyV3,
    )
    from openultrasast.core.evidence import NeutralOutcome

    def union(outcomes):
        if NeutralOutcome.VIOLATION in outcomes:
            return NeutralOutcome.VIOLATION
        if NeutralOutcome.INDETERMINATE in outcomes:
            return NeutralOutcome.INDETERMINATE
        return NeutralOutcome.SATISFIED

    rows = tuple(
        CombinationDecisionRowV3(outcomes, union(outcomes), "") for outcomes in product(tuple(NeutralOutcome), repeat=2)
    )
    return CombinationRuleV3(
        "arm-combined",
        ("arm-experimental", "arm-shipped"),
        CombinationOperatorV3.DECLARATIVE_TABLE,
        rows,
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


class _ExecCase:
    def __init__(self) -> None:
        self.freeze = _freeze()
        self.selection = _selection(self.freeze)
        self.material = _material_manifest(self.freeze)
        self.manifest, self.manifest_review, self.disclosure, self.resolver = _reviewed_manifest(
            self.freeze, self.selection, self.material
        )
        self.ordinary_census = (EcosystemOrdinaryCensusV3("python", ORDINARY_PUSHES),)
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
                _registration(registry.ArmRole.EXPERIMENTAL, _configuration("arm-experimental", (("injection", "python"),))),
                _registration(registry.ArmRole.SHIPPED, _configuration("arm-shipped", (("injection", "python"),))),
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
            output_namespace_digest=NAMESPACE,
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
            row.configuration
            for row in self.plan.registrations
            if row.configuration.kind is ArmKindV3.COMBINED
        )
        assert combined_configuration.combination_rule is not None
        self.combination_registrations = (
            CombinationRuleRegistrationV1(
                "arm-combined",
                CombinationRuleKindV1.UNION,
                combined_configuration.combination_rule.rule_digest,
                "",
            ),
        )
        self.attempt_subject = initial_attempt_event_payload_digest(self.plan_manifest, self.attempt_status_ref)
        self.attempt_review = _attestation(self.attempt_subject, _digest("attempt-producer"), self.disclosure)
        self.default_factory = _capture(self.plan)

    def run_request(self, **overrides: object) -> AdmissionRunRequestV1:
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
            "review_policy": _policy(),
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

    def execution_request(self, preflight, *, adapter, review=None, selectors=(None, None), run_request=None):
        return AdmissionExecutionRequestV1(
            preflight,
            run_request if run_request is not None else self.run_request(),
            self.selection,
            self.material,
            self.cases,
            self.budgets,
            adapter,
            selectors,
            self.combination_registrations,
            review,
            self.attempt_review,
            self.attempt_status_ref,
            self.durable_identity,
            RETENTION,
            NAMESPACE,
        )


@lru_cache(maxsize=1)
def _case() -> _ExecCase:
    return _ExecCase()


class _Env:
    def __init__(self, case: _ExecCase, *, factory=None, lifecycle_active: bool = True) -> None:
        self.case = case
        self.durable = _Client()
        self.transient = _Client()
        durable_settings = _settings(StorePurpose.DURABLE)
        self.repository = S3ArtifactRepository(durable_settings, self.durable)
        self.custody_policy = PopulationCustodyPolicy(
            (CUSTODIAN,), derive_population_custody_policy_digest((CUSTODIAN,))
        )
        self.custody = S3DurableCustodyStore(
            durable_settings,
            self.durable,
            self.custody_policy,
            case.report,
            case.transient_identity,
            case.transient_profile,
        )
        assert self.custody.initialize(empty_population_custody_log(case.freeze.population_digest, CUSTODIAN))
        self.journal = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), self.transient)
        self.lifecycle_active = lifecycle_active
        self.adapter = _Adapter(factory if factory is not None else case.default_factory)
        self.spy = _SpyExecutor()
        self.orchestrator = AdmissionOrchestrator(
            self.lifecycle(),
            self.repository,
            self.custody,
            self.journal,
            self.spy,
            ACCESS_POLICY,
        )

    def lifecycle(self):
        return _lifecycle(self.case.freeze.population_digest, self.case.freeze.freeze_digest, active=self.lifecycle_active)

    def preflight(self, **overrides):
        return self.orchestrator.preflight(self.case.run_request(**overrides))

    def execute(self, preflight=None, *, review=None, selectors=(None, None), run_request=None):
        resolved = preflight if preflight is not None else self.preflight()
        return execute_planned_observations(
            self.lifecycle(),
            self.repository,
            self.custody,
            self.journal,
            ACCESS_POLICY,
            self.case.execution_request(
                resolved, adapter=self.adapter, review=review, selectors=selectors, run_request=run_request
            ),
        )


@lru_cache(maxsize=1)
def _admission_review(case: _ExecCase) -> object:
    harvest = _Env(case)
    subject = harvest.execute().manifest_subject_digest
    return _attestation(subject, _digest("admission-producer"), case.disclosure)


def _selectors(product):
    return tuple(
        None if row.reference is None else _selector(row.reference, row.checkpoint_digest) for row in product.component_results
    )


def _selector(reference, digest):
    return checkpoint.CheckpointSelectorV1(reference, digest)


def _assert_impaired(environment: _Env, product, reason: AdmissionExecutionReason, *, sealed: bool, spent: bool = False) -> None:
    assert product.refusal_reason is reason
    assert product.admission_manifest is None or sealed
    assert not (product.spend_authorization and product.spend_authorization.may_spend)
    outcome = product.impaired_outcome
    assert outcome is not None
    assert outcome.status is WorkflowStatus.IMPAIRED
    assert outcome.labels_spent is False
    assert decode_workflow_outcome(workflow_outcome_bytes(outcome)) == outcome
    log = environment.custody.current_log(environment.case.freeze.population_digest)
    if spent:
        assert log.status is PopulationStatus.SPENT and log.receipt_count == 1
    else:
        assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0


def _observation_key(ref) -> str:
    return f"observations/custodian_sealed/{ref.observation.content_digest}.json"


def _stored_observation(environment: _Env, ref):
    accepted = validate_artifact(environment.durable.body(_observation_key(ref)))
    return decode_arm_observation_set(accepted.payload["observation"].encode())


def outcome_phase(product) -> str:
    assert product.impaired_outcome is not None
    return product.impaired_outcome.phase.value


def failed_gates(product) -> tuple[str, ...]:
    assert product.impaired_outcome is not None
    return tuple(gate.value for gate in product.impaired_outcome.failed_gate_names)


def test_missing_workflow_head_refuses_before_any_adapter_or_spend_call() -> None:
    case = _case()
    authorized = _Env(case).preflight()

    environment = _Env(case)
    product = environment.execute(preflight=authorized)

    _assert_impaired(environment, product, AdmissionExecutionReason.AUTHORITY_UNRESOLVED, sealed=False)
    assert environment.adapter.calls == []
    assert product.component_results == ()
    assert product.sealed_observations == ()
    assert outcome_phase(product) == "arm_execution"
    assert failed_gates(product) == ("retry_authority",)


def test_substituted_authority_bytes_are_rejected_before_any_adapter_call() -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    authority = authorized.retry_authority
    reference = authorized.retry_authority_reference
    assert authority is not None and reference is not None
    substituted = canonical_artifact_bytes(
        ArtifactKind.WORKFLOW,
        {
            "schema_version": "openultrasast.valid-detection-benchmark.automatic-retry-authority.v1",
            "population_digest": authority.population_digest,
            "freeze_digest": authority.freeze_digest,
            "admission_identity_digest": _digest("other-admission"),
            "plan_digest": authority.plan_digest,
            "ordered_arm_ids": authority.ordered_arm_ids,
            "ordered_bundle_digests": authority.ordered_bundle_digests,
            "ordered_checkpoint_slot_digests": authority.ordered_checkpoint_slot_digests,
            "ordered_input_set_digests": authority.ordered_input_set_digests,
            "ordered_budget_digests": authority.ordered_budget_digests,
            "ordered_environment_digests": authority.ordered_environment_digests,
            "ordered_destination_digests": authority.ordered_destination_digests,
            "authority_digest": authority.authority_digest,
        },
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=_digest("substituted-provenance"),
    )
    environment.durable.put_object(
        Bucket="valid-durable",
        Key=f"workflows/custodian_sealed/{reference.content_digest}.json",
        Body=substituted,
    )

    product = environment.execute(preflight=authorized)

    _assert_impaired(environment, product, AdmissionExecutionReason.AUTHORITY_SUBSTITUTED, sealed=False)
    assert environment.adapter.calls == []


def _initial_entry(case):
    from benchmarks.valid.workflow_journal import WorkflowJournalEntryV1
    from benchmarks.valid.workflow_outcome import WorkflowCounts, WorkflowPhase

    return WorkflowJournalEntryV1(
        WORKFLOW,
        0,
        None,
        "attempt-1",
        "owner-a",
        WorkflowPhase.PREFLIGHT,
        "2026-11-21T09:00:00Z",
        "2026-11-21T09:30:00Z",
        WorkflowCounts(3, 0, len(case.manifest.input_digests), 0, 0),
        "",
    )


def test_orphan_head_selecting_missing_authority_is_rejected() -> None:
    case = _case()
    authorized = _Env(case).preflight()
    environment = _Env(case)

    orphan = ArtifactReference(
        ArtifactKind.WORKFLOW,
        _digest("orphan-authority"),
        32,
        _digest("orphan-provenance"),
        ArtifactAccessClass.CUSTODIAN_SEALED,
    )
    environment.journal.initialize(_initial_entry(case), orphan, orphan.content_digest)

    product = environment.execute(preflight=authorized)

    _assert_impaired(environment, product, AdmissionExecutionReason.AUTHORITY_UNRESOLVED, sealed=False)
    assert environment.adapter.calls == []


def test_malformed_sealed_authority_payload_is_rejected_before_any_adapter_call() -> None:
    case = _case()
    authorized = _Env(case).preflight()
    environment = _Env(case)
    overlong_arm = "a" * 200

    malformed = canonical_artifact_bytes(
        ArtifactKind.WORKFLOW,
        {
            "schema_version": "openultrasast.valid-detection-benchmark.automatic-retry-authority.v1",
            "population_digest": _digest("malformed-population"),
            "freeze_digest": _digest("malformed-freeze"),
            "admission_identity_digest": _digest("malformed-admission"),
            "plan_digest": _digest("malformed-plan"),
            "ordered_arm_ids": (overlong_arm,),
            "ordered_bundle_digests": (_digest("malformed-bundle"),),
            "ordered_checkpoint_slot_digests": (_digest("malformed-slot"),),
            "ordered_input_set_digests": (_digest("malformed-inputs"),),
            "ordered_budget_digests": (_digest("malformed-budget"),),
            "ordered_environment_digests": (_digest("malformed-environment"),),
            "ordered_destination_digests": (_digest("malformed-destination"),),
            "authority_digest": _digest("malformed-authority"),
        },
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=_digest("malformed-provenance"),
    )
    reference = artifact_reference(malformed)
    environment.durable.put_object(
        Bucket="valid-durable",
        Key=f"workflows/custodian_sealed/{reference.content_digest}.json",
        Body=malformed,
    )
    environment.journal.initialize(_initial_entry(case), reference, reference.content_digest)

    product = environment.execute(preflight=authorized)

    _assert_impaired(environment, product, AdmissionExecutionReason.AUTHORITY_SUBSTITUTED, sealed=False)
    assert environment.adapter.calls == []
    assert outcome_phase(product) == "arm_execution"
    assert failed_gates(product) == ("retry_authority",)


def test_mismatched_authority_binding_is_rejected_before_any_adapter_call() -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    changed = tuple(
        replace(row, budget_digest=_digest("changed-budget")) if row.arm_id == "arm-shipped" else row for row in case.bindings
    )

    product = environment.execute(preflight=authorized, run_request=case.run_request(execution_bindings=changed))

    _assert_impaired(environment, product, AdmissionExecutionReason.AUTHORITY_MISMATCHED, sealed=False)
    assert environment.adapter.calls == []


def test_component_arms_receive_the_identical_ordered_label_blind_input_set() -> None:
    case = _case()
    environment = _Env(case)
    product = environment.execute(review=_admission_review(case))

    assert product.refusal_reason is None
    assert [bundle.arm.arm_id for bundle in environment.adapter.calls] == ["arm-experimental", "arm-shipped"]
    first, second = environment.adapter.calls
    assert tuple(row.input_identity_digest for row in first.case_inputs) == case.manifest.input_digests
    assert first.case_inputs == second.case_inputs
    assert first.input_set_digest == second.input_set_digest == case.manifest.input_set_digest
    assert first.bundle_digest != second.bundle_digest


def test_component_observations_are_frozen_custodian_sealed_with_nonzero_receipts() -> None:
    case = _case()
    environment = _Env(case)
    product = environment.execute(review=_admission_review(case))

    assert product.refusal_reason is None
    assert [row.status for row in product.component_results] == [checkpoint.CheckpointStatus.COMPLETE] * 2
    for result, bundle in zip(product.component_results, case.bundles, strict=True):
        assert result.reference is not None
        accepted = validate_artifact(
            environment.durable.body(f"observations/custodian_sealed/{result.reference.content_digest}.json"),
            reference=result.reference,
        )
        assert accepted.access_class is ArtifactAccessClass.CUSTODIAN_SEALED
        assert accepted.payload["execution_receipt"]["receipt_digest"]
        documents = accepted.payload["observations"]
        assert len(documents) == len(case.manifest.input_digests)
        decoded = tuple(decode_arm_observation_set(row.encode()) for row in documents)
        assert all(row.observation_digest and row.cases for row in decoded)
        assert bundle.bundle_digest


def test_exact_checkpoint_reuse_never_reruns_a_completed_arm() -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    first = environment.execute(preflight=authorized, review=_admission_review(case))
    assert first.refusal_reason is None

    environment.adapter = _Adapter(_boom)
    second = environment.execute(preflight=authorized, review=_admission_review(case), selectors=_selectors(first))

    assert second.refusal_reason is None
    assert environment.adapter.calls == []
    assert second.sealed_observations == first.sealed_observations
    assert second.admission_manifest == first.admission_manifest
    assert second.manifest_subject_digest == first.manifest_subject_digest


def test_mismatched_checkpoint_selector_yields_impaired_outcome_without_spend() -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    first = environment.execute(preflight=authorized)
    assert first.refusal_reason is None
    reference = first.component_results[0].reference
    assert reference is not None

    product = environment.execute(preflight=authorized, selectors=(_selector(reference, _digest("wrong-checkpoint")), None))

    _assert_impaired(environment, product, AdmissionExecutionReason.EXECUTION_IMPAIRED, sealed=False)
    assert environment.adapter.calls


def test_cross_arm_observation_yields_impaired_outcome_without_spend() -> None:
    case = _case()
    environment = _Env(case, factory=_cross_arm_factory(case.plan))
    product = environment.execute()

    _assert_impaired(environment, product, AdmissionExecutionReason.EXECUTION_IMPAIRED, sealed=False)
    assert environment.adapter.calls
    assert outcome_phase(product) == "observation_freeze"


def test_partial_input_read_yields_impaired_outcome_without_spend() -> None:
    case = _case()
    environment = _Env(case, factory=_partial_factory(case.plan))
    product = environment.execute()

    _assert_impaired(environment, product, AdmissionExecutionReason.EXECUTION_IMPAIRED, sealed=False)


def test_combined_observations_are_derived_from_registered_rules_and_sealed() -> None:
    case = _case()
    environment = _Env(case)
    product = environment.execute(review=_admission_review(case))

    assert product.refusal_reason is None
    assert product.combined_arm_ids == ("arm-combined",)
    assert product.combination_plan_digest
    combined_refs = [ref for ref in product.sealed_observations if ref.arm_id == "arm-combined"]
    assert len(combined_refs) == len(case.manifest.input_digests)
    registered = register_combination_plan(case.plan, case.combination_registrations)
    for ref in combined_refs:
        stored = _stored_observation(environment, ref)
        components = tuple(
            ComponentObservationV1(_stored_observation(environment, item), (), "")
            for item in product.sealed_observations
            if item.arm_id != "arm-combined" and item.input_identity_digest == ref.input_identity_digest
        )
        expected = combine_observations(registered, "arm-combined", components)
        assert stored == expected.combined_observation


def test_reviewed_admission_manifest_binds_exact_sealed_references_and_authorizes_spend() -> None:
    case = _case()
    environment = _Env(case)
    product = environment.execute(review=_admission_review(case))

    assert product.refusal_reason is None
    assert product.impaired_outcome is None
    manifest = product.admission_manifest
    assert manifest is not None
    assert derive_evaluation_admission_manifest_payload_digest(manifest) == product.manifest_subject_digest
    assert tuple(ref.slot_digest for ref in manifest.observations) == tuple(
        slot.slot_digest for slot in case.plan.declaration.expected_observation_slots
    )
    assert tuple(ref.ref_digest for ref in manifest.observations) == tuple(
        ref.ref_digest for ref in product.sealed_observations
    )
    assert manifest.custody_log_digest == case.custody_log_digest
    assert manifest.attempt_history.head_event_digest
    authorization = product.spend_authorization
    assert authorization is not None and authorization.may_spend is True
    assert authorization.refusal_reasons == ()
    assert authorization.manifest_digest == manifest.manifest_digest
    sealed = [key for key in environment.durable if key.startswith("workflows/custodian_sealed/")]
    schemas = {validate_artifact(environment.durable.body(key)).payload["schema_version"] for key in sealed}
    assert admission_execution.SPEND_AUTHORIZATION_SCHEMA in schemas
    assert admission_execution.ADMISSION_EXECUTION_WITNESS_SCHEMA not in schemas
    log = environment.custody.current_log(case.freeze.population_digest)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0


@pytest.mark.parametrize("mode", ["changed", "unsealed"])
def test_changed_or_unsealed_observation_bytes_prevent_spend(mode: str) -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    first = environment.execute(preflight=authorized, review=_admission_review(case))
    assert first.spend_authorization is not None and first.spend_authorization.may_spend is True
    target = next(ref for ref in first.sealed_observations if ref.arm_id == "arm-combined")
    key = _observation_key(target)
    if mode == "changed":
        payload = dict(validate_artifact(environment.durable.body(key)).payload)
        payload["slot_note"] = "tampered"
        tampered = canonical_artifact_bytes(
            ArtifactKind.OBSERVATION,
            payload,
            access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
            provenance_digest=_digest("tampered"),
        )
        environment.durable.put_object(Bucket="valid-durable", Key=key, Body=tampered)
    else:
        published = environment.durable.body(key)
        environment.durable.put_object(
            Bucket="valid-durable",
            Key=f"observations/public/{target.observation.content_digest}.json",
            Body=published,
        )

    authorization = reauthorize_before_spend(
        environment.lifecycle(),
        environment.repository,
        environment.custody,
        ACCESS_POLICY,
        case.run_request(),
        authorized,
        first.sealed_observations,
        first.admission_manifest,
    )
    reason = (
        AdmissionExecutionReason.OBSERVATION_CHANGED if mode == "changed" else AdmissionExecutionReason.OBSERVATION_UNSEALED
    )
    assert authorization.may_spend is False
    assert reason in authorization.refusal_reasons
    assert environment.custody.current_log(case.freeze.population_digest).status is PopulationStatus.AVAILABLE

    product = environment.execute(preflight=authorized, review=_admission_review(case), selectors=_selectors(first))
    _assert_impaired(environment, product, reason, sealed=True)
    if mode == "unsealed":
        assert outcome_phase(product) == "custody_spend"
        assert failed_gates(product) == ("spend_authority",)
    else:
        assert outcome_phase(product) == "observation_freeze"
        assert failed_gates(product) == ("observation_durability",)


@pytest.mark.parametrize("mode", ["missing", "unreadable"])
def test_missing_or_unreadable_observation_prevents_spend(mode: str) -> None:
    case = _case()
    environment = _Env(case)
    authorized = environment.preflight()
    first = environment.execute(preflight=authorized, review=_admission_review(case))
    refs = list(first.sealed_observations)
    if mode == "missing":
        target = refs[-1]
        replaced = replace(
            target,
            observation=replace(
                target.observation,
                artifact_id="absent-observation",
                content_digest=_digest("absent-content"),
                storage_receipt_digest=_digest("absent-receipt"),
            ),
            ref_digest="",
        )
        replaced.__post_init__()
        refs[-1] = replaced
    else:
        target = refs[0]
        environment.durable = _FailingClient(environment.durable, _observation_key(target))
        environment.repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), environment.durable)

    authorization = reauthorize_before_spend(
        environment.lifecycle(),
        environment.repository,
        environment.custody,
        ACCESS_POLICY,
        case.run_request(),
        authorized,
        tuple(refs),
    )
    reason = AdmissionExecutionReason.OBSERVATION_MISSING if mode == "missing" else AdmissionExecutionReason.OBSERVATION_UNREADABLE
    assert authorization.may_spend is False
    assert reason in authorization.refusal_reasons
    assert environment.custody.current_log(case.freeze.population_digest).status is PopulationStatus.AVAILABLE


class _FailingClient(_Client):
    def __init__(self, inner: _Client, key: str) -> None:
        super().__init__()
        self._inner = inner
        self._key = key

    def put_object(self, **kwargs: object) -> dict[str, object]:
        return self._inner.put_object(**kwargs)

    def get_object(self, **kwargs: object) -> dict[str, object]:
        if str(kwargs.get("Key")) == self._key:
            raise RuntimeError("provider unavailable")
        return self._inner.get_object(**kwargs)

    def __iter__(self):
        return iter(tuple(self._inner))

    def body(self, key: str) -> bytes:
        return self._inner.body(key)


def test_moved_custody_head_changed_lifecycle_and_failed_readiness_prevent_spend() -> None:
    case = _case()

    moved = _Env(case)
    authorized = moved.preflight()
    first = moved.execute(preflight=authorized, review=_admission_review(case))
    prior = moved.custody.current_log(case.freeze.population_digest)
    request = PopulationUseRequest(
        case.freeze.population_digest,
        "arm-combined",
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        None,
        prior.log_digest,
    )
    receipt_row = record_population_use(request, prior, CUSTODIAN, moved.custody_policy)
    assert moved.custody.compare_and_swap(prior.log_digest, append_population_use(prior, receipt_row, moved.custody_policy))
    product = moved.execute(preflight=authorized, review=_admission_review(case), selectors=_selectors(first))
    _assert_impaired(moved, product, AdmissionExecutionReason.CUSTODY_HEAD_MOVED, sealed=True, spent=True)
    assert outcome_phase(product) == "custody_spend"

    retired = _Env(case)
    authorized = retired.preflight()
    first = retired.execute(preflight=authorized, review=_admission_review(case))
    retired.lifecycle_active = False
    product = retired.execute(preflight=authorized, review=_admission_review(case), selectors=_selectors(first))
    _assert_impaired(retired, product, AdmissionExecutionReason.LIFECYCLE_NOT_ADMISSIBLE, sealed=True)

    unready = _Env(case)
    authorized = unready.preflight()
    first = unready.execute(preflight=authorized, review=_admission_review(case))
    profile = default_retention_profiles(current_expiry_days=30, noncurrent_expiry_days=30)[StorePurpose.TRANSIENT]
    product = unready.execute(
        preflight=authorized,
        review=_admission_review(case),
        selectors=_selectors(first),
        run_request=case.run_request(transient_retention_profile=profile),
    )
    _assert_impaired(unready, product, AdmissionExecutionReason.READINESS_FAILED, sealed=True)
