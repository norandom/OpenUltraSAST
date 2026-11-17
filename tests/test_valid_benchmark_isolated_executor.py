"""Task 6.3 isolated label-blind execution boundary tests."""

from __future__ import annotations

import json
import sys
from dataclasses import fields, replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_arm_registry import _digest, _registrations
from test_valid_benchmark_label_blind_manifest import _reviewed

from benchmarks.valid import arm_contract as registry
from benchmarks.valid import isolated_execution as execution
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
)
from openultrasast.core.evaluation_measurement import ArmKindV3
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest


def _plan(manifest=None) -> registry.RegisteredEvaluationPlanV1:
    manifest = _reviewed()[-1] if manifest is None else manifest
    return registry.register_evaluation_plan(
        registrations=_registrations(),
        population_digest=manifest.population_digest,
        freeze_digest=manifest.freeze_digest,
        input_set_digest=derive_evaluation_input_set_digest(manifest.input_digests),
        input_identity_digests=manifest.input_digests,
    )


def _case(
    input_digest: str,
    *,
    change_digest: str | None = None,
    reference_digest: str | None = None,
    byte_length: int = 128,
    provenance_digest: str | None = None,
    access: ArtifactAccessClass = ArtifactAccessClass.PUBLIC,
) -> execution.LabelBlindCaseInputV1:
    change = input_digest if change_digest is None else change_digest
    reference = ArtifactReference(
        ArtifactKind.POPULATION,
        reference_digest or change,
        byte_length,
        provenance_digest or _digest(f"provenance-{input_digest}"),
        access,
    )
    return execution.LabelBlindCaseInputV1(input_digest, change, reference, "")


def _cases(manifest=None) -> tuple[execution.LabelBlindCaseInputV1, ...]:
    _, selection, partition, *_, reviewed = _reviewed()
    manifest = reviewed if manifest is None else manifest
    pushes = {row.push_digest: row for row in selection.pushes}
    public = {row.change_digest: row for row in partition.manifest.public_sources}
    private = {row.change_digest: row for row in partition.manifest.private_refs}
    return tuple(
        _case(
            item,
            change_digest=pushes[item].change_content_digest,
            byte_length=pushes[item].change_byte_length,
            provenance_digest=pushes[item].history_source_digest,
            access=ArtifactAccessClass.PRIVATE,
        )
        if item in pushes
        else _case(
            item,
            reference_digest=(public[item].source_digest if item in public else private[item].source_digest),
            byte_length=(public[item].byte_length if item in public else private[item].byte_length),
            provenance_digest=(public[item].object_digest if item in public else partition.manifest.private_object_digest),
            access=(ArtifactAccessClass.PUBLIC if item in public else ArtifactAccessClass.PRIVATE),
        )
        for item in manifest.input_digests
    )


def _budgets(plan: registry.RegisteredEvaluationPlanV1) -> tuple[execution.ArmExecutionBudgetV1, ...]:
    return tuple(
        execution.ArmExecutionBudgetV1(
            row.arm_id,
            row.configuration.registered_budget_digest,
            120,
            512 * 1024 * 1024,
            1024 * 1024 * 1024,
            4 * 1024 * 1024,
            "",
        )
        for row in plan.registrations
        if row.configuration.kind is ArmKindV3.COMPONENT
    )


def _bundles(
    *,
    adapter_kind: execution.ExecutionAdapterKind = execution.ExecutionAdapterKind.LOCAL,
) -> tuple[execution.LabelBlindExecutionBundleV1, ...]:
    _, selection, partition, *_, manifest = _reviewed()
    plan = _plan(manifest)
    return execution.build_component_execution_bundles(
        plan,
        manifest,
        selection,
        partition.manifest,
        _cases(manifest),
        _budgets(plan),
        adapter_kind=adapter_kind,
        output_namespace_digest=_digest("observation-output-namespace"),
    )


def _authorities():
    _, selection, partition, *_, manifest = _reviewed()
    return manifest, partition.manifest, selection


def test_component_bundles_share_exact_ordered_label_blind_inputs() -> None:
    bundles = _bundles()

    assert tuple(row.arm.arm_id for row in bundles) == ("arm-experimental", "arm-shipped")
    assert all(row.case_inputs is bundles[0].case_inputs for row in bundles)
    assert tuple(item.input_identity_digest for item in bundles[0].case_inputs) == _reviewed()[-1].input_digests
    assert all(row.input_set_digest == _reviewed()[-1].input_set_digest for row in bundles)
    assert all(row.arm.role is not registry.ArmRole.COMBINED for row in bundles)
    assert all(row.arm.configuration_kind is ArmKindV3.COMPONENT for row in bundles)


def test_bundle_has_no_label_custody_review_or_secret_surface() -> None:
    bundles = _bundles(adapter_kind=execution.ExecutionAdapterKind.AX)
    plan = _plan()
    forbidden_fields = {
        "label",
        "labels",
        "expected_outcome",
        "finding",
        "custody",
        "review",
        "strategy_decision_authority",
        "credentials",
        "secret",
        "endpoint",
        "path",
    }
    for bundle in bundles:
        content = execution.label_blind_execution_bundle_bytes(plan, bundle, *_authorities())
        decoded = json.loads(content)
        assert forbidden_fields.isdisjoint(decoded)
        assert not any(name in forbidden_fields for name in (field.name for field in fields(bundle)))
        for sentinel in (
            b"sealed label",
            b"expected_outcome",
            b"password=",
            b"api_key",
            b"strategy_decision",
            b"/home/",
            b"s3://",
        ):
            assert sentinel not in content.lower()


@pytest.mark.parametrize("access", (ArtifactAccessClass.CUSTODIAN_SEALED, ArtifactAccessClass.OPERATOR_SAFE))
def test_sealed_or_operator_references_cannot_enter_case_inputs(access: ArtifactAccessClass) -> None:
    with pytest.raises(execution.IsolatedExecutionError):
        _case(_reviewed()[-1].input_digests[0], access=access)


@pytest.mark.parametrize(
    "mutation",
    ("missing", "extra", "duplicate", "order", "zero", "wrong_input", "wrong_change", "wrong_provenance"),
)
def test_bundle_builder_rejects_incomplete_or_changed_input_set(mutation: str) -> None:
    manifest = _reviewed()[-1]
    selection = _reviewed()[1]
    partition = _reviewed()[2]
    plan = _plan(manifest)
    cases = _cases(manifest)
    with pytest.raises((execution.IsolatedExecutionError, ValueError)):
        if mutation == "missing":
            cases = cases[:-1]
        elif mutation == "extra":
            cases = (*cases, _case(_digest("extra-input")))
        elif mutation == "duplicate":
            cases = (*cases[:-1], cases[0])
        elif mutation == "order":
            cases = tuple(reversed(cases))
        elif mutation == "zero":
            reference = replace(cases[0].code_reference, byte_length=0)
            cases = (replace(cases[0], code_reference=reference, case_digest=""), *cases[1:])
        elif mutation == "wrong_input":
            cases = (replace(cases[0], input_identity_digest=_digest("wrong-input"), case_digest=""), *cases[1:])
        elif mutation == "wrong_change":
            changed = _digest("wrong-change")
            reference = replace(cases[0].code_reference, content_digest=changed)
            cases = (replace(cases[0], change_input_digest=changed, code_reference=reference, case_digest=""), *cases[1:])
        else:
            reference = replace(cases[0].code_reference, provenance_digest=_digest("wrong-provenance"))
            cases = (replace(cases[0], code_reference=reference, case_digest=""), *cases[1:])
        execution.build_component_execution_bundles(
            plan,
            manifest,
            selection,
            partition.manifest,
            cases,
            _budgets(plan),
            adapter_kind=execution.ExecutionAdapterKind.LOCAL,
            output_namespace_digest=_digest("output"),
        )


def test_environment_is_fixed_and_does_not_inherit_ambient_or_aliases() -> None:
    tainted = {
        "PATH": "/attacker/bin",
        "OPENAI_API_KEY": "model-secret",
        "openai_api_key": "alias-secret",
        "AWS_SECRET_ACCESS_KEY": "store-secret",
        "CORPUS_S3_SECRET_KEY": "admin-secret",
        "LABEL_BYTES": "private-label",
        "REVIEW_TOKEN": "review-secret",
        "OUSAST_CUSTODY_TOKEN": "custody-secret",
    }
    environment = execution.build_execution_environment(execution.ExecutionAdapterKind.DOCKER, tainted)

    assert dict(environment.variables) == execution.SAFE_EXECUTION_ENVIRONMENT
    assert not (set(tainted) - {"PATH"}).intersection(dict(environment.variables))
    assert dict(environment.variables)["PATH"] != tainted["PATH"]
    content = execution.execution_environment_bytes(environment)
    assert all(value.encode() not in content for value in tainted.values())


def test_environment_contract_rejects_direct_allowlist_bypass() -> None:
    with pytest.raises(execution.IsolatedExecutionError):
        execution.ExecutionEnvironmentV1(
            execution.ExecutionAdapterKind.LOCAL,
            (("MODEL_PROVIDER_TOKEN", "private-canary"),),
            "",
        )


@pytest.mark.parametrize("field_name", ("deadline_seconds", "memory_bytes", "disk_bytes", "maximum_output_bytes"))
def test_budget_is_positive_bounded_and_bound_to_registered_arm(field_name: str) -> None:
    plan = _plan()
    selection = _reviewed()[1]
    partition = _reviewed()[2]
    budget = _budgets(plan)[0]
    with pytest.raises(execution.IsolatedExecutionError):
        replace(budget, **{field_name: 0}, budget_digest="")
    wrong = replace(budget, registered_budget_digest=_digest("wrong-budget"), budget_digest="")
    with pytest.raises(execution.IsolatedExecutionError):
        execution.build_component_execution_bundles(
            plan,
            _reviewed()[-1],
            selection,
            partition.manifest,
            _cases(),
            (wrong, *_budgets(plan)[1:]),
            adapter_kind=execution.ExecutionAdapterKind.LOCAL,
            output_namespace_digest=_digest("output"),
        )


class _Adapter:
    def __init__(self, *, reason: execution.ProcessOutcomeReason = execution.ProcessOutcomeReason.NONE) -> None:
        self.reason = reason
        self.calls: list[execution.LabelBlindExecutionBundleV1] = []

    def execute(self, bundle: execution.LabelBlindExecutionBundleV1) -> execution.ArmProcessOutcomeV1:
        self.calls.append(bundle)
        if self.reason is not execution.ProcessOutcomeReason.NONE:
            return execution.impaired_adapter_outcome(bundle, self.reason, runtime_ms=3)
        return execution.completed_adapter_outcome(bundle, b"detector-output", runtime_ms=7)


def test_adapter_runs_once_per_component_and_never_for_combined_arm() -> None:
    bundles = _bundles()
    adapter = _Adapter()

    outcomes = execution.execute_component_bundles(_plan(), bundles, adapter, *_authorities())

    assert tuple(row.arm_id for row in outcomes) == ("arm-experimental", "arm-shipped")
    assert adapter.calls == list(bundles)
    assert all(row.status is execution.ProcessOutcomeStatus.COMPLETED for row in outcomes)


@pytest.mark.parametrize(
    "reason",
    (
        execution.ProcessOutcomeReason.BACKPRESSURE,
        execution.ProcessOutcomeReason.DEADLINE,
        execution.ProcessOutcomeReason.BUDGET_EXHAUSTED,
        execution.ProcessOutcomeReason.RESOURCE_LIMIT,
        execution.ProcessOutcomeReason.PROCESS_FAILURE,
    ),
)
def test_adapter_impairment_is_closed_and_does_not_attribute_infrastructure(reason: execution.ProcessOutcomeReason) -> None:
    adapter = _Adapter(reason=reason)
    plan = _plan()
    bundles = _bundles(adapter_kind=execution.ExecutionAdapterKind.AX)
    outcomes = execution.execute_component_bundles(plan, bundles, adapter, *_authorities())
    content = b"".join(
        execution.arm_process_outcome_bytes(plan, bundle, row, *_authorities()) for bundle, row in zip(bundles, outcomes, strict=True)
    )

    assert all(row.status is execution.ProcessOutcomeStatus.IMPAIRED and row.reason is reason for row in outcomes)
    for forbidden in (b"cluster", b"worker", b"network", b"node", b"k3s", b"exception"):
        assert forbidden not in content.lower()


class _FailingAdapter:
    def execute(self, bundle: execution.LabelBlindExecutionBundleV1) -> execution.ArmProcessOutcomeV1:
        raise RuntimeError("provider-diagnostic private-canary /restricted/location")


def test_adapter_exception_becomes_closed_outcome_without_diagnostic_retention() -> None:
    plan = _plan()
    bundles = _bundles()
    outcomes = execution.execute_component_bundles(plan, bundles, _FailingAdapter(), *_authorities())
    content = b"".join(
        execution.arm_process_outcome_bytes(plan, bundle, row, *_authorities()) for bundle, row in zip(bundles, outcomes, strict=True)
    )

    assert all(row.reason is execution.ProcessOutcomeReason.PROCESS_FAILURE for row in outcomes)
    assert b"provider" not in content and b"private" not in content


class _CrossArmAdapter:
    def execute(self, bundle: execution.LabelBlindExecutionBundleV1) -> execution.ArmProcessOutcomeV1:
        outcome = execution.completed_adapter_outcome(bundle, b"detector-output", runtime_ms=1)
        return replace(outcome, arm_id="different-arm", outcome_digest="")


def test_adapter_cannot_return_an_outcome_for_a_different_arm() -> None:
    outcomes = execution.execute_component_bundles(
        _plan(),
        _bundles(),
        _CrossArmAdapter(),
        *_authorities(),
    )

    assert all(row.reason is execution.ProcessOutcomeReason.OUTPUT_INVALID for row in outcomes)


def test_direct_bundle_and_outcome_mutation_is_rejected_by_serialization() -> None:
    bundle = _bundles()[0]
    plan = _plan()
    with pytest.raises(execution.IsolatedExecutionError):
        execution.label_blind_execution_bundle_bytes(
            plan,
            replace(bundle, plan_digest=_digest("wrong-plan"), bundle_digest=""),
            *_authorities(),
        )
    outcome = execution.completed_adapter_outcome(bundle, b"output", runtime_ms=1)
    with pytest.raises(execution.IsolatedExecutionError):
        execution.arm_process_outcome_bytes(
            plan,
            bundle,
            replace(outcome, output_bytes=0, outcome_digest=""),
            *_authorities(),
        )


def test_execution_boundary_has_no_label_or_custody_hook() -> None:
    public = {name for name in execution.__all__ if not name.startswith("_")}
    assert not any(token in name.lower() for name in public for token in ("label_loader", "custody", "review", "credential"))
