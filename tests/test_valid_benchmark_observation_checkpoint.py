"""Task 6.4 nonzero receipts and exact component-observation checkpoints."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import fields, replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_artifact_repository import (  # noqa: E402
    _authority,
    _Client,
    _repo,
)
from test_valid_benchmark_artifact_repository import (
    _digest as _artifact_digest,
)
from test_valid_benchmark_isolated_executor import _authorities, _bundles, _digest, _plan  # noqa: E402

from benchmarks.valid import artifact_repository as repository  # noqa: E402
from benchmarks.valid import isolated_execution as execution  # noqa: E402
from benchmarks.valid import observation_checkpoint as checkpoint  # noqa: E402
from benchmarks.valid import observation_receipt as receipt  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    artifact_reference,
    canonical_artifact_bytes,
)
from openultrasast.core.evaluation_observation import ArmObservationSetV3  # noqa: E402


def _reads(bundle, status=receipt.InputReadStatus.COMPLETED):
    rows = []
    for item in bundle.case_inputs:
        expected = item.code_reference.byte_length
        count = expected if status is receipt.InputReadStatus.COMPLETED else 0
        if status is receipt.InputReadStatus.PARTIAL:
            count = max(1, expected - 1)
        rows.append(receipt.InputReadReceiptV1(item.input_identity_digest, expected, count, status, ""))
    return tuple(rows)


def _stages(status=receipt.StageExecutionStatus.COMPLETED):
    return tuple(
        receipt.StageExecutionReceiptV1(
            stage,
            status,
            _digest(f"stage-{stage.value}") if status is receipt.StageExecutionStatus.COMPLETED else "",
            "",
        )
        for stage in receipt.RequiredExecutionStage
    )


def _observations(bundle, *, reads=None, stages=None):
    plan = _plan()
    reads = _reads(bundle) if reads is None else reads
    stages = _stages() if stages is None else stages
    configuration = next(row for row in plan.declaration.arm_configurations if row.arm_id == bundle.arm.arm_id)
    slots = tuple(row for row in plan.declaration.expected_observation_slots if row.arm_id == bundle.arm.arm_id)
    return tuple(
        ArmObservationSetV3(
            slot.slot_digest,
            slot.arm_id,
            slot.input_identity_digest,
            slot.execution_identity,
            configuration.registered_budget_digest,
            configuration.configuration_identity_digest,
            receipt.input_read_evidence_digest(reads),
            receipt.stage_execution_evidence_digest(stages),
            (),
            "",
        )
        for slot in slots
    )


def _capture(
    bundle,
    *,
    read_status=receipt.InputReadStatus.COMPLETED,
    stage_status=receipt.StageExecutionStatus.COMPLETED,
    observations=None,
    output=None,
):
    reads = _reads(bundle, read_status)
    stages = _stages(stage_status)
    values = _observations(bundle, reads=reads, stages=stages) if observations is None else observations
    content = checkpoint.component_observation_output_bytes(values) if output is None else output
    outcome = execution.completed_adapter_outcome(bundle, content, runtime_ms=7)
    return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), values)


class _Adapter:
    def __init__(self, factory: Callable = _capture) -> None:
        self.factory = factory
        self.calls = []

    def execute(self, bundle):
        self.calls.append(bundle)
        return self.factory(bundle)


def _custodian():
    return _authority(
        repository.ArtifactActorRole.CUSTODIAN,
        (repository.ArtifactReadPermission.CUSTODIAN_SEALED,),
    )


def _run(bundle, adapter, client, *, selector=None, authority=None):
    manifest, public, selection = _authorities()
    return checkpoint.execute_or_resume_component(
        _plan(),
        bundle,
        adapter,
        _repo(client),
        _custodian() if authority is None else authority,
        _artifact_digest("read-policy"),
        manifest,
        public,
        selection,
        checkpoint=selector,
    )


def _frozen(bundle=None):
    bundle = _bundles()[0] if bundle is None else bundle
    client = _Client()
    adapter = _Adapter()
    result = _run(bundle, adapter, client)
    assert result.status is checkpoint.CheckpointStatus.COMPLETE
    assert result.reference is not None
    return bundle, client, adapter, result


def _completed_receipt(bundle, *, reads=None):
    reads = _reads(bundle) if reads is None else reads
    stages = _stages()
    observations = _observations(bundle, reads=reads, stages=stages)
    output = checkpoint.component_observation_output_bytes(observations)
    outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=7)
    value = receipt.build_execution_receipt(bundle, outcome, reads, stages)
    assert value.status is receipt.ReceiptStatus.COMPLETED
    return value, observations


def _sealed_selector(bundle, value, observations):
    observation_set_digest = checkpoint._validate_observations(_plan(), bundle, value, observations)
    payload, checkpoint_digest = checkpoint._checkpoint_payload(bundle, value, observations, observation_set_digest)
    content = canonical_artifact_bytes(
        ArtifactKind.OBSERVATION,
        payload,
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=checkpoint_digest,
    )
    reference = artifact_reference(content)
    client = _Client()
    _repo(client).put_if_absent(content, reference=reference)
    return client, checkpoint.CheckpointSelectorV1(reference, checkpoint_digest)


def _unchecked_receipt(value, **changes):
    forged = object.__new__(receipt.ExecutionReceiptV1)
    for field in fields(receipt.ExecutionReceiptV1):
        object.__setattr__(forged, field.name, changes.get(field.name, getattr(value, field.name)))
    return forged


def _forged_receipt_value(value):
    document = receipt.execution_receipt_value(value)
    document["outcome_digest"] = _digest("foreign-outcome")
    unsigned = dict(document)
    unsigned.pop("receipt_digest")
    document["receipt_digest"] = execution.canonical.content_digest(unsigned)
    return document


def _completed_outcome_digest(value, **changes):
    outcome = execution.ArmProcessOutcomeV1(
        changes.get("bundle_digest", value.bundle_digest),
        changes.get("arm_id", value.arm_id),
        execution.ProcessOutcomeStatus.COMPLETED,
        execution.ProcessOutcomeReason.NONE,
        changes.get("runtime_ms", value.runtime_ms),
        changes.get("output_digest", value.output_digest),
        changes.get("output_bytes", value.output_bytes),
        "",
    )
    return outcome.outcome_digest


def _checkpoint_identity_from_payload(payload):
    return {
        key: payload[key]
        for key in (
            "schema_version",
            "plan_digest",
            "registration_digest",
            "arm_id",
            "bundle_digest",
            "budget_digest",
            "environment_digest",
            "input_set_digest",
            "output_destination_digest",
            "output_digest",
            "receipt_digest",
            "observation_set_digest",
        )
    }


def test_complete_nonzero_receipt_is_written_and_read_back_as_custodian_sealed() -> None:
    bundle, client, adapter, result = _frozen()
    assert adapter.calls == [bundle]
    assert result.reason is checkpoint.CheckpointReason.NONE
    assert result.reference.artifact_kind is ArtifactKind.OBSERVATION
    assert result.reference.access_class is ArtifactAccessClass.CUSTODIAN_SEALED
    assert result.reference.provenance_digest == result.checkpoint_digest
    assert len(client.put_calls) == 1
    assert len(client.get_calls) >= 1
    accepted = _repo(client).get(
        result.reference,
        expected_kind=ArtifactKind.OBSERVATION,
        authority=_custodian(),
        expected_access_policy_digest=_artifact_digest("read-policy"),
    )
    stored = receipt.execution_receipt_from_value(accepted.artifact.payload["execution_receipt"])
    assert stored.status is receipt.ReceiptStatus.COMPLETED
    assert all(row.bytes_read == row.expected_bytes > 0 for row in stored.input_reads)
    assert all(row.status is receipt.StageExecutionStatus.COMPLETED for row in stored.stage_executions)
    assert stored.runtime_ms == 7
    assert stored.budget_digest == bundle.budget.budget_digest
    assert stored.output_digest and stored.output_bytes > 0


def test_every_planned_component_freezes_separately_and_combined_arm_never_executes() -> None:
    client = _Client()
    adapter = _Adapter()
    results = tuple(_run(bundle, adapter, client) for bundle in _bundles())
    assert tuple(row.arm_id for row in results) == ("arm-experimental", "arm-shipped")
    assert all(row.status is checkpoint.CheckpointStatus.COMPLETE for row in results)
    assert len({row.checkpoint_digest for row in results}) == 2
    assert tuple(row.arm.arm_id for row in adapter.calls) == ("arm-experimental", "arm-shipped")
    assert "arm-combined" not in {row.arm.arm_id for row in adapter.calls}


def test_exact_resume_reuses_completed_checkpoint_without_adapter_call() -> None:
    bundle, client, _, first = _frozen()
    adapter = _Adapter(lambda _: (_ for _ in ()).throw(AssertionError("adapter must not run")))
    selector = checkpoint.CheckpointSelectorV1(first.reference, first.checkpoint_digest)
    resumed = _run(bundle, adapter, client, selector=selector)
    assert resumed == first
    assert adapter.calls == []
    assert len(client.put_calls) == 1


def test_completed_receipt_construction_and_deserialization_reject_foreign_outcome_digest() -> None:
    value, _ = _completed_receipt(_bundles()[0])
    with pytest.raises(receipt.ExecutionReceiptError):
        replace(value, outcome_digest=_digest("foreign-outcome"), receipt_digest="")
    with pytest.raises(receipt.ExecutionReceiptError):
        receipt.execution_receipt_from_value(_forged_receipt_value(value))


def test_exact_resume_refuses_digest_consistent_foreign_outcome_without_adapter_call() -> None:
    bundle, client, _, frozen = _frozen()
    accepted = _repo(client).get(
        frozen.reference,
        expected_kind=ArtifactKind.OBSERVATION,
        authority=_custodian(),
        expected_access_policy_digest=_artifact_digest("read-policy"),
    )
    payload = dict(accepted.artifact.payload)
    payload["execution_receipt"] = _forged_receipt_value(receipt.execution_receipt_from_value(payload["execution_receipt"]))
    payload["receipt_digest"] = payload["execution_receipt"]["receipt_digest"]
    checkpoint_digest = execution.canonical.content_digest(_checkpoint_identity_from_payload(payload))
    payload["checkpoint_digest"] = checkpoint_digest
    content = canonical_artifact_bytes(
        ArtifactKind.OBSERVATION,
        payload,
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=checkpoint_digest,
    )
    reference = artifact_reference(content)
    forged_client = _Client()
    _repo(forged_client).put_if_absent(content, reference=reference)
    adapter = _Adapter()

    resumed = _run(
        bundle,
        adapter,
        forged_client,
        selector=checkpoint.CheckpointSelectorV1(reference, checkpoint_digest),
    )

    assert resumed.status is checkpoint.CheckpointStatus.IMPAIRED
    assert resumed.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


def test_new_freeze_refuses_foreign_outcome_digest_before_persistence(monkeypatch) -> None:
    bundle = _bundles()[0]
    value, _ = _completed_receipt(bundle)
    forged = _unchecked_receipt(value, outcome_digest=_digest("foreign-outcome"), receipt_digest="")
    monkeypatch.setattr(checkpoint, "build_execution_receipt", lambda *args, **kwargs: forged)
    client = _Client()
    adapter = _Adapter()

    result = _run(bundle, adapter, client)

    assert result.status is checkpoint.CheckpointStatus.IMPAIRED
    assert result.reason is checkpoint.CheckpointReason.RECEIPT_MISMATCH
    assert adapter.calls == [bundle]
    assert client.put_calls == []


@pytest.mark.parametrize(
    ("field", "foreign"),
    (
        ("plan_digest", "foreign-plan"),
        ("registration_digest", "foreign-registration"),
        ("bundle_digest", "foreign-bundle"),
        ("arm_id", "foreign-arm"),
        ("input_set_digest", "foreign-input-set"),
        ("budget_digest", "foreign-budget"),
        ("environment_digest", "foreign-environment"),
        ("output_destination_digest", "foreign-output-destination"),
    ),
)
def test_exact_resume_refuses_completed_receipt_from_foreign_execution_identity(field, foreign) -> None:
    bundle = _bundles()[0]
    value, observations = _completed_receipt(bundle)
    changes = {field: _digest(foreign)}
    changes["outcome_digest"] = _completed_outcome_digest(value, **changes)
    changed = replace(value, **changes, receipt_digest="")
    client, selector = _sealed_selector(bundle, changed, observations)
    adapter = _Adapter()

    resumed = _run(bundle, adapter, client, selector=selector)

    assert resumed.status is checkpoint.CheckpointStatus.IMPAIRED
    assert resumed.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("field", "foreign"),
    (
        ("deadline_seconds", 121),
        ("memory_bytes", 512 * 1024 * 1024 + 1),
        ("disk_bytes", 1024 * 1024 * 1024 + 1),
        ("maximum_output_bytes", 4 * 1024 * 1024 + 1),
    ),
)
def test_exact_resume_refuses_completed_receipt_with_changed_budget_value(field, foreign) -> None:
    bundle = _bundles()[0]
    value, observations = _completed_receipt(bundle)
    changed = replace(value, **{field: foreign, "receipt_digest": ""})
    client, selector = _sealed_selector(bundle, changed, observations)
    adapter = _Adapter()

    resumed = _run(bundle, adapter, client, selector=selector)

    assert resumed.status is checkpoint.CheckpointStatus.IMPAIRED
    assert resumed.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


@pytest.mark.parametrize("mutation", ("identity", "expected_bytes", "order", "missing", "extra"))
def test_exact_resume_refuses_completed_receipt_with_changed_input_read_set(mutation: str) -> None:
    bundle = _bundles()[0]
    rows = _reads(bundle)
    if mutation == "identity":
        rows = (replace(rows[0], input_identity_digest=_digest("foreign-read"), read_digest=""), *rows[1:])
    elif mutation == "expected_bytes":
        rows = (replace(rows[0], expected_bytes=rows[0].expected_bytes + 1, bytes_read=rows[0].bytes_read + 1, read_digest=""), *rows[1:])
    elif mutation == "order":
        rows = tuple(reversed(rows))
    elif mutation == "missing":
        rows = rows[:-1]
    else:
        rows = (*rows, receipt.InputReadReceiptV1(_digest("extra-read"), 1, 1, receipt.InputReadStatus.COMPLETED, ""))
    value, observations = _completed_receipt(bundle)
    observations = _observations(bundle, reads=rows, stages=_stages())
    output = checkpoint.component_observation_output_bytes(observations)
    changes = {
        "output_digest": execution.canonical.bytes_digest(output),
        "output_bytes": len(output),
    }
    changed = replace(
        value,
        input_reads=rows,
        input_read_evidence_digest=receipt.input_read_evidence_digest(rows),
        **changes,
        outcome_digest=_completed_outcome_digest(value, **changes),
        receipt_digest="",
    )
    client, selector = _sealed_selector(bundle, changed, observations)
    adapter = _Adapter()

    resumed = _run(bundle, adapter, client, selector=selector)

    assert resumed.status is checkpoint.CheckpointStatus.IMPAIRED
    assert resumed.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("read_status", "stage_status"),
    (
        (receipt.InputReadStatus.SKIPPED, receipt.StageExecutionStatus.COMPLETED),
        (receipt.InputReadStatus.EMPTY, receipt.StageExecutionStatus.COMPLETED),
        (receipt.InputReadStatus.COMPLETED, receipt.StageExecutionStatus.FAILED),
    ),
)
def test_exact_resume_refuses_digest_consistent_checkpoint_with_impaired_nested_receipt(
    read_status,
    stage_status,
) -> None:
    bundle = _bundles()[0]
    reads = _reads(bundle, read_status)
    stages = _stages(stage_status)
    observations = _observations(bundle, reads=reads, stages=stages)
    output = checkpoint.component_observation_output_bytes(observations)
    outcome = execution.completed_adapter_outcome(bundle, output, runtime_ms=7)
    impaired_receipt = receipt.build_execution_receipt(bundle, outcome, reads, stages)
    assert impaired_receipt.status is receipt.ReceiptStatus.IMPAIRED
    observation_set_digest = checkpoint._validate_observations(_plan(), bundle, impaired_receipt, observations)
    payload, checkpoint_digest = checkpoint._checkpoint_payload(
        bundle,
        impaired_receipt,
        observations,
        observation_set_digest,
    )
    content = canonical_artifact_bytes(
        ArtifactKind.OBSERVATION,
        payload,
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=checkpoint_digest,
    )
    reference = artifact_reference(content)
    client = _Client()
    _repo(client).put_if_absent(content, reference=reference)
    adapter = _Adapter()

    resumed = _run(
        bundle,
        adapter,
        client,
        selector=checkpoint.CheckpointSelectorV1(reference, checkpoint_digest),
    )

    assert resumed.status is checkpoint.CheckpointStatus.IMPAIRED
    assert resumed.reason is checkpoint.CheckpointReason.CHECKPOINT_INCOMPLETE
    assert resumed.reference is None
    assert adapter.calls == []


def test_missing_or_digest_mismatched_resume_is_impaired_and_never_reruns() -> None:
    bundle = _bundles()[0]
    _, _, _, existing = _frozen(bundle)
    missing_adapter = _Adapter()
    missing = _run(
        bundle,
        missing_adapter,
        _Client(),
        selector=checkpoint.CheckpointSelectorV1(existing.reference, existing.checkpoint_digest),
    )
    assert missing.reason is checkpoint.CheckpointReason.CHECKPOINT_MISSING
    assert missing_adapter.calls == []

    _, client, _, frozen = _frozen(bundle)
    mismatch_adapter = _Adapter()
    mismatch = _run(
        bundle,
        mismatch_adapter,
        client,
        selector=checkpoint.CheckpointSelectorV1(frozen.reference, _digest("other-checkpoint")),
    )
    assert mismatch.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert mismatch_adapter.calls == []


@pytest.mark.parametrize("changed", ("budget", "environment", "output"))
def test_changed_execution_identity_cannot_resume_old_checkpoint(changed: str) -> None:
    bundle, client, _, frozen = _frozen()
    if changed == "budget":
        budget = replace(bundle.budget, deadline_seconds=bundle.budget.deadline_seconds + 1, budget_digest="")
        current = replace(bundle, budget=budget, bundle_digest="")
    elif changed == "environment":
        environment = execution.build_execution_environment(execution.ExecutionAdapterKind.DOCKER)
        current = replace(bundle, environment=environment, bundle_digest="")
    else:
        destination = replace(bundle.output_destination, namespace_digest=_digest("changed-output"), destination_digest="")
        current = replace(bundle, output_destination=destination, bundle_digest="")
    adapter = _Adapter()
    result = _run(
        current,
        adapter,
        client,
        selector=checkpoint.CheckpointSelectorV1(frozen.reference, frozen.checkpoint_digest),
    )
    assert result.status is checkpoint.CheckpointStatus.IMPAIRED
    assert result.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


@pytest.mark.parametrize("status", tuple(receipt.InputReadStatus)[1:])
def test_unreadable_empty_skipped_or_partial_input_never_freezes_clean(status) -> None:
    result = _run(_bundles()[0], _Adapter(lambda bundle: _capture(bundle, read_status=status)), _Client())
    assert result.status is checkpoint.CheckpointStatus.IMPAIRED
    assert result.reason is checkpoint.CheckpointReason.RECEIPT_IMPAIRED
    assert result.reference is None


@pytest.mark.parametrize("status", tuple(receipt.StageExecutionStatus)[1:])
def test_skipped_failed_or_premature_required_stage_never_freezes_clean(status) -> None:
    result = _run(_bundles()[0], _Adapter(lambda bundle: _capture(bundle, stage_status=status)), _Client())
    assert result.status is checkpoint.CheckpointStatus.IMPAIRED
    assert result.reason is checkpoint.CheckpointReason.RECEIPT_IMPAIRED


def test_missing_partial_cross_arm_or_changed_output_observations_are_impaired() -> None:
    first, second = _bundles()
    mutations = (
        lambda bundle: _capture(bundle, observations=_observations(bundle)[:-1]),
        lambda bundle: _capture(bundle, observations=_observations(second)),
        lambda bundle: _capture(bundle, output=b"different-output"),
    )
    for mutation in mutations:
        result = _run(first, _Adapter(mutation), _Client())
        assert result.status is checkpoint.CheckpointStatus.IMPAIRED
        assert result.reason is checkpoint.CheckpointReason.OBSERVATION_INVALID


def test_zero_output_and_process_impairment_never_create_checkpoint() -> None:
    def impaired(bundle):
        reads = _reads(bundle)
        stages = _stages()
        outcome = execution.impaired_adapter_outcome(bundle, execution.ProcessOutcomeReason.PROCESS_FAILURE, runtime_ms=1)
        return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, (), _observations(bundle))

    client = _Client()
    result = _run(_bundles()[0], _Adapter(impaired), client)
    assert result.reason is checkpoint.CheckpointReason.RECEIPT_IMPAIRED
    assert client.put_calls == []


def test_new_freeze_revalidates_completed_receipt_against_current_bundle(monkeypatch) -> None:
    bundle = _bundles()[0]
    foreign, _ = _completed_receipt(bundle)
    foreign = replace(foreign, environment_digest=_digest("foreign-environment"), receipt_digest="")
    monkeypatch.setattr(checkpoint, "build_execution_receipt", lambda *args, **kwargs: foreign)
    client = _Client()
    adapter = _Adapter()

    result = _run(bundle, adapter, client)

    assert result.status is checkpoint.CheckpointStatus.IMPAIRED
    assert result.reason is checkpoint.CheckpointReason.RECEIPT_MISMATCH
    assert adapter.calls == [bundle]
    assert client.put_calls == []


def test_repository_write_readback_and_unauthorized_read_are_closed() -> None:
    unauthorized = _authority(repository.ArtifactActorRole.DETECTOR)
    client = _Client()
    result = _run(_bundles()[0], _Adapter(), client, authority=unauthorized)
    assert result.reason is checkpoint.CheckpointReason.ARTIFACT_READBACK_FAILED
    assert result.reference is None
    assert len(client.put_calls) == 1


def test_provider_exception_is_redacted_and_has_no_exception_chain() -> None:
    class Exploding:
        def execute(self, bundle):
            raise RuntimeError("private-canary password=/restricted/repository")

    result = _run(_bundles()[0], Exploding(), _Client())
    assert result.reason is checkpoint.CheckpointReason.ADAPTER_FAILURE
    assert "private" not in str(result)
    assert "restricted" not in str(result)


def test_receipt_and_checkpoint_direct_construction_bypasses_are_rejected() -> None:
    bundle = _bundles()[0]
    capture = _capture(bundle)
    value = receipt.build_execution_receipt(bundle, capture.process_outcome, capture.input_reads, capture.stage_executions)
    with pytest.raises(receipt.ExecutionReceiptError):
        replace(value, status=receipt.ReceiptStatus.COMPLETED, reason=receipt.ReceiptReason.INPUT_EMPTY, receipt_digest="")
    serialized = receipt.execution_receipt_value(value)
    serialized["unexpected"] = "bypass"
    with pytest.raises(receipt.ExecutionReceiptError):
        receipt.execution_receipt_from_value(serialized)
    with pytest.raises(checkpoint.ObservationCheckpointError):
        checkpoint.ArmCheckpointResultV1(
            checkpoint.CheckpointStatus.COMPLETE,
            checkpoint.CheckpointReason.NONE,
            bundle.plan_digest,
            bundle.arm.arm_id,
            _digest("checkpoint"),
            None,
            "",
        )


def test_serialized_checkpoint_extra_field_is_impaired_without_adapter_call() -> None:
    bundle, client, _, frozen = _frozen()
    accepted = _repo(client).get(
        frozen.reference,
        expected_kind=ArtifactKind.OBSERVATION,
        authority=_custodian(),
        expected_access_policy_digest=_artifact_digest("read-policy"),
    )
    payload = dict(accepted.artifact.payload)
    payload["unexpected"] = "bypass"
    content = canonical_artifact_bytes(
        ArtifactKind.OBSERVATION,
        payload,
        access_class=ArtifactAccessClass.CUSTODIAN_SEALED,
        provenance_digest=frozen.checkpoint_digest,
    )
    changed_reference = artifact_reference(content)
    changed_client = _Client()
    _repo(changed_client).put_if_absent(content, reference=changed_reference)
    adapter = _Adapter()

    result = _run(
        bundle,
        adapter,
        changed_client,
        selector=checkpoint.CheckpointSelectorV1(changed_reference, frozen.checkpoint_digest),
    )
    assert result.reason is checkpoint.CheckpointReason.CHECKPOINT_MISMATCH
    assert adapter.calls == []


def test_serialization_surfaces_are_closed_and_contain_no_labels_paths_or_secrets() -> None:
    bundle, client, _, frozen = _frozen()
    accepted = _repo(client).get(
        frozen.reference,
        expected_kind=ArtifactKind.OBSERVATION,
        authority=_custodian(),
        expected_access_policy_digest=_artifact_digest("read-policy"),
    )
    content = accepted.content.lower()
    for forbidden in (b"label", b"expected_outcome", b"password", b"secret", b"/home/", b"repository content"):
        assert forbidden not in content
    assert {field.name for field in fields(checkpoint.ArmCheckpointResultV1)} == {
        "status",
        "reason",
        "plan_digest",
        "arm_id",
        "checkpoint_digest",
        "reference",
        "result_digest",
    }
    assert bundle.arm.arm_id.encode() in content
