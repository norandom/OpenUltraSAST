"""Authority regressions for the Task 6.3 isolated executor."""

from __future__ import annotations

import inspect
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_arm_registry import _digest, _registrations
from test_valid_benchmark_isolated_executor import _authorities, _budgets, _bundles, _cases, _plan
from test_valid_benchmark_label_blind_manifest import _reviewed

from benchmarks.valid import arm_contract as registry
from benchmarks.valid import isolated_execution as execution
from benchmarks.valid import isolated_execution_bundle as execution_bundle
from benchmarks.valid import isolated_execution_source as execution_source
from benchmarks.valid import ordinary_change_contract as ordinary_contract
from benchmarks.valid import population_material_contract as material_contract
from benchmarks.valid import population_materials as materials
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
)
from openultrasast.core import canonical


def test_bundle_serialization_rejects_canonical_arm_substitution_under_original_plan() -> None:
    bundle = _bundles()[0]
    attacker_arm = replace(bundle.arm, analyzer_identity="attacker-analyzer", execution_arm_digest="")

    with pytest.raises(execution.IsolatedExecutionError):
        attacker_bundle = replace(bundle, arm=attacker_arm, bundle_digest="")
        execution.label_blind_execution_bundle_bytes(_plan(), attacker_bundle, *_authorities())


def test_real_ordinary_push_keeps_distinct_case_and_change_identities() -> None:
    _, selection, *_ = _reviewed()
    push = selection.pushes[0]
    assert push.push_digest != push.change_content_digest
    reference = ArtifactReference(
        ArtifactKind.POPULATION,
        push.change_content_digest,
        push.change_byte_length,
        push.history_source_digest,
        ArtifactAccessClass.PRIVATE,
    )

    case = execution.LabelBlindCaseInputV1(push.push_digest, push.change_content_digest, reference, "")

    assert case.input_identity_digest == push.push_digest
    assert case.change_input_digest == push.change_content_digest


def test_controller_serializer_requires_exact_registered_plan_authority() -> None:
    parameters = inspect.signature(execution.label_blind_execution_bundle_bytes).parameters

    assert {
        "plan",
        "manifest",
        "public_material_manifest",
        "selection",
    } <= parameters.keys()


def test_controller_rejects_bundle_derived_from_different_valid_analyzer_plan() -> None:
    _, selection, partition, *_, manifest = _reviewed()
    original = _plan(manifest)
    registrations = list(_registrations())
    target_index = next(index for index, row in enumerate(registrations) if row.arm_id == "arm-experimental")
    target = registrations[target_index]
    changed_configuration = replace(
        target.configuration,
        analyzer_identity="attacker-analyzer",
        configuration_identity_digest="",
    )
    registrations[target_index] = replace(target, configuration=changed_configuration, registration_digest="")
    forged = registry.register_evaluation_plan(
        registrations=tuple(registrations),
        population_digest=manifest.population_digest,
        freeze_digest=manifest.freeze_digest,
        input_set_digest=manifest.input_set_digest,
        input_identity_digests=manifest.input_digests,
    )
    forged_bundle = execution.build_component_execution_bundles(
        forged,
        manifest,
        selection,
        partition.manifest,
        _cases(manifest),
        _budgets(forged),
        adapter_kind=execution.ExecutionAdapterKind.LOCAL,
        output_namespace_digest=_digest("output"),
    )[0]

    with pytest.raises(execution.IsolatedExecutionError):
        execution.label_blind_execution_bundle_bytes(
            original,
            forged_bundle,
            manifest,
            partition.manifest,
            selection,
        )


@pytest.mark.parametrize("mutation", ("stale", "missing", "extra"))
def test_controller_rejects_rehashed_projection_with_changed_baseline_vector(mutation: str) -> None:
    bundle = _bundles()[0]
    projection = bundle.plan_projection
    if mutation == "missing":
        baselines = projection.baseline_digests[:-1]
    elif mutation == "extra":
        baselines = (*projection.baseline_digests, _digest("extra-baseline"))
    else:
        baselines = (_digest("stale-baseline"), *projection.baseline_digests[1:])
    plan_value = {
        "schema_version": registry.REGISTERED_PLAN_SCHEMA,
        "registration_digests": tuple(row.registration_digest for row in projection.arm_bindings),
        "declaration_digest": projection.declaration_digest,
        "baseline_digests": baselines,
    }
    changed_projection = replace(
        projection,
        baseline_digests=baselines,
        plan_digest=canonical.content_digest(plan_value),
        projection_digest="",
    )
    destination = replace(
        bundle.output_destination,
        plan_digest=changed_projection.plan_digest,
        destination_digest="",
    )
    changed_bundle = replace(
        bundle,
        plan_projection=changed_projection,
        plan_digest=changed_projection.plan_digest,
        output_destination=destination,
        bundle_digest="",
    )

    with pytest.raises(execution.IsolatedExecutionError):
        execution.label_blind_execution_bundle_bytes(_plan(), changed_bundle, *_authorities())


@pytest.mark.parametrize("mutation", ("source", "length", "provenance", "access", "swapped"))
def test_positive_reference_cannot_detach_from_material_authority(mutation: str) -> None:
    _, selection, partition, *_, manifest = _reviewed()
    plan = _plan(manifest)
    cases = _cases(manifest)
    positives = tuple(index for index, case in enumerate(cases) if case.input_identity_digest in selection.positive_change_digests)
    positive = positives[0]
    reference = cases[positive].code_reference
    if mutation == "source":
        changed_reference = replace(reference, content_digest=_digest("wrong-source"))
    elif mutation == "length":
        changed_reference = replace(reference, byte_length=1)
    elif mutation == "provenance":
        changed_reference = replace(reference, provenance_digest=_digest("wrong-source-provenance"))
    elif mutation == "access":
        changed_reference = replace(reference, access_class=ArtifactAccessClass.PRIVATE)
    else:
        changed_reference = cases[positives[1]].code_reference
    changed_case = replace(cases[positive], code_reference=changed_reference, case_digest="")
    changed_cases = (*cases[:positive], changed_case, *cases[positive + 1 :])

    with pytest.raises(execution.IsolatedExecutionError):
        execution.build_component_execution_bundles(
            plan,
            manifest,
            selection,
            partition.manifest,
            changed_cases,
            _budgets(plan),
            adapter_kind=execution.ExecutionAdapterKind.LOCAL,
            output_namespace_digest=_digest("output"),
        )


def test_execution_source_projection_and_bundles_never_open_sealed_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, selection, partition, *_, manifest = _reviewed()
    sealed_byte_count = sum(len(row.label_content) + len(row.judgment_content) for row in partition.sealed_label_records)
    assert sealed_byte_count > 0
    plan = _plan(manifest)
    cases = _cases(manifest)
    budgets = _budgets(plan)
    calls: list[str] = []

    def fail_if_called(name: str):
        def fail(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"forbidden sealed-material hook called: {name}")

        return fail

    for module, name in (
        (material_contract, "sealed_label_object_bytes"),
        (material_contract, "_label_record_value"),
        (materials, "sealed_label_object_bytes"),
        (materials, "material_artifact_bytes"),
        (materials, "resolve_sealed_labels"),
    ):
        monkeypatch.setattr(module, name, fail_if_called(name))

    projection = execution.build_execution_source_projection(
        manifest,
        partition.manifest,
        selection,
    )
    bundles = execution.build_component_execution_bundles(
        plan,
        manifest,
        selection,
        partition.manifest,
        cases,
        budgets,
        adapter_kind=execution.ExecutionAdapterKind.LOCAL,
        output_namespace_digest=_digest("zero-access-output"),
    )

    assert len(bundles) == 2
    assert all(bundle.source_projection == projection for bundle in bundles)
    assert calls == []


def test_execution_bundle_import_and_signature_exclude_full_material_authority() -> None:
    parameters = inspect.signature(execution.build_component_execution_bundles).parameters
    source = inspect.getsource(execution_bundle)

    assert "public_material_manifest" in parameters
    assert "material_partition" not in parameters
    for forbidden in (
        "PopulationMaterialPartitionV1",
        "PrivateSourceRecordV1",
        "SealedLabelRecordV1",
        "IndependenceAttestation",
    ):
        assert forbidden not in source


@pytest.mark.parametrize("mutation", ("public_manifest", "artifact_set", "input_set"))
def test_execution_source_authority_identity_mutation_is_rejected(mutation: str) -> None:
    _, selection, partition, *_, manifest = _reviewed()
    if mutation == "public_manifest":
        changed_public_manifest = replace(
            partition.manifest,
            manifest_digest=_digest("wrong-public-manifest"),
        )
        with pytest.raises(execution.IsolatedExecutionError):
            execution.build_execution_source_projection(
                manifest,
                changed_public_manifest,
                selection,
            )
        return

    bundle = _bundles()[0]
    with pytest.raises(execution.IsolatedExecutionError):
        changed_projection = replace(
            bundle.source_projection,
            **{"material_artifact_set_digest" if mutation == "artifact_set" else "input_set_digest": _digest(f"wrong-{mutation}")},
        )
        execution.label_blind_execution_bundle_bytes(
            _plan(),
            replace(bundle, source_projection=changed_projection, bundle_digest=""),
            *_authorities(),
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "public_material_manifest_digest",
        "material_artifact_set_digest",
        "ordinary_selection_digest",
    ),
)
def test_rehashed_source_projection_cannot_replace_controller_authority(field_name: str) -> None:
    bundle = _bundles()[0]
    changed_projection = replace(
        bundle.source_projection,
        **{field_name: _digest(f"attacker-{field_name}"), "projection_digest": ""},
    )
    attacker_bundle = replace(
        bundle,
        source_projection=changed_projection,
        bundle_digest="",
    )

    with pytest.raises(execution.IsolatedExecutionError):
        execution.label_blind_execution_bundle_bytes(_plan(), attacker_bundle, *_authorities())


def _different_valid_selection(selection: ordinary_contract.OrdinarySelectionV1) -> ordinary_contract.OrdinarySelectionV1:
    policy_digest = _digest("different-valid-selection-policy")
    provenance_digest = canonical.content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in selection.pushes})
            ),
            "accepted_fix_exclusions": tuple(ordinary_contract._fix_exclusion_value(item) for item in selection.fix_exclusions),
            "policy_digest": policy_digest,
        }
    )
    changed = replace(
        selection,
        policy_digest=policy_digest,
        provenance_digest=provenance_digest,
        selection_digest="",
    )
    return replace(
        changed,
        selection_digest=canonical.content_digest(ordinary_contract._selection_value(changed, include_digest=False)),
    )


@pytest.mark.parametrize("authority", ("public_manifest", "ordinary_selection"))
def test_bundle_rejects_different_internally_valid_source_authority(authority: str) -> None:
    manifest, public_manifest, selection = _authorities()
    if authority == "public_manifest":
        changed = replace(
            public_manifest,
            partition_policy_digest=_digest("different-valid-partition-policy"),
            manifest_digest="",
        )
        public_manifest = replace(
            changed,
            manifest_digest=canonical.content_digest(material_contract._manifest_value(changed, include_digest=False)),
        )
        assert execution_source._public_manifest_bytes(public_manifest)
    else:
        selection = _different_valid_selection(selection)
        assert ordinary_contract.ordinary_selection_bytes(selection)

    with pytest.raises(execution.IsolatedExecutionError):
        execution.label_blind_execution_bundle_bytes(
            _plan(),
            _bundles()[0],
            manifest,
            public_manifest,
            selection,
        )


class _NeverExecuteAdapter:
    def execute(self, _bundle: execution.LabelBlindExecutionBundleV1) -> execution.ArmProcessOutcomeV1:
        raise AssertionError("source authority substitution reached the adapter")


@pytest.mark.parametrize("boundary", ("outcome", "execution"))
def test_rehashed_source_projection_is_rejected_at_controller_boundaries(boundary: str) -> None:
    bundle = _bundles()[0]
    changed_projection = replace(
        bundle.source_projection,
        material_artifact_set_digest=_digest("attacker-boundary-artifact-set"),
        projection_digest="",
    )
    attacker_bundle = replace(bundle, source_projection=changed_projection, bundle_digest="")
    with pytest.raises(execution.IsolatedExecutionError):
        if boundary == "outcome":
            outcome = execution.completed_adapter_outcome(attacker_bundle, b"output", runtime_ms=1)
            execution.arm_process_outcome_bytes(
                _plan(),
                attacker_bundle,
                outcome,
                *_authorities(),
            )
        else:
            execution.execute_component_bundles(
                _plan(),
                (attacker_bundle,),
                _NeverExecuteAdapter(),
                *_authorities(),
            )
