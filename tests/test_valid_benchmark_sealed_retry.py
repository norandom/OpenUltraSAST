"""Task 8.6 exact pre-spend and post-spend sealed retry resume."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_admission_execution import (  # noqa: E402
    WORKFLOW,
    _Adapter,
    _boom,
    _selectors,
)
from test_valid_benchmark_admission_execution import (
    _case as _execution_case,
)
from test_valid_benchmark_admission_spend import _SpendEnv  # noqa: E402
from test_valid_benchmark_artifact_repository import _Client  # noqa: E402
from test_valid_benchmark_isolated_executor import _bundles, _plan  # noqa: E402
from test_valid_benchmark_lifecycle import _withdrawal  # noqa: E402
from test_valid_benchmark_observation_checkpoint import _Adapter as _CheckpointAdapter  # noqa: E402
from test_valid_benchmark_observation_checkpoint import _run  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    _digest,
    _settings,
)

from benchmarks.valid import admission_spend as spend  # noqa: E402
from benchmarks.valid import arm_contract as registry  # noqa: E402
from benchmarks.valid import artifact_repository as repository  # noqa: E402
from benchmarks.valid import lifecycle, observation_checkpoint, sealed_retry  # noqa: E402
from benchmarks.valid.admission_orchestrator import (  # noqa: E402
    RETRY_AUTHORITY_SCHEMA,
    AutomaticRetryAuthorityV1,
)
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    canonical_artifact_bytes,
)
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from benchmarks.valid.workflow_journal import (  # noqa: E402
    S3WorkflowJournal,
    WorkflowJournalEntryV1,
    journal_entry_bytes,
    successor_head,
    workflow_entry_key,
)
from benchmarks.valid.workflow_outcome import WorkflowCounts, WorkflowPhase  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import PopulationStatus  # noqa: E402
from openultrasast.core.evaluation_measurement import ArmKindV3  # noqa: E402
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest  # noqa: E402

_FORBIDDEN_BYTES = (b"label", b"finding", b"path", b"exception", b"password", b"repository")


def _custodian() -> repository.ArtifactReadAuthority:
    return repository.artifact_read_authority(
        repository.ArtifactActorRole.CUSTODIAN,
        (
            repository.ArtifactReadPermission.CUSTODIAN_SEALED,
            repository.ArtifactReadPermission.PRIVATE,
        ),
        ACCESS_POLICY,
        expected_access_policy_digest=ACCESS_POLICY,
    )


def _frozen_plan():
    bundles = _bundles()
    client = _Client()
    results = tuple(_run(bundle, _CheckpointAdapter(), client) for bundle in bundles)
    selectors = tuple(
        observation_checkpoint.CheckpointSelectorV1(result.reference, result.checkpoint_digest) for result in results
    )
    return bundles, client, selectors


def _identity(bundles, selectors, admission: str | None = None):
    return sealed_retry.build_automatic_retry_identity(
        bundles[0].population_digest,
        bundles[0].freeze_digest,
        _digest("admission-identity") if admission is None else admission,
        bundles,
        selectors,
    )


def _active(population: str, freeze: str) -> lifecycle.BaselineLifecycleAuthority:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=population,
        freeze_digest=freeze,
        producer_identity="lifecycle-producer",
        reviewer_identity="lifecycle-reviewer",
        conflict_disclosed=True,
        policy_digest=_digest("lifecycle-policy"),
    )
    authority = lifecycle.BaselineLifecycleAuthority()
    authority.append(root)
    authority.append(replacement)
    return authority


def _review() -> dict[str, object]:
    return {
        "producer_identity": "retry-controller",
        "reviewer_identity": "retry-reviewer",
        "conflict_disclosed": True,
        "policy_digest": _digest("lifecycle-policy"),
    }


def _matching_authority(bundles, selectors, plan, admission: str) -> AutomaticRetryAuthorityV1:
    candidate = _identity(bundles, selectors, admission)
    components = tuple(
        sorted(row.arm_id for row in plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT)
    )
    return AutomaticRetryAuthorityV1(
        candidate.population_digest,
        candidate.freeze_digest,
        admission,
        plan.plan_digest,
        tuple(row.arm_id for row in plan.registrations),
        candidate.bundle_digests,
        tuple(slot.slot_digest for slot in plan.declaration.expected_observation_slots),
        tuple(candidate.input_set_digest for _ in components),
        candidate.budget_digests,
        candidate.environment_digests,
        candidate.output_destination_digests,
        "",
    )


class _CrashingLoader:
    """Crashes exactly between the committed custody CAS and the first label byte."""

    def __init__(self) -> None:
        self.reads = 0

    def __call__(self) -> bytes:
        self.reads += 1
        raise RuntimeError("crash between custody CAS and label load")


class _RetryEnv(_SpendEnv):
    def __init__(self, case) -> None:
        super().__init__(case)
        self.selectors = _selectors(self.product)
        assert self.authorized.retry_authority is not None

    def preflight(self, **overrides):
        self.authorized = super().preflight(**overrides)
        return self.authorized

    def rebuilt_journal(self) -> S3WorkflowJournal:
        return S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), self.transient)

    def rebuilt_repository(self) -> S3ArtifactRepository:
        return S3ArtifactRepository(_settings(StorePurpose.DURABLE), self.durable)


def _review_authority(env, candidate, *, plan=None, bundles=None, selectors=None, lifecycle_authority=None):
    return sealed_retry.review_retry_mismatch_authority(
        env.authorized.retry_authority,
        candidate,
        bundles=env.case.bundles if bundles is None else bundles,
        checkpoint_selectors=env.selectors if selectors is None else selectors,
        plan=env.case.plan if plan is None else plan,
        lifecycle_authority=env.lifecycle() if lifecycle_authority is None else lifecycle_authority,
        **_review(),
    )


def _pre_spend_resume(env, **overrides):
    value = {
        "component_index": 0,
        "admission_identity_digest": env.authorized.retry_authority.admission_identity_digest,
        "bundles": env.case.bundles,
        "checkpoint_selectors": env.selectors,
        "plan": env.case.plan,
        "adapter": _Adapter(_boom),
        "journal": env.rebuilt_journal(),
        "workflow_digest": WORKFLOW,
        "repository": env.rebuilt_repository(),
        "artifact_authority": _custodian(),
        "access_policy_digest": ACCESS_POLICY,
        "manifest": env.case.manifest,
        "public_material_manifest": env.case.material,
        "selection": env.case.selection,
        "lifecycle_authority": env.lifecycle(),
        "custody": env.custody,
    }
    value.update(overrides)
    return sealed_retry.resume_pre_spend_sealed_retry(**value)


def _spent_resume(env, **overrides):
    from benchmarks.valid import sealed_retry_recovery

    value = {
        "admission_identity_digest": env.authorized.retry_authority.admission_identity_digest,
        "bundles": env.case.bundles,
        "checkpoint_selectors": env.selectors,
        "plan": env.case.plan,
        "journal": env.rebuilt_journal(),
        "workflow_digest": WORKFLOW,
        "repository": env.rebuilt_repository(),
        "access_policy_digest": ACCESS_POLICY,
        "custody": env.custody,
    }
    value.update(overrides)
    return sealed_retry_recovery.resume_spent_sealed_run(**value)


def _crash_after_cas(env) -> object:
    loader = _CrashingLoader()
    release = spend.commit_spend_and_release(env.spend_request(load_labels=loader))
    assert release.refusal_reason is spend.AdmissionSpendReason.LABELS_UNREADABLE
    assert release.labels_spent and release.custody_receipt_digest
    log = env.custody.current_log(env.population)
    assert log.status is PopulationStatus.SPENT and log.receipt_count == 1
    assert loader.reads == 1
    return release


def _advance_phase(env, phase: WorkflowPhase) -> None:
    head = env.journal.current_head(WORKFLOW)
    entry = WorkflowJournalEntryV1(
        WORKFLOW,
        head.sequence + 1,
        head.entry_digest,
        "attempt-1",
        "owner-a",
        phase,
        "2026-11-21T09:10:00Z",
        "2026-11-21T09:40:00Z",
        WorkflowCounts(3, 2, len(env.case.manifest.input_digests), 0, 0),
        "",
    )
    assert env.journal.append_and_swap(head.head_digest, entry, successor_head(head, entry))


def _foreign_plan(case, *, changed_inputs: bool = False):
    current = case.plan
    input_digests = tuple(row.input_identity_digest for row in case.bundles[0].case_inputs)
    if changed_inputs:
        input_digests = (_digest("foreign-plan-input"), *input_digests[1:])
    return registry.register_evaluation_plan(
        registrations=current.registrations,
        population_digest=(
            current.declaration.population_digest if changed_inputs else _digest("foreign-plan-population")
        ),
        freeze_digest=current.declaration.freeze_digest,
        input_set_digest=derive_evaluation_input_set_digest(input_digests),
        input_identity_digests=input_digests,
    )


def _no_lifecycle_artifacts(env) -> None:
    assert not [key for key in env.durable if "lifecycle" in key]


def _rebuilt_retired_authority(env, reference) -> lifecycle.BaselineLifecycleAuthority:
    accepted = env.rebuilt_repository().get(
        reference,
        expected_kind=ArtifactKind.LIFECYCLE,
        authority=_custodian(),
        expected_access_policy_digest=ACCESS_POLICY,
    )
    authority = env.lifecycle()
    authority.append(canonical.canonical_bytes(accepted.artifact.payload))
    return authority


def test_scratch_loss_pre_spend_resume_resolves_only_head_selected_authority_without_rerun() -> None:
    env = _RetryEnv(_execution_case())
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(env, adapter=adapter)

    assert result.status is sealed_retry.AutomaticRetryStatus.RESUMED
    assert result.reason is sealed_retry.AutomaticRetryReason.NONE
    assert result.checkpoint is not None
    assert result.checkpoint.status is observation_checkpoint.CheckpointStatus.COMPLETE
    assert result.checkpoint.checkpoint_digest == env.product.component_results[0].checkpoint_digest
    assert adapter.calls == []
    assert env.custody.current_log(env.population).status is PopulationStatus.AVAILABLE
    env.lifecycle().require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    content = sealed_retry.automatic_retry_result_bytes(result).lower()
    for forbidden in _FORBIDDEN_BYTES:
        assert forbidden not in content


def test_caller_supplied_original_identity_cannot_authorize_changed_current_bundles() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    changed_budget = replace(
        case.bundles[0].budget, deadline_seconds=case.bundles[0].budget.deadline_seconds + 1, budget_digest=""
    )
    bundles = (replace(case.bundles[0], budget=changed_budget, bundle_digest=""), *case.bundles[1:])
    candidate = _identity(bundles, env.selectors, env.authorized.retry_authority.admission_identity_digest)
    mismatch = _review_authority(env, candidate, bundles=bundles, lifecycle_authority=lifecycle_authority)
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(
        env, bundles=bundles, adapter=adapter, mismatch_authority=mismatch, lifecycle_authority=lifecycle_authority
    )

    assert result.status is sealed_retry.AutomaticRetryStatus.BLOCKED
    assert result.reason is sealed_retry.AutomaticRetryReason.IDENTITY_CHANGED
    assert result.checkpoint is None and result.lifecycle_reference is not None
    assert adapter.calls == []
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        lifecycle_authority.require_admission_eligible(
            env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
        )


@pytest.mark.parametrize("mutation", ("admission", "plan", "plan-inputs", "bundle-budget"))
def test_changed_identity_dimension_terminally_blocks_admission_without_execution(mutation: str) -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    bundles, plan = case.bundles, case.plan
    admission = env.authorized.retry_authority.admission_identity_digest
    if mutation == "admission":
        admission = _digest("changed-admission")
    elif mutation == "plan":
        plan = _foreign_plan(case)
    elif mutation == "plan-inputs":
        plan = _foreign_plan(case, changed_inputs=True)
    else:
        changed = replace(
            case.bundles[0].budget, deadline_seconds=case.bundles[0].budget.deadline_seconds + 1, budget_digest=""
        )
        bundles = (replace(case.bundles[0], budget=changed, bundle_digest=""), *case.bundles[1:])
    candidate = _identity(bundles, env.selectors, admission)
    mismatch = _review_authority(
        env, candidate, plan=plan, bundles=bundles, lifecycle_authority=lifecycle_authority
    )
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(
        env,
        admission_identity_digest=admission,
        bundles=bundles,
        plan=plan,
        adapter=adapter,
        mismatch_authority=mismatch,
        lifecycle_authority=lifecycle_authority,
    )

    assert result.status is sealed_retry.AutomaticRetryStatus.BLOCKED
    assert result.reason is sealed_retry.AutomaticRetryReason.IDENTITY_CHANGED
    assert adapter.calls == []
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        lifecycle_authority.require_admission_eligible(
            env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
        )


def test_reordered_checkpoint_selectors_never_resume_a_foreign_completed_arm() -> None:
    env = _RetryEnv(_execution_case())
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(env, checkpoint_selectors=tuple(reversed(env.selectors)), adapter=adapter)

    assert result.status is sealed_retry.AutomaticRetryStatus.IMPAIRED
    assert result.reason is sealed_retry.AutomaticRetryReason.CHECKPOINT_IMPAIRED
    assert adapter.calls == []
    assert env.custody.current_log(env.population).status is PopulationStatus.AVAILABLE


def test_unreadable_checkpoint_is_impaired_and_leaves_custody_available() -> None:
    env = _RetryEnv(_execution_case())
    for selector in env.selectors:
        env.durable.put_object(
            Bucket="valid-durable",
            Key=f"observations/custodian_sealed/{selector.reference.content_digest}.json",
            Body=b"corrupted-checkpoint",
        )
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(env, adapter=adapter)

    assert result.status is sealed_retry.AutomaticRetryStatus.IMPAIRED
    assert result.reason is sealed_retry.AutomaticRetryReason.CHECKPOINT_IMPAIRED
    assert adapter.calls == []
    assert env.custody.current_log(env.population).status is PopulationStatus.AVAILABLE


def test_missing_mismatch_evidence_fails_closed_without_retirement_or_lifecycle_mutation() -> None:
    env = _RetryEnv(_execution_case())
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(env, admission_identity_digest=_digest("changed-admission"), adapter=adapter)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED
    assert adapter.calls == []
    env.lifecycle().require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    _no_lifecycle_artifacts(env)


def test_forged_mismatch_evidence_fails_closed_without_retirement() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    candidate = _identity(case.bundles, env.selectors, _digest("changed-admission"))
    valid = _review_authority(env, candidate, lifecycle_authority=lifecycle_authority)
    forged = object.__new__(sealed_retry.RetryMismatchAuthorityV1)
    for name, value in vars(valid).items():
        object.__setattr__(forged, name, value)
    object.__setattr__(forged, "candidate_retry_digest", _digest("forged-candidate"))
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(
            env,
            admission_identity_digest=_digest("changed-admission"),
            adapter=adapter,
            mismatch_authority=forged,
            lifecycle_authority=lifecycle_authority,
        )

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST
    assert adapter.calls == []
    lifecycle_authority.require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    _no_lifecycle_artifacts(env)


def test_deeply_nested_mismatch_evidence_fails_closed_without_mutation() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    candidate = _identity(case.bundles, env.selectors, _digest("changed-admission"))
    valid = _review_authority(env, candidate, lifecycle_authority=lifecycle_authority)
    forged = object.__new__(sealed_retry.RetryMismatchAuthorityV1)
    for name, value in vars(valid).items():
        object.__setattr__(forged, name, value)
    object.__setattr__(
        forged, "retirement_event_content", b'{"a":' * 100_000 + b"1" + b"}" * 100_000
    )
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(
            env,
            admission_identity_digest=_digest("changed-admission"),
            adapter=adapter,
            mismatch_authority=forged,
            lifecycle_authority=lifecycle_authority,
        )

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST
    assert adapter.calls == []
    lifecycle_authority.require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    _no_lifecycle_artifacts(env)


def test_mismatch_evidence_reviewed_for_another_change_is_refused_closed() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    first = _identity(case.bundles, env.selectors, _digest("first-change"))
    wrong = _review_authority(env, first, lifecycle_authority=lifecycle_authority)
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(
            env,
            admission_identity_digest=_digest("second-change"),
            adapter=adapter,
            mismatch_authority=wrong,
            lifecycle_authority=lifecycle_authority,
        )

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED
    assert adapter.calls == []
    lifecycle_authority.require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    _no_lifecycle_artifacts(env)


def test_malformed_supplied_plan_is_refused_before_execution_without_mutation() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    malformed = object.__new__(registry.RegisteredEvaluationPlanV1)
    object.__setattr__(malformed, "registrations", case.plan.registrations)
    object.__setattr__(malformed, "declaration", case.plan.declaration)
    object.__setattr__(malformed, "baselines", case.plan.baselines)
    object.__setattr__(malformed, "plan_digest", _digest("forged-plan-digest"))
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(env, plan=malformed, adapter=adapter)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST
    assert adapter.calls == []
    env.lifecycle().require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )


def test_terminal_baseline_cannot_retry_even_with_exact_identity() -> None:
    case = _execution_case()
    env = _RetryEnv(case)
    lifecycle_authority = env.lifecycle()
    changed = _identity(case.bundles, env.selectors, _digest("changed-admission"))
    mismatch = _review_authority(env, changed, lifecycle_authority=lifecycle_authority)
    first = _pre_spend_resume(
        env,
        admission_identity_digest=_digest("changed-admission"),
        mismatch_authority=mismatch,
        lifecycle_authority=lifecycle_authority,
    )
    assert first.reason is sealed_retry.AutomaticRetryReason.IDENTITY_CHANGED
    assert first.lifecycle_reference is not None
    adapter = _Adapter(_boom)

    rebuilt = _rebuilt_retired_authority(env, first.lifecycle_reference)
    second = _pre_spend_resume(env, adapter=adapter, lifecycle_authority=rebuilt)

    assert second.status is sealed_retry.AutomaticRetryStatus.BLOCKED
    assert second.reason is sealed_retry.AutomaticRetryReason.LIFECYCLE_INELIGIBLE
    assert adapter.calls == []


def test_pre_spend_resume_over_committed_spend_is_refused_closed() -> None:
    env = _RetryEnv(_execution_case())
    _crash_after_cas(env)
    spent_log = env.custody.current_log(env.population)
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(env, adapter=adapter)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.SPEND_ALREADY_COMMITTED
    assert adapter.calls == []
    assert env.custody.current_log(env.population) == spent_log
    env.lifecycle().require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )


def test_missing_workflow_head_fails_closed_before_any_execution() -> None:
    env = _RetryEnv(_execution_case())
    empty = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), _Client())
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(env, journal=empty, adapter=adapter)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.AUTHORITY_UNRESOLVED
    assert adapter.calls == []


def test_substituted_authority_bytes_fail_closed_before_execution() -> None:
    env = _RetryEnv(_execution_case())
    authority = env.authorized.retry_authority
    reference = env.authorized.retry_authority_reference
    assert reference is not None
    substituted = canonical_artifact_bytes(
        ArtifactKind.WORKFLOW,
        {
            "schema_version": RETRY_AUTHORITY_SCHEMA,
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
    env.durable.put_object(
        Bucket="valid-durable",
        Key=f"workflows/custodian_sealed/{reference.content_digest}.json",
        Body=substituted,
    )
    adapter = _Adapter(_boom)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _pre_spend_resume(env, adapter=adapter)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.AUTHORITY_SUBSTITUTED
    assert adapter.calls == []
    assert env.custody.current_log(env.population).status is PopulationStatus.AVAILABLE


def test_orphan_journal_entry_is_never_selected_after_restart() -> None:
    env = _RetryEnv(_execution_case())
    head = env.journal.current_head(WORKFLOW)
    orphan = WorkflowJournalEntryV1(
        WORKFLOW,
        head.sequence + 5,
        head.entry_digest,
        "attempt-9",
        "owner-z",
        WorkflowPhase.SCORING,
        "2026-11-21T09:20:00Z",
        "2026-11-21T09:50:00Z",
        WorkflowCounts(3, 2, len(env.case.manifest.input_digests), 0, 0),
        "",
    )
    env.transient.put_object(
        Bucket="valid-transient",
        Key=workflow_entry_key(WORKFLOW, orphan.entry_digest),
        Body=journal_entry_bytes(orphan),
    )
    adapter = _Adapter(_boom)

    result = _pre_spend_resume(env, adapter=adapter)

    assert result.status is sealed_retry.AutomaticRetryStatus.RESUMED
    assert result.checkpoint is not None
    assert result.checkpoint.checkpoint_digest == env.product.component_results[0].checkpoint_digest
    assert adapter.calls == []


def test_post_spend_resume_keeps_labels_spent_and_the_same_immutable_run() -> None:
    env = _RetryEnv(_execution_case())
    _crash_after_cas(env)
    spent_log = env.custody.current_log(env.population)

    resumed = _spent_resume(env)

    assert resumed.labels_spent is True
    assert resumed.authority_digest == env.authorized.retry_authority.authority_digest
    assert resumed.retry_digest == _identity(
        env.case.bundles, env.selectors, env.authorized.retry_authority.admission_identity_digest
    ).retry_digest
    assert resumed.custody_receipt_digest == spent_log.head_receipt_digest
    assert env.custody.current_log(env.population) == spent_log
    assert env.custody.current_log(env.population).status is PopulationStatus.SPENT
    from benchmarks.valid import sealed_retry_recovery

    content = sealed_retry_recovery.spent_run_resume_bytes(resumed).lower()
    for forbidden in (b"finding", b"path", b"exception", b"password", b"repository"):
        assert forbidden not in content
    assert content.count(b"label") == content.count(b"labels_spent")


def test_post_spend_resume_refuses_unspent_custody_and_never_restores_untouched() -> None:
    env = _RetryEnv(_execution_case())
    untouched = env.custody.current_log(env.population)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _spent_resume(env)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.CUSTODY_NOT_SPENT
    assert env.custody.current_log(env.population) == untouched
    assert env.custody.current_log(env.population).status is PopulationStatus.AVAILABLE


def test_post_spend_resume_refuses_changed_identity_without_mutation() -> None:
    env = _RetryEnv(_execution_case())
    _crash_after_cas(env)
    spent_log = env.custody.current_log(env.population)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        _spent_resume(env, admission_identity_digest=_digest("changed-admission"))

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED
    assert env.custody.current_log(env.population) == spent_log
    env.lifecycle().require_admission_eligible(
        env.authorized.retry_authority.population_digest, env.authorized.retry_authority.freeze_digest
    )
    _no_lifecycle_artifacts(env)


def test_crash_points_converge_to_the_same_terminal_identity() -> None:
    case = _execution_case()
    identities = set()

    before_cas = _RetryEnv(case)
    pre = _pre_spend_resume(before_cas, adapter=_Adapter(_boom))
    assert pre.status is sealed_retry.AutomaticRetryStatus.RESUMED
    identities.add((before_cas.authorized.retry_authority.authority_digest, pre.retry_digest))

    after_cas = _RetryEnv(case)
    _crash_after_cas(after_cas)
    resumed = _spent_resume(after_cas)
    assert resumed.labels_spent is True
    identities.add((resumed.authority_digest, resumed.retry_digest))

    during_scoring = _RetryEnv(case)
    _crash_after_cas(during_scoring)
    _advance_phase(during_scoring, WorkflowPhase.SCORING)
    scoring = _spent_resume(during_scoring)
    identities.add((scoring.authority_digest, scoring.retry_digest))

    before_publication = _RetryEnv(case)
    _crash_after_cas(before_publication)
    _advance_phase(before_publication, WorkflowPhase.SCORING)
    _advance_phase(before_publication, WorkflowPhase.REPORTING)
    publication = _spent_resume(before_publication)
    identities.add((publication.authority_digest, publication.retry_digest))

    assert len(identities) == 1


def test_retry_identity_digest_binds_every_dimension() -> None:
    bundles, _, selectors = _frozen_plan()
    identity = _identity(bundles, selectors)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        replace(identity, input_set_digest=_digest("forged-inputs"), retry_digest=identity.retry_digest)

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST


@pytest.mark.parametrize(
    "field",
    (
        "population_digest",
        "freeze_digest",
        "admission_identity_digest",
        "plan_digest",
        "ordered_arm_ids",
        "ordered_bundle_digests",
        "ordered_checkpoint_slot_digests",
        "ordered_input_set_digests",
        "ordered_budget_digests",
        "ordered_environment_digests",
        "ordered_destination_digests",
    ),
)
def test_every_head_selected_identity_dimension_must_match(field: str) -> None:
    bundles, _, selectors = _frozen_plan()
    plan = _plan()
    admission = _digest("admission-identity")
    authority = _matching_authority(bundles, selectors, plan, admission)
    candidate = _identity(bundles, selectors, admission)
    assert sealed_retry.retry_identity_matches_authority(candidate, bundles, plan, authority)

    current = getattr(authority, field)
    if field == "ordered_arm_ids":
        mutated: object = tuple(reversed(current))
    elif field.startswith("ordered_"):
        mutated = (_digest(f"other-{field}"), *current[1:])
    else:
        mutated = _digest(f"other-{field}")
    changed = replace(authority, **{field: mutated}, authority_digest="")

    assert not sealed_retry.retry_identity_matches_authority(candidate, bundles, plan, changed)


def test_review_refuses_a_matching_candidate() -> None:
    bundles, _, selectors = _frozen_plan()
    plan = _plan()
    admission = _digest("admission-identity")
    authority = _matching_authority(bundles, selectors, plan, admission)
    candidate = _identity(bundles, selectors, admission)

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        sealed_retry.review_retry_mismatch_authority(
            authority,
            candidate,
            bundles=bundles,
            checkpoint_selectors=selectors,
            plan=plan,
            lifecycle_authority=_active(candidate.population_digest, candidate.freeze_digest),
            **_review(),
        )

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST


def test_mismatch_authority_requires_its_exact_retirement_event() -> None:
    bundles, _, selectors = _frozen_plan()
    plan = _plan()
    admission = _digest("admission-identity")
    authority = _matching_authority(bundles, selectors, plan, admission)
    changed = _identity(bundles, selectors, _digest("changed-admission"))
    lifecycle_authority = _active(authority.population_digest, authority.freeze_digest)
    valid = sealed_retry.review_retry_mismatch_authority(
        authority,
        changed,
        bundles=bundles,
        checkpoint_selectors=selectors,
        plan=plan,
        lifecycle_authority=lifecycle_authority,
        **_review(),
    )
    forged = object.__new__(sealed_retry.RetryMismatchAuthorityV1)
    for name, value in vars(valid).items():
        object.__setattr__(forged, name, value)
    object.__setattr__(forged, "predecessor_digest", _digest("forged-predecessor"))

    with pytest.raises(sealed_retry.AutomaticRetryError) as captured:
        forged.__post_init__()

    assert captured.value.reason is sealed_retry.AutomaticRetryAuthorityReason.INVALID_REQUEST
