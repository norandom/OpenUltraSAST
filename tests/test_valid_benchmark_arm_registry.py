"""Task 6.1 immutable label-blind arm registry tests."""

from __future__ import annotations

import json
import sys
from dataclasses import fields, replace
from itertools import product
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import InMemoryContentResolver, stored_artifact  # noqa: E402

from benchmarks.valid import arm_contract as registry
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentRef
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    CombinationDecisionRowV3,
    CombinationOperatorV3,
    CombinationRuleV3,
    Comparator,
    DenominatorPolicyV3,
    EvaluationMeasurementError,
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
from openultrasast.core.evaluation_plan import (
    EvaluationPlanDeclarationV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    derive_evaluation_input_set_digest,
)
from openultrasast.core.factpack import (  # noqa: E402
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _resolver(*values: InMemoryContentResolver) -> InMemoryContentResolver:
    return InMemoryContentResolver({key: item for value in values for key, item in value.artifacts.items()})


def _policy(reviewer: str) -> ReviewIndependencePolicy:
    digest = derive_review_independence_policy_digest((reviewer,), (), ("trusted-store",), 4096)
    return ReviewIndependencePolicy((reviewer,), (), ("trusted-store",), 4096, digest)


def _review(subject: str, disclosure: ContentRef, *, self_reviewed: bool = False) -> IndependenceAttestation:
    producer = _digest("strategy-producer")
    reviewer = producer if self_reviewed else _digest("strategy-reviewer")
    draft = IndependenceAttestation(subject, producer, reviewer, disclosure, "0" * 64)
    return replace(draft, attestation_digest=derive_independence_attestation_digest(draft))


def _combination_rule() -> CombinationRuleV3:
    arm_ids = ("arm-experimental", "arm-shipped")
    rows = tuple(
        CombinationDecisionRowV3(
            outcomes,
            NeutralOutcome.VIOLATION if NeutralOutcome.VIOLATION in outcomes else outcomes[0],
            "",
        )
        for outcomes in product(tuple(NeutralOutcome), repeat=len(arm_ids))
    )
    return CombinationRuleV3(
        "arm-combined",
        arm_ids,
        CombinationOperatorV3.DECLARATIVE_TABLE,
        rows,
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


def _configuration(
    arm_id: str,
    *,
    family: str = "injection",
    ecosystem: str = "python",
    combined: bool = False,
    analyzer: str = "analyzer@sha256:abc",
    configuration: str = "configuration",
) -> ArmConfigurationV3:
    scope = ScopeKey(family, ecosystem)
    key = ArmScopeKey(arm_id, scope)
    thresholds = tuple(
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
    precision = tuple(IntervalPrecisionRuleV3(metric_id, 0.25, 4, "") for metric_id in MetricId)
    return ArmConfigurationV3(
        arm_id,
        ArmKindV3.COMBINED if combined else ArmKindV3.COMPONENT,
        (scope,),
        (DenominatorPolicyV3(key, standard_scoped_metric_rules(key), IntervalMethod.WILSON_95, ""),),
        thresholds,
        (ScopeSufficiencyRuleV3(key, 4, 8, precision, ""),),
        _digest("judgment-vocabulary"),
        analyzer,
        _digest("facts"),
        _digest(configuration),
        _digest("budget"),
        "container@sha256:def",
        _digest("outcome-mapping"),
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE if combined else CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        _combination_rule() if combined else None,
        "",
    )


def _reviewed_strategy_decision(
    configuration: ArmConfigurationV3,
    *,
    label: str = "strategy",
) -> tuple[registry.StrategyDecisionAuthorityV1, ReviewIndependencePolicy, InMemoryContentResolver]:
    content = registry.strategy_decision_artifact_bytes(
        configuration.arm_id,
        configuration.configuration_identity_digest,
        registry.StrategyDecisionDisposition.ADMIT_TO_PLAN,
    )
    reference, decision_resolver = stored_artifact(content, artifact_id=f"{label}-decision")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id=f"{label}-conflicts")
    review = _review(reference.content_digest, disclosure)
    policy = _policy(review.reviewer_identity)
    resolver = _resolver(decision_resolver, disclosure_resolver)
    authority = registry.review_strategy_decision_authority(
        configuration,
        reference,
        review,
        policy,
        resolver,
    )
    return authority, policy, resolver


def _registration(
    role: registry.ArmRole,
    configuration: ArmConfigurationV3,
    *,
    lifecycle: registry.ArmLifecycleState = registry.ArmLifecycleState.ACTIVE,
    decision: registry.StrategyDecisionAuthorityV1 | None = None,
) -> registry.ArmRegistrationV1:
    return registry.ArmRegistrationV1(role, lifecycle, decision, configuration, "")


def _registrations() -> tuple[registry.ArmRegistrationV1, ...]:
    return (
        _registration(registry.ArmRole.COMBINED, _configuration("arm-combined", combined=True)),
        _registration(registry.ArmRole.EXPERIMENTAL, _configuration("arm-experimental")),
        _registration(registry.ArmRole.SHIPPED, _configuration("arm-shipped")),
    )


def _plan(
    registrations: tuple[registry.ArmRegistrationV1, ...] | None = None,
    *,
    policy: ReviewIndependencePolicy | None = None,
    resolver: InMemoryContentResolver | None = None,
) -> registry.RegisteredEvaluationPlanV1:
    inputs = (_digest("input-b"), _digest("input-a"))
    return registry.register_evaluation_plan(
        registrations=_registrations() if registrations is None else registrations,
        population_digest=_digest("population"),
        freeze_digest=_digest("freeze"),
        input_set_digest=derive_evaluation_input_set_digest(inputs),
        input_identity_digests=inputs,
        strategy_review_policy=policy,
        strategy_resolver=resolver,
    )


def _direct_plan(registration: registry.ArmRegistrationV1) -> registry.RegisteredEvaluationPlanV1:
    inputs = (_digest("input-b"), _digest("input-a"))
    declaration = create_evaluation_plan_declaration(
        population_digest=_digest("population"),
        freeze_digest=_digest("freeze"),
        input_set_digest=derive_evaluation_input_set_digest(inputs),
        arm_configurations=(registration.configuration,),
        input_identity_digests=inputs,
    )
    return registry.RegisteredEvaluationPlanV1(
        (registration,),
        declaration,
        derive_evaluation_baselines(declaration),
        "",
    )


def test_registry_builds_one_canonical_plan_with_separate_arm_roles() -> None:
    plan = _plan()

    assert tuple(row.role for row in plan.registrations) == (
        registry.ArmRole.SHIPPED,
        registry.ArmRole.EXPERIMENTAL,
        registry.ArmRole.COMBINED,
    )
    assert type(plan.declaration) is EvaluationPlanDeclarationV3
    assert tuple(row.arm_id for row in plan.declaration.arm_configurations) == (
        "arm-combined",
        "arm-experimental",
        "arm-shipped",
    )
    assert tuple(row.arm_id for row in plan.baselines) == (
        "arm-combined",
        "arm-experimental",
        "arm-shipped",
    )
    assert registry.registered_evaluation_plan_bytes(plan) == registry.registered_evaluation_plan_bytes(_plan())


@pytest.mark.parametrize(
    "changed",
    (
        _configuration("arm-shipped", analyzer="analyzer@sha256:changed"),
        _configuration("arm-shipped", configuration="changed-configuration"),
        _configuration("arm-shipped", ecosystem="javascript"),
    ),
)
def test_identity_or_scope_change_creates_a_new_plan(changed: ArmConfigurationV3) -> None:
    base = _plan()
    registrations = tuple(
        _registration(row.role, changed if row.arm_id == "arm-shipped" else row.configuration) for row in base.registrations
    )

    altered = _plan(registrations)

    assert altered.plan_digest != base.plan_digest
    assert altered.declaration.declaration_digest != base.declaration.declaration_digest


def test_each_claimed_scope_requires_one_exact_v3_policy_and_sufficiency_rule() -> None:
    configuration = _configuration("arm-shipped")

    with pytest.raises(EvaluationMeasurementError, match="denominator policies"):
        replace(configuration, denominator_policies=(), configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="denominator policies"):
        replace(
            configuration,
            denominator_policies=configuration.denominator_policies * 2,
            configuration_identity_digest="",
        )

    assert len(configuration.denominator_policies) == len(configuration.exact_scopes) == 1
    assert len(configuration.sufficiency_rules) == len(configuration.exact_scopes) == 1
    assert all(type(row) is DenominatorPolicyV3 for row in configuration.denominator_policies)


def test_parked_arm_requires_a_strategy_decision_and_active_arm_forbids_one() -> None:
    configuration = _configuration("generic-parked", family="path_traversal")
    authority, policy, resolver = _reviewed_strategy_decision(configuration)

    with pytest.raises(registry.ArmRegistryError, match="parked arm requires"):
        _registration(registry.ArmRole.EXPERIMENTAL, configuration, lifecycle=registry.ArmLifecycleState.PARKED)
    with pytest.raises(registry.ArmRegistryError, match="active arm must not"):
        _registration(registry.ArmRole.EXPERIMENTAL, configuration, decision=authority)
    with pytest.raises(registry.ArmRegistryError, match="exact reviewed strategy-decision authority"):
        registry.ArmRegistrationV1(  # type: ignore[arg-type]
            registry.ArmRole.EXPERIMENTAL,
            registry.ArmLifecycleState.PARKED,
            ContentRef("fabricated", _digest("content"), "application/json", 1, _digest("retention"), _digest("receipt")),
            configuration,
            "",
        )

    plan = _plan(
        (
            _registration(
                registry.ArmRole.EXPERIMENTAL,
                configuration,
                lifecycle=registry.ArmLifecycleState.PARKED,
                decision=authority,
            ),
        ),
        policy=policy,
        resolver=resolver,
    )
    assert plan.registrations[0].lifecycle_state is registry.ArmLifecycleState.PARKED


def test_lifecycle_or_strategy_decision_change_creates_a_new_registry_plan() -> None:
    configuration = _configuration("generic-arm", family="path_traversal")
    active = _plan((_registration(registry.ArmRole.EXPERIMENTAL, configuration),))
    first, first_policy, first_resolver = _reviewed_strategy_decision(configuration, label="strategy-a")
    second, second_policy, second_resolver = _reviewed_strategy_decision(configuration, label="strategy-b")
    parked = _plan(
        (
            _registration(
                registry.ArmRole.EXPERIMENTAL,
                configuration,
                lifecycle=registry.ArmLifecycleState.PARKED,
                decision=first,
            ),
        ),
        policy=first_policy,
        resolver=first_resolver,
    )
    changed_decision = _plan(
        (
            _registration(
                registry.ArmRole.EXPERIMENTAL,
                configuration,
                lifecycle=registry.ArmLifecycleState.PARKED,
                decision=second,
            ),
        ),
        policy=second_policy,
        resolver=second_resolver,
    )

    assert active.declaration.declaration_digest == parked.declaration.declaration_digest
    assert len({active.plan_digest, parked.plan_digest, changed_decision.plan_digest}) == 3


def test_parked_authority_is_re_resolved_and_bound_to_exact_configuration() -> None:
    configuration = _configuration("generic-arm", family="path_traversal")
    authority, policy, resolver = _reviewed_strategy_decision(configuration)
    registration = _registration(
        registry.ArmRole.EXPERIMENTAL,
        configuration,
        lifecycle=registry.ArmLifecycleState.PARKED,
        decision=authority,
    )

    with pytest.raises(registry.ArmRegistryError, match="cannot be resolved"):
        _plan((registration,), policy=policy, resolver=InMemoryContentResolver({}))

    changed = _configuration("generic-arm", family="path_traversal", configuration="changed")
    changed_registration = _registration(
        registry.ArmRole.EXPERIMENTAL,
        changed,
        lifecycle=registry.ArmLifecycleState.PARKED,
        decision=authority,
    )
    with pytest.raises(registry.ArmRegistryError, match="configuration identity"):
        _plan((changed_registration,), policy=policy, resolver=resolver)


def test_strategy_decision_rejects_wrong_kind_self_review_and_mutated_bytes() -> None:
    configuration = _configuration("generic-arm", family="path_traversal")
    valid = registry.strategy_decision_artifact_bytes(
        configuration.arm_id,
        configuration.configuration_identity_digest,
        registry.StrategyDecisionDisposition.ADMIT_TO_PLAN,
    )
    wrong_value = json.loads(valid)
    wrong_value["kind"] = "unreviewed_note"
    wrong_reference, wrong_resolver = stored_artifact(canonical.canonical_bytes(wrong_value), artifact_id="wrong-kind")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="wrong-kind-conflicts")
    wrong_review = _review(wrong_reference.content_digest, disclosure)
    policy = _policy(wrong_review.reviewer_identity)

    with pytest.raises(registry.ArmRegistryError, match="kind"):
        registry.review_strategy_decision_authority(
            configuration,
            wrong_reference,
            wrong_review,
            policy,
            _resolver(wrong_resolver, disclosure_resolver),
        )

    reference, decision_resolver = stored_artifact(valid, artifact_id="self-reviewed")
    self_review = _review(reference.content_digest, disclosure, self_reviewed=True)
    self_policy = _policy(self_review.reviewer_identity)
    with pytest.raises(registry.ArmRegistryError, match="independent"):
        registry.review_strategy_decision_authority(
            configuration,
            reference,
            self_review,
            self_policy,
            _resolver(decision_resolver, disclosure_resolver),
        )

    authority, valid_policy, valid_resolver = _reviewed_strategy_decision(configuration, label="mutated")
    artifacts = dict(valid_resolver.artifacts)
    original = artifacts[authority.decision_ref.artifact_id]
    artifacts[authority.decision_ref.artifact_id] = canonical.ResolvedContent(b"mutated", original.receipt)
    registration = _registration(
        registry.ArmRole.EXPERIMENTAL,
        configuration,
        lifecycle=registry.ArmLifecycleState.PARKED,
        decision=authority,
    )
    with pytest.raises(registry.ArmRegistryError, match="cannot be resolved"):
        _plan(
            (registration,),
            policy=valid_policy,
            resolver=InMemoryContentResolver(artifacts),
        )


def test_direct_parked_plan_cannot_serialize_self_reviewed_or_unresolved_authority() -> None:
    configuration = _configuration("direct-parked", family="path_traversal")
    content = registry.strategy_decision_artifact_bytes(
        configuration.arm_id,
        configuration.configuration_identity_digest,
        registry.StrategyDecisionDisposition.ADMIT_TO_PLAN,
    )
    reference, decision_resolver = stored_artifact(content, artifact_id="direct-decision")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="direct-conflicts")
    self_review = _review(reference.content_digest, disclosure, self_reviewed=True)
    policy = _policy(self_review.reviewer_identity)
    authority = registry.StrategyDecisionAuthorityV1(
        configuration.arm_id,
        configuration.configuration_identity_digest,
        registry.StrategyDecisionDisposition.ADMIT_TO_PLAN,
        reference,
        self_review,
        policy.policy_digest,
        "",
    )
    plan = _direct_plan(
        _registration(
            registry.ArmRole.EXPERIMENTAL,
            configuration,
            lifecycle=registry.ArmLifecycleState.PARKED,
            decision=authority,
        )
    )

    with pytest.raises(registry.ArmRegistryError, match="review policy and resolver"):
        registry.registered_evaluation_plan_bytes(plan)
    with pytest.raises(registry.ArmRegistryError, match="independent"):
        registry.registered_evaluation_plan_bytes(
            plan,
            strategy_review_policy=policy,
            strategy_resolver=_resolver(decision_resolver, disclosure_resolver),
        )


def test_direct_parked_plan_serialization_rejects_unresolved_and_policy_mismatch() -> None:
    configuration = _configuration("direct-reviewed", family="path_traversal")
    authority, policy, resolver = _reviewed_strategy_decision(configuration, label="direct-reviewed")
    plan = _direct_plan(
        _registration(
            registry.ArmRole.EXPERIMENTAL,
            configuration,
            lifecycle=registry.ArmLifecycleState.PARKED,
            decision=authority,
        )
    )

    with pytest.raises(registry.ArmRegistryError, match="cannot be resolved"):
        registry.registered_evaluation_plan_bytes(
            plan,
            strategy_review_policy=policy,
            strategy_resolver=InMemoryContentResolver({}),
        )
    wrong_policy = _policy(_digest("other-maintainer"))
    with pytest.raises(registry.ArmRegistryError, match="review policy identity"):
        registry.registered_evaluation_plan_bytes(
            plan,
            strategy_review_policy=wrong_policy,
            strategy_resolver=resolver,
        )

    artifacts = dict(resolver.artifacts)
    original = artifacts[authority.decision_ref.artifact_id]
    artifacts[authority.decision_ref.artifact_id] = canonical.ResolvedContent(b"mutated", original.receipt)
    with pytest.raises(registry.ArmRegistryError, match="cannot be resolved"):
        registry.registered_evaluation_plan_bytes(
            plan,
            strategy_review_policy=policy,
            strategy_resolver=InMemoryContentResolver(artifacts),
        )

    changed = _configuration("direct-reviewed", family="path_traversal", configuration="changed")
    changed_plan = _direct_plan(
        _registration(
            registry.ArmRole.EXPERIMENTAL,
            changed,
            lifecycle=registry.ArmLifecycleState.PARKED,
            decision=authority,
        )
    )
    with pytest.raises(registry.ArmRegistryError, match="configuration identity"):
        registry.registered_evaluation_plan_bytes(
            changed_plan,
            strategy_review_policy=policy,
            strategy_resolver=resolver,
        )


@pytest.mark.parametrize("lifecycle", tuple(registry.ArmLifecycleState))
def test_parked_access_control_scope_cannot_enter_a_plan(lifecycle: registry.ArmLifecycleState) -> None:
    configuration = _configuration("access-control-arm", family="access_control")
    if lifecycle is registry.ArmLifecycleState.PARKED:
        decision, policy, resolver = _reviewed_strategy_decision(configuration, label="unaccepted-access-control")
    else:
        decision, policy, resolver = None, None, None
    registration = _registration(
        registry.ArmRole.EXPERIMENTAL,
        configuration,
        lifecycle=lifecycle,
        decision=decision,
    )

    with pytest.raises(registry.ArmRegistryError, match="access-control arm remains parked"):
        _plan((registration,), policy=policy, resolver=resolver)


def test_duplicate_arm_and_role_kind_mismatch_are_refused() -> None:
    configuration = _configuration("same-arm")
    duplicate = (
        _registration(registry.ArmRole.SHIPPED, configuration),
        _registration(registry.ArmRole.EXPERIMENTAL, configuration),
    )

    with pytest.raises(registry.ArmRegistryError, match="unique arm identities"):
        _plan(duplicate)
    with pytest.raises(registry.ArmRegistryError, match="combined role requires"):
        _registration(registry.ArmRole.COMBINED, configuration)


def test_direct_plan_construction_rejects_an_extra_unregistered_core_arm() -> None:
    plan = _plan()
    inputs = tuple(sorted({slot.input_identity_digest for slot in plan.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=plan.declaration.population_digest,
        freeze_digest=plan.declaration.freeze_digest,
        input_set_digest=plan.declaration.input_set_digest,
        arm_configurations=(*plan.declaration.arm_configurations, _configuration("unregistered-arm")),
        input_identity_digests=inputs,
    )

    with pytest.raises(registry.ArmRegistryError, match="do not equal registered arms"):
        registry.RegisteredEvaluationPlanV1(
            plan.registrations,
            declaration,
            derive_evaluation_baselines(declaration),
            "",
        )


def test_registry_requires_exact_core_v3_configuration_type() -> None:
    class Lookalike:
        arm_id = "lookalike"

    with pytest.raises(registry.ArmRegistryError, match="exact ArmConfigurationV3"):
        registry.ArmRegistrationV1(  # type: ignore[arg-type]
            registry.ArmRole.EXPERIMENTAL,
            registry.ArmLifecycleState.ACTIVE,
            None,
            Lookalike(),
            "",
        )


def test_registry_rejects_strategy_authority_lookalikes() -> None:
    class LookalikeAuthority:
        authority_digest = _digest("lookalike-authority")

    with pytest.raises(registry.ArmRegistryError, match="exact reviewed strategy-decision authority"):
        registry.ArmRegistrationV1(  # type: ignore[arg-type]
            registry.ArmRole.EXPERIMENTAL,
            registry.ArmLifecycleState.PARKED,
            LookalikeAuthority(),
            _configuration("lookalike-arm", family="path_traversal"),
            "",
        )


def test_plan_contract_has_no_label_or_result_surface() -> None:
    plan = _plan()
    contract_fields = {field.name for field in fields(registry.RegisteredEvaluationPlanV1)}
    registration_fields = {field.name for field in fields(registry.ArmRegistrationV1)}
    content = registry.registered_evaluation_plan_bytes(plan)

    assert not {"labels", "label_bytes", "expected_outcomes", "results", "findings"} & contract_fields
    assert not {"labels", "label_bytes", "expected_outcomes", "results", "findings"} & registration_fields
    for forbidden in (b"label_bytes", b"expected_outcomes", b"findings", b"password=", b"/home/"):
        assert forbidden not in content
