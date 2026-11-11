"""Exact arm/family/ecosystem quality partitioning for evaluation V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_evaluation_case_validation import (
    _bundle,
    _multi_scope_authority_case,
)

from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.evaluation_measurement import ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_release import ArmAdmissionCasesV3
from openultrasast.core.model import ModelStatus


def _partition(bundle):
    from openultrasast.core.evaluation_scoped_metrics import partition_scoped_quality_evidence_v3

    reviewed_case = bundle[5]
    return partition_scoped_quality_evidence_v3(
        bundle[3],
        bundle[6],
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        bundle[2],
        reviewed_case[0].context,
        reviewed_case[0].port,
        bundle[4],
    )


def test_multi_arm_multi_scope_evidence_is_partitioned_by_exact_key() -> None:
    partitions = _partition(_bundle(authority_case=_multi_scope_authority_case()))

    assert tuple(partition.key for partition in partitions) == (
        ArmScopeKey("arm-a", ScopeKey("reference-family", "python")),
        ArmScopeKey("arm-b", ScopeKey("reference-family", "javascript")),
        ArmScopeKey("arm-combined", ScopeKey("reference-family", "python")),
    )
    for partition in partitions:
        assert partition.denominator_policy.key == partition.key
        assert all(case.key == partition.key for case in partition.cases)
        assert all(case.family_decision_codes == ("unsafe",) for case in partition.cases)
        assert partition.family_decision_vocabulary == ("unsafe", "safe")
        assert len(partition.pairs) == 1
        assert partition.pairs[0].key == partition.key
        assert partition.precision_denominator_case_digests == tuple(case.case_id_digest for case in partition.cases)
        assert partition.precision_numerator_case_digests == tuple(
            case.case_id_digest for case in partition.cases if case.role is AdmissionCaseRole.VULNERABLE
        )


def test_pair_membership_and_precision_membership_never_cross_scope() -> None:
    partitions = _partition(_bundle(authority_case=_multi_scope_authority_case()))
    all_case_digests = {partition.key: {case.case_id_digest for case in partition.cases} for partition in partitions}

    for partition in partitions:
        pair = partition.pairs[0]
        assert {pair.vulnerable_case_id_digest, pair.fixed_case_id_digest} <= all_case_digests[partition.key]
        assert set(partition.precision_denominator_case_digests) <= all_case_digests[partition.key]
        assert set(partition.precision_numerator_case_digests) <= set(partition.precision_denominator_case_digests)
        assert not any(
            {pair.vulnerable_case_id_digest, pair.fixed_case_id_digest} & case_digests
            for key, case_digests in all_case_digests.items()
            if key != partition.key
        )


def test_partition_preserves_outcomes_bases_models_and_semantic_coverage_per_case() -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case())
    partitions = _partition(bundle)
    source_cases = {(case.key, case.case_id_digest): case for group in bundle[2] for case in group.cases}

    for partition in partitions:
        for evidence in partition.cases:
            source = source_cases[(partition.key, evidence.case_id_digest)]
            assert evidence.neutral_outcome is source.outcome_projection.normalized_outcome
            assert evidence.evidence_bases == tuple(claim.basis for claim in source.claims)
            assert evidence.model_outcomes == tuple(
                value.model_result.status for value in source.evidence_inputs if value.model_result is not None
            )
            assert evidence.semantic_coverage == source.coverage
            assert evidence.has_findings is bool(source.claims)


def test_pair_correctness_and_precision_membership_derive_from_key_local_findings() -> None:
    from openultrasast.core.evaluation_scoped_metrics import ScopedQualityPartitionError

    partition = _partition(_bundle(authority_case=_multi_scope_authority_case()))[0]
    vulnerable = next(case for case in partition.cases if case.role is AdmissionCaseRole.VULNERABLE)
    fixed = next(case for case in partition.cases if case.role is AdmissionCaseRole.FIXED)
    ordinary = next(case for case in partition.cases if case.role is AdmissionCaseRole.ORDINARY)
    fixed = replace(fixed, has_findings=False, evidence_bases=())
    ordinary = replace(ordinary, model_outcomes=(ModelStatus.SUCCEEDED,))
    cases = tuple(
        sorted(
            (vulnerable, fixed, ordinary),
            key=lambda case: case.case_id_digest,
        )
    )
    pair = replace(partition.pairs[0], is_correct=True)
    precision_denominator = tuple(case.case_id_digest for case in cases if case.has_findings)
    precision_numerator = tuple(case.case_id_digest for case in cases if case.has_findings and case.role is AdmissionCaseRole.VULNERABLE)
    derived = replace(
        partition,
        cases=cases,
        pairs=(pair,),
        precision_numerator_case_digests=precision_numerator,
        precision_denominator_case_digests=precision_denominator,
    )

    assert derived.pairs[0].is_correct is True
    assert derived.precision_numerator_case_digests == (vulnerable.case_id_digest,)
    assert set(derived.precision_numerator_case_digests) < set(derived.precision_denominator_case_digests)
    assert next(case for case in derived.cases if case.role is AdmissionCaseRole.ORDINARY).model_outcomes == (ModelStatus.SUCCEEDED,)
    with pytest.raises(ScopedQualityPartitionError, match="precision membership"):
        replace(derived, precision_denominator_case_digests=(ordinary.case_id_digest,))


@pytest.mark.parametrize(
    "key",
    (
        ArmScopeKey("arm-a", ScopeKey("reference-family", "javascript")),
        ArmScopeKey("arm-b", ScopeKey("other-family", "javascript")),
        ArmScopeKey("other-arm", ScopeKey("reference-family", "javascript")),
    ),
)
def test_cross_ecosystem_family_or_arm_case_contribution_is_refused(key: ArmScopeKey) -> None:
    from openultrasast.core.evaluation_scoped_metrics import ScopedQualityPartitionError

    bundle = _bundle(authority_case=_multi_scope_authority_case())
    group = bundle[2][1]
    original = group.cases[0]
    changed = replace(original, key=key)
    if key.arm_id == group.arm_id:
        changed_cases = tuple(
            sorted(
                (changed,) + group.cases[1:],
                key=lambda case: (case.key.scope.family_id, case.key.scope.ecosystem, case.case_id_digest),
            )
        )
        changed_group = replace(group, cases=changed_cases, cases_digest="")
    else:
        changed_group = object.__new__(ArmAdmissionCasesV3)
        object.__setattr__(changed_group, "arm_id", group.arm_id)
        object.__setattr__(changed_group, "baseline_digest", group.baseline_digest)
        object.__setattr__(changed_group, "cases", (changed,) + group.cases[1:])
        object.__setattr__(changed_group, "cases_digest", group.cases_digest)
    groups = bundle[2][:1] + (changed_group,) + bundle[2][2:]

    reviewed_case = bundle[5]
    from openultrasast.core.evaluation_scoped_metrics import partition_scoped_quality_evidence_v3

    with pytest.raises(ScopedQualityPartitionError, match="release|scope|arm|case"):
        partition_scoped_quality_evidence_v3(
            bundle[3],
            bundle[6],
            bundle[7],
            bundle[8],
            bundle[9],
            bundle[1],
            groups,
            reviewed_case[0].context,
            reviewed_case[0].port,
            bundle[4],
        )


def test_partition_rows_are_non_authorizing_and_do_not_contain_metrics_or_decisions() -> None:
    from openultrasast.core.evaluation_scoped_metrics import ScopedQualityPartitionV3

    fields = ScopedQualityPartitionV3.__dataclass_fields__
    assert not {"metrics", "gate", "decision", "authorization"} & fields.keys()


def test_partition_refuses_non_exact_root_collections() -> None:
    from openultrasast.core.evaluation_scoped_metrics import (
        ScopedQualityPartitionError,
        partition_scoped_quality_evidence_v3,
    )

    bundle = _bundle(authority_case=_multi_scope_authority_case())
    reviewed_case = bundle[5]
    with pytest.raises(ScopedQualityPartitionError, match="exact tuple"):
        partition_scoped_quality_evidence_v3(
            bundle[3],
            bundle[6],
            bundle[7],
            bundle[8],
            bundle[9],
            bundle[1],
            list(bundle[2]),  # type: ignore[arg-type]
            reviewed_case[0].context,
            reviewed_case[0].port,
            bundle[4],
        )


def test_v2_admission_metric_contract_is_unchanged() -> None:
    from openultrasast.core import admission_metrics

    assert admission_metrics.AdmissionMetricEvidence.__dataclass_fields__.keys() == {
        "family_decision_vocabulary",
        "family_decision_counts",
        "neutral_outcome_counts",
        "evidence_basis_counts",
        "metrics",
        "stage_funnel",
        "model_outcome_counts",
        "model_failures",
        "runtime_ms",
        "whole_population_funnel",
        "whole_population_runtime_ms",
        "in_scope_case_count",
        "whole_population_case_count",
        "case_result_digests",
    }
