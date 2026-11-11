"""Independent current-trust validation for complete evaluation-admission V3 replay."""

from __future__ import annotations

from openultrasast.core import canonical
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.custody import PopulationCustodyPort
from openultrasast.core.evaluation_aggregate import EvaluationAggregateV3, derive_evaluation_aggregate_v3
from openultrasast.core.evaluation_attempt import validate_evaluation_attempt_history
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionAuthorityV3,
    _make_authority,
    _validate_manifest_review,
    _validate_readiness,
)
from openultrasast.core.evaluation_combination import CombinationLineageV3, derive_combination_lineages_v3
from openultrasast.core.evaluation_feasibility import EvaluationFeasibilityV3, derive_evaluation_feasibility
from openultrasast.core.evaluation_measurement import MetricId
from openultrasast.core.evaluation_metric_derivation import derive_scoped_metrics_v3
from openultrasast.core.evaluation_observation import ArmObservationSetV3, validate_evaluation_observations
from openultrasast.core.evaluation_ordinary_projection import project_ordinary_pushes_v3
from openultrasast.core.evaluation_release import validate_admission_case_release_v3
from openultrasast.core.evaluation_replay import (
    EvaluationReplayReportSourceV3,
    EvaluationReplayV3,
    assemble_evaluation_replay_v3,
)
from openultrasast.core.evaluation_report import (
    ArmEvaluationReportV3,
    WholePopulationCoverageV3,
    derive_completed_evaluation_reports_v3,
)
from openultrasast.core.evaluation_spend import EvaluationSpendBindingV3, bind_evaluation_spend
from openultrasast.core.evaluation_version import require_exact_v3_contract


class EvaluationReplayValidationError(ValueError):
    """A complete replay did not reproduce against current trust and custody state."""


_ReplayedReports = tuple[
    EvaluationReplayReportSourceV3,
    tuple[ArmEvaluationReportV3, ...],
    WholePopulationCoverageV3,
    tuple[CombinationLineageV3, ...],
]


def _revalidate_admission_sources(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[EvaluationFeasibilityV3, EvaluationAdmissionAuthorityV3, tuple[ArmObservationSetV3, ...]]:
    if type(context) is not AdmissionValidationContext:
        raise EvaluationReplayValidationError("validation context must use exact AdmissionValidationContext")
    _validate_context(context)
    policy = context.admission_review_policy
    feasibility = derive_evaluation_feasibility(replay.plan_manifest, policy, resolver)
    _validate_manifest_review(replay.admission_manifest, context, resolver)
    observations = validate_evaluation_observations(
        replay.plan_manifest.declaration,
        replay.admission_manifest.observations,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_evidence_bytes,
    )
    validate_evaluation_attempt_history(
        replay.plan_manifest,
        replay.admission_manifest.attempt_history,
        policy,
        resolver,
    )
    readiness = replay.report_source.readiness
    _validate_readiness(replay.admission_manifest, readiness)
    return feasibility, _make_authority(replay.admission_manifest, context), observations


def _revalidate_spend_and_release(
    replay: EvaluationReplayV3,
    authority: EvaluationAdmissionAuthorityV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationSpendBindingV3:
    spend = bind_evaluation_spend(
        replay.admission_manifest,
        replay.preparation,
        replay.receipt,
        context,
        custody,
    )
    validate_admission_case_release_v3(
        replay.admission_manifest,
        authority,
        replay.preparation,
        replay.receipt,
        spend,
        replay.case_release,
        replay.cases_by_arm,
        context,
        custody,
        resolver,
    )
    return spend


def _rederive_reports(
    replay: EvaluationReplayV3,
    authority: EvaluationAdmissionAuthorityV3,
    spend: EvaluationSpendBindingV3,
    observations: tuple[ArmObservationSetV3, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> _ReplayedReports:
    metrics = derive_scoped_metrics_v3(
        replay.admission_manifest,
        authority,
        replay.preparation,
        replay.receipt,
        spend,
        replay.case_release,
        replay.cases_by_arm,
        context,
        custody,
        resolver,
    )
    projection = project_ordinary_pushes_v3(
        replay.admission_manifest,
        authority,
        replay.preparation,
        replay.receipt,
        spend,
        replay.case_release,
        replay.cases_by_arm,
        context,
        custody,
        resolver,
    )
    lineages = derive_combination_lineages_v3(replay.plan_manifest.declaration, replay.case_release.bindings)
    readiness = replay.report_source.readiness
    reports, whole = derive_completed_evaluation_reports_v3(
        replay.plan_manifest,
        replay.cases_by_arm,
        metrics,
        readiness,
        observations,
        lineages,
        projection.whole_population,
    )
    source = EvaluationReplayReportSourceV3(metrics, readiness, observations, projection.whole_population, "")
    return source, reports, whole, lineages


def _rederive_aggregate(
    replay: EvaluationReplayV3,
    reports: tuple[ArmEvaluationReportV3, ...],
) -> EvaluationAggregateV3 | None:
    if replay.aggregate is None:
        return None
    metrics = tuple(metric for report in reports for result in report.scoped_results for metric in result.metrics)
    keys = tuple(sorted({metric.key for metric in metrics}))
    sample_counts = tuple(
        next(metric.sample_count for metric in metrics if metric.key == key and metric.metric_id is MetricId.PRECISION) for key in keys
    )
    return derive_evaluation_aggregate_v3(metrics, sample_counts, replay.aggregate.weights)


def _expected_replay(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationReplayV3:
    feasibility, authority, observations = _revalidate_admission_sources(replay, context, resolver)
    spend = _revalidate_spend_and_release(replay, authority, context, custody, resolver)
    source, reports, whole, lineages = _rederive_reports(replay, authority, spend, observations, context, custody, resolver)
    aggregate = _rederive_aggregate(replay, reports)
    return assemble_evaluation_replay_v3(
        replay.plan_manifest,
        feasibility,
        replay.admission_manifest,
        authority,
        replay.preparation,
        replay.receipt,
        spend,
        replay.case_release,
        replay.cases_by_arm,
        source,
        reports,
        lineages,
        replay.admission_manifest.attempt_history.head_event_digest,
        whole,
        aggregate,
    )


def validate_evaluation_replay_v3(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ArmEvaluationReportV3, ...]:
    """Re-resolve current sources and return reports only from one exactly reproduced replay."""
    try:
        require_exact_v3_contract(replay, EvaluationReplayV3, field="evaluation replay")
        expected = _expected_replay(replay, context, custody, resolver)
        if replay != expected:
            raise EvaluationReplayValidationError("replay differs from canonical current source derivation")
        return tuple(expected.reports)
    except EvaluationReplayValidationError:
        raise
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReplayValidationError(f"authoritative V3 replay validation refused: {exc}") from exc


__all__ = ["EvaluationReplayValidationError", "validate_evaluation_replay_v3"]
