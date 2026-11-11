"""Replay-carried sources and deterministic report reproduction."""

from __future__ import annotations

import re
from typing import Any

from openultrasast.core import canonical
from openultrasast.core.evaluation_aggregate import validate_evaluation_aggregate_v3
from openultrasast.core.evaluation_measurement import ScopedMetricResultV3
from openultrasast.core.evaluation_observation import ArmObservationSetV3
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3
from openultrasast.core.evaluation_report import _metric_digest, derive_completed_evaluation_reports_v3
from openultrasast.core.evaluation_version import require_exact_v3_contract
from openultrasast.core.readiness import ReadinessResult, validate_readiness_result

_SCHEMA = "openultrasast.detection-core.evaluation-replay-report-source.v3"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class EvaluationReplayReportError(ValueError):
    """Replay reports do not reproduce from their carried canonical sources."""


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif type(actual) is not str or _DIGEST.fullmatch(actual) is None or actual != expected:
        raise EvaluationReplayReportError(f"{field} does not match canonical report-source content")


def _source_payload(value: Any) -> canonical.JsonValue:
    return {
        "metric_digests": tuple(_metric_digest(metric) for metric in value.metrics),
        "readiness_digests": tuple(item.result_digest for item in value.readiness),
        "observation_digests": tuple(item.observation_digest for item in value.observations),
        "whole_projection_digest": value.whole_projection.projection_digest,
    }


def validate_report_source(value: Any) -> None:
    from openultrasast.core.evaluation_replay import EvaluationReplayReportSourceV3

    require_exact_v3_contract(value, EvaluationReplayReportSourceV3, field="evaluation replay report source")
    if type(value.metrics) is not tuple or not value.metrics or any(type(item) is not ScopedMetricResultV3 for item in value.metrics):
        raise EvaluationReplayReportError("report-source metrics must be a nonempty exact tuple")
    if type(value.readiness) is not tuple or any(type(item) is not ReadinessResult for item in value.readiness):
        raise EvaluationReplayReportError("report-source readiness must use an exact tuple")
    if type(value.observations) is not tuple or any(type(item) is not ArmObservationSetV3 for item in value.observations):
        raise EvaluationReplayReportError("report-source observations must use an exact tuple")
    if type(value.whole_projection) is not WholePopulationProjectionV3:
        raise EvaluationReplayReportError("report-source whole projection must use the exact V3 contract")
    for metric in value.metrics:
        metric.__post_init__()
    for readiness in value.readiness:
        validate_readiness_result(readiness)
    for observation in value.observations:
        observation.__post_init__()
    value.whole_projection.__post_init__()
    payload = _source_payload(value)
    _bind(value, "source_digest", canonical.content_digest({"schema_version": _SCHEMA, "payload": payload}))


def validate_replayed_reports(value: Any) -> None:
    """Reproduce reports and coverage from replay-carried sources, then bind an optional aggregate."""
    from openultrasast.core.evaluation_replay import EvaluationReplayReportSourceV3

    source = value.report_source
    if type(source) is not EvaluationReplayReportSourceV3:
        raise EvaluationReplayReportError("replay report source must use exact EvaluationReplayReportSourceV3")
    source.__post_init__()
    if tuple(item.result_digest for item in source.readiness) != value.plan_manifest.readiness_digests:
        raise EvaluationReplayReportError("report-source readiness order must exactly equal the reviewed plan")
    try:
        reports, whole = derive_completed_evaluation_reports_v3(
            value.plan_manifest,
            value.cases_by_arm,
            source.metrics,
            source.readiness,
            source.observations,
            value.combination_lineages,
            source.whole_projection,
        )
        if value.reports != reports or value.whole_population_coverage != whole:
            raise EvaluationReplayReportError("reports or whole coverage do not rederive from replay-carried sources")
        metrics = tuple(metric for report in reports for result in report.scoped_results for metric in result.metrics)
        if value.aggregate is not None:
            validate_evaluation_aggregate_v3(value.aggregate, metrics)
    except EvaluationReplayReportError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReplayReportError(f"report source replay refused invalid evidence: {exc}") from exc


def validate_replay_collections(value: Any) -> None:
    from openultrasast.core.evaluation_aggregate import EvaluationAggregateV3
    from openultrasast.core.evaluation_combination import CombinationLineageV3
    from openultrasast.core.evaluation_release import ArmAdmissionCasesV3
    from openultrasast.core.evaluation_replay import EvaluationReplayReportSourceV3
    from openultrasast.core.evaluation_report import ArmEvaluationReportV3

    collections = (
        (value.cases_by_arm, ArmAdmissionCasesV3, "case groups"),
        (value.reports, ArmEvaluationReportV3, "reports"),
        (value.combination_lineages, CombinationLineageV3, "combination lineages"),
    )
    for items, item_type, field in collections:
        if type(items) is not tuple or any(type(item) is not item_type for item in items):
            raise EvaluationReplayReportError(f"{field} must use an exact tuple of {item_type.__name__}")
        for item in items:
            item.__post_init__()
    if type(value.report_source) is not EvaluationReplayReportSourceV3:
        raise EvaluationReplayReportError("report source must use exact EvaluationReplayReportSourceV3")
    value.report_source.__post_init__()
    if value.aggregate is not None and type(value.aggregate) is not EvaluationAggregateV3:
        raise EvaluationReplayReportError("aggregate must use exact EvaluationAggregateV3 when present")


__all__ = ["EvaluationReplayReportError", "validate_replay_collections", "validate_report_source", "validate_replayed_reports"]
