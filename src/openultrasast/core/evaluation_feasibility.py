"""Label-blind per-arm/per-scope feasibility for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, cast

from openultrasast.core import canonical
from openultrasast.core._metric_algebra import metric_values
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmScopeKey,
    Comparator,
    IntervalPrecisionRuleV3,
    MetricId,
    ScopeKey,
    Statistic,
)
from openultrasast.core.evaluation_plan import (
    EvaluationPlanError,
    EvaluationPlanManifestV3,
    ExactScopeCensusV3,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
    validate_reviewed_evaluation_plan,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.factpack import ReviewIndependencePolicy

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "openultrasast.detection-core.evaluation-feasibility.v3"


class EvaluationFeasibilityError(ValueError):
    """A feasibility value is incomplete, non-canonical, or caller-summarized."""


class FeasibilityStatusV3(Enum):
    FEASIBLE = "feasible"
    INSUFFICIENT = "insufficient"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationFeasibilityError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise EvaluationFeasibilityError(f"{field} must be a non-negative integer")
    return value


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _SCHEMA, "kind": kind, "payload": payload}


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationFeasibilityError(f"{field} does not match canonical content")


@dataclass(frozen=True)
class ThresholdFeasibilityV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    threshold_digest: str
    attainable: bool
    witness_numerator: int
    witness_denominator: int
    witness_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ThresholdFeasibilityV3, field="threshold feasibility")
        _digest(self.threshold_digest, "threshold digest")
        if type(self.attainable) is not bool:
            raise EvaluationFeasibilityError("attainable must be exact boolean")
        numerator = _count(self.witness_numerator, "witness numerator")
        denominator = _count(self.witness_denominator, "witness denominator")
        if numerator > denominator:
            raise EvaluationFeasibilityError("witness numerator exceeds denominator")
        payload = {
            "threshold_digest": self.threshold_digest,
            "attainable": self.attainable,
            "witness_numerator": numerator,
            "witness_denominator": denominator,
        }
        _bind(self, "witness_digest", canonical.content_digest(_value("threshold_feasibility", cast(canonical.JsonValue, payload))))


@dataclass(frozen=True)
class SufficiencyResultV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    rule_digest: str
    minimum_size_passed: bool
    interval_precision_passed: bool
    reasons: tuple[str, ...]
    result_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, SufficiencyResultV3, field="sufficiency result")
        _digest(self.rule_digest, "sufficiency rule digest")
        if type(self.minimum_size_passed) is not bool or type(self.interval_precision_passed) is not bool:
            raise EvaluationFeasibilityError("sufficiency flags must be exact booleans")
        if type(self.reasons) is not tuple or any(type(item) is not str or not item for item in self.reasons):
            raise EvaluationFeasibilityError("sufficiency reasons must be exact nonempty text")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise EvaluationFeasibilityError("sufficiency reasons must be unique and canonical")
        if (self.minimum_size_passed and self.interval_precision_passed) != (not self.reasons):
            raise EvaluationFeasibilityError("sufficiency reasons do not match flags")
        payload = {
            "rule_digest": self.rule_digest,
            "minimum_size_passed": self.minimum_size_passed,
            "interval_precision_passed": self.interval_precision_passed,
            "reasons": self.reasons,
        }
        _bind(self, "result_digest", canonical.content_digest(_value("sufficiency_result", cast(canonical.JsonValue, payload))))


@dataclass(frozen=True)
class ScopeFeasibilityV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    threshold_witnesses: tuple[ThresholdFeasibilityV3, ...]
    sufficiency_results: tuple[SufficiencyResultV3, ...]
    status: FeasibilityStatusV3
    reasons: tuple[str, ...]
    result_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopeFeasibilityV3, field="scope feasibility")
        if type(self.key) is not ArmScopeKey:
            raise EvaluationFeasibilityError("scope feasibility requires exact ArmScopeKey")
        self.key.__post_init__()
        if (
            type(self.threshold_witnesses) is not tuple
            or len(self.threshold_witnesses) != len(MetricId)
            or any(type(x) is not ThresholdFeasibilityV3 for x in self.threshold_witnesses)
        ):
            raise EvaluationFeasibilityError("threshold witnesses must contain every standard metric in canonical order")
        if type(self.sufficiency_results) is not tuple or len(self.sufficiency_results) != 1:
            raise EvaluationFeasibilityError("scope feasibility requires one sufficiency result")
        for witness in self.threshold_witnesses:
            witness.__post_init__()
        for sufficiency in self.sufficiency_results:
            sufficiency.__post_init__()
        if (
            type(self.status) is not FeasibilityStatusV3
            or type(self.reasons) is not tuple
            or any(type(item) is not str or not item for item in self.reasons)
        ):
            raise EvaluationFeasibilityError("scope status and reasons must use closed values")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise EvaluationFeasibilityError("scope reasons must be unique and canonical")
        passed = all(x.attainable for x in self.threshold_witnesses) and not self.sufficiency_results[0].reasons
        if (self.status is FeasibilityStatusV3.FEASIBLE) != passed or (not self.reasons) != passed:
            raise EvaluationFeasibilityError("scope status does not match derived feasibility")
        payload = {
            "key": {"arm_id": self.key.arm_id, "family_id": self.key.scope.family_id, "ecosystem": self.key.scope.ecosystem},
            "threshold_witness_digests": tuple(x.witness_digest for x in self.threshold_witnesses),
            "sufficiency_result_digests": tuple(x.result_digest for x in self.sufficiency_results),
            "status": self.status.value,
            "reasons": self.reasons,
        }
        _bind(self, "result_digest", canonical.content_digest(_value("scope_feasibility", cast(canonical.JsonValue, payload))))


@dataclass(frozen=True)
class EvaluationFeasibilityV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    plan_manifest_digest: str
    rows: tuple[ScopeFeasibilityV3, ...]
    may_spend: bool
    feasibility_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationFeasibilityV3, field="evaluation feasibility")
        _digest(self.plan_manifest_digest, "plan manifest digest")
        if type(self.rows) is not tuple or not self.rows or any(type(x) is not ScopeFeasibilityV3 for x in self.rows):
            raise EvaluationFeasibilityError("feasibility rows must be nonempty exact values")
        for row in self.rows:
            row.__post_init__()
        if tuple(row.key for row in self.rows) != tuple(sorted({row.key for row in self.rows})):
            raise EvaluationFeasibilityError("feasibility rows must be unique and canonical")
        expected = all(row.status is FeasibilityStatusV3.FEASIBLE for row in self.rows)
        if type(self.may_spend) is not bool or self.may_spend != expected:
            raise EvaluationFeasibilityError("may_spend must equal all-row feasibility")
        payload = {
            "plan_manifest_digest": self.plan_manifest_digest,
            "row_digests": tuple(row.result_digest for row in self.rows),
            "may_spend": self.may_spend,
        }
        _bind(self, "feasibility_digest", canonical.content_digest(_value("evaluation_feasibility", cast(canonical.JsonValue, payload))))


def _counts(metric: MetricId, scope: ExactScopeCensusV3, ordinary: int) -> tuple[int, int]:
    capacities = {
        MetricId.PAIRED_CORRECTNESS: scope.pair_count,
        MetricId.VULNERABLE_RECALL: scope.vulnerable_side_count,
        MetricId.FIXED_FALSE_ALARM_RATE: scope.fixed_side_count,
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: ordinary,
        MetricId.SEMANTIC_STAGE_COVERAGE: scope.semantic_site_capacity,
        MetricId.MODEL_SUCCESS_RATE: scope.model_call_capacity,
    }
    if metric is MetricId.PRECISION:
        if scope.vulnerable_side_count:
            return scope.vulnerable_side_count, scope.vulnerable_side_count
        return (0, 1) if scope.fixed_side_count or ordinary else (0, 0)
    denominator = capacities[metric]
    return (0 if metric in {MetricId.FIXED_FALSE_ALARM_RATE, MetricId.ORDINARY_FALSE_ALARMS_PER_100} else denominator, denominator)


def _stat(metric: MetricId, numerator: int, denominator: int, statistic: Statistic) -> float | None:
    if denominator == 0:
        return None
    value, lower, upper = metric_values(metric.value, numerator, denominator)
    return {
        Statistic.COUNT: float(numerator),
        Statistic.RATE: value,
        Statistic.PER_100: value,
        Statistic.WILSON_LOWER: lower,
        Statistic.WILSON_UPPER: upper,
    }[statistic]


def _validated_manifest(
    manifest: object,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> EvaluationPlanManifestV3:
    if type(manifest) is not EvaluationPlanManifestV3:
        raise EvaluationFeasibilityError("manifest must use exact EvaluationPlanManifestV3")
    try:
        validate_reviewed_evaluation_plan(manifest.census, manifest, policy, resolver)
    except EvaluationPlanError as exc:
        raise EvaluationFeasibilityError(f"reviewed plan is invalid: {exc}") from exc
    if manifest.census.payload_digest != derive_evaluation_census_payload_digest(manifest.census):
        raise EvaluationFeasibilityError("census payload digest cannot be re-derived")
    if manifest.census.census_digest != derive_evaluation_census_digest(manifest.census):
        raise EvaluationFeasibilityError("census digest cannot be re-derived")
    if manifest.payload_digest != derive_evaluation_plan_manifest_payload_digest(manifest):
        raise EvaluationFeasibilityError("manifest payload digest cannot be re-derived")
    if manifest.manifest_digest != derive_evaluation_plan_manifest_digest(manifest):
        raise EvaluationFeasibilityError("manifest digest cannot be re-derived")
    return manifest


def _census_maps(
    manifest: EvaluationPlanManifestV3,
) -> tuple[dict[ScopeKey, ExactScopeCensusV3], dict[str, int]]:
    planned_scopes = tuple(
        sorted({scope for configuration in manifest.declaration.arm_configurations for scope in configuration.exact_scopes})
    )
    actual_scopes = tuple(row.scope for row in manifest.census.scope_rows)
    if actual_scopes != planned_scopes:
        raise EvaluationFeasibilityError("census scopes do not exactly match planned scopes")
    planned_ecosystems = tuple(sorted({scope.ecosystem for scope in planned_scopes}))
    actual_ecosystems = tuple(row.ecosystem for row in manifest.census.ordinary_rows)
    if actual_ecosystems != planned_ecosystems:
        raise EvaluationFeasibilityError("ordinary census ecosystems do not exactly match planned ecosystems")
    return (
        {row.scope: row for row in manifest.census.scope_rows},
        {row.ecosystem: row.ordinary_push_count for row in manifest.census.ordinary_rows},
    )


def _precision_passes(precision: IntervalPrecisionRuleV3, census: ExactScopeCensusV3, ordinary: int) -> bool:
    numerator, denominator = _counts(precision.metric_id, census, ordinary)
    _, lower, upper = metric_values(precision.metric_id.value, numerator, denominator)
    return (
        denominator >= precision.minimum_denominator
        and lower is not None
        and upper is not None
        and upper - lower <= precision.maximum_wilson_width
    )


def _scope_row(config: ArmConfigurationV3, scope_key: ScopeKey, census: ExactScopeCensusV3, ordinary: int) -> ScopeFeasibilityV3:
    key = ArmScopeKey(config.arm_id, scope_key)
    thresholds = {(row.key, row.metric_id): row for row in config.thresholds}
    witnesses = []
    for metric in MetricId:
        threshold = thresholds[(key, metric)]
        numerator, denominator = _counts(metric, census, ordinary)
        observed = _stat(metric, numerator, denominator, threshold.statistic)
        attainable = observed is not None and (
            observed >= threshold.target if threshold.comparator is Comparator.AT_LEAST else observed <= threshold.target
        )
        witnesses.append(ThresholdFeasibilityV3(threshold.threshold_digest, attainable, numerator, denominator, ""))
    rule = next(row for row in config.sufficiency_rules if row.key == key)
    minimum_ok = census.pair_count >= rule.minimum_pairs and ordinary >= rule.minimum_ordinary_pushes
    precision_ok = all(_precision_passes(item, census, ordinary) for item in rule.precision_rules)
    reasons = tuple(sorted(({"minimum_size"} if not minimum_ok else set()) | ({"interval_precision"} if not precision_ok else set())))
    sufficiency = SufficiencyResultV3(rule.rule_digest, minimum_ok, precision_ok, reasons, "")
    thresholds_ok = all(item.attainable for item in witnesses)
    row_reasons = tuple(sorted(({"threshold_unreachable"} if not thresholds_ok else set()) | set(reasons)))
    status = FeasibilityStatusV3.FEASIBLE if thresholds_ok and not reasons else FeasibilityStatusV3.INSUFFICIENT
    return ScopeFeasibilityV3(key, tuple(witnesses), (sufficiency,), status, row_reasons, "")


def derive_evaluation_feasibility(
    manifest: EvaluationPlanManifestV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> EvaluationFeasibilityV3:
    manifest = _validated_manifest(manifest, policy, resolver)
    scopes, ordinary = _census_maps(manifest)
    result_rows = tuple(
        _scope_row(config, scope, scopes[scope], ordinary[scope.ecosystem])
        for config in manifest.declaration.arm_configurations
        for scope in config.exact_scopes
    )
    return EvaluationFeasibilityV3(
        manifest.manifest_digest, result_rows, all(row.status is FeasibilityStatusV3.FEASIBLE for row in result_rows), ""
    )


def validate_evaluation_feasibility(
    manifest: EvaluationPlanManifestV3,
    feasibility: EvaluationFeasibilityV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    if type(feasibility) is not EvaluationFeasibilityV3:
        raise EvaluationFeasibilityError("feasibility must use exact EvaluationFeasibilityV3")
    if feasibility != derive_evaluation_feasibility(manifest, policy, resolver):
        raise EvaluationFeasibilityError("feasibility does not match canonical derivation")


__all__ = [
    "EvaluationFeasibilityError",
    "EvaluationFeasibilityV3",
    "FeasibilityStatusV3",
    "ScopeFeasibilityV3",
    "SufficiencyResultV3",
    "ThresholdFeasibilityV3",
    "derive_evaluation_feasibility",
    "validate_evaluation_feasibility",
]
