"""Authorize fitted components from one exact completed V3 arm scope."""

from __future__ import annotations

from openultrasast.core import canonical
from openultrasast.core._closed_graph import exact_dataclass_problem
from openultrasast.core._evaluation_fitted_shape import (
    fitted_evidence_problem,
    fitting_lineage_problem,
    probe_input_problem,
    repository_holdout_problem,
)
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_fitted import (
    FittedComponentAuthorizationError,
    FittedComponentEvidence,
    _evaluate_probes,
    _validate_evidence,
    _validate_fitting_lineage_for_population,
    _validate_holdout,
)
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.custody import PopulationCustodyPort
from openultrasast.core.evaluation_measurement import ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_replay_validation import validate_evaluation_replay_v3
from openultrasast.core.evaluation_report import ArmEvaluationReportV3, ScopeAdmissionResultV3
from openultrasast.core.family_catalog import resolve_contract
from openultrasast.core.lineage import LineageManifest
from openultrasast.core.measurement_record import RepositoryHoldoutReport
from openultrasast.core.model import ModelProgramDeclaration
from openultrasast.core.probes import ProbeEvaluationInput


def _exact(value: object, expected_type: type[object], field: str) -> None:
    problem = exact_dataclass_problem(value, expected_type, field)
    if problem is not None:
        raise FittedComponentAuthorizationError(problem)


def _validate_boundary(
    evidence: FittedComponentEvidence,
    probe_inputs: tuple[ProbeEvaluationInput, ...],
    fitting_lineage: LineageManifest,
    repository_holdout: RepositoryHoldoutReport,
    key: ArmScopeKey,
) -> None:
    _shape(fitted_evidence_problem(evidence))
    if type(probe_inputs) is not tuple or not probe_inputs:
        raise FittedComponentAuthorizationError("probe inputs must use a nonempty exact tuple")
    for index, item in enumerate(probe_inputs):
        _shape(probe_input_problem(item, index))
    _shape(fitting_lineage_problem(fitting_lineage))
    _shape(repository_holdout_problem(repository_holdout))
    _validate_evidence(evidence)
    _exact(key, ArmScopeKey, "arm-scope key")
    _exact(key.scope, ScopeKey, "arm-scope key scope")
    key.__post_init__()


def _shape(problem: str | None) -> None:
    if problem is not None:
        raise FittedComponentAuthorizationError(f"closed V3 fitted graph violation: {problem}")


def _select_result(
    reports: tuple[ArmEvaluationReportV3, ...],
    key: ArmScopeKey,
) -> tuple[ArmEvaluationReportV3, ScopeAdmissionResultV3]:
    report_matches = tuple(report for report in reports if report.baseline.arm_id == key.arm_id)
    if len(report_matches) != 1:
        raise FittedComponentAuthorizationError("arm-scope key must select exactly one completed arm report")
    report = report_matches[0]
    result_matches = tuple(result for result in report.scoped_results if result.key == key)
    if len(result_matches) != 1:
        raise FittedComponentAuthorizationError("arm-scope key must select exactly one completed scope result")
    result = result_matches[0]
    if result.decision is not AdmissionDecision.GO:
        raise FittedComponentAuthorizationError("selected completed arm-scope result is not GO")
    return report, result


def _select_program(
    replay: EvaluationReplayV3,
    key: ArmScopeKey,
    component_digest: str,
    context: AdmissionValidationContext,
) -> ModelProgramDeclaration:
    configurations = tuple(
        item for item in replay.plan_manifest.declaration.arm_configurations if item.arm_id == key.arm_id and key.scope in item.exact_scopes
    )
    if len(configurations) != 1:
        raise FittedComponentAuthorizationError("arm-scope key must select exactly one planned configuration")
    configuration = configurations[0]
    matches = tuple(
        item
        for item in context.evidence.model_programs
        if item.fitted_component_digest == component_digest
        and item.configuration_digest == configuration.configuration_digest
        and _program_resolves_scope(item, key, context)
    )
    if len(matches) != 1:
        raise FittedComponentAuthorizationError("fitted component must resolve one exact planned model declaration")
    return matches[0]


def _program_resolves_scope(
    program: ModelProgramDeclaration,
    key: ArmScopeKey,
    context: AdmissionValidationContext,
) -> bool:
    try:
        resolve_contract(
            context.evidence.family_catalog,
            key.scope.family_id,
            program.family_contract_digest,
            key.scope.ecosystem,
        )
    except (LookupError, ValueError):
        return False
    return True


def _authorize_validated(
    evidence: FittedComponentEvidence,
    probe_inputs: tuple[ProbeEvaluationInput, ...],
    fitting_lineage: LineageManifest,
    repository_holdout: RepositoryHoldoutReport,
    replay: EvaluationReplayV3,
    key: ArmScopeKey,
    reports: tuple[ArmEvaluationReportV3, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    _validate_boundary(evidence, probe_inputs, fitting_lineage, repository_holdout, key)
    report, _ = _select_result(reports, key)
    if evidence.admission_report_digest != report.report_digest:
        raise FittedComponentAuthorizationError("selected arm report does not match fitted evidence")
    program = _select_program(replay, key, evidence.component_digest, context)
    _validate_holdout(evidence, repository_holdout, program, context, resolver)
    results = _evaluate_probes(probe_inputs, evidence.component_digest, program, context, resolver)
    if results != evidence.probe_result_digests:
        raise FittedComponentAuthorizationError("derived probe results do not match fitted evidence")
    _validate_fitting_lineage_for_population(
        evidence,
        fitting_lineage,
        program,
        replay.plan_manifest.declaration.population_digest,
        context,
        custody,
    )


def authorize_fitted_component_v3(
    evidence: FittedComponentEvidence,
    probe_inputs: tuple[ProbeEvaluationInput, ...],
    fitting_lineage: LineageManifest,
    repository_holdout: RepositoryHoldoutReport,
    replay: EvaluationReplayV3,
    key: ArmScopeKey,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    """Require a complete replay and one exact GO scope before fitted checks."""
    try:
        reports = validate_evaluation_replay_v3(replay, context, custody, resolver)
        _authorize_validated(
            evidence,
            probe_inputs,
            fitting_lineage,
            repository_holdout,
            replay,
            key,
            reports,
            context,
            custody,
            resolver,
        )
    except FittedComponentAuthorizationError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise FittedComponentAuthorizationError(f"V3 fitted component authorization refused: {exc}") from exc


__all__ = ["authorize_fitted_component_v3"]
