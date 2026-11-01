"""Authorize fitted components only from independently replayed evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._admission_replay import AdmissionReplay
from openultrasast.core.admission_context import AdmissionValidationContext, derive_outcome_mapping_digest
from openultrasast.core.admission_report import AdmissionDecision, validate_admission_replay
from openultrasast.core.custody import LineagePurpose, PopulationCustodyPort
from openultrasast.core.family import FamilyContract
from openultrasast.core.family_catalog import FamilyCatalog, derive_catalog_digest, resolve_contract
from openultrasast.core.lineage import LineageExpectation, LineageManifest, validate_lineage
from openultrasast.core.measurement import derive_identity_set_digest
from openultrasast.core.measurement_record import RepositoryHoldoutReport, validate_repository_holdout_report
from openultrasast.core.model import ModelProgramDeclaration
from openultrasast.core.probes import ProbeEvaluationInput, evaluate_probe

REPOSITORY_POPULATION_MANIFEST_SCHEMA = "openultrasast.detection-core.repository-population-manifest.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class FittedComponentAuthorizationError(ValueError):
    """A fitted component lacks reproducible release evidence."""


@dataclass(frozen=True)
class FittedComponentEvidence:
    component_digest: str
    probe_result_digests: tuple[str, ...]
    fitting_lineage_manifest_digest: str
    training_population_manifest: canonical.ContentRef
    training_repository_digests: tuple[str, ...]
    repository_holdout_report_digest: str
    admission_report_digest: str

    def __post_init__(self) -> None:
        _validate_evidence(self)


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FittedComponentAuthorizationError(f"{field} must be a full lowercase SHA-256 digest")


def _canonical_digests(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise FittedComponentAuthorizationError(f"{field} must be a nonempty tuple")
    for item in value:
        _digest(item, field.removesuffix("s"))
    if value != tuple(sorted(set(value))):
        raise FittedComponentAuthorizationError(f"{field} must be unique and canonical")
    return value


def _validate_evidence(value: FittedComponentEvidence) -> None:
    if type(value) is not FittedComponentEvidence:
        raise FittedComponentAuthorizationError("evidence must be an exact FittedComponentEvidence")
    _digest(value.component_digest, "component digest")
    _canonical_digests(value.probe_result_digests, "probe result digests")
    _digest(value.fitting_lineage_manifest_digest, "fitting lineage manifest digest")
    if type(value.training_population_manifest) is not canonical.ContentRef:
        raise FittedComponentAuthorizationError("training population manifest must be an exact ContentRef")
    value.training_population_manifest.__post_init__()
    _canonical_digests(value.training_repository_digests, "training repository digests")
    _digest(value.repository_holdout_report_digest, "repository holdout report digest")
    _digest(value.admission_report_digest, "admission report digest")


def _resolve_repository_manifest(
    reference: canonical.ContentRef,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[str, ...]:
    policy = context.evidence.provenance_trust_policy
    content = canonical.resolve_content(
        reference,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_input_bytes,
    )
    try:
        parsed = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FittedComponentAuthorizationError("repository population manifest is not valid JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "repository_digests"}:
        raise FittedComponentAuthorizationError("repository population manifest has an invalid schema")
    if parsed["schema_version"] != REPOSITORY_POPULATION_MANIFEST_SCHEMA:
        raise FittedComponentAuthorizationError("repository population manifest has an unknown schema version")
    raw = parsed["repository_digests"]
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise FittedComponentAuthorizationError("repository population manifest digests are invalid")
    values = _canonical_digests(tuple(raw), "repository digests")
    canonical_value: canonical.JsonValue = {
        "schema_version": REPOSITORY_POPULATION_MANIFEST_SCHEMA,
        "repository_digests": values,
    }
    if content != canonical.canonical_bytes(canonical_value):
        raise FittedComponentAuthorizationError("repository population manifest is not canonical")
    return values


def _program_for_component(
    component: str,
    replay: AdmissionReplay,
    context: AdmissionValidationContext,
) -> ModelProgramDeclaration:
    baseline = set(replay.report.identity.model_program_digests)
    matches = tuple(
        item
        for item in context.evidence.model_programs
        if item.fitted_component_digest == component and item.declaration_digest in baseline
    )
    if len(matches) != 1:
        raise FittedComponentAuthorizationError("component must resolve one baseline-listed model declaration")
    return matches[0]


def _contract_for_probe(
    value: ProbeEvaluationInput,
    program: ModelProgramDeclaration,
    context: AdmissionValidationContext,
) -> FamilyContract:
    if type(value) is not ProbeEvaluationInput:
        raise FittedComponentAuthorizationError("probe inputs must use exact ProbeEvaluationInput values")
    probe = value.probe
    records = (probe.forward_record, probe.reversed_record)
    families = {(item.packet.family_id, item.packet.ecosystem) for item in records}
    if len(families) != 1:
        raise FittedComponentAuthorizationError("probe records must agree on family and ecosystem")
    family_id, ecosystem = next(iter(families))
    if probe.family_contract_digest != program.family_contract_digest or any(
        item.packet.family_contract_digest != program.family_contract_digest for item in records
    ):
        raise FittedComponentAuthorizationError("probe contract does not match the fitted declaration")
    return resolve_contract(context.evidence.family_catalog, family_id, program.family_contract_digest, ecosystem)


def _evaluate_probes(
    probe_inputs: Sequence[ProbeEvaluationInput],
    component: str,
    program: ModelProgramDeclaration,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[str, ...]:
    frozen = tuple(probe_inputs)
    if not frozen:
        raise FittedComponentAuthorizationError("fitted authorization requires at least one probe")
    if len({item.probe.probe_id for item in frozen if isinstance(item, ProbeEvaluationInput)}) != len(frozen):
        raise FittedComponentAuthorizationError("fitted authorization contains duplicate probes")
    results = []
    for item in sorted(frozen, key=lambda value: value.probe.probe_id):
        contract = _contract_for_probe(item, program, context)
        if item.observation.component_digest != component:
            raise FittedComponentAuthorizationError("probe observation component does not match fitted evidence")
        result = evaluate_probe(item.probe, item.observation, contract, context.evidence.fact_review_policy, resolver)
        if not result.valid or not result.passed:
            raise FittedComponentAuthorizationError("fitted component failed a canonical reversed-pair probe")
        results.append(result.result_digest)
    return tuple(sorted(results))


def _validate_holdout(
    evidence: FittedComponentEvidence,
    holdout: RepositoryHoldoutReport,
    program: ModelProgramDeclaration,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> None:
    validate_repository_holdout_report(holdout)
    identity = holdout.measurement.identity
    if identity.population_digest != holdout.holdout_population_manifest.content_digest:
        raise FittedComponentAuthorizationError("holdout population identity does not match its resolved manifest")
    components = (evidence.component_digest,)
    if identity.model_program_digests != components or identity.model_program_set_digest != derive_identity_set_digest(
        "model_program", components
    ):
        raise FittedComponentAuthorizationError("holdout model component set does not match the selected component")
    _validate_holdout_contract(holdout, program, context)
    exact = (
        (holdout.component_digest, evidence.component_digest, "holdout component"),
        (holdout.fitting_lineage_manifest_digest, evidence.fitting_lineage_manifest_digest, "fitting lineage"),
        (holdout.report_digest, evidence.repository_holdout_report_digest, "holdout report"),
        (holdout.training_population_manifest, evidence.training_population_manifest, "training population manifest"),
        (holdout.training_repository_digests, evidence.training_repository_digests, "training repositories"),
    )
    if any(actual != expected for actual, expected, _ in exact):
        field = next(field for actual, expected, field in exact if actual != expected)
        raise FittedComponentAuthorizationError(f"{field} does not match fitted evidence")
    training = _resolve_repository_manifest(holdout.training_population_manifest, context, resolver)
    held_out = _resolve_repository_manifest(holdout.holdout_population_manifest, context, resolver)
    if training != holdout.training_repository_digests or held_out != holdout.holdout_repository_digests:
        raise FittedComponentAuthorizationError("resolved population manifests do not match repository identities")
    if set(training) & set(held_out):
        raise FittedComponentAuthorizationError("training and repository holdout populations overlap")


def _validate_holdout_contract(
    holdout: RepositoryHoldoutReport,
    program: ModelProgramDeclaration,
    context: AdmissionValidationContext,
) -> None:
    identity = holdout.measurement.identity
    if identity.family_contract_digests != (program.family_contract_digest,):
        raise FittedComponentAuthorizationError("holdout family contract does not match the fitted declaration")
    entries = tuple(entry for entry in context.evidence.family_catalog.entries if entry.contract_digest == program.family_contract_digest)
    if len(entries) != 1:
        raise FittedComponentAuthorizationError("fitted declaration contract is not unique in the admission catalog")
    selected = FamilyCatalog(entries, derive_catalog_digest(entries))
    if identity.family_contract_set_digest != selected.catalog_digest:
        raise FittedComponentAuthorizationError("holdout family contract set is not the selected exact contract")
    if identity.outcome_mapping_digest != derive_outcome_mapping_digest(selected):
        raise FittedComponentAuthorizationError("holdout outcome mapping does not match the selected exact contract")
    try:
        for scope in identity.claimed_scopes:
            resolve_contract(selected, scope.family_id, program.family_contract_digest, scope.ecosystem)
    except (LookupError, ValueError) as exc:
        raise FittedComponentAuthorizationError("holdout scope does not resolve under the selected family contract") from exc


def _validate_fitting_lineage(
    evidence: FittedComponentEvidence,
    lineage: LineageManifest,
    program: ModelProgramDeclaration,
    replay: AdmissionReplay,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> None:
    if type(lineage) is not LineageManifest or lineage.manifest_digest != evidence.fitting_lineage_manifest_digest:
        raise FittedComponentAuthorizationError("fitting lineage does not match fitted evidence")
    program_lineages = tuple(item for item in context.evidence.lineages if item.manifest_digest == program.lineage_manifest_digest)
    if len(program_lineages) != 1:
        raise FittedComponentAuthorizationError("selected program lineage is not uniquely available in the admission context")
    program_lineage = program_lineages[0]
    fitted_uses = tuple(item for item in program_lineage.uses if item.purpose is LineagePurpose.FITTED_MODEL)
    if len(fitted_uses) != 1 or fitted_uses[0].influenced_artifact_digest != evidence.component_digest:
        raise FittedComponentAuthorizationError("selected program lineage lacks one exact fitted-model use")
    if lineage.arm_id != program_lineage.arm_id or lineage.subject_digest != evidence.component_digest or lineage.uses != fitted_uses:
        raise FittedComponentAuthorizationError("fitting lineage is not the selected program lineage projection")
    if {item.source_population_digest for item in lineage.uses} != {evidence.training_population_manifest.content_digest}:
        raise FittedComponentAuthorizationError("fitting lineage does not match the training population identity")
    expectation = LineageExpectation(LineagePurpose.FITTED_MODEL, evidence.component_digest, 1, 1)
    decision = validate_lineage(
        lineage,
        evidence.component_digest,
        (expectation,),
        replay.report.identity.population_digest,
        False,
        custody,
        context.evidence.custody_policy,
    )
    if not decision.allowed:
        raise FittedComponentAuthorizationError("fitting lineage is contaminated: " + ",".join(decision.reasons))


def authorize_fitted_component(
    evidence: FittedComponentEvidence,
    probe_inputs: Sequence[ProbeEvaluationInput],
    context: AdmissionValidationContext,
    fitting_lineage: LineageManifest,
    repository_holdout: RepositoryHoldoutReport,
    admission: AdmissionReplay,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> None:
    """Require current replay, disjoint holdout, lineage and re-evaluated probes."""
    try:
        report = validate_admission_replay(admission, context, custody, resolver)
        _validate_evidence(evidence)
        if report.decision is not AdmissionDecision.GO:
            raise FittedComponentAuthorizationError("admission replay decision is not GO")
        if report.report_digest != evidence.admission_report_digest:
            raise FittedComponentAuthorizationError("admission report does not match fitted evidence")
        program = _program_for_component(evidence.component_digest, admission, context)
        _validate_holdout(evidence, repository_holdout, program, context, resolver)
        results = _evaluate_probes(probe_inputs, evidence.component_digest, program, context, resolver)
        if results != evidence.probe_result_digests:
            raise FittedComponentAuthorizationError("derived probe results do not match fitted evidence")
        _validate_fitting_lineage(evidence, fitting_lineage, program, admission, context, custody)
    except FittedComponentAuthorizationError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise FittedComponentAuthorizationError(f"fitted component authorization refused: {exc}") from exc


__all__ = [
    "REPOSITORY_POPULATION_MANIFEST_SCHEMA",
    "FittedComponentAuthorizationError",
    "FittedComponentEvidence",
    "authorize_fitted_component",
]
