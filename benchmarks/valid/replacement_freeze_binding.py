"""Integration freeze and causal binding of the exact replacement baseline.

This module closes task group 10: it composes the committed population,
review, material, lifecycle, reservation, and store authorities into the one
binding that turns the closed replacement population into an active baseline.
It registers no evaluation arms, runs no core preflight, and never spends
labels; every check it performs is read-only against exact reviewed evidence.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from benchmarks.valid.cohort_ingestion import CohortBatchOutcomeV1
from benchmarks.valid.historical_authorization import HistoricalWithdrawalV1, withdrawal_bytes
from benchmarks.valid.lifecycle import (
    BaselineLifecycleAuthority,
    PopulationLifecycleProjectionV1,
    decode_lifecycle_event,
    reviewed_replacement_event,
    withdrawn_event,
)
from benchmarks.valid.ordinary_change_contract import (
    OrdinarySelectionV1,
    ReviewedPositiveInput,
    _fix_exclusion_value,
    _selection_value,
    ordinary_selection_bytes,
)
from benchmarks.valid.ordinary_draw_contract import OrdinaryPopulationDrawV1, ordinary_population_draw_bytes
from benchmarks.valid.population_freeze import PopulationFreezeV3, freeze_population, population_freeze_bytes
from benchmarks.valid.population_freeze_contract import PopulationClass, ScopeMinimumV1
from benchmarks.valid.population_label_blind import (
    IndependenceAttestation,
    LabelBlindPopulationDraftV3,
    LabelBlindPopulationManifestV3,
    ReviewIndependencePolicy,
    build_label_blind_population_draft,
    review_label_blind_population_manifest,
    validate_label_blind_population_manifest,
)
from benchmarks.valid.population_material_contract import PopulationMaterialInputV1
from benchmarks.valid.population_materials import PopulationMaterialPartitionV1, build_population_material_partition
from benchmarks.valid.positive_set_closure import (
    PositiveSetClosureStateError,
    PositiveSetClosureStatus,
    PositiveSetClosureV1,
    project_positive_set_closure,
)
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from benchmarks.valid.reservation import ReservationAuthority, ReservationCensusV1, ReservationError, census_bytes
from benchmarks.valid.reservation_guard import (
    PRODUCTION_GUARD_SCAN_ROOTS,
    ExactReservationSourceV1,
    ReplacementReservationAcceptanceV1,
    scan_permanent_reservations,
    validate_replacement_population,
)
from benchmarks.valid.store_configuration import StoreCapabilityEvidence, StorePurpose, assess_store_startup, require_store_startup
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue, content_digest
from openultrasast.core.custody import PopulationCustodyLog, PopulationStatus

REPLACEMENT_BASELINE_BINDING_SCHEMA = "openultrasast.valid-detection-benchmark.replacement-baseline-binding.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ReplacementBindingReason(StrEnum):
    """Closed binding refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    POSITIVE_SET_NOT_CLOSED = "positive_set_not_closed"
    ORDINARY_DRAW_REFUSED = "ordinary_draw_refused"
    FREEZE_REFUSED = "freeze_refused"
    POPULATION_NOT_ADMISSION_CLASS = "population_not_admission_class"
    MATERIAL_PARTITION_REFUSED = "material_partition_refused"
    MANIFEST_UNREVIEWED = "manifest_unreviewed"
    MANIFEST_UNRESOLVED = "manifest_unresolved"
    LIFECYCLE_REFUSED = "lifecycle_refused"
    RESERVATION_REFUSED = "reservation_refused"
    STORE_CAPABILITY_MISSING = "store_capability_missing"
    CUSTODY_NOT_AVAILABLE = "custody_not_available"


class ReplacementBindingError(RuntimeError):
    """Refuse one binding step with a closed reason and no caller content."""

    def __init__(self, reason: ReplacementBindingReason) -> None:
        self.reason = reason
        super().__init__(f"replacement_binding_{reason.value}")


class ReplacementBindingStateReason(StrEnum):
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


class ReplacementBindingStateError(ValueError):
    """Closed binding-state refusal carrying one structural reason."""

    def __init__(self, reason: ReplacementBindingStateReason) -> None:
        self.reason = reason
        super().__init__(f"replacement binding state {reason.value}")


def _mismatch() -> ReplacementBindingStateError:
    return ReplacementBindingStateError(ReplacementBindingStateReason.STATE_MISMATCH)


def _refused(reason: ReplacementBindingReason) -> ReplacementBindingError:
    return ReplacementBindingError(reason)


@dataclass(frozen=True)
class ReplacementBaselineBindingV1:
    """Identities of every authority the exact replacement baseline binds."""

    historical_withdrawal_digest: str
    population_digest: str
    freeze_digest: str
    closure_digest: str
    ordinary_draw_digest: str
    ordinary_selection_digest: str
    material_manifest_digest: str
    private_object_digest: str
    sealed_label_digest: str
    manifest_digest: str
    reservation_census_digest: str
    guard_report_digest: str
    acceptance_digest: str
    lifecycle_projection_digest: str
    binding_digest: str


_BINDING_FIELDS = (
    "historical_withdrawal_digest",
    "population_digest",
    "freeze_digest",
    "closure_digest",
    "ordinary_draw_digest",
    "ordinary_selection_digest",
    "material_manifest_digest",
    "private_object_digest",
    "sealed_label_digest",
    "manifest_digest",
    "reservation_census_digest",
    "guard_report_digest",
    "acceptance_digest",
    "lifecycle_projection_digest",
)


def _binding_value(binding: ReplacementBaselineBindingV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {"schema_version": REPLACEMENT_BASELINE_BINDING_SCHEMA}
    value.update({field: getattr(binding, field) for field in _BINDING_FIELDS})
    if include_digest:
        value["binding_digest"] = binding.binding_digest
    return value


def _validate_binding(binding: ReplacementBaselineBindingV1) -> None:
    if type(binding) is not ReplacementBaselineBindingV1:
        raise _mismatch()
    for field in (*_BINDING_FIELDS, "binding_digest"):
        value = getattr(binding, field)
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise _mismatch()


def replacement_baseline_binding_bytes(binding: ReplacementBaselineBindingV1) -> bytes:
    """Encode one digest-consistent binding record as canonical bytes."""
    _validate_binding(binding)
    if binding.binding_digest != content_digest(_binding_value(binding, include_digest=False)):
        raise _mismatch()
    return canonical_json_bytes(_binding_value(binding, include_digest=True))


@dataclass(frozen=True)
class _FreezeValidator:
    """Exact-identity freeze validator for the material partition boundary."""

    expected: PopulationFreezeV3

    def validate(self, freeze: PopulationFreezeV3) -> bytes:
        if freeze != self.expected:
            raise ValueError("freeze does not replay from exact authorities")
        return population_freeze_bytes(freeze)


def _selection_provenance(draw: OrdinaryPopulationDrawV1) -> str:
    return content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in draw.pushes})
            ),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in draw.fix_exclusions),
            "policy_digest": draw.policy_digest,
        }
    )


def ordinary_selection_from_draw(draw: OrdinaryPopulationDrawV1) -> OrdinarySelectionV1:
    """Bridge one validated ordinary population draw into the freeze-bound selection."""
    if type(draw) is not OrdinaryPopulationDrawV1:
        raise _refused(ReplacementBindingReason.ORDINARY_DRAW_REFUSED)
    try:
        content = ordinary_population_draw_bytes(draw)
        draft = OrdinarySelectionV1(
            draw.required_per_positive,
            draw.policy_digest,
            draw.positive_change_digests,
            draw.fix_exclusions,
            draw.pushes,
            draw.assignments,
            draw.exclusions,
            _selection_provenance(draw),
            "",
        )
        selection = OrdinarySelectionV1(
            **{**vars(draft), "selection_digest": content_digest(_selection_value(draft, include_digest=False))}
        )
        ordinary_selection_bytes(selection)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.ORDINARY_DRAW_REFUSED) from error
    if not content:
        raise _refused(ReplacementBindingReason.ORDINARY_DRAW_REFUSED)
    return selection


def freeze_replacement_baseline(
    positives: Iterable[ReviewedPositiveInput],
    *,
    ordinary_selection: OrdinarySelectionV1,
    reservation_census: ReservationCensusV1,
    reservation_authority: ReservationAuthority,
    scope_minimums: Iterable[ScopeMinimumV1] = (),
    exclusion_counts: Iterable[tuple[str, int]] = (),
    source_provenance_digest: str,
    freeze_policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
    forbidden_historical_identities: Iterable[str] = (),
) -> PopulationFreezeV3:
    """Freeze the reviewed population under new identities via the population authority."""
    try:
        return freeze_population(
            positives,
            ordinary_selection=ordinary_selection,
            reservation_census=reservation_census,
            reservation_authority=reservation_authority,
            scope_minimums=scope_minimums,
            exclusion_counts=exclusion_counts,
            source_provenance_digest=source_provenance_digest,
            freeze_policy_digest=freeze_policy_digest,
            expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
            expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
            forbidden_historical_identities=forbidden_historical_identities,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.FREEZE_REFUSED) from error


def replacement_lifecycle_events(
    historical_withdrawal: HistoricalWithdrawalV1,
    *,
    population_digest: str,
    freeze_digest: str,
    producer_identity: str,
    reviewer_identity: str,
    policy_digest: str,
) -> tuple[bytes, bytes]:
    """Build the reviewed withdrawal root and exact replacement-binding event."""
    try:
        withdrawal_bytes(historical_withdrawal)
        root = withdrawn_event(historical_withdrawal)
        root_event = decode_lifecycle_event(root)
        if root_event.historical_withdrawal_digest is None:
            raise _refused(ReplacementBindingReason.LIFECYCLE_REFUSED)
        replacement = reviewed_replacement_event(
            predecessor_digest=root_event.event_digest,
            historical_withdrawal_digest=root_event.historical_withdrawal_digest,
            population_digest=population_digest,
            freeze_digest=freeze_digest,
            producer_identity=producer_identity,
            reviewer_identity=reviewer_identity,
            conflict_disclosed=True,
            policy_digest=policy_digest,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.LIFECYCLE_REFUSED) from error
    return root, replacement


def _required_capabilities(
    store_environ: Mapping[str, str],
    capability_evidence: Mapping[StorePurpose, StoreCapabilityEvidence],
) -> None:
    try:
        require_store_startup(assess_store_startup(store_environ, capability_evidence))
    except (RuntimeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.STORE_CAPABILITY_MISSING) from error


def _validated_census(census: ReservationCensusV1) -> None:
    try:
        content = census_bytes(census)
    except (AttributeError, ReservationError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.INVALID_REQUEST) from error
    if not content:
        raise _refused(ReplacementBindingReason.INVALID_REQUEST)


def _current_census(census: ReservationCensusV1, authority: ReservationAuthority) -> None:
    try:
        authority.require_current_census(census)
    except (AttributeError, ReservationError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.RESERVATION_REFUSED) from error


def _closed_positive_set(batches: Sequence[CohortBatchOutcomeV1], draw: OrdinaryPopulationDrawV1) -> PositiveSetClosureV1:
    try:
        closure = project_positive_set_closure(batches)
    except (PositiveSetClosureStateError, AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.INVALID_REQUEST) from error
    if closure.status is not PositiveSetClosureStatus.CLOSED or closure.closure_digest != draw.closure_digest:
        raise _refused(ReplacementBindingReason.POSITIVE_SET_NOT_CLOSED)
    return closure


def _frozen_baseline(
    positives: Sequence[ReviewedPositiveInput],
    selection: OrdinarySelectionV1,
    census: ReservationCensusV1,
    authority: ReservationAuthority,
    *,
    scope_minimums: Iterable[ScopeMinimumV1],
    exclusion_counts: Iterable[tuple[str, int]],
    source_provenance_digest: str,
    freeze_policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
    forbidden_historical_identities: Iterable[str],
) -> PopulationFreezeV3:
    freeze = freeze_replacement_baseline(
        positives,
        ordinary_selection=selection,
        reservation_census=census,
        reservation_authority=authority,
        scope_minimums=scope_minimums,
        exclusion_counts=exclusion_counts,
        source_provenance_digest=source_provenance_digest,
        freeze_policy_digest=freeze_policy_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
        forbidden_historical_identities=forbidden_historical_identities,
    )
    if freeze.population_class is not PopulationClass.ADMISSION:
        raise _refused(ReplacementBindingReason.POPULATION_NOT_ADMISSION_CLASS)
    return freeze


def _partitioned_materials(
    freeze: PopulationFreezeV3,
    material_inputs: Iterable[PopulationMaterialInputV1],
    partition_policy_digest: str,
) -> PopulationMaterialPartitionV1:
    try:
        return build_population_material_partition(
            freeze,
            material_inputs,
            freeze_validator=_FreezeValidator(freeze),
            partition_policy_digest=partition_policy_digest,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.MATERIAL_PARTITION_REFUSED) from error


def _reviewed_manifest(
    freeze: PopulationFreezeV3,
    partition: PopulationMaterialPartitionV1,
    selection: OrdinarySelectionV1,
    review: Callable[[LabelBlindPopulationDraftV3], IndependenceAttestation],
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> LabelBlindPopulationManifestV3:
    try:
        draft = build_label_blind_population_draft(freeze, partition, selection)
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.MANIFEST_UNRESOLVED) from error
    try:
        attestation = review(draft)
    except ReplacementBindingError:
        raise
    except Exception as error:
        raise _refused(ReplacementBindingReason.MANIFEST_UNREVIEWED) from error
    try:
        manifest = review_label_blind_population_manifest(draft, attestation, policy, resolver)
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.MANIFEST_UNREVIEWED) from error
    try:
        content = validate_label_blind_population_manifest(manifest, freeze, partition, selection, attestation, policy, resolver)
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.MANIFEST_UNRESOLVED) from error
    if not content:
        raise _refused(ReplacementBindingReason.MANIFEST_UNRESOLVED)
    return manifest


def _bound_lifecycle(
    historical_withdrawal: HistoricalWithdrawalV1,
    freeze: PopulationFreezeV3,
    producer_identity: str,
    reviewer_identity: str,
    policy_digest: str,
) -> tuple[BaselineLifecycleAuthority, PopulationLifecycleProjectionV1]:
    try:
        root, replacement = replacement_lifecycle_events(
            historical_withdrawal,
            population_digest=freeze.population_digest,
            freeze_digest=freeze.freeze_digest,
            producer_identity=producer_identity,
            reviewer_identity=reviewer_identity,
            policy_digest=policy_digest,
        )
        authority = BaselineLifecycleAuthority()
        authority.append(root)
        projection = authority.append(replacement)
        eligible = authority.require_admission_eligible(freeze.population_digest, freeze.freeze_digest)
    except ReplacementBindingError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.LIFECYCLE_REFUSED) from error
    if projection != eligible:
        raise _refused(ReplacementBindingReason.LIFECYCLE_REFUSED)
    return authority, projection


def _accepted_reservation(
    guard_scan_root: Path,
    positives: Sequence[ReviewedPositiveInput],
    freeze: PopulationFreezeV3,
    projection: PopulationLifecycleProjectionV1,
    census: ReservationCensusV1,
    authority: ReservationAuthority,
    historical_withdrawal: HistoricalWithdrawalV1,
    reservation_sources: tuple[ExactReservationSourceV1, ...],
) -> ReplacementReservationAcceptanceV1:
    try:
        repositories = tuple(sorted({item.candidate.canonical_repository for item in positives}))
        requests = tuple((entry.path, entry.content_digest) for entry in historical_withdrawal.candidate.entries)
        report = scan_permanent_reservations(
            guard_scan_root,
            scan_roots=PRODUCTION_GUARD_SCAN_ROOTS,
            authority=authority,
            census=census,
            reservation_sources=reservation_sources,
            historical_withdrawal=historical_withdrawal,
        )
        return validate_replacement_population(
            guard_scan_root,
            repositories=repositories,
            population_digest=freeze.population_digest,
            freeze_digest=freeze.freeze_digest,
            lifecycle=projection,
            guard_report=report,
            authority=authority,
            census=census,
            historical_withdrawal=historical_withdrawal,
            reservation_sources=reservation_sources,
            historical_requests=requests,
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.RESERVATION_REFUSED) from error


def _reverified(
    lifecycle_authority: BaselineLifecycleAuthority,
    reservation_authority: ReservationAuthority,
    census: ReservationCensusV1,
    freeze: PopulationFreezeV3,
    store_environ: Mapping[str, str],
    capability_evidence: Mapping[StorePurpose, StoreCapabilityEvidence],
) -> None:
    _required_capabilities(store_environ, capability_evidence)
    _current_census(census, reservation_authority)
    try:
        lifecycle_authority.require_admission_eligible(freeze.population_digest, freeze.freeze_digest)
    except (AttributeError, TypeError, ValueError) as error:
        raise _refused(ReplacementBindingReason.LIFECYCLE_REFUSED) from error


def _baseline_binding(
    historical_withdrawal: HistoricalWithdrawalV1,
    freeze: PopulationFreezeV3,
    closure: PositiveSetClosureV1,
    draw: OrdinaryPopulationDrawV1,
    selection: OrdinarySelectionV1,
    partition: PopulationMaterialPartitionV1,
    manifest: LabelBlindPopulationManifestV3,
    census: ReservationCensusV1,
    acceptance: ReplacementReservationAcceptanceV1,
    projection: PopulationLifecycleProjectionV1,
) -> ReplacementBaselineBindingV1:
    draft = ReplacementBaselineBindingV1(
        historical_withdrawal.withdrawal_digest,
        freeze.population_digest,
        freeze.freeze_digest,
        closure.closure_digest,
        draw.draw_digest,
        selection.selection_digest,
        partition.manifest.manifest_digest,
        partition.manifest.private_object_digest,
        partition.manifest.sealed_label_digest,
        manifest.manifest_digest,
        census.census_digest,
        acceptance.guard_report_digest,
        acceptance.acceptance_digest,
        projection.projection_digest,
        "",
    )
    binding = ReplacementBaselineBindingV1(**{**vars(draft), "binding_digest": content_digest(_binding_value(draft, include_digest=False))})
    replacement_baseline_binding_bytes(binding)
    return binding


def bind_replacement_baseline(
    positives: Iterable[ReviewedPositiveInput],
    batches: Sequence[CohortBatchOutcomeV1],
    *,
    ordinary_draw: OrdinaryPopulationDrawV1,
    reservation_census: ReservationCensusV1,
    reservation_authority: ReservationAuthority,
    material_inputs: Iterable[PopulationMaterialInputV1],
    partition_policy_digest: str,
    manifest_review: Callable[[LabelBlindPopulationDraftV3], IndependenceAttestation],
    manifest_policy: ReviewIndependencePolicy,
    disclosure_resolver: canonical.ContentResolver,
    historical_withdrawal: HistoricalWithdrawalV1,
    binding_producer_identity: str,
    binding_reviewer_identity: str,
    binding_policy_digest: str,
    guard_scan_root: Path,
    guard_reservation_sources: tuple[ExactReservationSourceV1, ...] = (),
    scope_minimums: Iterable[ScopeMinimumV1] = (),
    exclusion_counts: Iterable[tuple[str, int]] = (),
    source_provenance_digest: str,
    freeze_policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
    forbidden_historical_identities: Iterable[str] = (),
    store_environ: Mapping[str, str],
    capability_evidence: Mapping[StorePurpose, StoreCapabilityEvidence],
) -> ReplacementBaselineBindingV1:
    """Freeze, review, partition, and causally bind the exact replacement baseline.

    The binding composes only committed authorities, re-runs the permanent
    reservation, lifecycle, and store capability checks read-only, and never
    registers an arm, executes a plan, or releases label bytes.
    """
    if type(ordinary_draw) is not OrdinaryPopulationDrawV1:
        raise _refused(ReplacementBindingReason.INVALID_REQUEST)
    reviewed_inputs = tuple(positives)
    _required_capabilities(store_environ, capability_evidence)
    _validated_census(reservation_census)
    _current_census(reservation_census, reservation_authority)
    closure = _closed_positive_set(batches, ordinary_draw)
    selection = ordinary_selection_from_draw(ordinary_draw)
    if ordinary_draw.reservation_census_digest != reservation_census.census_digest:
        raise _refused(ReplacementBindingReason.ORDINARY_DRAW_REFUSED)
    freeze = _frozen_baseline(
        reviewed_inputs,
        selection,
        reservation_census,
        reservation_authority,
        scope_minimums=scope_minimums,
        exclusion_counts=exclusion_counts,
        source_provenance_digest=source_provenance_digest,
        freeze_policy_digest=freeze_policy_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
        forbidden_historical_identities=forbidden_historical_identities,
    )
    partition = _partitioned_materials(freeze, material_inputs, partition_policy_digest)
    manifest = _reviewed_manifest(freeze, partition, selection, manifest_review, manifest_policy, disclosure_resolver)
    lifecycle_authority, projection = _bound_lifecycle(
        historical_withdrawal,
        freeze,
        binding_producer_identity,
        binding_reviewer_identity,
        binding_policy_digest,
    )
    acceptance = _accepted_reservation(
        guard_scan_root,
        reviewed_inputs,
        freeze,
        projection,
        reservation_census,
        reservation_authority,
        historical_withdrawal,
        guard_reservation_sources,
    )
    _reverified(lifecycle_authority, reservation_authority, reservation_census, freeze, store_environ, capability_evidence)
    return _baseline_binding(
        historical_withdrawal, freeze, closure, ordinary_draw, selection, partition, manifest, reservation_census, acceptance, projection
    )


def require_baseline_custody_available(
    binding: ReplacementBaselineBindingV1,
    custody_log: PopulationCustodyLog,
) -> None:
    """Prove the bound population is still untouched without spending labels."""
    replacement_baseline_binding_bytes(binding)
    if type(custody_log) is not PopulationCustodyLog:
        raise _refused(ReplacementBindingReason.CUSTODY_NOT_AVAILABLE)
    if (
        custody_log.population_digest != binding.population_digest
        or custody_log.status is not PopulationStatus.AVAILABLE
        or custody_log.receipt_count != 0
        or custody_log.receipts
    ):
        raise _refused(ReplacementBindingReason.CUSTODY_NOT_AVAILABLE)


__all__ = [
    "REPLACEMENT_BASELINE_BINDING_SCHEMA",
    "ReplacementBaselineBindingV1",
    "ReplacementBindingError",
    "ReplacementBindingReason",
    "ReplacementBindingStateError",
    "ReplacementBindingStateReason",
    "bind_replacement_baseline",
    "freeze_replacement_baseline",
    "ordinary_selection_from_draw",
    "replacement_baseline_binding_bytes",
    "replacement_lifecycle_events",
    "require_baseline_custody_available",
]
