"""Non-authorizing ordinary-push projection and whole-population identity for V3."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3, EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_measurement import ArmScopeKey
from openultrasast.core.evaluation_plan import PopulationCensusV3
from openultrasast.core.evaluation_release import AdmissionCaseReleaseV3, ArmAdmissionCasesV3
from openultrasast.core.evaluation_scoped_metrics import ScopedQualityPartitionV3, partition_scoped_quality_evidence_v3
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_VALUE_SCHEMA = "openultrasast.detection-core.evaluation-ordinary-projection.v3"


class EvaluationOrdinaryProjectionError(ValueError):
    """Released ordinary pushes cannot be reconciled to reviewed scope and census."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationOrdinaryProjectionError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise EvaluationOrdinaryProjectionError(f"{field} must be a non-negative exact integer")
    return value


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _VALUE_SCHEMA, "kind": kind, "payload": payload}


def _bind_digest(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
        return
    _digest(actual, field)
    if actual != expected:
        raise EvaluationOrdinaryProjectionError(f"{field} does not match canonical content")


@dataclass(frozen=True, order=True)
class OrdinaryPushCaseV3(EvaluationV3Contract, NonAuthorizingV3):
    """One released ordinary case contributing to one exact scope."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    case_id_digest: str
    binding_digest: str
    underlying_push_digest: str
    identity_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, OrdinaryPushCaseV3, field="ordinary push case")
        if type(self.key) is not ArmScopeKey:
            raise EvaluationOrdinaryProjectionError("ordinary push case key must use exact ArmScopeKey")
        self.key.__post_init__()
        payload: canonical.JsonValue = {
            "key": {"arm_id": self.key.arm_id, "family_id": self.key.scope.family_id, "ecosystem": self.key.scope.ecosystem},
            "case_id_digest": _digest(self.case_id_digest, "ordinary case identity"),
            "binding_digest": _digest(self.binding_digest, "ordinary binding identity"),
            "underlying_push_digest": _digest(self.underlying_push_digest, "ordinary underlying push identity"),
        }
        _bind_digest(self, "identity_digest", canonical.content_digest(_value("ordinary_push_case", payload)))


@dataclass(frozen=True)
class ScopedOrdinaryProjectionV3(EvaluationV3Contract, NonAuthorizingV3):
    """Canonical ordinary cases projected into one exact arm scope."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    cases: tuple[OrdinaryPushCaseV3, ...]
    ordinary_push_count: int
    projection_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ScopedOrdinaryProjectionV3, field="scoped ordinary projection")
        if type(self.key) is not ArmScopeKey or type(self.cases) is not tuple:
            raise EvaluationOrdinaryProjectionError("scoped ordinary projection requires exact key and case tuple")
        self.key.__post_init__()
        if any(type(case) is not OrdinaryPushCaseV3 for case in self.cases):
            raise EvaluationOrdinaryProjectionError("scoped ordinary cases must use exact OrdinaryPushCaseV3 values")
        for case in self.cases:
            case.__post_init__()
        expected = tuple(sorted(self.cases, key=lambda case: (case.underlying_push_digest, case.case_id_digest)))
        if self.cases != expected or any(case.key != self.key for case in self.cases):
            raise EvaluationOrdinaryProjectionError("scoped ordinary cases must use canonical same-key order")
        pushes = tuple(case.underlying_push_digest for case in self.cases)
        if len(set(pushes)) != len(pushes):
            raise EvaluationOrdinaryProjectionError("one ordinary push may contribute only once to an exact scope")
        if _count(self.ordinary_push_count, "scoped ordinary push count") != len(pushes):
            raise EvaluationOrdinaryProjectionError("scoped ordinary push count differs from released identities")
        payload = {"key": _key_value(self.key), "case_identity_digests": tuple(case.identity_digest for case in self.cases)}
        _bind_digest(self, "projection_digest", canonical.content_digest(_value("scoped_ordinary_projection", payload)))


@dataclass(frozen=True)
class WholePopulationProjectionV3(EvaluationV3Contract, NonAuthorizingV3):
    """One globally deduplicated set of released underlying pushes."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    underlying_push_digests: tuple[str, ...]
    underlying_push_count: int
    projection_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, WholePopulationProjectionV3, field="whole population projection")
        if type(self.underlying_push_digests) is not tuple:
            raise EvaluationOrdinaryProjectionError("whole underlying pushes must use an exact tuple")
        for digest in self.underlying_push_digests:
            _digest(digest, "whole underlying push identity")
        if self.underlying_push_digests != tuple(sorted(set(self.underlying_push_digests))):
            raise EvaluationOrdinaryProjectionError("whole underlying pushes must be unique and canonical")
        if _count(self.underlying_push_count, "whole underlying push count") != len(self.underlying_push_digests):
            raise EvaluationOrdinaryProjectionError("whole underlying push count differs from released identities")
        payload = {"underlying_push_digests": self.underlying_push_digests}
        _bind_digest(self, "projection_digest", canonical.content_digest(_value("whole_population_projection", payload)))


@dataclass(frozen=True)
class EvaluationOrdinaryProjectionV3(EvaluationV3Contract, NonAuthorizingV3):
    """Reviewed-census-bound scoped ordinary and whole-population projection."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    census_digest: str
    scoped_projections: tuple[ScopedOrdinaryProjectionV3, ...]
    whole_population: WholePopulationProjectionV3
    projection_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationOrdinaryProjectionV3, field="evaluation ordinary projection")
        _digest(self.census_digest, "reviewed census identity")
        if type(self.scoped_projections) is not tuple or not self.scoped_projections:
            raise EvaluationOrdinaryProjectionError("scoped projections must be a nonempty exact tuple")
        if any(type(row) is not ScopedOrdinaryProjectionV3 for row in self.scoped_projections):
            raise EvaluationOrdinaryProjectionError("scoped projections must use exact values")
        for row in self.scoped_projections:
            row.__post_init__()
        keys = tuple(row.key for row in self.scoped_projections)
        if keys != tuple(sorted(set(keys))):
            raise EvaluationOrdinaryProjectionError("scoped projections must have unique canonical keys")
        if type(self.whole_population) is not WholePopulationProjectionV3:
            raise EvaluationOrdinaryProjectionError("whole population projection must use the exact V3 value")
        self.whole_population.__post_init__()
        _validate_ecosystem_projection(self.scoped_projections)
        ordinary_pushes = {case.underlying_push_digest for row in self.scoped_projections for case in row.cases}
        if not ordinary_pushes <= set(self.whole_population.underlying_push_digests):
            raise EvaluationOrdinaryProjectionError("ordinary projection escapes whole-population coverage")
        payload: canonical.JsonValue = {
            "census_digest": self.census_digest,
            "scoped_projection_digests": tuple(row.projection_digest for row in self.scoped_projections),
            "whole_population_projection_digest": self.whole_population.projection_digest,
        }
        _bind_digest(self, "projection_digest", canonical.content_digest(_value("evaluation_ordinary_projection", payload)))


def _key_value(key: ArmScopeKey) -> canonical.JsonValue:
    return {"arm_id": key.arm_id, "family_id": key.scope.family_id, "ecosystem": key.scope.ecosystem}


def _exact_inputs(
    census: PopulationCensusV3,
    planned_keys: tuple[ArmScopeKey, ...],
    ordinary_cases: tuple[OrdinaryPushCaseV3, ...],
    whole_pushes: tuple[str, ...],
) -> None:
    if type(census) is not PopulationCensusV3:
        raise EvaluationOrdinaryProjectionError("census must use exact PopulationCensusV3")
    census.__post_init__()
    if type(planned_keys) is not tuple or any(type(key) is not ArmScopeKey for key in planned_keys):
        raise EvaluationOrdinaryProjectionError("planned keys must use an exact tuple of ArmScopeKey")
    if planned_keys != tuple(sorted(set(planned_keys))) or not planned_keys:
        raise EvaluationOrdinaryProjectionError("planned keys must be nonempty, unique, and canonical")
    if type(ordinary_cases) is not tuple or any(type(case) is not OrdinaryPushCaseV3 for case in ordinary_cases):
        raise EvaluationOrdinaryProjectionError("ordinary cases must use an exact tuple of OrdinaryPushCaseV3")
    for case in ordinary_cases:
        case.__post_init__()
    expected = tuple(sorted(ordinary_cases, key=lambda case: (case.key, case.underlying_push_digest, case.case_id_digest)))
    if ordinary_cases != expected:
        raise EvaluationOrdinaryProjectionError("ordinary cases must use canonical key and push order")
    if type(whole_pushes) is not tuple:
        raise EvaluationOrdinaryProjectionError("whole underlying pushes must use an exact tuple")


def _census_counts(census: PopulationCensusV3, keys: tuple[ArmScopeKey, ...]) -> dict[str, int]:
    expected_ecosystems = tuple(sorted({key.scope.ecosystem for key in keys}))
    rows = {row.ecosystem: row.ordinary_push_count for row in census.ordinary_rows}
    if tuple(sorted(rows)) != expected_ecosystems:
        raise EvaluationOrdinaryProjectionError("ordinary census ecosystems differ from planned exact scopes")
    return rows


def _scoped_rows(
    keys: tuple[ArmScopeKey, ...],
    cases: tuple[OrdinaryPushCaseV3, ...],
    counts: dict[str, int],
) -> tuple[ScopedOrdinaryProjectionV3, ...]:
    cases_by_key: dict[ArmScopeKey, list[OrdinaryPushCaseV3]] = defaultdict(list)
    for case in cases:
        if case.key not in keys:
            raise EvaluationOrdinaryProjectionError("ordinary case belongs to an unplanned exact scope")
        cases_by_key[case.key].append(case)
    rows = []
    for key in keys:
        selected = tuple(sorted(cases_by_key[key], key=lambda case: (case.underlying_push_digest, case.case_id_digest)))
        row = ScopedOrdinaryProjectionV3(key, selected, len(selected), "")
        if row.ordinary_push_count != counts[key.scope.ecosystem]:
            raise EvaluationOrdinaryProjectionError("scoped ordinary identities differ from the reviewed ordinary census")
        rows.append(row)
    return tuple(rows)


def _validate_ecosystem_projection(rows: tuple[ScopedOrdinaryProjectionV3, ...]) -> None:
    sets_by_ecosystem: dict[str, list[set[str]]] = defaultdict(list)
    ecosystem_by_push: dict[str, str] = {}
    for row in rows:
        ecosystem = row.key.scope.ecosystem
        pushes = {case.underlying_push_digest for case in row.cases}
        sets_by_ecosystem[ecosystem].append(pushes)
        for push in pushes:
            previous = ecosystem_by_push.setdefault(push, ecosystem)
            if previous != ecosystem:
                raise EvaluationOrdinaryProjectionError("an ordinary push cannot project into another ecosystem")
    for push_sets in sets_by_ecosystem.values():
        if any(pushes != push_sets[0] for pushes in push_sets[1:]):
            raise EvaluationOrdinaryProjectionError("every same-ecosystem scope must project the identical eligible ordinary push set")


def _derive_ordinary_push_projection_v3(
    census: PopulationCensusV3,
    planned_keys: tuple[ArmScopeKey, ...],
    ordinary_cases: tuple[OrdinaryPushCaseV3, ...],
    whole_underlying_push_digests: tuple[str, ...],
) -> EvaluationOrdinaryProjectionV3:
    """Derive a non-authorizing projection from already validated release identities."""
    _exact_inputs(census, planned_keys, ordinary_cases, whole_underlying_push_digests)
    counts = _census_counts(census, planned_keys)
    rows = _scoped_rows(planned_keys, ordinary_cases, counts)
    _validate_ecosystem_projection(rows)
    whole = WholePopulationProjectionV3(
        whole_underlying_push_digests,
        len(whole_underlying_push_digests),
        "",
    )
    ordinary_pushes = {case.underlying_push_digest for case in ordinary_cases}
    if not ordinary_pushes <= set(whole.underlying_push_digests):
        raise EvaluationOrdinaryProjectionError("ordinary projection contains an identity outside whole-population coverage")
    if whole.underlying_push_count != census.whole_underlying_push_count:
        raise EvaluationOrdinaryProjectionError("released identities differ from the reviewed whole-population census")
    return EvaluationOrdinaryProjectionV3(census.census_digest, rows, whole, "")


def _released_projection_inputs(
    release: AdmissionCaseReleaseV3,
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...],
    partitions: tuple[ScopedQualityPartitionV3, ...],
) -> tuple[tuple[ArmScopeKey, ...], tuple[OrdinaryPushCaseV3, ...], tuple[str, ...]]:
    bindings = {(binding.key, binding.case_id_digest): binding for binding in release.bindings}
    cases = tuple(case for group in cases_by_arm for case in group.cases)
    roles_by_push: dict[str, set[AdmissionCaseRole]] = defaultdict(set)
    ecosystems_by_push: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        roles_by_push[case.underlying_push_digest].add(case.role)
        ecosystems_by_push[case.underlying_push_digest].add(case.key.scope.ecosystem)
    if any(len(roles) != 1 for roles in roles_by_push.values()):
        raise EvaluationOrdinaryProjectionError("one underlying push cannot carry different released roles")
    if any(len(ecosystems) != 1 for ecosystems in ecosystems_by_push.values()):
        raise EvaluationOrdinaryProjectionError("one underlying push cannot cross reviewed ecosystems")
    planned_keys = tuple(row.key for row in partitions)
    ordinary = []
    for case in cases:
        if case.role is AdmissionCaseRole.ORDINARY:
            binding = bindings.get((case.key, case.case_id_digest))
            if binding is None:
                raise EvaluationOrdinaryProjectionError("ordinary released case lacks its exact binding identity")
            ordinary.append(OrdinaryPushCaseV3(case.key, case.case_id_digest, binding.binding_digest, case.underlying_push_digest, ""))
    ordered = tuple(sorted(ordinary, key=lambda case: (case.key, case.underlying_push_digest, case.case_id_digest)))
    whole = tuple(sorted(roles_by_push))
    return planned_keys, ordered, whole


def project_ordinary_pushes_v3(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    cases_by_arm: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationOrdinaryProjectionV3:
    """Validate the complete release graph before projecting ordinary and whole identities."""
    try:
        if type(cases_by_arm) is not tuple:
            raise EvaluationOrdinaryProjectionError("cases_by_arm must use an exact tuple")
        partitions = partition_scoped_quality_evidence_v3(
            manifest, authority, preparation, receipt, spend, release, cases_by_arm, context, custody, resolver
        )
        keys, ordinary, whole = _released_projection_inputs(release, cases_by_arm, partitions)
        return _derive_ordinary_push_projection_v3(manifest.plan_manifest.census, keys, ordinary, whole)
    except EvaluationOrdinaryProjectionError:
        raise
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationOrdinaryProjectionError(f"ordinary projection refused by reviewed release: {exc}") from exc


__all__ = [
    "EvaluationOrdinaryProjectionError",
    "EvaluationOrdinaryProjectionV3",
    "OrdinaryPushCaseV3",
    "ScopedOrdinaryProjectionV3",
    "WholePopulationProjectionV3",
    "project_ordinary_pushes_v3",
]
