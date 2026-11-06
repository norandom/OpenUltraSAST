"""Closed version-boundary primitives for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import partial, partialmethod
from inspect import getattr_static
from types import BuiltinFunctionType, FunctionType
from typing import ClassVar, TypeVar, cast

EVALUATION_ADMISSION_V3_SCHEMA = "openultrasast.detection-core.evaluation-admission.v3"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_AUTHORITY_NAMES = frozenset(
    {
        "__call__",
        "authorize",
        "authorization",
        "authorization_capability",
        "authorize_consumer",
        "consumer_authority",
        "consumer_authorization",
        "may_authorize",
    }
)
_ContractT = TypeVar("_ContractT")
_REGISTERED_V3_CONTRACT_TYPES: list[type[object]] = []
_MISSING = object()
_MAX_CALLABLE_UNWRAP_DEPTH = 16


class EvaluationVersionError(ValueError):
    """An evaluation value crosses or violates the V3 contract boundary."""


class EvaluationContractVersion(Enum):
    """Closed evaluation-admission versions accepted by the V3 path."""

    V3 = EVALUATION_ADMISSION_V3_SCHEMA


class PartialArtifactKindV3(Enum):
    """Closed non-authorizing artifact categories shared by later V3 roots."""

    FEASIBILITY = "feasibility"
    INSUFFICIENCY = "insufficiency"
    IMPAIRED_RESULT = "impaired_result"
    RAW_REPORT = "raw_report"
    AGGREGATE = "aggregate"
    INCOMPLETE_ARM_RESULT = "incomplete_arm_result"
    OTHER_PARTIAL = "other_partial"


def _wrapped_callable(value: object) -> object:
    if type(value) is partial or type(value) is partialmethod:
        return value.func
    if type(value) is FunctionType:
        return value.__dict__.get("__wrapped__", _MISSING)
    return getattr_static(value, "__wrapped__", _MISSING)


def _callable_identities(value: object) -> tuple[str, ...]:
    if isinstance(value, (classmethod, staticmethod)):
        value = value.__func__
    if isinstance(value, property):
        accessors = (value.fget, value.fset, value.fdel)
        return tuple(name for accessor in accessors if accessor is not None for name in _callable_identities(accessor))
    names: list[str] = []
    seen: set[int] = set()
    current = value
    for _ in range(_MAX_CALLABLE_UNWRAP_DEPTH):
        identity = id(current)
        if identity in seen:
            break
        seen.add(identity)
        if type(current) in (FunctionType, BuiltinFunctionType):
            names.append(cast(FunctionType | BuiltinFunctionType, current).__name__)
        wrapped = _wrapped_callable(current)
        if wrapped is _MISSING:
            break
        current = wrapped
    return tuple(names)


def _is_authority_name(name: object) -> bool:
    if type(name) is not str:
        return False
    return name in _FORBIDDEN_AUTHORITY_NAMES or name.startswith("authorize_") or name.endswith("_authorization")


def _authority_capability_names(contract_type: type[object]) -> tuple[str, ...]:
    forbidden: set[str] = set()
    for owner in contract_type.__mro__:
        namespace = vars(owner)
        annotations = namespace.get("__annotations__", {})
        dataclass_fields = namespace.get("__dataclass_fields__", {})
        names = set(namespace)
        if isinstance(annotations, dict):
            names.update(annotations)
        if isinstance(dataclass_fields, dict):
            names.update(dataclass_fields)
        for name in names:
            value = namespace.get(name)
            callable_names = _callable_identities(value)
            if _is_authority_name(name) or any(_is_authority_name(item) for item in callable_names):
                forbidden.add(name)
    return tuple(sorted(forbidden))


def _validate_non_authorizing_type(contract_type: type[object]) -> None:
    forbidden = _authority_capability_names(contract_type)
    if forbidden:
        names = ", ".join(forbidden)
        raise TypeError(f"non-authorizing V3 artifacts cannot declare authority capability: {names}")


def _propagates_to_non_authorizing_type(contract_type: type[object]) -> bool:
    marker = globals().get("NonAuthorizingV3")
    if not isinstance(marker, type):
        return False
    pending = [contract_type]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if marker in type.__getattribute__(current, "__mro__"):
            return True
        pending.extend(type.__subclasses__(current))
    return False


class _NonAuthorizingMeta(type):
    def __new__(
        mcls,
        name: str,
        bases: tuple[type[object], ...],
        namespace: dict[str, object],
        **kwargs: object,
    ) -> _NonAuthorizingMeta:
        contract_type = super().__new__(mcls, name, bases, namespace, **kwargs)
        if bases:
            _validate_non_authorizing_type(contract_type)
        return contract_type

    def __setattr__(cls, name: str, value: object) -> None:
        callable_names = _callable_identities(value)
        is_authority = _is_authority_name(name) or any(_is_authority_name(item) for item in callable_names)
        if is_authority and _propagates_to_non_authorizing_type(cls):
            raise TypeError(f"non-authorizing V3 artifacts cannot declare authority capability: {name}")
        super().__setattr__(name, value)


class NonAuthorizingV3(metaclass=_NonAuthorizingMeta):
    """Nominal marker for V3 values that cannot authorize consumer use."""

    __slots__ = ()


class _EvaluationV3ContractMeta(_NonAuthorizingMeta):
    def __new__(
        mcls,
        name: str,
        bases: tuple[type[object], ...],
        namespace: dict[str, object],
        **kwargs: object,
    ) -> _EvaluationV3ContractMeta:
        contract_type = cast(_EvaluationV3ContractMeta, super().__new__(mcls, name, bases, namespace, **kwargs))
        declared_schema = namespace.get("__evaluation_v3_contract_schema__")
        owner = namespace.get("__module__")
        if (
            bases
            and type(owner) is str
            and owner.startswith("openultrasast.core.evaluation_")
            and type(declared_schema) is str
            and declared_schema == EVALUATION_ADMISSION_V3_SCHEMA
        ):
            _REGISTERED_V3_CONTRACT_TYPES.append(contract_type)
        return contract_type


class EvaluationV3Contract(metaclass=_EvaluationV3ContractMeta):
    """Nominal base for explicitly registered contracts owned by V3 core modules."""

    __slots__ = ()


def route_evaluation_schema(schema: str) -> EvaluationContractVersion:
    """Route only the reserved V3 root identity; never reinterpret V2 or unknown shapes."""
    if type(schema) is not str:
        raise EvaluationVersionError("evaluation schema must be exact text")
    if schema == EVALUATION_ADMISSION_V3_SCHEMA:
        return EvaluationContractVersion.V3
    if schema.endswith(".v2"):
        raise EvaluationVersionError("V2 evidence cannot be converted; construct a new V3 baseline")
    raise EvaluationVersionError(f"unknown evaluation schema: {schema}")


def require_v3_child_schema(schema: object, *, field: str) -> None:
    """Require a later V3 root child to name the exact parent contract version."""
    if type(field) is not str or not field:
        raise EvaluationVersionError("child field must be nonempty exact text")
    if type(schema) is not str or schema != EVALUATION_ADMISSION_V3_SCHEMA:
        raise EvaluationVersionError(f"{field} has a mixed or incompatible evaluation schema")


def require_exact_v3_contract(value: object, expected_type: type[_ContractT], *, field: str) -> _ContractT:
    """Refuse subclasses and shape inference at every later V3 contract boundary."""
    if type(field) is not str or not field:
        raise EvaluationVersionError("contract field must be nonempty exact text")
    if not isinstance(expected_type, type):
        raise EvaluationVersionError("expected contract must be an exact runtime type")
    if not any(expected_type is registered_type for registered_type in _REGISTERED_V3_CONTRACT_TYPES):
        raise EvaluationVersionError(f"{field} must name a registered V3 contract type")
    if type(value) is not expected_type:
        raise EvaluationVersionError(f"{field} must use exact {expected_type.__name__}")
    return value


@dataclass(frozen=True)
class PartialEvaluationArtifactV3(EvaluationV3Contract, NonAuthorizingV3):
    """Representative partial V3 value with no consumer-authority interface."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    evaluation_schema: str
    kind: PartialArtifactKindV3
    artifact_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, PartialEvaluationArtifactV3, field="partial evaluation artifact")
        require_v3_child_schema(self.evaluation_schema, field="partial evaluation artifact")
        if type(self.kind) is not PartialArtifactKindV3:
            raise EvaluationVersionError("partial artifact kind must use the closed PartialArtifactKindV3 enum")
        if type(self.artifact_digest) is not str or _DIGEST.fullmatch(self.artifact_digest) is None:
            raise EvaluationVersionError("partial artifact digest must be a full lowercase SHA-256 digest")


__all__ = [
    "EVALUATION_ADMISSION_V3_SCHEMA",
    "EvaluationContractVersion",
    "EvaluationV3Contract",
    "EvaluationVersionError",
    "NonAuthorizingV3",
    "PartialArtifactKindV3",
    "PartialEvaluationArtifactV3",
    "require_exact_v3_contract",
    "require_v3_child_schema",
    "route_evaluation_schema",
]
