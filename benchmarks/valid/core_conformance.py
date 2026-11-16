"""Fail-closed benchmark consumer boundary for scoped admission V3."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeVar, cast

from openultrasast.core import evaluation_admission

_EXPECTED_SCHEMA = "openultrasast.detection-core.evaluation-admission.v3"
_REQUIRED_OPERATIONS = (
    "authorize_evaluation",
    "decode_evaluation_v3",
    "preflight_evaluation",
    "score_and_replay",
    "validate_evaluation_replay",
    "validate_shared_spend",
)
_EXPECTED_EXPORTS = (
    "EVALUATION_ADMISSION_V3_SCHEMA",
    "EvaluationAdmissionV3Error",
    *_REQUIRED_OPERATIONS,
)
_ValueT = TypeVar("_ValueT")


class _ConsumerFacade(Protocol):
    def decode_evaluation_v3(self, schema: str, value: object, expected_type: type[_ValueT]) -> _ValueT: ...

    def validate_evaluation_replay(
        self,
        replay: object,
        context: object,
        custody: object,
        resolver: object,
    ) -> tuple[object, ...]: ...


class ScopedAdmissionV3ConformanceError(RuntimeError):
    """The installed core cannot serve the pinned benchmark contract."""


@dataclass(frozen=True)
class ScopedAdmissionV3Capability:
    """Validated identity of the core contract consumed by the benchmark."""

    schema: str
    operations: tuple[str, ...]


def _require_exact_exports(facade: object) -> None:
    exports = getattr(facade, "__all__", None)
    if type(exports) not in (list, tuple) or not all(type(name) is str for name in exports):
        raise ScopedAdmissionV3ConformanceError("V3 facade public exports are missing or malformed")
    actual = tuple(exports)
    missing = tuple(name for name in _EXPECTED_EXPORTS if name not in actual)
    unexpected = tuple(name for name in actual if name not in _EXPECTED_EXPORTS)
    if actual != _EXPECTED_EXPORTS:
        raise ScopedAdmissionV3ConformanceError(
            f"V3 facade exports differ from the pinned contract; missing={missing}, unexpected={unexpected}"
        )


def _require_operations(facade: object) -> None:
    missing = tuple(name for name in _REQUIRED_OPERATIONS if not callable(getattr(facade, name, None)))
    if missing:
        raise ScopedAdmissionV3ConformanceError(f"V3 facade required callable capabilities are missing: {missing}")


def require_scoped_admission_v3(
    facade: object = evaluation_admission,
) -> ScopedAdmissionV3Capability:
    """Refuse benchmark startup unless the exact V3 predecessor is available."""
    _require_exact_exports(facade)
    schema = getattr(facade, "EVALUATION_ADMISSION_V3_SCHEMA", None)
    if type(schema) is not str or schema != _EXPECTED_SCHEMA:
        raise ScopedAdmissionV3ConformanceError(
            f"V3 facade schema differs from the pinned contract: expected {_EXPECTED_SCHEMA!r}, got {schema!r}"
        )
    _require_operations(facade)
    return ScopedAdmissionV3Capability(schema=schema, operations=_REQUIRED_OPERATIONS)


def decode_scoped_admission_v3(
    schema: str,
    value: object,
    expected_type: type[_ValueT],
    *,
    facade: object = evaluation_admission,
) -> _ValueT:
    """Decode only an exact V3 root; historical roots are never converted."""
    require_scoped_admission_v3(facade)
    return cast(_ConsumerFacade, facade).decode_evaluation_v3(schema, value, expected_type)


def validate_scoped_admission_replay(
    replay: object,
    context: object,
    custody: object,
    resolver: object,
    *,
    facade: object = evaluation_admission,
) -> tuple[object, ...]:
    """Validate a complete replay only after startup conformance succeeds."""
    require_scoped_admission_v3(facade)
    return cast(_ConsumerFacade, facade).validate_evaluation_replay(replay, context, custody, resolver)


__all__ = [
    "ScopedAdmissionV3Capability",
    "ScopedAdmissionV3ConformanceError",
    "decode_scoped_admission_v3",
    "require_scoped_admission_v3",
    "validate_scoped_admission_replay",
]
