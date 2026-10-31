"""Recursive closed-graph checks for reviewed admission payloads."""

from __future__ import annotations

from dataclasses import fields
from typing import Any, cast

_SCALAR_TYPES: tuple[type[object], ...] = (str, int, float, bool, type(None))
_ENUM_STATE_FIELDS = frozenset(("_value_", "_name_", "__objclass__", "_sort_order_"))


def closed_graph_problem(
    value: object,
    *,
    dataclass_types: tuple[type[object], ...],
    enum_types: tuple[type[object], ...],
    path: str = "payload",
) -> str | None:
    """Return the first non-closed node in a whitelisted payload graph."""
    value_type = type(value)
    if value_type in dataclass_types:
        return _dataclass_problem(value, value_type, dataclass_types, enum_types, path)
    if value_type is tuple:
        for index, item in enumerate(cast(tuple[object, ...], value)):
            problem = closed_graph_problem(
                item,
                dataclass_types=dataclass_types,
                enum_types=enum_types,
                path=f"{path}[{index}]",
            )
            if problem is not None:
                return problem
        return None
    if value_type in enum_types:
        return _enum_problem(value, value_type, path)
    if value_type in _SCALAR_TYPES:
        return None
    return f"{path} uses non-closed type {value_type.__name__}"


def _dataclass_problem(
    value: object,
    value_type: type[object],
    dataclass_types: tuple[type[object], ...],
    enum_types: tuple[type[object], ...],
    path: str,
) -> str | None:
    declared_fields = fields(cast(Any, value_type))
    declared_names = {field.name for field in declared_fields}
    try:
        actual_names = set(vars(value))
    except TypeError:
        actual_names = declared_names
    if actual_names != declared_names:
        return f"{path} must have exactly its declared fields"
    for field in declared_fields:
        try:
            field_value = getattr(value, field.name)
        except AttributeError:
            return f"{path}.{field.name} is missing"
        problem = closed_graph_problem(
            field_value,
            dataclass_types=dataclass_types,
            enum_types=enum_types,
            path=f"{path}.{field.name}",
        )
        if problem is not None:
            return problem
    return None


def _enum_problem(value: object, enum_type: type[object], path: str) -> str | None:
    state = vars(value)
    if set(state) != _ENUM_STATE_FIELDS:
        return f"{path} enum member must have exactly its canonical state fields"
    expected = _canonical_enum_state(value, enum_type)
    if expected is None:
        return f"{path} enum type has aliases or nonunique member mappings"
    expected_name, expected_value, expected_order = expected
    if (
        state["_name_"] is not expected_name
        or state["_value_"] is not expected_value
        or state["__objclass__"] is not enum_type
        or type(state["_sort_order_"]) is not int
        or state["_sort_order_"] != expected_order
    ):
        return f"{path} enum member state is not canonical"
    return None


def _canonical_enum_state(value: object, enum_type: type[object]) -> tuple[object, object, int] | None:
    enum_class = cast(Any, enum_type)
    canonical_members = tuple(enum_class)
    name_entries = tuple(enum_class.__members__.items())
    value_entries = tuple(enum_class._value2member_map_.items())
    if len(name_entries) != len(canonical_members) or len(value_entries) != len(canonical_members):
        return None
    if any(sum(candidate is member for _, candidate in name_entries) != 1 for member in canonical_members):
        return None
    if any(sum(candidate is member for _, candidate in value_entries) != 1 for member in canonical_members):
        return None
    names = tuple(name for name, member in name_entries if member is value)
    values = tuple(item for item, member in value_entries if member is value)
    orders = tuple(index for index, member in enumerate(canonical_members) if member is value)
    if len(names) != 1 or len(values) != 1 or len(orders) != 1:
        return None
    return names[0], values[0], orders[0]


__all__ = ["closed_graph_problem"]
