"""Strict immutable manifest values shared by engine and adapters (pre-push Req 7.3).

These schemas validate structure, not source readability, Git object existence or alert
eligibility. Live resources deliberately have no manifest decoder.
"""

from __future__ import annotations

import math
from dataclasses import fields
from types import UnionType
from typing import Any, Literal, Self, get_args, get_origin, get_type_hints

_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = get_type_hints(cls)
    return _HINTS[cls]


def _value(value: object, kind: Any, *, decode: bool) -> object:
    origin, args = get_origin(kind), get_args(kind)
    if origin is UnionType:
        for candidate in args:
            try:
                return _value(value, candidate, decode=decode)
            except ValueError:
                pass
        raise ValueError(f"invalid union value: {value!r}")
    if origin is Literal:
        if any(type(value) is type(option) and value == option for option in args):
            return value
    elif origin is tuple:
        if type(value) is tuple or (decode and type(value) is list):
            items = tuple(value)  # type: ignore[arg-type]
            if len(args) == 2 and args[1] is Ellipsis:
                return tuple(_value(item, args[0], decode=decode) for item in items)
            if len(items) == len(args):
                return tuple(_value(item, item_type, decode=decode) for item, item_type in zip(items, args, strict=True))
    elif isinstance(kind, type) and issubclass(kind, Contract):
        if decode:
            return kind.from_payload(value)
        if isinstance(value, kind):
            return value
    elif kind is float:
        if type(value) in (int, float):
            try:
                if math.isfinite(value):  # type: ignore[arg-type]
                    return value
            except OverflowError:
                pass
    elif kind is str:
        if type(value) is str and value.strip():
            return value
    elif type(value) is kind:
        return value
    raise ValueError(f"invalid {kind}: {value!r}")


def _payload(value: object) -> object:
    if isinstance(value, Contract):
        return value.to_payload()
    if isinstance(value, tuple):
        return [_payload(item) for item in value]
    return value


class Contract:
    """Base for frozen dataclasses with strict construction and JSON round trips."""

    def __post_init__(self) -> None:
        for name, kind in _hints(type(self)).items():
            try:
                _value(getattr(self, name), kind, decode=False)
            except ValueError as error:
                raise ValueError(f"{type(self).__name__}.{name}: {error}") from error

    def to_payload(self) -> dict[str, object]:
        return {item.name: _payload(getattr(self, item.name)) for item in fields(self)}  # type: ignore[arg-type]

    @classmethod
    def from_payload(cls, payload: object) -> Self:
        if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
            raise ValueError(f"{cls.__name__} requires an object")
        hints = _hints(cls)
        if unknown := payload.keys() - hints.keys():
            raise ValueError(f"unknown {cls.__name__} fields: {sorted(unknown)}")
        try:
            return cls(**{name: _value(value, hints[name], decode=True) for name, value in payload.items()})
        except TypeError as error:
            raise ValueError(f"invalid {cls.__name__}: {error}") from error
