"""Sibling handler sets and consistency anomalies (authorization-obligations, Req 3).

Handlers that operate on the same resource under the same router or module are siblings. When at least the configured
minimum number of siblings discharge an obligation and one does not (Req 3.2), that one is the anomaly; its evidence is
the siblings that discharge. A set with fewer members than the minimum is counted as under-populated and never produces
a finding (Req 3.3). Nothing here touches other findings.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .facts import DISCHARGER_KINDS
from .operations import Discharge, Operation, valid_witness


@dataclass(frozen=True)
class SiblingSet:
    key: tuple[str, str]  # (module path without suffix, resource token)
    handlers: tuple[str, ...]  # "path::function"
    discharging: dict[str, tuple[str, ...]]  # discharger kind -> handlers that carry a valid witness of that kind
    operation_kinds: tuple[str, ...]
    access_levels: dict[str, str] = field(default_factory=dict)  # handler -> entry-point access classification


@dataclass(frozen=True)
class Anomaly:
    handler: str
    missing: str  # discharger kind the siblings practice and this handler lacks
    operation_kind: str
    siblings: tuple[str, ...]  # handlers that discharge
    key: tuple[str, str]
    access_level: str = "unknown"
    evidence: tuple[str, ...] = ()


def sibling_sets(entries: Sequence[object], operations: Sequence[Operation], discharges: Sequence[Discharge]) -> tuple[SiblingSet, ...]:
    """Group entry-point handlers by (module, resource) over the operations they perform; record who discharges what."""
    by_handler_ops: dict[str, list[Operation]] = {}
    for operation in operations:
        by_handler_ops.setdefault(f"{operation.path}::{operation.function}", []).append(operation)
    access: dict[str, str] = {}
    for entry in entries:
        name = getattr(entry, "function_name", None)
        path = getattr(entry, "path", None)
        if name and path:
            access[f"{path}::{name}"] = str(getattr(entry, "access_level", "unknown"))
    valid: dict[str, set[str]] = {}
    for witness in discharges:
        if valid_witness(witness):
            valid.setdefault(f"{witness.path}::{witness.function}", set()).add(witness.kind)
    groups: dict[tuple[str, str], dict[str, list[Operation]]] = {}
    for handler, ops in by_handler_ops.items():
        if handler not in access:
            continue  # only entry-point handlers are siblings; helpers are reached through them
        module = _module_of(handler.split("::", 1)[0])
        for operation in ops:
            if operation.resource is None:
                continue
            groups.setdefault((module, operation.resource), {}).setdefault(handler, []).append(operation)
    sets: list[SiblingSet] = []
    for key, members in sorted(groups.items()):
        handlers = tuple(sorted(members))
        discharging = {
            kind: tuple(sorted(handler for handler in handlers if kind in valid.get(handler, set()))) for kind in DISCHARGER_KINDS
        }
        kinds = tuple(sorted({operation.kind for ops in members.values() for operation in ops}))
        sets.append(
            SiblingSet(
                key=key,
                handlers=handlers,
                discharging={kind: who for kind, who in discharging.items() if who},
                operation_kinds=kinds,
                access_levels={handler: access.get(handler, "unknown") for handler in handlers},
            )
        )
    return tuple(sets)


def consistency_anomalies(sets: Sequence[SiblingSet], *, min_siblings: int) -> tuple[tuple[Anomaly, ...], tuple[tuple[str, str], ...]]:
    """Anomalies where at least ``min_siblings`` siblings discharge a kind another sibling lacks; sets with fewer members than
    ``min_siblings`` are returned as under-populated instead. One threshold, read as Req 3.2 states it."""
    anomalies: list[Anomaly] = []
    under: list[tuple[str, str]] = []
    for group in sets:
        if len(group.handlers) < min_siblings:
            under.append(group.key)
            continue
        for kind, dischargers in sorted(group.discharging.items()):
            if len(dischargers) < min_siblings:
                continue  # one sibling does not set a norm
            for handler in group.handlers:
                if handler in dischargers:
                    continue
                access = group.access_levels.get(handler, "unknown")
                evidence: list[str] = [f"{sibling} discharges {kind}" for sibling in dischargers]
                if kind == "path_guard":
                    evidence.append(
                        f"route access: {access}; siblings: "
                        + ", ".join(sorted({group.access_levels.get(s, "unknown") for s in dischargers}))
                    )
                for operation_kind in group.operation_kinds:
                    anomalies.append(
                        Anomaly(
                            handler=handler,
                            missing=kind,
                            operation_kind=operation_kind,
                            siblings=dischargers,
                            key=group.key,
                            access_level=access,
                            evidence=tuple(evidence),
                        )
                    )
    return tuple(anomalies), tuple(under)


def _module_of(path: str) -> str:
    """The module path without its suffix: `api/v1/books.py` -> `api/v1/books`. Two same-named files in different
    directories are different modules, so their handlers are never siblings."""
    return Path(path).with_suffix("").as_posix()


__all__ = ["Anomaly", "SiblingSet", "consistency_anomalies", "sibling_sets"]
