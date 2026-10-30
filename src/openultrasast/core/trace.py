"""Canonical trace schema for the detection core (Req 1).

One family-agnostic trace record per analyzed change, serialized deterministically:
identical inputs produce byte-identical canonical output. The access-control
prover's trace is the first implementation of this contract.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from openultrasast.core.verdict import Judgment


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class Hop:
    """One ordered hop with its call-target completeness."""

    function: str
    call_line: int | None
    complete: bool


@dataclass(frozen=True)
class Witness:
    """Evidence for or against a guard, with provenance and match relation."""

    kind: str
    provenance: str
    relation: str


@dataclass(frozen=True)
class Guard:
    """A guard effect observed on a path (kind plus effect)."""

    kind: str
    effect: str


@dataclass(frozen=True)
class TraceRecord:
    """The canonical security trace: entry, hops, operation, witnesses, guards, judgment, digests."""

    entry: str
    hops: tuple[Hop, ...]
    operation_kind: str
    resource: str
    authority: str
    witnesses: tuple[Witness, ...] = ()
    guards: tuple[Guard, ...] = ()
    completeness_reasons: tuple[str, ...] = ()
    judgment: Judgment = Judgment.INDETERMINATE
    digests: dict[str, str] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        """JSON-ready dict with sorted keys; enums encode as their value strings."""
        payload: dict[str, Any] = asdict(self)
        payload["judgment"] = self.judgment.value
        record: dict[str, Any] = json.loads(json.dumps(payload, sort_keys=True))
        return record

    def canonical(self) -> bytes:
        """Deterministic byte serialization (Req 1.2)."""
        return _canonical_bytes(self.record())


__all__ = ["Hop", "TraceRecord", "Witness"]
