"""Verdict vocabulary and verdict contract for the detection core (Req 2, 5, 9).

Every analyzed operation is judged as exactly one of unguarded, discharged, or
indeterminate. A verdict is either a proven claim (witness attached, exact
location) or a bounded silence (coverage reason attached). Indeterminate never
converts to clean, and models may only judge residuals zero-shot over a trace.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class Judgment(enum.Enum):
    """The three-way judgment vocabulary; value strings are the wire format."""

    UNGUARDED = "unguarded"
    DISCHARGED = "discharged"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ProvenClaim:
    """A defect claim carrying its witness and exact location (Req 5.1)."""

    trace_id: str
    witness: str
    path: str
    line: int
    family: str


@dataclass(frozen=True)
class BoundedSilence:
    """An undecided site with its coverage reason; never a clean result (Req 5.2)."""

    path: str
    reason: str
    coverage: dict[str, Any]


def as_clean(judgment: Judgment) -> Judgment:
    """Return a clean judgment, refusing to convert indeterminate (Req 2.1)."""
    if judgment is Judgment.INDETERMINATE:
        raise ValueError("indeterminate never converts to a clean judgment")
    return judgment


__all__ = ["BoundedSilence", "Judgment", "ProvenClaim", "as_clean"]
