"""Coverage accounting for the detection core (Req 3).

Every input is accounted for: entry recognition, exactly one resolution bucket per
call, named reasons for unchecked operations. A zero-byte or unreadable input is an
instrument failure -- a zero from an unread input is a failed run, never a clean one.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field


class InstrumentFailure(ValueError):
    """The run's input was not read; any result from it is invalid."""


class ResolutionOutcome(enum.Enum):
    """Exactly one bucket per call (Req 3.1)."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class Coverage:
    """Coverage of one analyzed change."""

    entry_points: int
    frameworks_recognised: dict[str, int] = field(default_factory=dict)
    calls: int = 0
    complete: int = 0
    incomplete: int = 0
    unresolved: int = 0
    unchecked_reasons: dict[str, int] = field(default_factory=dict)

    def validate(self) -> None:
        """Refuse coverage where calls lack exactly one resolution bucket."""
        buckets = (self.complete, self.incomplete, self.unresolved)
        if min(buckets) < 0:
            raise ValueError(f"negative resolution bucket in {buckets}")
        if sum(buckets) != self.calls:
            raise ValueError(
                f"resolution buckets ({self.complete}+{self.incomplete}+{self.unresolved}) must equal the call count ({self.calls})"
            )


def check_reads(reads: Mapping[str, int]) -> None:
    """Fail the run when any tracked input was read as zero bytes (Req 3.2)."""
    zero = sorted(path for path, size in reads.items() if size <= 0)
    if zero:
        raise InstrumentFailure(f"zero-byte read of tracked input: {', '.join(zero)}")


__all__ = ["Coverage", "InstrumentFailure", "ResolutionOutcome", "check_reads"]
