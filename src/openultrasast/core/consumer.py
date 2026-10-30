"""Consumer contracts for the detection core (Req 9, 11).

The pre-push transaction consumes traces and verdicts through this interface within
its (measured) budget; the proof layer attaches demonstrated evidence to a verdict.
Every claim must carry a witness; every silence must carry a coverage reason.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core.trace import TraceRecord
from openultrasast.core.verdict import BoundedSilence, ProvenClaim


@dataclass(frozen=True)
class PushRequest:
    """One push transaction handed to the core."""

    base: str
    head: str
    budget_class: str


@dataclass(frozen=True)
class PushVerdict:
    """What the push consumer receives: proven claims plus bounded silence."""

    claims: tuple[ProvenClaim, ...]
    silence: tuple[BoundedSilence, ...]
    digests: dict[str, str]


def consume_verdict(
    request: PushRequest,
    record: TraceRecord,
    claims: Sequence[ProvenClaim],
    silence: Sequence[BoundedSilence],
) -> PushVerdict:
    """Validate and wrap one trace's verdict for the push consumer (Req 5, 11.1).

    A claim without a witness or a silence without a reason is refused: silence is
    never a clean bill of health.
    """
    for claim in claims:
        if not claim.witness or not claim.path or claim.line <= 0:
            raise ValueError(f"proven claim lacks witness or exact location: {claim}")
    for entry in silence:
        if not entry.reason:
            raise ValueError(f"bounded silence lacks a coverage reason: {entry}")
    return PushVerdict(claims=tuple(claims), silence=tuple(silence), digests=dict(record.digests))


__all__ = ["PushRequest", "PushVerdict", "consume_verdict"]
