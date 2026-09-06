"""One rule for who may teach, and one refusal for anything that touches the holdout (Req 5.1, 5.2).

Every learning path in the tool asks this module the same question, so the split cannot be enforced in
one place and forgotten in another. A teacher is a vendored pair, at a review tier a maintainer stands
behind, on the train split, and scorable. Everything else may be measured; nothing else may teach.

A refusal is data, not an exception: the path records which holdout pairs a candidate touched and moves
on, so a leak is visible in the run rather than silently accepted.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

GATING_TIERS = frozenset({"seeded", "reviewed"})
TRAIN = "train"
HOLDOUT = "holdout"
REFUSED = "holdout_pair_refused"


@dataclass(frozen=True)
class Refusal:
    """A candidate that a holdout pair taught, or that touches one."""

    pairs: tuple[str, ...]
    reason: str = REFUSED

    def degradation(self) -> dict[str, object]:
        return {
            "stage": "learning",
            "reason": self.reason,
            "pairs": list(self.pairs),
            "detail": f"refused: taught by or touching holdout pair(s) {', '.join(self.pairs)}",
        }


def teachers(cases: Sequence[object]) -> tuple[object, ...]:
    """The pairs a learning path may learn from. Everything else is measured, never learned from."""
    return tuple(case for case in cases if is_teacher(case))


def is_teacher(case: object) -> bool:
    if not bool(getattr(case, "vendored", True)):
        return False
    if str(getattr(case, "review_tier", "")) not in GATING_TIERS:
        return False
    if str(getattr(case, "split", TRAIN)) != TRAIN:
        return False
    return getattr(case, "unscorable", None) is None


def holdout_names(cases: Sequence[object]) -> frozenset[str]:
    return frozenset(str(getattr(case, "name", "")) for case in cases if str(getattr(case, "split", "")) == HOLDOUT)


def refuse_if_holdout(taught_by: Iterable[str], cases: Sequence[object]) -> Refusal | None:
    """None when nothing in ``taught_by`` is a holdout pair; a refusal naming them when something is."""
    held = holdout_names(cases)
    touched = tuple(sorted({name for name in taught_by if name in held}))
    return Refusal(pairs=touched) if touched else None


__all__ = ["GATING_TIERS", "HOLDOUT", "REFUSED", "TRAIN", "Refusal", "holdout_names", "is_teacher", "refuse_if_holdout", "teachers"]
