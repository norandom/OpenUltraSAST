"""The evidence ladder: what established a finding (model-grounded-detection Req 5).

Every finding carries the rung that established it, so a deterministic model result is never confused with an
LLM suspicion. The two middle rungs are the point of this feature:

    suspicion           a site was enumerated and something flagged it
    model_corroborated  the LLM's claim is consistent with the CPG -- the source it names reaches the sink it
                        names, or a guard its siblings carry is absent
    model_entailed      the CPG establishes it alone, independent of trusting the LLM
    execution_confirmed a sandbox reproduced it (deferred tier, memory/C first)

`model_corroborated` and above are established with no model call, and deterministically: run the checker
twice over the same CPG and the verdict sequence is identical. That is what removes the run-to-run noise the
prior architecture tried to average away.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Rung(StrEnum):
    SUSPICION = "suspicion"
    CORROBORATED = "model_corroborated"
    ENTAILED = "model_entailed"
    EXECUTION_CONFIRMED = "execution_confirmed"


# Ascending strength; `_ORDER.index` is the comparison, so a new rung cannot be silently mis-ranked.
_ORDER = (Rung.SUSPICION, Rung.CORROBORATED, Rung.ENTAILED, Rung.EXECUTION_CONFIRMED)


def at_or_above(rung: Rung, threshold: Rung) -> bool:
    return _ORDER.index(rung) >= _ORDER.index(threshold)


@dataclass(frozen=True)
class Verdict:
    """What the model established, and the evidence it established it from."""

    rung: Rung
    family: str
    witness: str = ""  # the taint path or the dominance fact; empty only at `suspicion`
    contradiction: str = ""  # why an LLM claim was dropped, when it was


__all__ = ["Rung", "Verdict", "at_or_above"]
