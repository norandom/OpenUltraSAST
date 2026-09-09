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
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from ..findings import StaticFinding

_Finding = TypeVar("_Finding", bound="StaticFinding")


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
    # ``path:line`` of the evidence, when the arbiter knows it. Once a flow may cross into another module,
    # the region that asked the question is no longer where the answer lives, and a finding reported against
    # the handler's file when the bug is two modules away is unactionable.
    location: str = ""


def at_rung(finding: _Finding, verdict: Verdict | None) -> _Finding:
    """Return ``finding`` carrying ``verdict``'s rung and witness, or unchanged when there is no verdict.

    This is the only way a finding rises above ``suspicion`` (Req 5.4). The witness travels with the rung
    because a rung without the evidence that justifies it is just a louder assertion.
    """
    from dataclasses import replace

    if verdict is None or verdict.rung is Rung.SUSPICION:
        return finding
    rationale = finding.rationale
    if verdict.witness and verdict.witness not in rationale:
        rationale = f"{rationale} [{verdict.rung.value}: {verdict.witness}]".strip()
    return replace(finding, rung=verdict.rung.value, rationale=rationale)


__all__ = ["Rung", "Verdict", "at_or_above", "at_rung"]
