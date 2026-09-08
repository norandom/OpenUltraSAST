"""The execution tier: deferred, adopted, and deliberately narrow (model-grounded-detection, Req 10).

This is the rung this project does **not** build. Clearwing already runs sandbox lifecycles, container pools,
sanitizer images, PoC replay and stability classification, and the corrective brief that started this feature
concluded — from this project's own defect history — that reimplementing that class of machinery is exactly
where we go wrong. So the module is a seam: it decides *eligibility*, calls an adopted tool, and records what
happened. A test asserts structurally that it imports no container or subprocess machinery and defines no
build/run/compile/patch function, because the failure mode to prevent is this file quietly growing a sandbox.

Eligibility is narrow on purpose, and both halves matter:

* **Only a family a static model cannot arbitrate.** Memory safety in C turns on runtime layout, so a crash
  is the right oracle. Every web/logic family has taint reachability, guard dominance or constant
  abstraction, and Req 10.3 forbids any of them depending on this tier.
* **Only a finding the model could not decide.** The tier escalates uncertainty; it never re-checks a verdict
  the model already reached.

And a failure to reproduce is *not* a refutation. A sandbox that does not trigger a bug has not shown the bug
is absent — it has shown this attempt did not trigger it. The candidate stays exactly where the model left it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from .ladder import Rung

# Families whose bugs a static model genuinely cannot arbitrate. Everything else is served by taint
# reachability, guard dominance or constant abstraction, and must not wait on a sandbox.
EXECUTION_FAMILIES = frozenset({"memory"})

# Rungs that mean "the model could not decide". Anything above is already arbitrated.
UNDECIDED = frozenset({"suspicion", ""})

CLEARWING_ENV = "OPENULTRASAST_CLEARWING"
_OFF = frozenset({"0", "off", "false", "no"})
_ON = frozenset({"1", "on", "true", "yes"})


@dataclass(frozen=True)
class Candidate:
    """What the execution tier is asked about: a finding the static model left undecided."""

    finding_id: str
    family: str
    rung: str
    path: str
    line: int | None = None


@dataclass(frozen=True)
class Outcome:
    """What the tier concluded. ``rung`` is ``None`` whenever nothing was established."""

    rung: Rung | None
    reason: str


class ExecutionBackend(Protocol):
    def available(self) -> bool: ...

    def reproduce(self, candidate: Candidate) -> bool: ...


@dataclass
class NullExecutionBackend:
    """No adopted tool present. The normal case, and not an error."""

    def available(self) -> bool:
        return False

    def reproduce(self, candidate: Candidate) -> bool:
        del candidate
        return False


def eligible(candidate: Candidate) -> bool:
    """Is this candidate one the execution tier should even look at?"""
    return candidate.family in EXECUTION_FAMILIES and candidate.rung in UNDECIDED


def confirm(candidate: Candidate, *, backend: ExecutionBackend | None = None) -> Outcome:
    """Escalate one undecided candidate to the adopted execution tier, if there is one."""
    if not eligible(candidate):
        return Outcome(
            rung=None,
            reason=f"not_eligible: family {candidate.family!r} at rung {candidate.rung!r} is arbitrated statically",
        )
    engine = backend if backend is not None else resolve_execution_backend()
    if not engine.available():
        return Outcome(rung=None, reason="clearwing_unavailable: no adopted execution tier on this machine")
    if not engine.reproduce(candidate):
        # Deliberate wording: this is not a refutation. Failing to trigger a bug is not showing it is absent.
        return Outcome(rung=None, reason="not_reproduced: the attempt did not trigger it; the finding is unchanged")
    return Outcome(rung=Rung.EXECUTION_CONFIRMED, reason="reproduced in the adopted sandbox")


def resolve_execution_backend() -> ExecutionBackend:
    """The adopted tier for this machine. Absent by default; the environment flag is what the matrix drives."""
    flag = os.environ.get(CLEARWING_ENV, "").strip().lower()
    if flag in _OFF or flag not in _ON:
        return NullExecutionBackend()
    return NullExecutionBackend()  # the adopted tool is wired here when a class needs it (Req 10.1)


__all__ = [
    "CLEARWING_ENV",
    "EXECUTION_FAMILIES",
    "Candidate",
    "ExecutionBackend",
    "NullExecutionBackend",
    "Outcome",
    "confirm",
    "eligible",
    "resolve_execution_backend",
]
