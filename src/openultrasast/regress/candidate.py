"""Safety-gated regression execution (task 4.3)."""

from __future__ import annotations

from dataclasses import dataclass

from ..sandbox import SandboxJob, SandboxResult, SandboxRunner
from .safety import UnsafeSnippetError, check_snippet_safety

INCONCLUSIVE = "inconclusive"
SAFETY_REJECTED = "safety_rejected"
TRIGGERABLE = "triggerable"
NOT_TRIGGERABLE = "not_triggerable"


@dataclass(frozen=True)
class RegressionVerdict:
    verdict: str
    reason: str = ""


class RegressionRunner:
    """Run a snippet in the sandbox only after the structural safety check passes."""

    def __init__(self, sandbox: SandboxRunner) -> None:
        self._sandbox = sandbox

    def run_snippet(self, snippet: str, job: SandboxJob) -> RegressionVerdict:
        try:
            check_snippet_safety(snippet)
        except UnsafeSnippetError:
            return RegressionVerdict(verdict=INCONCLUSIVE, reason=SAFETY_REJECTED)
        return _verdict_from_result(self._sandbox.run(job))


def _verdict_from_result(result: SandboxResult) -> RegressionVerdict:
    if result.timed_out:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason="timeout")
    if result.exit_code != 0:
        return RegressionVerdict(verdict=TRIGGERABLE, reason="nonzero_exit")
    return RegressionVerdict(verdict=NOT_TRIGGERABLE, reason="exit_zero")
