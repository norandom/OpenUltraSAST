"""Map sandbox outcomes to verdicts and the worth-fixing gate."""

from __future__ import annotations

from dataclasses import dataclass

from ..sandbox import SandboxResult

TRIGGERABLE = "triggerable"
NOT_TRIGGERABLE = "not_triggerable"
ALREADY_COVERED = "already_covered"
INCONCLUSIVE = "inconclusive"

MISSING_RECIPE = "missing_recipe"
SAFETY_REJECTED = "safety_rejected"
SANDBOX_UNAVAILABLE = "sandbox_unavailable"
TIMEOUT = "timeout"
COVERED_TEST_PASSED = "covered_test_passed"
ASSERTION = "assertion"
SANITIZER_ABORT = "sanitizer_abort"
CRASH = "crash"
NONZERO_EXIT = "nonzero_exit"
EXIT_ZERO = "exit_zero"

WORTH_FIXING_REACHABILITY = frozenset({"reachable", "inferred-file-surface"})

_SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
    "LeakSanitizer",
)
_ASSERTION_MARKERS = (
    "AssertionError",
    "Assertion failed",
    "assertion failed",
    "assert failed",
)
_CRASH_MARKERS = (
    "Fatal Python error",
    "Segmentation fault",
    "SIGSEGV",
    "SIGABRT",
    "Aborted",
)


@dataclass(frozen=True)
class RegressionVerdict:
    verdict: str
    reason: str = ""
    worth_fixing: bool = False


def is_worth_fixing(verdict: str, reachability: str) -> bool:
    """True iff the candidate is triggerable on a reachable or inferred-file-surface finding."""
    return verdict == TRIGGERABLE and reachability in WORTH_FIXING_REACHABILITY


def verdict_from_result(
    result: SandboxResult | None = None,
    *,
    recipe_missing: bool = False,
    sandbox_missing: bool = False,
    safety_rejected: bool = False,
    covering_test: bool = False,
) -> RegressionVerdict:
    """Map a sandbox observation onto one of the four regression verdicts."""
    if recipe_missing:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason=MISSING_RECIPE)
    if sandbox_missing:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason=SANDBOX_UNAVAILABLE)
    if safety_rejected:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason=SAFETY_REJECTED)
    if result is None:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason=SANDBOX_UNAVAILABLE)
    if result.timed_out:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason=TIMEOUT)
    if covering_test and result.exit_code == 0:
        return RegressionVerdict(verdict=ALREADY_COVERED, reason=COVERED_TEST_PASSED)
    if result.exit_code != 0:
        return RegressionVerdict(verdict=TRIGGERABLE, reason=_nonzero_reason(result))
    return RegressionVerdict(verdict=NOT_TRIGGERABLE, reason=EXIT_ZERO)


def _nonzero_reason(result: SandboxResult) -> str:
    text = f"{result.stdout}\n{result.stderr}".lower()
    if any(marker.lower() in text for marker in _SANITIZER_MARKERS):
        return SANITIZER_ABORT
    if any(marker.lower() in text for marker in _ASSERTION_MARKERS):
        return ASSERTION
    if any(marker.lower() in text for marker in _CRASH_MARKERS):
        return CRASH
    return NONZERO_EXIT
