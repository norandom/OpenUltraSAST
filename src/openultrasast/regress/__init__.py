"""Isolated regression snippets and verdicts."""

from .candidate import CandidateVerdict, RegressionRunner, run_regression, select_candidates, write_verdicts
from .recipes import recipe_for
from .safety import UnsafeSnippetError, check_snippet_safety
from .verdict import (
    ALREADY_COVERED,
    INCONCLUSIVE,
    MISSING_RECIPE,
    NOT_TRIGGERABLE,
    SAFETY_REJECTED,
    TRIGGERABLE,
    RegressionVerdict,
    is_worth_fixing,
    verdict_from_result,
)

__all__ = [
    "ALREADY_COVERED",
    "INCONCLUSIVE",
    "MISSING_RECIPE",
    "NOT_TRIGGERABLE",
    "SAFETY_REJECTED",
    "TRIGGERABLE",
    "CandidateVerdict",
    "RegressionRunner",
    "RegressionVerdict",
    "UnsafeSnippetError",
    "check_snippet_safety",
    "is_worth_fixing",
    "recipe_for",
    "run_regression",
    "select_candidates",
    "verdict_from_result",
    "write_verdicts",
]
