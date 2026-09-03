"""Isolated regression snippets and verdicts."""

from .candidate import RegressionRunner, select_candidates
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
    "RegressionRunner",
    "RegressionVerdict",
    "UnsafeSnippetError",
    "check_snippet_safety",
    "is_worth_fixing",
    "recipe_for",
    "select_candidates",
    "verdict_from_result",
]
