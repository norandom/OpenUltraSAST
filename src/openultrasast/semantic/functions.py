"""Function ranges now belong to source."""

from ..source import FunctionRange, enclosing, ranges

__all__ = ["FunctionRange", "enclosing", "ranges", "function_at"]


def function_at(ranges: tuple[FunctionRange, ...], line: int | None) -> str:
    """kept one release; use source.enclosing"""
    return enclosing(ranges, line)
