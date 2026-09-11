"""Where the `[[layout]]` facts meet a repository: which paths are vendored, which are tests.

One place, imported by the preprocessor (vendored trees leave the targets), the scan (test regions are
not product, and vendored directories leave the graph) and the position benchmark (so it measures the
order the scan spends). Facts are rows; this is only the matching.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from pathlib import Path

from ..semantic.facts import LayoutFact, load_facts
from .regions import ScanRegion


def layout_facts(language: str | None = None) -> tuple[LayoutFact, ...]:
    """The layout rows -- for one language, or for every language when the question is about a tree."""
    facts = load_facts()
    return tuple(facts.for_language(language).layouts if language else facts.layouts)


def _matches(relative: str, patterns: Iterable[str]) -> bool:
    """gitignore-style: `dir/` names a directory at any depth, anything else a path or basename glob."""
    parts = relative.split("/")
    for pattern in patterns:
        if pattern.endswith("/"):
            if pattern.rstrip("/") in parts[:-1] or pattern.rstrip("/") in parts:
                return True
        elif fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(parts[-1], pattern):
            return True
    return False


def is_vendored(relative: str, facts: Sequence[LayoutFact] | None = None) -> bool:
    rows = facts if facts is not None else layout_facts()
    return _matches(relative, (p for fact in rows for p in fact.vendored))


def is_test_path(relative: str, facts: Sequence[LayoutFact] | None = None) -> bool:
    rows = facts if facts is not None else layout_facts()
    return _matches(relative, (p for fact in rows for p in fact.tests))


def vendored_directories(root: Path, facts: Sequence[LayoutFact] | None = None) -> tuple[str, ...]:
    """The vendored directories actually present under ``root``, repository-relative, shallowest first --
    what a frontend's ``--exclude`` takes."""
    rows = facts if facts is not None else layout_facts()
    names = {p.rstrip("/") for fact in rows for p in fact.vendored if p.endswith("/")}
    found: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_dir() or path.name not in names:
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative.startswith(f"{seen}/") for seen in found):
            continue  # already covered by a shallower vendored directory
        found.append(relative)
    return tuple(found)


def with_layout(regions: Sequence[ScanRegion], facts: Sequence[LayoutFact] | None = None) -> tuple[ScanRegion, ...]:
    """Test-path regions marked not shipped -- ordered after the product's, never removed. A region a
    build manifest already declared shipped stays so: the manifest is the project's own word."""
    from dataclasses import replace

    rows = facts if facts is not None else layout_facts()
    return tuple(replace(r, shipped=False) if r.shipped and is_test_path(r.path, rows) else r for r in regions)
