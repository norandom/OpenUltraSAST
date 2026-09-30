"""Requirement 2.4 of the removal spec: the removed agentic plane is named only in its retirement notes.

A case-insensitive search of ``src/``, ``tests/``, ``pyproject.toml`` and the README may match only lines tagged
``retired 2026-..``: the retired-key table and the one warning in ``config.py``, the retirement tests, and the README's
plane section. The spec's own slug (its directory name, the equality instrument's file name) is a citation of the
removal, not a use of the plane, and is not counted. The pattern is built at runtime so this file does not match it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_NAME = "harness" + "x"
_PATTERN = re.compile(_NAME, re.IGNORECASE)
_SPEC_SLUG = re.compile(_NAME + r"[-_]removal", re.IGNORECASE)
_TAG = re.compile(r"retired 2026-\d\d-\d\d", re.IGNORECASE)


def _untagged(paths: list[Path]) -> list[str]:
    offenders = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if _PATTERN.search(_SPEC_SLUG.sub("", line)) and not _TAG.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:120]}")
    return offenders


def _tree(*roots: str) -> list[Path]:
    return sorted(p for root in roots for p in (ROOT / root).rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_no_harnessx_outside_retirement_notes() -> None:  # the Req 2.4 check itself, retired 2026-09-30
    offenders = _untagged([*_tree("src", "tests"), ROOT / "pyproject.toml"])
    assert offenders == [], "the removed plane is named outside a tagged retirement note:\n" + "\n".join(offenders)


def test_the_retirement_notes_exist() -> None:
    """The search is not vacuous: the one warning and the retired keys are where the design puts them."""
    config = (ROOT / "src/openultrasast/config.py").read_text()
    assert _PATTERN.search(config) and _TAG.search(config)


@pytest.mark.xfail(strict=True, reason="the README's plane sections are rewritten in task 8; drop this mark there")
def test_the_readme_names_the_removed_plane_only_in_its_retirement_note() -> None:
    offenders = _untagged([ROOT / "README.md"])
    assert offenders == [], "\n".join(offenders)
