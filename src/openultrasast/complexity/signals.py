from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..findings import StaticFinding
from ..preprocess import FileTarget

# Inventory density is a recorded feature and a capped rationale term, not the rank driver.
_LOC_COEFF = 0.85
_NESTING_COEFF = 0.2
_REACHABILITY_COEFF = 0.55
_TEST_GAP_COEFF = 0.35
_INVENTORY_COEFF = 0.12
_TAG_WEIGHTS: dict[str, float] = {
    "parser": 4.0,
    "deserialization": 3.5,
    "network_entry": 1.75,
    "auth_boundary": 1.5,
    "fuzzable": 1.5,
    "memory_unsafe": 1.25,
    "crypto": 1.25,
    "syscall_entry": 1.25,
    "filesystem_entry": 1.0,
}
_TEST_ROOT_PARTS = frozenset({"tests", "test", "__tests__", "spec"})


@dataclass(frozen=True)
class ComplexitySignals:
    path: str
    function_name: str | None
    loc: int
    nesting: int
    tags: tuple[str, ...]
    reachability: int
    inventory_hit_count: int
    has_adjacent_test: bool
    score: float


def collect_signals(
    targets: Sequence[FileTarget],
    findings: Sequence[StaticFinding] = (),
    repo_files: Iterable[str] = (),
    sources: Mapping[str, str] | None = None,
) -> tuple[ComplexitySignals, ...]:
    inventory = _inventory_counts(findings)
    repo_paths = {str(path).replace("\\", "/") for path in repo_files}
    collected: list[ComplexitySignals] = []
    for target in targets:
        text = _source_text(target, sources)
        nesting = measure_nesting(text)
        hit_count = inventory.get(target.path, 0)
        adjacent = _has_adjacent_test(target.path, repo_paths)
        tags = tuple(target.tags)
        names = _function_names(target.reachability_hints)
        identities: tuple[str | None, ...] = names or (None,)
        for function_name in identities:
            reachability = _reachability(target.reachability_hints, function_name)
            collected.append(
                ComplexitySignals(
                    path=target.path,
                    function_name=function_name,
                    loc=target.loc,
                    nesting=nesting,
                    tags=tags,
                    reachability=reachability,
                    inventory_hit_count=hit_count,
                    has_adjacent_test=adjacent,
                    score=_score(
                        loc=target.loc,
                        nesting=nesting,
                        tags=tags,
                        reachability=reachability,
                        inventory_hit_count=hit_count,
                        has_adjacent_test=adjacent,
                    ),
                )
            )
    return tuple(sorted(collected, key=lambda item: (-item.score, item.path, item.function_name or "")))


def measure_nesting(text: str) -> int:
    if not text:
        return 0
    max_indent = 0
    max_braces = 0
    braces = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        expanded = raw.expandtabs(4)
        indent = len(expanded) - len(expanded.lstrip(" "))
        max_indent = max(max_indent, indent // 4)
        for char in raw:
            if char == "{":
                braces += 1
                max_braces = max(max_braces, braces)
            elif char == "}":
                braces = max(0, braces - 1)
    return max(max_indent, max_braces)


def _score(
    *,
    loc: int,
    nesting: int,
    tags: Sequence[str],
    reachability: int,
    inventory_hit_count: int,
    has_adjacent_test: bool,
) -> float:
    loc_term = math.log1p(max(loc, 0)) * _LOC_COEFF
    nest_term = min(max(nesting, 0), 16) * _NESTING_COEFF
    tag_term = sum(_TAG_WEIGHTS.get(tag, 0.0) for tag in dict.fromkeys(tags))
    reach_term = max(reachability, 0) * _REACHABILITY_COEFF
    gap_term = 0.0 if has_adjacent_test else _TEST_GAP_COEFF
    density = inventory_hit_count / max(loc, 1)
    inventory_term = min(max(density, 0.0), 1.0) * _INVENTORY_COEFF
    return round(loc_term + nest_term + tag_term + reach_term + gap_term + inventory_term, 4)


def _source_text(target: FileTarget, sources: Mapping[str, str] | None) -> str:
    if sources:
        if target.path in sources:
            return sources[target.path]
        if target.absolute_path in sources:
            return sources[target.absolute_path]
    path = Path(target.absolute_path)
    if not path.is_file():
        return ""
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _inventory_counts(findings: Sequence[StaticFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.path] = counts.get(finding.path, 0) + 1
    return counts


def _function_names(hints: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for hint in hints:
        name = _hint_function_name(hint)
        if name is not None and name not in seen:
            names.append(name)
            seen.add(name)
    return tuple(names)


def _hint_function_name(hint: Mapping[str, object]) -> str | None:
    if "function_name" in hint:
        value = hint.get("function_name")
        return value if isinstance(value, str) and value else None
    value = hint.get("name")
    return value if isinstance(value, str) and value else None


def _reachability(hints: Sequence[Mapping[str, object]], function_name: str | None) -> int:
    selected: Sequence[Mapping[str, object]] = hints
    if function_name is not None:
        matching = [hint for hint in hints if _hint_function_name(hint) == function_name]
        if matching:
            selected = matching
    if not selected:
        return 0
    score = 2
    for hint in selected:
        access_level = hint.get("access_level")
        kind = hint.get("kind")
        if access_level == "public":
            score = max(score, 5 if kind in {"route", "parser", "fuzz"} else 4)
        elif access_level in {"authenticated", "contract-only/callback"}:
            score = max(score, 4)
        elif access_level == "role-restricted":
            score = max(score, 3)
        else:
            score = max(score, 2)
    return score


def _has_adjacent_test(path: str, repo_files: set[str]) -> bool:
    source = PurePosixPath(path)
    source_stem = source.stem.lower()
    source_parent = _parent(source)
    for candidate in repo_files:
        name = PurePosixPath(candidate).name
        if not _is_test_filename(name):
            continue
        if _tested_stem(name).lower() != source_stem:
            continue
        parent = _parent(PurePosixPath(candidate))
        if parent == source_parent or _under_common_test_root(candidate):
            return True
    return False


def _parent(path: PurePosixPath) -> str:
    parent = path.parent.as_posix()
    return "" if parent == "." else parent


def _is_test_filename(name: str) -> bool:
    if name.startswith("test_") or name.endswith("Test.java"):
        return True
    return PurePosixPath(name).stem.endswith("_test")


def _tested_stem(filename: str) -> str:
    if filename.endswith("Test.java"):
        return filename[: -len("Test.java")]
    stem = PurePosixPath(filename).stem
    if stem.startswith("test_"):
        return stem[len("test_") :]
    if stem.endswith("_test"):
        return stem[: -len("_test")]
    return stem


def _under_common_test_root(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if len(parts) >= 2 and parts[0] == "src" and parts[1] == "test":
        return True
    return any(part in _TEST_ROOT_PARTS for part in parts[:-1])
