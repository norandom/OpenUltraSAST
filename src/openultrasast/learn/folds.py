"""Folds by repository group (learned-decision-engine design 4.3-4.4, Req 3.4, 7.1, 8.3).

Every split is by ``group`` (the label builder's repository group, after its alias/advisory/commit merges), across
all corpora, seeded and deterministic:

- the **compile split** ``C``: 25% of the groups, stratified by each group's primary family, never an evaluation
  fold; inside it ``C_boot`` (60%, demonstrations) and ``C_val`` (40%, instruction scoring);
- **outer** grouped K = 5 over the groups outside ``C``, stratified by primary family and label mix;
- **leave-one-source-out**: each source held out whole (its groups evaluated, the source absent from retrieval);
- **leave-one-framework-out** on F where F has >= 10 groups; below that the fold is ``insufficient data``.

A :class:`Fold` is what :func:`.retrieve.eligible` checks every example against. :func:`assert_disjoint` is run
before a compile: the compile split and the evaluation folds share no group.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .examples import Example

COMPILE_FRACTION = 0.25
BOOT_FRACTION = 0.6
OUTER_K = 5
FRAMEWORK_MIN_GROUPS = 10
INSUFFICIENT = "insufficient data"


class FoldError(RuntimeError):
    """A group in both the compile split and an evaluation fold, or in two evaluation folds of one kind."""


@dataclass(frozen=True)
class Fold:
    """One evaluation (or compile, or deployment) boundary: the groups evaluated, and what retrieval must not use."""

    kind: str  # outer | leave_one_source_out | leave_one_framework_out | compile | deployment
    name: str
    eval_groups: frozenset[str]
    held_source: str | None = None
    held_framework: str | None = None
    phase: str = "evaluation"  # evaluation | compile | deployment: the near-duplicate drop applies outside deployment
    status: str = "ok"


@dataclass(frozen=True)
class GroupInfo:
    group: str
    families: Counter[str] = field(default_factory=Counter)
    labels: frozenset[int] = frozenset()
    sources: frozenset[str] = frozenset()
    frameworks: frozenset[str] = frozenset()

    @property
    def primary_family(self) -> str:
        return sorted(self.families.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if self.families else "unknown"


@dataclass(frozen=True)
class CompileSplit:
    groups: frozenset[str]
    boot: frozenset[str]
    val: frozenset[str]

    def fold(self) -> Fold:
        """The compile phase's boundary: nothing is excluded but the target's own group."""
        return Fold("compile", "compile", frozenset(), phase="compile")


def group_table(examples: Iterable[Example]) -> dict[str, GroupInfo]:
    families: dict[str, Counter[str]] = {}
    labels: dict[str, set[int]] = {}
    sources: dict[str, set[str]] = {}
    frameworks: dict[str, set[str]] = {}
    for example in examples:
        families.setdefault(example.group, Counter())[example.family] += 1
        labels.setdefault(example.group, set()).add(example.label)
        sources.setdefault(example.group, set()).add(example.source)
        frameworks.setdefault(example.group, set()).update(example.frameworks)
    return {g: GroupInfo(g, families[g], frozenset(labels[g]), frozenset(sources[g]), frozenset(frameworks[g])) for g in sorted(families)}


def _order(items: Iterable[str], seed: int, salt: str) -> list[str]:
    return sorted(items, key=lambda item: hashlib.sha256(f"{seed}\x00{salt}\x00{item}".encode()).hexdigest())


def _take(groups: Sequence[str], fraction: float) -> int:
    return int(len(groups) * fraction + 0.5) if len(groups) > 1 else 0  # a family's only group is never taken


def compile_split(
    examples: Sequence[Example], *, fraction: float = COMPILE_FRACTION, boot: float = BOOT_FRACTION, seed: int = 0
) -> CompileSplit:
    """25% of the groups per primary family (seeded), split 60/40 into ``C_boot`` and ``C_val``."""
    table = group_table(examples)
    strata: dict[str, list[str]] = {}
    for group, info in table.items():
        strata.setdefault(info.primary_family, []).append(group)
    chosen: list[str] = []
    boot_groups: list[str] = []
    for family in sorted(strata):
        ordered = _order(strata[family], seed, f"compile:{family}")
        taken = ordered[: _take(ordered, fraction)]
        chosen += taken
        boot_groups += taken[: int(len(taken) * boot + 0.5)]
    return CompileSplit(frozenset(chosen), frozenset(boot_groups), frozenset(chosen) - frozenset(boot_groups))


def outer_folds(examples: Sequence[Example], *, k: int = OUTER_K, seed: int = 0, exclude: Iterable[str] = ()) -> list[Fold]:
    """Grouped K-fold over the groups outside ``exclude``, stratified by (primary family, label mix), one repetition."""
    excluded = set(exclude)
    table = {g: i for g, i in group_table(examples).items() if g not in excluded}
    strata: dict[tuple[str, tuple[int, ...]], list[str]] = {}
    for group, info in table.items():
        strata.setdefault((info.primary_family, tuple(sorted(info.labels))), []).append(group)
    assigned: list[set[str]] = [set() for _ in range(k)]
    turn = 0
    for key in sorted(strata):
        for group in _order(strata[key], seed, f"outer:{key}"):
            assigned[turn % k].add(group)
            turn += 1
    return [Fold("outer", f"outer-{i}", frozenset(groups)) for i, groups in enumerate(assigned)]


def leave_one_source_out(examples: Sequence[Example], *, exclude: Iterable[str] = ()) -> list[Fold]:
    excluded = set(exclude)
    by_source: dict[str, set[str]] = {}
    for example in examples:
        if example.group not in excluded:
            by_source.setdefault(example.source, set()).add(example.group)
    return [Fold("leave_one_source_out", f"source-{s}", frozenset(g), held_source=s) for s, g in sorted(by_source.items())]


def leave_one_framework_out(
    examples: Sequence[Example], *, exclude: Iterable[str] = (), min_groups: int = FRAMEWORK_MIN_GROUPS
) -> list[Fold]:
    """One fold per framework seen; below ``min_groups`` groups it is ``insufficient data`` and evaluates nothing."""
    excluded = set(exclude)
    by_framework: dict[str, set[str]] = {}
    for example in examples:
        for framework in example.frameworks:
            if example.group not in excluded:
                by_framework.setdefault(framework, set()).add(example.group)
    folds = []
    for framework, groups in sorted(by_framework.items()):
        enough = len(groups) >= min_groups
        folds.append(
            Fold(
                "leave_one_framework_out", f"framework-{framework}", frozenset(groups) if enough else frozenset(),
                held_framework=framework, status="ok" if enough else INSUFFICIENT,
            )
        )  # fmt: skip
    return folds


def assert_disjoint(split: CompileSplit, folds: Iterable[Fold]) -> None:
    """The compile split shares no group with any evaluation fold; outer folds are pairwise disjoint."""
    seen: dict[str, str] = {}
    for fold in folds:
        shared = split.groups & fold.eval_groups
        if shared:
            raise FoldError(f"{fold.name}: groups in both the compile split and the evaluation fold: {sorted(shared)[:5]}")
        if fold.kind == "outer":
            for group in fold.eval_groups:
                if group in seen:
                    raise FoldError(f"group {group!r} in {seen[group]} and {fold.name}")
                seen[group] = fold.name


def folds_digest(split: CompileSplit, folds: Iterable[Fold]) -> str:
    canonical = {
        "compile": sorted(split.groups), "boot": sorted(split.boot),
        "folds": [[f.kind, f.name, sorted(f.eval_groups), f.held_source, f.held_framework, f.status] for f in folds],
    }  # fmt: skip
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()


__all__ = [
    "COMPILE_FRACTION", "FRAMEWORK_MIN_GROUPS", "INSUFFICIENT", "OUTER_K", "CompileSplit", "Fold", "FoldError", "GroupInfo",
    "assert_disjoint", "compile_split", "folds_digest", "group_table", "leave_one_framework_out", "leave_one_source_out",
    "outer_folds",
]  # fmt: skip
