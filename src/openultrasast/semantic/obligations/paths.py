"""Compose bounded caller chains whose first hop is a recognised entry."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class PathRecord:
    hops: tuple[tuple[str, int | None], ...]
    entry: str
    complete: bool


def compose_paths(
    *,
    callers: Callable[[str, str], Sequence[tuple[str, int]]],
    entries: set[str],
    targets: Sequence[tuple[str, str]],
    max_depth: int = 3,
    fan_out: int = 25,
) -> tuple[list[PathRecord], list[str]]:
    """Walk at most max_depth caller edges. The adapter resolves sites to path::function nodes.

    Each caller hop holds the line of its outgoing call; the final target has no outgoing call.
    Stop at the first entry, and never revisit a node within a chain.
    """
    if max_depth < 0 or fan_out < 1:
        raise ValueError("invalid path bounds")
    found: dict[tuple[tuple[str, int | None], ...], PathRecord] = {}
    unreached: list[str] = []
    if not entries:
        # Nothing can complete a chain; one ordinary change of a 3000-file tree spent eleven minutes walking
        # callers towards entries that did not exist.
        return [], [f"{path}::{function}" for path, function in dict.fromkeys(targets)]
    # Each node's callers are looked up once per change: the walk revisits nodes across chains and targets.
    known: dict[str, list[tuple[str, int]]] = {}

    def callers_of_node(node: str) -> list[tuple[str, int]]:
        if node not in known:
            node_path, _, node_function = node.rpartition("::")
            known[node] = list(dict.fromkeys(callers(node_path, node_function)))[:fan_out]
        return known[node]

    for path, function in dict.fromkeys(targets):
        target = f"{path}::{function}"
        reached = False
        pending: list[tuple[tuple[str, int | None], ...]] = [((target, None),)]
        while pending:
            hops = pending.pop()
            node = hops[0][0]
            if node in entries:
                found.setdefault(hops, PathRecord(hops, node, True))
                reached = True
                continue
            if len(hops) - 1 >= max_depth:
                continue
            seen = {hop[0] for hop in hops}
            for caller, line in callers_of_node(node):
                if caller not in seen:
                    pending.append(((caller, line), *hops))
        if not reached:
            unreached.append(target)
    return list(found.values()), unreached
