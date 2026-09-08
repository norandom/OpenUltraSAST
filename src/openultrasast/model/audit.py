"""Module audit: what is load-bearing, what stands alone, and what is orphaned (Req 3).

The tool outgrew itself — 99 modules and 832 tests at the point this feature began, a large share of them
serving an architecture its own measurements retired. This classifier exists so outgrowth is visible and
checkable rather than a thing someone notices two specs later.

A module is:

    load_bearing          reachable from a gate, the scan CLI, or a surviving requirement
    standalone_capability its own entry point and users, not on the scan path
    orphaned              no importer, no entry point, no requirement — it should not be in the tree

Pure stdlib, no imports of the package it audits: it reads the import graph with ``ast`` so a broken module
is still classifiable.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "openultrasast"

# Entry points a module can be reachable from. The three gates are the contract; the CLI is the product.
ROOTS = ("gate", "map_gate", "pair_gate", "cli", "__main__")

# Modules that stand alone: their own CLI subcommand or external protocol, deliberately off the scan path.
SPEC_OWNED = {
    "model.specs": "model-grounded-detection Req 7.2-7.4: the security vocabularies the CPG queries are parameterised by",
    "model.endpoint": "model-grounded-detection Req 8: the judge client, wired by model/judge.py in group 3",
    "model.audit": "model-grounded-detection Req 3: this classifier; run by the maintainer, not by the scan",
    "model.ladder": "model-grounded-detection Req 5: the evidence ladder every finding carries",
    "model.taint": "model-grounded-detection Req 6.1: taint reachability over the CPG, the flow-family arbiter",
    "model.judge": "model-grounded-detection Req 8: one bounded question, checked against the model",
    "model.dominance": "model-grounded-detection Req 6.2: guard dominance, the arbiter for bugs that never crash",
    "model.config_value": "model-grounded-detection Req 6.3: constant abstraction for the configuration families",
    "model.calibrate": "model-grounded-detection Req 9: the corpus as the model's calibration set",
    "model.report": "model-grounded-detection Req 9.3/11.1: per-slice reporting with the overfitting gap",
    "model.execution": "model-grounded-detection Req 10: the deferred execution tier seam, adopted not built",
    "cpg": "model-grounded-detection Req 4: the CPG seam package",
    "cpg.backend": "model-grounded-detection Req 4.1/4.5: the single Joern subprocess boundary",
    "cpg.capability": "model-grounded-detection Req 4.2/4.3: the engine probe that degrades to suspicion",
}

STANDALONE = {
    "mcp": "narrow MCP server over stdio; its own `ousast mcp` entry point and OpenCode integration",
    "skills": "skill router; consumed by mcp and by the OpenCode integration, not by the scan path",
    "fusion": "two-panel adjudication engine; reached from the scan's report stage and used standalone",
    "harness_ext": "HarnessX extension surface; loaded by name when the optional harness is present",
    "hunter_harness": "harness wiring for the tool hunter; used by the hunter path and by mcp",
    "stage_processors": "HarnessX slot-contracted scan stages; pinned by the zero-dependency guard in test_gate",
    "slot_contract": "the slot/contract protocol stage_processors implements",
}


@dataclass(frozen=True)
class ModuleAudit:
    module: str
    classification: str  # load_bearing | standalone_capability | orphaned
    reason: str
    importers: tuple[str, ...]


def module_name(path: Path, root: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = [part for part in relative.parts if part != "__init__"]
    return ".".join(parts)


def import_graph(root: Path) -> dict[str, set[str]]:
    """``module -> the modules it imports`` for every module under ``root``, resolved to package-relative names."""
    graph: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        name = module_name(path, root)
        # For a package's `__init__`, the containing package *is* this module, so `from .x import y` resolves to
        # `<name>.x`; for a plain module it resolves against the parent. Getting this backwards made every module
        # a package re-exports look unimported.
        is_package = path.name == "__init__.py"
        imported: set[str] = set()
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            graph[name] = imported
            continue
        package_parts = name.split(".") if is_package else name.split(".")[:-1]
        package_parts = [part for part in package_parts if part]
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package_parts[: len(package_parts) - node.level + 1]
                    target = ".".join([*base, node.module]) if node.module else ".".join(base)
                else:
                    target = node.module or ""
                    if target.startswith(f"{PACKAGE}."):
                        target = target[len(PACKAGE) + 1 :]
                    elif target == PACKAGE:
                        target = ""
                    else:
                        continue
                if target:
                    imported.add(target)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(f"{PACKAGE}."):
                        imported.add(alias.name[len(PACKAGE) + 1 :])
        graph[name] = imported
    return graph


def _reachable(graph: Mapping[str, set[str]], roots: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    stack = [root for root in roots if root in graph]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for target in graph.get(current, ()):
            # an import of `a.b` also keeps the package `a` alive
            for candidate in (target, target.rsplit(".", 1)[0]):
                if candidate in graph and candidate not in seen:
                    stack.append(candidate)
    return seen


def audit(root: Path) -> tuple[ModuleAudit, ...]:
    """Classify every module under ``root``."""
    graph = import_graph(root)
    importers: dict[str, set[str]] = {name: set() for name in graph}
    for name, targets in graph.items():
        for target in targets:
            for candidate in (target, target.rsplit(".", 1)[0]):
                if candidate in importers and candidate != name:
                    importers[candidate].add(name)
    live = _reachable(graph, ROOTS)
    results: list[ModuleAudit] = []
    for name in sorted(graph):
        if not name:  # the package __init__ itself
            continue
        who = tuple(sorted(importers[name]))
        if name in SPEC_OWNED:
            results.append(ModuleAudit(name, "load_bearing", SPEC_OWNED[name], who))
        elif name in ROOTS:
            results.append(ModuleAudit(name, "load_bearing", "entry point", who))
        elif name in STANDALONE:
            results.append(ModuleAudit(name, "standalone_capability", STANDALONE[name], who))
        elif name in live:
            results.append(ModuleAudit(name, "load_bearing", f"reachable from {', '.join(ROOTS[:3])} or the CLI", who))
        elif who:
            results.append(ModuleAudit(name, "load_bearing", f"imported by {', '.join(who)}", who))
        else:
            results.append(ModuleAudit(name, "orphaned", "no importer, no entry point, no surviving requirement", who))
    return tuple(results)


def to_dict(results: Iterable[ModuleAudit]) -> dict[str, object]:
    rows = list(results)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.classification] = counts.get(row.classification, 0) + 1
    return {
        "modules": len(rows),
        "counts": dict(sorted(counts.items())),
        "orphaned": [row.module for row in rows if row.classification == "orphaned"],
        "standalone": {row.module: row.reason for row in rows if row.classification == "standalone_capability"},
        "rows": [
            {"module": row.module, "classification": row.classification, "reason": row.reason, "importers": list(row.importers)}
            for row in rows
        ],
    }


__all__ = ["ModuleAudit", "SPEC_OWNED", "STANDALONE", "audit", "import_graph", "module_name", "to_dict"]
