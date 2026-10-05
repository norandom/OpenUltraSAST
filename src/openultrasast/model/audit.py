"""Module audit: what is load-bearing, what stands alone, and what is orphaned (Req 3).

The tool outgrew itself — 99 modules and 832 tests at the point this feature began, a large share of them
serving an architecture its own measurements retired. This classifier exists so outgrowth is visible and
checkable rather than a thing someone notices two specs later.

A module is:

    load_bearing          reachable by imports from a gate, the CLI, or a module run with ``python -m``
    standalone_capability reachable the same way, but its own entry point and users, not on the scan path
    orphaned              not reachable from any of those -- it should not be in the tree

Reachability decides the class. ``SPEC_OWNED`` and ``STANDALONE`` only supply the reason text: being named
by a spec does not keep a module nobody imports alive.

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

# Reason text for reachable modules, by the requirement that owns them. Not a classification: see audit().
SPEC_OWNED = {
    "push.cache": "pre-push-safety-net task 6.2: bounded artifact publication and leased eviction; runner integration in 6.4",
    "push.report": "pre-push-safety-net Req 5.1/5.2/5.5/7.3: compact output and complete artifacts; runner integration pending",
    "push.policy": "pre-push-safety-net Req 2.4/3.1/3.4/4.1: targeted same-semantics base comparison; replay integration pending",
    "push.snapshot": "pre-push-safety-net Req 1.1/1.3/1.4/7.1: local immutable ref resolution; runner integration pending",
    "contracts": "pre-push-safety-net Req 7.3: strict shared manifest serialization, independent of push",
    "model.contracts": "pre-push-safety-net Req 4.1/7.3: generic deadline, change and exact scope contracts; integration pending",
    "cpg.artifact": "pre-push-safety-net Req 4.3/7.3: backend graph identity and live lease contract; validation integration pending",
    "push": "pre-push-safety-net Req 5.5/7.3: experimental push contract package; no hook installed",
    "push.contracts": "pre-push-safety-net Req 5.5/7.3: immutable comparisons and independent result statuses; runner pending",
    "model.specs": "model-grounded-detection Req 7.2-7.4: the security vocabularies the CPG queries are parameterised by",
    "model.endpoint": "model-grounded-detection Req 8: the bounded model client the hunter, the plane and the CLI share",
    "model.audit": "model-grounded-detection Req 3: this classifier; run by the maintainer, not by the scan",
    "model.ladder": "model-grounded-detection Req 5: the evidence ladder every finding carries",
    "model.taint": "model-grounded-detection Req 6.1: taint reachability over the CPG, the flow-family arbiter",
    "model.dominance": "model-grounded-detection Req 6.2: guard dominance, the arbiter for bugs that never crash",
    "model.config_value": "model-grounded-detection Req 6.3: constant abstraction for the configuration families",
    "model.report": "model-grounded-detection Req 9.3/11.1: per-slice reporting with the overfitting gap",
    "model.pipeline": "model-grounded-detection Req 8: the enumerator proposes, the LLM answers, the model disposes",
    "model.regions": "contributor-scan Req 2: regions from entry points, with the families each admits",
    "model.scan": "contributor-scan Req 3: the repository driver -- one CPG, one budget, ranked spend",
    "cpg": "model-grounded-detection Req 4: the CPG seam package",
    "cpg.backend": "model-grounded-detection Req 4.1/4.5: the single Joern subprocess boundary",
    "cpg.capability": "model-grounded-detection Req 4.2/4.3: the engine probe that degrades to suspicion",
    "plane": "ai-service-plane Req 1-4: the service plane package; runner and reconciler integration in tasks 3-4",
    "plane.budget": "ai-service-plane Req 2.3/2.4: metered chat client with usd and calls ceilings; task integration in tasks 3, 6",
    "plane.manifests": "ai-service-plane Req 1.1-1.4: ax-shaped Task/Workspace/Model and the Run kind, validated before anything runs",
    "plane.tasks": "ai-service-plane Req 4.1: the task entrypoint package the runner imports by name; runner integration pending (task 3)",
    "plane.tasks.repo_facts": "ai-service-plane Req 5.1/5.2: source-only functions and callers per file; runner integration pending",
    "plane.tasks.verify": "ai-service-plane Req 5.3/2.1-2.3/7.2: the batched hunt with known callers, metered and resumable per file hunt",
    "plane.tasks.agree": "ai-service-plane Req 5.3/2.1: agreement across two verify passes with per-candidate cost, turns and site match",
    "plane.reconciler": "ai-service-plane Req 3.1-3.5, 7.3: ax-backed Run execution, status attribution and doctor; `ousast plane`",
    "plane.generate": "ai-service-plane task 7: an increment's Workspaces, per-case Tasks and Run from a recorded set",
    "plane.memory": "harnessx-removal Req 6.1/6.4: the memory store (file, S3), ingest and fact reuse; `ousast plane remember`",
    "plane.tasks.remember": "harnessx-removal Req 6.1: a case's delivered artifacts as memory rows, model-free",
    "plane.tasks.alerts": "harnessx-removal Req 6.3: quick-mode alerts on a case's vulnerable and fixed pins, model-free",
    "plane.engine_alerts": "harnessx-removal Req 6.3: engine alerts where quick mode has no rules (PHP), on the host",
    "plane.tasks.loop": "harnessx-removal Req 6.3: the improvement loop's snapshot, measure, propose and improve steps",
    "plane.tasks.features": "learned-decision-engine Req 1.1-1.3/7.2: one allow-listed feature record per candidate, model-free",
    "plane.tasks.roles": (
        "learned-decision-engine Req 8.1: model role classification per file chunk (model_sinks.py moved in); "
        "its Run template comes with the harvest (task 5)"
    ),
    "learn.program": (
        "learned-decision-engine Req 3.1/3.3: the AI classifier program (signature, Retrieve -> Classify(k), response "
        "cache); `ousast learn compile` (task 6.5) and the decide task (task 8) are its callers"
    ),
    "plane.workspaces": "ai-service-plane task 4: Workspace manifests per case pin of a population; `ousast plane workspaces`",
    "plane.runner": "ai-service-plane Req 4.1-4.4: the ax-task-runner entrypoint (PID 1 of the task image); delivers the output directory",
}

# Reachable modules that stand alone: their own CLI subcommand or external protocol, off the scan path.
STANDALONE = {
    "search.coordinator": (
        "search-with-proof Req 1/2/4: injected search executor and offline board checkpoint inspector; agent worker pending"
    ),
    "push_scoring": "pre-push-safety-net task 1.3: frozen-profile diagnostic outcome scorer; python -m openultrasast.push_scoring",
    "push_inputs": "pre-push-safety-net task 1.2: offline input provenance validator; python -m openultrasast.push_inputs",
    "mcp": "narrow MCP server over stdio; its own `ousast mcp` entry point and OpenCode integration",
    "skills": "skill router; consumed by mcp and by the OpenCode integration, not by the scan path",
    "fusion": "two-panel adjudication engine; reached from the scan's report stage and used standalone",
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
                # `from .plane import engine_alerts` imports the submodule `plane.engine_alerts`, not only the
                # package; names that are not modules are dropped later because they are not in the graph.
                prefix = f"{target}." if target else ""
                imported.update(f"{prefix}{alias.name}" for alias in node.names if alias.name != "*")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(f"{PACKAGE}."):
                        imported.add(alias.name[len(PACKAGE) + 1 :])
        graph[name] = imported
    return graph


def main_modules(root: Path) -> set[str]:
    """Modules with a ``__main__`` block: run by name (``python -m``, the plane runner), so they are entry points."""
    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in node.test.comparators)
            ):
                found.add(module_name(path, root))
    return found


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
    run_by_name = main_modules(root)
    live = _reachable(graph, (*ROOTS, *sorted(run_by_name)))
    results: list[ModuleAudit] = []
    for name in sorted(graph):
        if not name:  # the package __init__ itself
            continue
        who = tuple(sorted(importers[name]))
        listed = SPEC_OWNED.get(name) or STANDALONE.get(name)
        # Reachability decides; the lists only supply reason text. A listed module nothing reaches is still
        # orphaned -- the list is what hid five dead modules behind "load_bearing" until 2026-10-02.
        if name not in live:
            reason = "no import path from an entry point or a python -m module"
            if who:
                reason += f" (imported only by unreachable {', '.join(who)})"
            if listed:
                reason += f"; listed as: {listed}"
            results.append(ModuleAudit(name, "orphaned", reason, who))
        elif name in STANDALONE:
            results.append(ModuleAudit(name, "standalone_capability", STANDALONE[name], who))
        elif name in SPEC_OWNED:
            results.append(ModuleAudit(name, "load_bearing", SPEC_OWNED[name], who))
        elif name in ROOTS:
            results.append(ModuleAudit(name, "load_bearing", "entry point", who))
        elif name in run_by_name:
            results.append(ModuleAudit(name, "load_bearing", f"python -m openultrasast.{name}", who))
        else:
            results.append(ModuleAudit(name, "load_bearing", f"reachable from {', '.join(ROOTS[:4])}", who))
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


__all__ = ["ModuleAudit", "SPEC_OWNED", "STANDALONE", "audit", "import_graph", "main_modules", "module_name", "to_dict"]


if __name__ == "__main__":  # python -m openultrasast.model.audit [SRC] -- the manifest's regeneration command
    import json
    import sys

    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    print(json.dumps(to_dict(audit(source)), indent=2))
