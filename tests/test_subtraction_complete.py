"""model-grounded-detection Req 1.3: nothing survives that imports what this feature removed.

The noise architecture and the mechanism/evolve loop are deleted, not deprecated. This walks the AST of every
surviving module and fails on any import that names one of them — the check that turns a five-thousand-line
deletion from crash-driven discovery into one assertion.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path("src/openultrasast")

REMOVED_MODULES = frozenset(
    {
        # the noise architecture (the whole learning/ package; taxonomy, candidates and endpoint re-homed to model/)
        "learning",
        # the mechanism/evolve optimisation loop
        "semantic.mechanisms",
        "semantic.variants",
        "semantic.variant_search",
        "semantic.prove_budget",
        "semantic.loo",
        "semantic.seed",
    }
)


def _module_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def _names_a_removed_module(imported: str) -> bool:
    trimmed = imported.lstrip(".")
    return any(trimmed == removed or trimmed.startswith(f"{removed}.") for removed in REMOVED_MODULES)


def test_no_surviving_module_imports_a_removed_one() -> None:
    offenders: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        named = sorted(name for name in _module_names(ast.parse(path.read_text())) if _names_a_removed_module(name))
        if named:
            offenders[str(path)] = named
    assert not offenders, f"dangling imports of removed modules: {offenders}"


def test_the_removed_modules_are_gone_from_the_tree() -> None:
    assert not (SRC / "learning").exists(), "the learning package is removed; taxonomy/candidates/endpoint live under model/"
    for relative in (
        "semantic/mechanisms.py",
        "semantic/variants.py",
        "semantic/variant_search.py",
        "semantic/prove_budget.py",
        "semantic/loo.py",
        "semantic/seed.py",
    ):
        assert not (SRC / relative).exists(), f"{relative} still exists"


def test_the_re_homed_modules_are_where_the_model_layer_expects_them() -> None:
    for relative in ("model/taxonomy.py", "model/candidates.py", "model/endpoint.py", "model/specs.py"):
        assert (SRC / relative).is_file(), f"{relative} is missing"
