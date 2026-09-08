"""model-grounded-detection Req 3: outgrowth is visible and checkable, not noticed two specs later."""

from __future__ import annotations

import json
from pathlib import Path

SRC = Path("src/openultrasast")
MANIFEST = Path("benchmarks/measurements/2026-09-08-module-audit.json")


def test_no_module_in_the_tree_is_orphaned() -> None:
    from openultrasast.model.audit import audit

    orphans = [row.module for row in audit(SRC) if row.classification == "orphaned"]
    assert not orphans, f"orphaned modules must be removed, not carried: {orphans}"


def test_every_module_is_classified() -> None:
    from openultrasast.model.audit import audit, module_name

    classified = {row.module for row in audit(SRC)}
    on_disk = {module_name(path, SRC) for path in SRC.rglob("*.py") if "__pycache__" not in path.parts}
    assert on_disk - classified <= {""}, f"unclassified: {sorted(on_disk - classified - {''})}"


def test_the_named_subsystems_each_carry_an_explicit_decision() -> None:
    """Req 3.3: the five older-phase subsystems get a decision, not silence."""
    from openultrasast.model.audit import audit

    rows = {row.module: row for row in audit(SRC)}
    for name in ("fusion", "mcp", "skills", "harness_ext", "hunter_harness"):
        assert name in rows, f"{name} vanished without a recorded decision"
        assert rows[name].reason, f"{name} has no stated reason"


def test_the_manifest_matches_the_tree() -> None:
    """A later reader can check the tree against the committed manifest (Req 3.4)."""
    from openultrasast.model.audit import audit, to_dict

    assert MANIFEST.is_file(), "the audit manifest is committed evidence, not a local artifact"
    committed = json.loads(MANIFEST.read_text())
    current = to_dict(audit(SRC))
    assert committed["counts"] == current["counts"], "the tree drifted from its committed audit"
    assert committed["orphaned"] == current["orphaned"] == []
