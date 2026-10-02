"""model-grounded-detection Req 3: outgrowth is visible and checkable, not noticed two specs later."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
    """Req 3.3: the older-phase subsystems still in the tree get a decision, not silence."""
    from openultrasast.model.audit import audit

    rows = {row.module: row for row in audit(SRC)}
    for name in ("fusion", "mcp", "skills"):
        assert name in rows, f"{name} vanished without a recorded decision"
        assert rows[name].reason, f"{name} has no stated reason"
    # The removed agentic plane's modules are gone from the tree, not carried as rows (harnessx-removal Req 2.1).
    assert not {"harness_ext", "hunter_harness", "verify_judge"} & set(rows)
    # The five the reachability-first audit found orphaned are gone too (legacy cleanup 2026-10-02).
    assert not {"model.judge", "model.execution", "model.calibrate", "stage_processors", "slot_contract"} & set(rows)


def test_the_manifest_matches_the_tree() -> None:
    """A later reader can check the tree against the committed manifest (Req 3.4)."""
    from openultrasast.model.audit import audit, to_dict

    assert MANIFEST.is_file(), "the audit manifest is committed evidence, not a local artifact"
    committed = json.loads(MANIFEST.read_text())
    current = to_dict(audit(SRC))
    assert committed["counts"] == current["counts"], "the tree drifted from its committed audit"
    assert committed["orphaned"] == current["orphaned"] == []


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def test_a_spec_listed_module_nothing_imports_is_still_orphaned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reachability decides; SPEC_OWNED and STANDALONE only supply the reason (the list hid five dead modules)."""
    from openultrasast.model import audit as module

    src = _tree(tmp_path, {"cli.py": "from . import used\n", "used.py": "", "ghost.py": "", "lonely.py": ""})
    monkeypatch.setitem(module.SPEC_OWNED, "ghost", "some spec Req 1: still listed")
    monkeypatch.setitem(module.STANDALONE, "lonely", "its own entry point, supposedly")
    rows = {row.module: row for row in module.audit(src)}
    assert rows["used"].classification == "load_bearing"
    assert rows["ghost"].classification == "orphaned"
    assert "still listed" in rows["ghost"].reason
    assert rows["lonely"].classification == "orphaned"


def test_submodule_imports_and_python_m_modules_count_as_reachable(tmp_path: Path) -> None:
    from openultrasast.model.audit import audit

    src = _tree(
        tmp_path,
        {
            "cli.py": "def run():\n    from .pkg import sub\n",
            "pkg/__init__.py": "",
            "pkg/sub.py": "",
            "tool.py": 'from . import helper\n\nif __name__ == "__main__":\n    pass\n',
            "helper.py": "",
            "dead.py": "from . import deader\n",
            "deader.py": "",
        },
    )
    rows = {row.module: row.classification for row in audit(src)}
    assert rows["pkg.sub"] == rows["tool"] == rows["helper"] == "load_bearing"
    assert rows["dead"] == rows["deader"] == "orphaned"
