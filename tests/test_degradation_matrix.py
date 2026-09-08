"""What every optional dependency's absence looks like, and that the gates never move (task 5.1, Req 11.4, 11.5).

The core install has no dependencies. Every capability beyond it is optional, and the rule for all of them is the
same: when it is missing the run says so by name and finishes, rather than crashing or — worse — quietly producing
a smaller number that reads like a result. Each absence is exercised once here, with the reason it records.

The gate baseline is the other half. Three gates are the only place in this project where a detector change is
allowed to be invisible; if one of them moves, something that was never supposed to change did.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

BASELINE = Path("benchmarks/measurements/2026-09-06-gate-baseline.txt")
MARKER = "# --- output begins ---\n"


def test_the_three_gate_outputs_match_the_committed_pre_feature_baseline() -> None:
    """Req 11.5. The baseline was captured at `71efc9c`, before the first line of this feature."""
    assert BASELINE.is_file()
    expected = BASELINE.read_text().split(MARKER, 1)[1]
    produced = "".join(
        subprocess.run(  # noqa: S603 — this repository's own modules, no shell
            [sys.executable, "-m", f"openultrasast.{module}"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        for module in ("gate", "map_gate", "pair_gate")
    )
    assert produced == expected, "a gate moved; diff this against benchmarks/measurements/2026-09-06-gate-baseline.txt"


def test_the_baseline_records_where_it_came_from() -> None:
    head = BASELINE.read_text().split(MARKER, 1)[0]
    assert "71efc9c" in head and "openultrasast.pair_gate" in head


# --- one optional dependency at a time ---------------------------------------


def test_without_the_network_a_pointer_pair_is_skipped_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.pairs import evaluate_catalog, load_pair_catalog, select_slice

    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    pointers = [case for case in select_slice(load_pair_catalog(), "vibe-py") if not case.vendored][:2]
    assert pointers, "the vibe-py slice carries pointer rows; without them this proves nothing"
    result = evaluate_catalog(pointers, pointers=False)
    assert {item["reason"] for item in result.degradations} == {"pointer_pair_skipped"}
    assert result.outcomes == ()


def test_without_the_semantic_extra_an_unsupported_language_is_named_not_guessed(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.semantic import extra as extra_module
    from openultrasast.semantic.ir import parse_file

    monkeypatch.setattr(extra_module, "has_semantic_extra", lambda: False)
    ir = parse_file("app.go", "package main\n\nfunc main() {}\n", "go")
    assert ir.reason == "language_unsupported" and ir.parse_ok is False


def test_without_a_sandbox_the_regress_stage_is_skipped_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A claim that could not be proved because nothing could run it is not the same as a claim that failed."""
    import json

    from openultrasast.cli import main

    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    (tmp_path / "app.py").write_text("import os\n\n\ndef run(cmd):\n    os.system(cmd)\n")
    assert main(["scan", str(tmp_path), "--mode", "deep"]) in {0, 1}
    runs = sorted((tmp_path / ".openultrasast" / "runs").iterdir())
    manifest = json.loads((runs[-1] / "manifest.json").read_text())
    reasons = {item["reason"] for item in manifest.get("degradations", [])}
    assert "sandbox_unavailable" in reasons
