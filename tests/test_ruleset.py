"""Rules-as-data store and the loop-owned ledger overlay (Phase 2 tasks 3.1, 4.3)."""

import json
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.ruleset import (
    DEFAULT_RULESET_DIR,
    PatternRule,
    load_ruleset,
    read_rule_ledger,
    write_rule_ledger,
    write_ruleset,
)


def test_default_ruleset_loads_as_data() -> None:
    rules = load_ruleset(DEFAULT_RULESET_DIR)
    assert len(rules) == 32
    assert all(rule.status == "enabled" for rule in rules)
    assert all(not hasattr(rule, "severity") for rule in rules)  # severity is policy-governed, not rule-local


def test_empty_ledger_is_byte_identical() -> None:
    assert load_ruleset(DEFAULT_RULESET_DIR) == load_ruleset(DEFAULT_RULESET_DIR, None)


def test_ledger_overlay_changes_only_targeted_rule(tmp_path: Path) -> None:
    ledger = tmp_path / "rule_policy.json"
    ledger.write_text(json.dumps({"python-unsafe-eval": {"status": "disabled", "precision_estimate": 0.3}}))

    rules = {rule.rule_id: rule for rule in load_ruleset(DEFAULT_RULESET_DIR, ledger)}

    assert rules["python-unsafe-eval"].status == "disabled"
    assert rules["python-unsafe-eval"].precision_estimate == 0.3
    assert rules["c-shell-exec"].status == "enabled"  # untargeted rule untouched


def test_rule_ledger_round_trips(tmp_path: Path) -> None:
    ledger = tmp_path / "rule_policy.json"
    entries = {"python-unsafe-eval": {"status": "shadow", "precision_estimate": 0.41}}
    write_rule_ledger(ledger, entries)
    assert read_rule_ledger(ledger) == entries


def test_write_ruleset_round_trips(tmp_path: Path) -> None:
    rule = PatternRule(rule_id="x-demo", title="Demo", languages=("python",), cwe="CWE-89", tags=("injection",), pattern=r"\bfoo\(")
    write_ruleset(tmp_path / "r" / "rules.toml", [rule])
    assert load_ruleset(tmp_path / "r")[0] == rule


def test_disabled_rule_via_ledger_does_not_fire_in_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\n")
    ledger_dir = repo / ".openultrasast" / "calibration"
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "rule_policy.json").write_text(json.dumps({"python-unsafe-eval": {"status": "disabled"}}))
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "quick"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    assert all(not finding["finding_id"].startswith("python-unsafe-eval:") for finding in findings)
