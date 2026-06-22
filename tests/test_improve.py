"""Self-improvement loop: bounded levers, validator, gates, accept/revert (Phase 3 task 7)."""

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import load_benchmark_manifest
from openultrasast.improve import (
    EvolveValidator,
    PolicyConstantEdit,
    RuleStatusEdit,
    StrictValidationError,
    build_rule_signals,
    propose_status_edits,
    run_improvement,
    run_round,
)
from openultrasast.policy import load_policy
from openultrasast.ruleset import PatternRule, read_rule_ledger, write_ruleset

POLICY = load_policy()


def _rule(rule_id: str, pattern: str, cwe: str = "CWE-95") -> PatternRule:
    return PatternRule(rule_id=rule_id, title=rule_id, languages=("python",), cwe=cwe, tags=("injection",), pattern=pattern)


def _expected(rule_id: str) -> str:
    return (
        '[[expected]]\ncwe = "CWE-95"\nclass = "code injection"\npath = "app.py"\n'
        f'line = 2\nrule_id = "{rule_id}"\nsink = "eval"\nevidence = "eval executes input"\n'
    )


# ---- validator (7.1, 7.2) ---------------------------------------------------


def test_validator_rejects_enabled_to_disabled_jump() -> None:
    ruleset = {"r": _rule("r", r"\beval\s*\(")}
    with pytest.raises(StrictValidationError, match="shadow"):
        EvolveValidator().validate(RuleStatusEdit("r", "enabled", "disabled"), ruleset, POLICY)


def test_validator_accepts_enabled_to_shadow() -> None:
    ruleset = {"r": _rule("r", r"\beval\s*\(")}
    EvolveValidator().validate(RuleStatusEdit("r", "enabled", "shadow"), ruleset, POLICY)  # no raise


def test_validator_rejects_unknown_rule_and_bad_status() -> None:
    ruleset = {"r": _rule("r", r"\beval\s*\(")}
    with pytest.raises(StrictValidationError, match="unknown rule_id"):
        EvolveValidator().validate(RuleStatusEdit("nope", "enabled", "shadow"), ruleset, POLICY)
    with pytest.raises(StrictValidationError):
        EvolveValidator().validate(RuleStatusEdit("r", "enabled", "bogus"), ruleset, POLICY)


def test_validator_never_tunes_severity_and_bounds_constants() -> None:
    with pytest.raises(StrictValidationError, match="severity is upstream-owned"):
        EvolveValidator().validate(PolicyConstantEdit("severity", 3, 5), {}, POLICY)
    with pytest.raises(StrictValidationError):
        EvolveValidator().validate(PolicyConstantEdit("K", 60, 5000), {}, POLICY)  # out of bounds
    EvolveValidator().validate(PolicyConstantEdit("K", 60, 90), {}, POLICY)  # in bounds, no raise


# ---- proposer + signals (7.4, 7.6) -----------------------------------------


def test_propose_status_edits_auto_shadows_precision_draggers_only() -> None:
    ruleset = {"good": _rule("good", r"\beval\s*\("), "noisy": _rule("noisy", r"\bprint\s*\(")}
    per_rule = {"good": {"matched": 1, "missed": 0, "false_positives": 0}, "noisy": {"matched": 0, "missed": 0, "false_positives": 2}}

    edits = propose_status_edits(per_rule, ruleset, current_ledger={}, blocked_keys=set())
    assert [(e.rule_id, e.to_status) for e in edits] == [("noisy", "shadow")]
    # novelty gate: a previously-reverted edit is not re-proposed.
    assert propose_status_edits(per_rule, ruleset, {}, {edits[0].key()}) == []
    # already shadow -> not re-proposed.
    assert propose_status_edits(per_rule, ruleset, {"noisy": {"status": "shadow"}}, set()) == []


# ---- end-to-end loop (7.5) --------------------------------------------------


def _manifest(tmp_path: Path, expected_block: str) -> tuple[Path, object]:
    manifest_path = tmp_path / "bench.toml"
    manifest_path.write_text('name = "t"\nlanguage = "python_web"\n\n[source]\npath = "repo"\n\n' + expected_block)
    return manifest_path, load_benchmark_manifest(manifest_path)


def _ruleset_dir(tmp_path: Path, rules: list[PatternRule]) -> Path:
    rd = tmp_path / "ruleset" / "python"
    write_ruleset(rd / "rules.toml", rules)
    return tmp_path / "ruleset"


def test_round_auto_shadows_noisy_rule_and_accepts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("good-eval"))
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"

    outcome = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir)

    assert outcome.accepted and outcome.reason == "accepted"
    assert outcome.fp_before > 0.0 and outcome.fp_after == 0.0
    assert outcome.recall_after == 1.0  # the true positive is preserved
    assert read_rule_ledger(ledger)["noisy-print"]["status"] == "shadow"
    assert json.loads(journal.read_text())[0]["outcome"] == "accepted"


def test_round_reverts_byte_for_byte_when_shadowing_would_drop_recall(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g(y):\n    return eval(y)\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("dual-eval", r"\beval\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("dual-eval"))
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"

    outcome = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir)

    assert not outcome.accepted and outcome.reason == "reverted"
    assert outcome.score_after > outcome.score_before  # score improved but the recall gate blocks it
    assert not ledger.exists()  # byte-for-byte revert: the ledger was never written
    assert json.loads(journal.read_text())[0]["outcome"] == "reverted"


def test_run_improvement_converges_after_accepting(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("good-eval"))

    outcomes = run_improvement(
        repo,
        manifest,
        ledger_path=tmp_path / "rule_policy.json",
        journal_path=tmp_path / "journal.json",
        ruleset_dir=ruleset_dir,
        max_rounds=4,
    )

    assert outcomes[0].accepted  # round 1 shadows the noisy rule
    assert outcomes[-1].reason == "no_proposals"  # converges (nothing left to improve)


def test_build_rule_signals_separates_miss_and_fp() -> None:
    from openultrasast.benchmark import BenchmarkFalsePositive, BenchmarkMetrics, BenchmarkMiss, BenchmarkResult

    result = BenchmarkResult(
        benchmark_run_id="r",
        benchmark_name="n",
        language="python_web",
        mode="quick",
        scan_id=None,
        scan_run_dir=None,
        metrics=BenchmarkMetrics(1, 1, 0, 1, 1, 0.0, 0.0, None, {}, {}, {}),
        misses=[BenchmarkMiss("CWE-89", "sqli", "a.py", "ev", "no match", rule_id="sqli")],
        false_positives=[BenchmarkFalsePositive("noisy:a.py:1", "a.py", 1, "fp", rule_id="noisy")],
        baseline_deltas=[],
        calibration_records=[],
        rule_recommendations=[],
    )
    signals = build_rule_signals(result)
    assert {s["signal"] for s in signals} == {"miss", "fp"}
    assert {s["rule_id"] for s in signals} == {"sqli", "noisy"}
