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


# ---- pair-corpus-honesty: per-profile holdout clause (Req 7.2-7.4) ----------


def _pair(
    tmp_path: Path, name: str, vuln_src: str, fixed_src: str, rule_id: str, sink: str, *, provenance: str, review_tier: str = "reviewed"
):
    from openultrasast.benchmark import ExpectedFinding
    from openultrasast.pairs import PairCase

    vuln = tmp_path / f"{name}-vuln.py"
    fixed = tmp_path / f"{name}-fixed.py"
    vuln.write_text(vuln_src)
    fixed.write_text(fixed_src)
    return PairCase(
        name=name,
        slice="github",
        language="python",
        origin="test",
        vuln_file=vuln,
        fixed_file=fixed,
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-95",
                vulnerability_class="x",
                path="app.py",
                evidence="",
                rule_id=rule_id,
                sink=sink,
                mechanism="source_reaches_sink",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        provenance=provenance,
        split="holdout",
        review_tier=review_tier,
        reviewer="test" if review_tier == "reviewed" else "",
    )


def test_round_rejects_when_a_profile_regresses_on_holdout(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("good-eval"))
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"
    # The agent profile's holdout pair is only detected by the rule the round wants to shadow.
    agent_pairs = [
        _pair(tmp_path, f"agent{i}", "def h(y):\n    print(y)\n", "def h(y):\n    return y\n", "noisy-print", "print", provenance="agent")
        for i in range(5)
    ]
    outcome = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir, pair_cases=agent_pairs)
    assert not outcome.accepted
    assert outcome.reason == "profile_regression:agent"
    assert outcome.profile_regressions == ["agent"]
    assert outcome.per_profile_before["agent"]["pair_correct"] == 5.0 and outcome.per_profile_after["agent"]["pair_correct"] == 0.0
    assert not ledger.exists()
    assert json.loads(journal.read_text())[0]["profile_regressions"] == ["agent"]


def test_round_accepts_when_profiles_hold_and_reports_small_profiles(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("good-eval"))
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"
    human_pairs = [
        _pair(tmp_path, f"h{i}", "def h(y):\n    return eval(y)\n", "def h(y):\n    return y\n", "good-eval", "eval", provenance="human")
        for i in range(5)
    ]
    tiny_agent = [
        _pair(tmp_path, "a0", "def h(y):\n    print(y)\n", "def h(y):\n    return y\n", "noisy-print", "print", provenance="agent")
    ]
    outcome = run_round(
        repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir, pair_cases=human_pairs + tiny_agent
    )
    assert outcome.accepted and outcome.reason == "accepted"
    assert outcome.profile_regressions == []
    assert outcome.profiles_under_minimum == ["agent"]  # one pair: reported, not gated
    assert ledger.exists()


def test_profile_gate_ignores_title_and_advisory_tiers(tmp_path: Path) -> None:
    """Req 9.3: only seeded and reviewed pairs gate; a regression confined to title pairs never rejects a round."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = _ruleset_dir(tmp_path, [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    _, manifest = _manifest(tmp_path, _expected("good-eval"))
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"
    title_pairs = [
        _pair(
            tmp_path,
            f"t{i}",
            "def h(y):\n    print(y)\n",
            "def h(y):\n    return y\n",
            "noisy-print",
            "print",
            provenance="agent",
            review_tier="title",
        )
        for i in range(5)
    ]
    outcome = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir, pair_cases=title_pairs)
    assert outcome.accepted and outcome.reason == "accepted"
    assert outcome.profile_regressions == [] and "agent" not in outcome.per_profile_before
    ledger.unlink()
    journal.unlink()
    reviewed_pairs = [
        _pair(tmp_path, f"r{i}", "def h(y):\n    print(y)\n", "def h(y):\n    return y\n", "noisy-print", "print", provenance="agent")
        for i in range(5)
    ]
    outcome = run_round(
        repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=ruleset_dir, pair_cases=reviewed_pairs + title_pairs
    )
    assert not outcome.accepted and outcome.reason == "profile_regression:agent"
    assert outcome.per_profile_before["agent"]["pairs"] == 5.0  # the five title pairs are scored elsewhere, never here


def test_profile_gate_scores_vendored_pairs_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 10.4 / design: gates call select_vendored; a pointer pair never reaches the improve gate, cached or not."""
    from openultrasast.improve.evolve import evaluate_profiles
    from openultrasast.pairs import PairCase
    from openultrasast.ruleset import load_ruleset

    monkeypatch.setenv("OPENULTRASAST_PAIRS_NETWORK", "1")
    vendored = _pair(
        tmp_path, "v", "def h(y):\n    return eval(y)\n", "def h(y):\n    return y\n", "python-unsafe-eval", "eval", provenance="human"
    )
    pointer_src = tmp_path / "cache" / "github" / "p"
    pointer_src.mkdir(parents=True)
    (pointer_src / "vuln.py").write_text("def h(y):\n    return eval(y)\n")
    (pointer_src / "fixed.py").write_text("def h(y):\n    return y\n")
    pointer = PairCase(
        **{
            **vendored.__dict__,
            "name": "p",
            "provenance": "agent",
            "vendored": False,
            "vuln_file": pointer_src / "vuln.py",
            "fixed_file": pointer_src / "fixed.py",
            "recipe": (("repo", "o/r"), ("parent", "a"), ("commit", "b"), ("path", "app.py"), ("mode", "name")),
        }
    )
    profiles = evaluate_profiles([vendored, pointer], load_ruleset())
    assert set(profiles) == {"human"}  # the agent pointer pair is scored by `pairs --pointers`, never by the gate
