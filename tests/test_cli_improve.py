"""`ousast improve` CLI: drives the self-improvement loop and the loop-owned ledger."""

from pathlib import Path

from openultrasast.cli import main
from openultrasast.ruleset import PatternRule, read_rule_ledger, write_ruleset


def _rule(rule_id: str, pattern: str) -> PatternRule:
    return PatternRule(rule_id=rule_id, title=rule_id, languages=("python",), cwe="CWE-95", tags=("injection",), pattern=pattern)


def _expected_block(rule_id: str) -> str:
    return (
        '[[expected]]\ncwe = "CWE-95"\nclass = "code injection"\npath = "app.py"\n'
        f'line = 2\nrule_id = "{rule_id}"\nsink = "eval"\nevidence = "eval executes input"\n'
    )


def _scaffold(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g():\n    print('hello')\n")
    ruleset_dir = tmp_path / "ruleset"
    write_ruleset(ruleset_dir / "python" / "rules.toml", [_rule("good-eval", r"\beval\s*\("), _rule("noisy-print", r"\bprint\s*\(")])
    manifest = tmp_path / "bench.toml"
    manifest.write_text('name = "t"\nlanguage = "python_web"\n\n[source]\npath = "repo"\n\n' + _expected_block("good-eval"))
    return repo, ruleset_dir


def test_improve_accepts_and_writes_loop_owned_ledger(tmp_path: Path) -> None:
    repo, ruleset_dir = _scaffold(tmp_path)
    manifest = tmp_path / "bench.toml"

    exit_code = main(["improve", str(manifest), "--ruleset-dir", str(ruleset_dir)])

    assert exit_code == 0
    # The ledger lands exactly where `scan`/`benchmark` read it for this target.
    ledger = repo / ".openultrasast" / "calibration" / "rule_policy.json"
    assert ledger.exists()
    assert read_rule_ledger(ledger)["noisy-print"]["status"] == "shadow"
    journal = repo / ".openultrasast" / "calibration" / "improve_journal.json"
    assert journal.exists()


def test_improve_dry_run_never_touches_the_targets_ledger(tmp_path: Path) -> None:
    repo, ruleset_dir = _scaffold(tmp_path)
    manifest = tmp_path / "bench.toml"

    exit_code = main(["improve", str(manifest), "--ruleset-dir", str(ruleset_dir), "--dry-run"])

    assert exit_code == 0
    assert not (repo / ".openultrasast" / "calibration" / "rule_policy.json").exists()


def test_improve_rejects_missing_manifest(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(SystemExit):
        main(["improve", str(tmp_path / "nope.toml")])
