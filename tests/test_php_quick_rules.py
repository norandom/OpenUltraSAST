"""PHP quick-mode rules (ruleset/php): loading, the fixture benchmark, and the tie to the committed measurement."""

import json
import re
import tomllib
from pathlib import Path

import pytest

from openultrasast.benchmark import BenchmarkRun, evaluate_benchmark, load_benchmark_manifest, resolve_benchmark_source
from openultrasast.gate import _quick_scan
from openultrasast.ruleset import DEFAULT_RULESET_DIR, load_ruleset

MEASUREMENT = Path("benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json")
SEMANTIC = tomllib.loads((DEFAULT_RULESET_DIR / "semantic" / "php.toml").read_text())


def _php_rules() -> dict:
    return {rule.rule_id: rule for rule in load_ruleset(DEFAULT_RULESET_DIR) if rule.rule_id.startswith("php-")}


def _benchmark(name: str, *, reported_only: bool):  # type: ignore[no-untyped-def]
    path = Path("benchmarks/manifests") / f"{name}.toml"
    manifest = load_benchmark_manifest(path)
    findings = _quick_scan(resolve_benchmark_source(path, manifest))
    if reported_only:  # what `ousast benchmark` scores: shadow findings are kept aside, not reported
        findings = [finding for finding in findings if finding.status != "shadow"]
    run = BenchmarkRun(benchmark_run_id="t", root=Path("/tmp/t"), manifest=manifest)
    return evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)


def test_php_rules_load_compile_and_are_php_scoped() -> None:
    rules = _php_rules()
    assert len(rules) == 14, "13 measured rules; php-unserialize split into its language and WordPress parts (task 2)"
    for rule in rules.values():
        assert rule.languages == ("php",) and rule.status in {"enabled", "shadow"}
        re.compile(rule.pattern)


def test_every_php_rule_sink_is_in_the_engines_vocabulary() -> None:
    """One vocabulary: each rule's CWE is a sink family of semantic/php.toml, and the calls it names are that family's."""
    families = {sink["cwe"] for sink in SEMANTIC["sink"]}
    calls = {call.split("->")[-1] for sink in SEMANTIC["sink"] for call in sink["calls"]}
    for rule in _php_rules().values():
        assert rule.cwe in families, rule.rule_id
        named = re.findall(r"\(([a-z_|]+)\)", rule.pattern)  # the rule's captured sink alternation, if any
        for group in named:
            # sprintf builds the query php-sql-sprintf-unescaped reads; curl_init takes the URL curl_exec then fetches
            assert set(group.split("|")) <= calls | {"sprintf", "curl_init"}, (rule.rule_id, group)


def test_status_and_precision_are_the_committed_measurement() -> None:
    measured = json.loads(MEASUREMENT.read_text())["rules"]
    for rule_id, rule in _php_rules().items():
        rule_id = "php-unserialize" if rule_id == "php-maybe-unserialize" else rule_id  # split from it, keeps its numbers
        assert rule.status == measured[rule_id]["status"], rule_id
        assert rule.precision_estimate == measured[rule_id]["precision_lower_bound"], rule_id


def test_php_vulnerable_fixture_benchmark() -> None:
    reported = _benchmark("php-vulnerable", reported_only=True)
    assert (reported.metrics.expected_findings_total, reported.metrics.matched_findings_total) == (14, 9)
    assert reported.metrics.false_positive_findings_total == 0
    everything = _benchmark("php-vulnerable", reported_only=False)
    assert everything.metrics.matched_findings_total == 13, "the shadow rules still fire on their fixtures"
    assert [miss.rule_id for miss in everything.misses] == [None], "the cross-line flow is invisible to a line rule"


def test_php_benign_twin_records_its_false_alerts() -> None:
    result = _benchmark("php-benign", reported_only=False)
    assert sorted(fp.finding_id for fp in result.false_positives) == [
        "php-file-inclusion-input:app.php:64",  # the allowlist guard sits on the include's own line
        "php-sql-unquoted-concat:app.php:87",  # intval() ran on the line before the concatenation
    ]


@pytest.mark.parametrize("line", ["    # eval($_POST['code']) is a comment", "    // system('rm ' . $_GET['d'])"])
def test_php_comments_do_not_fire(tmp_path: Path, line: str) -> None:
    (tmp_path / "a.php").write_text(f"<?php\n{line}\n")
    assert _quick_scan(tmp_path) == []
    (tmp_path / "a.php").write_text("<?php\n#[Pure] function f() { system('rm ' . $_GET['d']); }\n")
    assert [f.finding_id for f in _quick_scan(tmp_path)] == ["php-command-injection:a.php:2"], "#[...] is an attribute"
