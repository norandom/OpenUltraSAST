"""Vuln-vs-fixed pair corpus: isolated trees, local gate, github honesty dashboard."""

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.cli import main
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.pair_gate import pair_gate
from openultrasast.pairs import (
    DEFAULT_CATALOG,
    DEFAULT_SAST_CATALOG,
    PairCase,
    build_pair_signals,
    evaluate_catalog,
    evaluate_pair,
    load_datasets,
    load_pair_catalog,
    select_slice,
)


def test_catalog_loads_local_and_github_slices() -> None:
    cases = load_pair_catalog(DEFAULT_CATALOG)
    slices = {case.slice for case in cases}
    names = {case.name for case in cases}
    assert {"local", "github", "sast"} <= slices
    assert "local-python-vulnerable" in names
    assert "sven-cwe-078-os-system" in names
    assert "hutool-cve-2018-17297" in names
    assert "owasp-python-codeinj" in names
    assert "juliet-c-cwe134-printf" in names
    assert all(case.vuln_file.is_file() and case.fixed_file.is_file() for case in cases)


def test_pair_catalog_is_outside_stage1_smoke_gate() -> None:
    listed = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    leaked = [case.name for case in load_pair_catalog() if case.name in listed]
    assert leaked == [], "pair catalog must not join LANGUAGE_MANIFESTS (stage-1 90% smoke gate)"


def test_datasets_catalog_lists_public_vfc_repos() -> None:
    names = {str(item["name"]) for item in load_datasets()}
    assert {
        "CVEfixes",
        "CWE-Bench-Java",
        "SVEN",
        "Vul4J",
        "DiverseVul",
        "MoreFixes",
        "OWASP Benchmark Java",
        "OWASP Benchmark Python",
        "Juliet Test Suite C/C++",
        "Juliet Test Suite Java",
    } <= names
    assert DEFAULT_SAST_CATALOG.is_file()
    java = Path("benchmarks/pairs/datasets/cwe-bench-java-project_info.csv")
    assert java.is_file()
    assert "CVE-2018-17297" in java.read_text()


def test_synthetic_pair_fires_on_vuln_and_stays_silent_on_fix(tmp_path: Path) -> None:
    vuln = tmp_path / "vuln.py"
    fixed = tmp_path / "fixed.py"
    vuln.write_text("def run(x):\n    return eval(x)\n")
    fixed.write_text("def run(x):\n    return str(x)\n")
    case = PairCase(
        name="synth-eval",
        slice="local",
        language="python",
        origin="test",
        vuln_file=vuln,
        fixed_file=fixed,
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-95",
                vulnerability_class="code injection",
                path="app.py",
                evidence="eval executes input",
                rule_id="python-unsafe-eval",
                sink="eval",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
    )
    outcome = evaluate_pair(case)
    assert outcome.pair_correct
    assert outcome.vuln_matched == 1 and outcome.fix_findings == 0
    assert build_pair_signals([outcome]) == []


def test_pair_signals_emit_miss_on_vuln_and_fp_on_fix(tmp_path: Path) -> None:
    vuln = tmp_path / "vuln.py"
    fixed = tmp_path / "fixed.py"
    vuln.write_text("def run(x):\n    return str(x)\n")
    fixed.write_text("def run(x):\n    return eval(x)\n")
    case = PairCase(
        name="inverted",
        slice="github",
        language="python",
        origin="test",
        vuln_file=vuln,
        fixed_file=fixed,
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-95",
                vulnerability_class="code injection",
                path="app.py",
                evidence="eval executes input",
                rule_id="python-unsafe-eval",
                sink="eval",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
    )
    outcome = evaluate_pair(case)
    assert not outcome.detected_vuln and not outcome.silent_fix
    signals = {item["signal"] for item in build_pair_signals([outcome])}
    assert signals == {"miss", "fp"}


def test_local_slice_clears_the_pair_gate() -> None:
    verdict = pair_gate()
    assert verdict.passed, verdict.reasons
    local = verdict.result.per_slice["local"]
    assert local.pairs >= 3
    assert local.pair_pass_rate == 1.0
    assert local.specificity == 1.0


def test_github_slice_measures_real_vfc_pairs() -> None:
    cases = select_slice(load_pair_catalog(), "github")
    result = evaluate_catalog(cases)
    by_name = {outcome.name: outcome for outcome in result.outcomes}
    assert by_name["sven-cwe-078-os-system"].pair_correct
    assert by_name["sven-cwe-078-shell-true"].pair_correct
    assert by_name["sven-cwe-089-execute-percent"].pair_correct
    assert by_name["node-serialize-cve-2017-5941"].pair_correct
    # Real corpus honesty: concat-via-query and Zip Slip are currently regex-blind.
    assert not by_name["sven-cwe-089-query-concat"].detected_vuln
    assert not by_name["hutool-cve-2018-17297"].detected_vuln
    assert result.overall.pairs == len(cases)
    assert any(signal["signal"] == "miss" for signal in result.signals)


def test_sast_slice_scores_owasp_and_juliet() -> None:
    cases = select_slice(load_pair_catalog(), "sast")
    result = evaluate_catalog(cases)
    by_name = {outcome.name: outcome for outcome in result.outcomes}
    assert by_name["juliet-c-cwe134-printf"].pair_correct
    assert by_name["owasp-python-deser"].pair_correct
    # Overlay follows intra-file names, not ConfigParser heap; 00074 stays unadjudicated.
    assert not by_name["owasp-python-codeinj"].detected_vuln
    assert by_name["owasp-java-cmdi"].detected_vuln
    assert result.overall.pairs == len(cases)
    # Youden is TPR - FPR; a regex harness is not expected to clear OWASP.
    assert -1.0 <= result.overall.youden <= 1.0


def test_cli_pairs_json_scoreboard() -> None:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "github", "--json"]) == 0
    payload = json.loads(buf.getvalue())
    assert payload["overall"]["pairs"] >= 4
    assert "sven-cwe-078-os-system" in {item["name"] for item in payload["outcomes"]}
