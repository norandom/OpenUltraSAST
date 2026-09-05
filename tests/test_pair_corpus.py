"""Vuln-vs-fixed pair corpus: isolated trees, local gate, github honesty dashboard."""

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.cli import main
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.pair_gate import pair_gate
from openultrasast.pairs import (
    DEFAULT_CATALOG,
    DEFAULT_SAST_CATALOG,
    DEFAULT_VFC_CATALOG,
    PairCase,
    build_pair_signals,
    evaluate_catalog,
    evaluate_pair,
    load_datasets,
    load_pair_catalog,
    select_slice,
    select_vendored,
)


def test_catalog_loads_local_and_github_slices() -> None:
    cases = load_pair_catalog(DEFAULT_CATALOG)
    slices = {case.slice for case in cases}
    names = {case.name for case in cases}
    assert {"local", "github", "sast", "vfc"} <= slices
    assert "local-python-vulnerable" in names
    assert "sven-cwe-078-os-system" in names
    assert "hutool-cve-2018-17297" in names
    assert "owasp-python-codeinj" in names
    assert "juliet-c-cwe134-printf" in names
    assert "openssl-cve-2014-0160" in names
    assert "firefox-cve-2020-15667" in names
    assert "chromium-cve-2019-5786" in names
    assert all(case.vuln_file.is_file() and case.fixed_file.is_file() for case in select_vendored(cases))


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
        "OpenSSL",
        "Firefox mozilla-central",
        "Chromium",
        "curl",
    } <= names
    assert DEFAULT_SAST_CATALOG.is_file()
    assert DEFAULT_VFC_CATALOG.is_file()
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


def test_vfc_slice_is_labeled_openssl_firefox_chromium() -> None:
    cases = select_slice(load_pair_catalog(), "vfc")
    by_name = {case.name: case for case in cases}
    assert set(by_name) >= {
        "openssl-cve-2014-0160",
        "firefox-cve-2020-15667",
        "chromium-cve-2019-5786",
        "openssl-cve-2022-1292",
        "chromium-cve-2022-2162",
        "curl-cve-2023-38545",
        "openssl-cve-2025-69421",
    }
    for case in cases:
        header = case.vuln_file.read_text() + case.fixed_file.read_text()
        assert case.commit_url
        assert case.cve
        assert case.license
        assert case.cve in header
        assert case.license.split()[0] in header
        assert case.vuln_file != case.fixed_file
    sample = tuple(case for case in cases if case.name in {"openssl-cve-2014-0160", "firefox-cve-2020-15667", "chromium-cve-2019-5786"})
    result = evaluate_catalog(sample)
    assert result.overall.pairs == len(sample)
    assert "overlay" in result.scorers["vfc"]
    assert "inventory" in result.scorers["vfc"]
    # Honesty dashboard: memcpy-after-fix and UAF are labeled, not a 100% gate.
    assert -1.0 <= result.overall.youden <= 1.0


def test_vfc_training_manifest_has_vuln_and_fixed_labels() -> None:
    import json

    manifest = Path("benchmarks/pairs/vfc/training/manifest.jsonl")
    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line.strip()]
    assert rows
    assert {row["label"] for row in rows} == {"vuln", "fixed"}
    by_pair: dict[str, set[str]] = {}
    for row in rows:
        by_pair.setdefault(str(row["pair"]), set()).add(str(row["label"]))
        excerpt = Path("benchmarks/pairs/vfc") / str(row["file"])
        assert excerpt.is_file(), row["id"]
        assert 2014 <= int(row["year"]) <= 2026
    assert all(labels == {"vuln", "fixed"} for labels in by_pair.values())
    recent = {row["pair"] for row in rows if 2020 <= int(row["year"]) <= 2026}
    assert len(recent) >= 80
    assert len(by_pair) >= 100
    assert len(rows) == 2 * len(by_pair)


def test_cli_pairs_json_scoreboard() -> None:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "github", "--json"]) == 0
    payload = json.loads(buf.getvalue())
    assert payload["overall"]["pairs"] >= 4
    assert "sven-cwe-078-os-system" in {item["name"] for item in payload["outcomes"]}


def test_cli_vfc_json_includes_dual_scorers() -> None:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "vfc", "--json"]) == 0
    payload = json.loads(buf.getvalue())
    names = {item["name"] for item in payload["outcomes"]}
    assert {"openssl-cve-2014-0160", "firefox-cve-2020-15667", "chromium-cve-2019-5786"} <= names
    assert payload["overall"]["pairs"] >= 3
    assert "overlay" in payload["scorers"]["vfc"]
    assert "inventory" in payload["scorers"]["vfc"]
    assert payload["per_slice"]["vfc"]["pairs"] == payload["scorers"]["vfc"]["overlay"]["pairs"]


# --- pair-corpus-honesty: honest scorer -------------------------------------


def _case(
    tmp_path: Path, name: str, vuln_src: str, fixed_src: str, expected: ExpectedFinding, *, slice_name: str = "sast", **extra: object
) -> PairCase:
    vuln = tmp_path / f"{name}-vuln.py"
    fixed = tmp_path / f"{name}-fixed.py"
    vuln.write_text(vuln_src)
    fixed.write_text(fixed_src)
    return PairCase(
        name=name,
        slice=slice_name,
        language="python",
        origin="test",
        vuln_file=vuln,
        fixed_file=fixed,
        relpath="app.py",
        expected=(expected,),
        min_recall=1.0,
        fix_policy="silent",
        provenance=str(extra.get("provenance", "synthetic")),
        split=str(extra.get("split", "train")),
        known_limit=extra.get("known_limit"),  # type: ignore[arg-type]
    )


def test_coverage_with_source_counts_as_detection_and_as_leak(tmp_path: Path) -> None:
    # hashlib.new is a fact sink the regex inventory does not spell -> overlay coverage, never promote.
    src = "import hashlib\nfrom flask import request\n\ndef h():\n    data = request.args.get('x')\n    return hashlib.new(data)\n"
    expected = ExpectedFinding(
        cwe="CWE-327",
        vulnerability_class="weak hash",
        path="app.py",
        evidence="",
        rule_id="python-weak-hash",
        sink="hashlib",
        mechanism="config_sink_weak_literal",
    )
    both = evaluate_pair(_case(tmp_path, "cov", src, src, expected))
    assert both.detected_vuln and "coverage" in both.detection_kinds
    assert not both.silent_fix  # the same coverage record on the fixed side is a leak


def test_function_scoped_match_rejects_detection_outside_the_named_function(tmp_path: Path) -> None:
    src = "from flask import request\n\ndef other():\n    return eval(request.args.get('x'))\n\ndef target():\n    return 1\n"
    row = ExpectedFinding(
        cwe="CWE-95",
        vulnerability_class="code injection",
        path="app.py",
        evidence="",
        rule_id="python-unsafe-eval",
        sink="eval",
        function="target",
        mechanism="source_reaches_sink",
    )
    outcome = evaluate_pair(_case(tmp_path, "fn", src, "def target():\n    return 1\n", row))
    assert not outcome.detected_vuln and outcome.silent_fix
    row_ok = ExpectedFinding(**{**row.__dict__, "function": "other"})
    assert evaluate_pair(_case(tmp_path, "fn2", src, "def target():\n    return 1\n", row_ok)).detected_vuln


def test_cwe_only_row_is_a_weak_label_and_never_matches(tmp_path: Path) -> None:
    src = "from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n"
    weak = ExpectedFinding(cwe="CWE-95", vulnerability_class="code injection", path="app.py", evidence="", mechanism="source_reaches_sink")
    outcome = evaluate_pair(_case(tmp_path, "weak", src, "def f():\n    return 1\n", weak))
    assert outcome.weak_labels == 1
    assert not outcome.detected_vuln


def test_catalog_rejects_unknown_mechanism_and_sink_unknown_without_anchor(tmp_path: Path) -> None:
    from openultrasast.pairs import CatalogError, _load_catalog_file

    (tmp_path / "v.py").write_text("x = 1\n")
    (tmp_path / "f.py").write_text("x = 1\n")
    head = (
        '[[pair]]\nname = "t"\nslice = "sast"\nvuln = "v.py"\nfixed = "f.py"\nrelpath = "app.py"\n\n'
        '[[pair.expected]]\ncwe = "CWE-95"\nclass = "x"\npath = "app.py"\n'
    )
    (tmp_path / "bad_mech.toml").write_text(head + 'sink = "eval"\nmechanism = "not_a_mechanism"\n')
    with pytest.raises(CatalogError, match="unknown mechanism"):
        _load_catalog_file(tmp_path / "bad_mech.toml")
    (tmp_path / "bad_sink.toml").write_text(head + 'sink = "unknown"\nmechanism = "other"\n')
    with pytest.raises(CatalogError, match="sink=unknown"):
        _load_catalog_file(tmp_path / "bad_sink.toml")
    (tmp_path / "bad_prov.toml").write_text(
        head.replace('slice = "sast"\n', 'slice = "sast"\nprovenance = "robot"\n') + 'sink = "eval"\nmechanism = "other"\n'
    )
    with pytest.raises(CatalogError, match="unknown provenance"):
        _load_catalog_file(tmp_path / "bad_prov.toml")


def test_known_limit_pairs_are_evaluated_but_excluded_from_achievable(tmp_path: Path) -> None:
    src = "from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n"
    row = ExpectedFinding(
        cwe="CWE-95",
        vulnerability_class="code injection",
        path="app.py",
        evidence="",
        rule_id="python-unsafe-eval",
        sink="eval",
        mechanism="cross_artifact",
    )
    limited = _case(tmp_path, "lim", src, "def f():\n    return 1\n", row, known_limit="cross_artifact: needs a properties file")
    plain = _case(
        tmp_path,
        "plain",
        src,
        "def f():\n    return 1\n",
        ExpectedFinding(**{**row.__dict__, "mechanism": "source_reaches_sink"}),
        provenance="agent",
        split="holdout",
    )
    result = evaluate_catalog([limited, plain])
    assert result.known_limit == ("lim",)
    assert result.per_slice["sast"].pairs == 2 and result.achievable["sast"].pairs == 1
    assert set(result.per_profile) == {"synthetic", "agent"}
    assert set(result.per_mechanism) == {"cross_artifact", "source_reaches_sink"}
    assert result.loss["sast"]["known_limit"] == 1
    assert "overlay" in result.scorers["sast"] and "inventory" in result.scorers["sast"]
    assert result.degradations and result.degradations[0]["reason"] == "hunter_model_unavailable"


def test_hunter_scorer_uses_same_rules_with_a_scripted_client(tmp_path: Path) -> None:
    from openultrasast.findings import StaticFinding

    src = "from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n"
    row = ExpectedFinding(
        cwe="CWE-95",
        vulnerability_class="code injection",
        path="app.py",
        evidence="",
        sink="eval",
        function="f",
        mechanism="source_reaches_sink",
    )

    def scripted(root: Path) -> list[StaticFinding]:
        text = (root / "app.py").read_text()
        if "eval(" not in text:
            return []
        return [
            StaticFinding(
                finding_id="tool-hunter:app.py:4",
                path="app.py",
                title="eval of request input",
                severity="high",
                confidence="medium",
                evidence_level="suspicion",
                rationale="CWE-95 eval executes attacker input",
                line=4,
                function_name=None,
                reachability_status="unknown",
                reachability_evidence=[],
                reachability_conditions=[],
                tags=[],
                ranking_priority=1.0,
            )
        ]

    case = _case(tmp_path, "hunt", src, "def f():\n    return 1\n", row)
    result = evaluate_catalog([case], hunter=scripted)
    hunter = result.scorers["sast"]["hunter"]
    assert hunter.pair_correct == 1 and hunter.detected_vuln == 1 and hunter.silent_fix == 1
    assert not result.degradations


def test_juliet_strcpy_pair_bodies_differ_and_java_hash_is_known_limit() -> None:
    cases = {case.name: case for case in select_slice(load_pair_catalog(), "sast")}
    strcpy = cases["juliet-c-cwe121-strcpy"]
    assert strcpy.vuln_file.read_text() != strcpy.fixed_file.read_text()
    assert "dataBadBuffer[10]" in strcpy.vuln_file.read_text() and "data = dataGoodBuffer" in strcpy.fixed_file.read_text()
    assert cases["owasp-java-hash"].known_limit and cases["owasp-java-hash"].known_limit.startswith("cross_artifact")
    assert all(row.mechanism for case in cases.values() for row in case.expected)
    assert all(case.provenance == "synthetic" for case in cases.values())


def test_vfc_rows_name_functions_and_carry_no_weak_labels() -> None:
    cases = select_slice(load_pair_catalog(), "vfc")
    from openultrasast.pairs import is_weak_label

    assert cases and all(row.function for case in cases for row in case.expected)
    assert not any(is_weak_label(row) for case in cases for row in case.expected)
    assert {case.split for case in cases} == {"train", "holdout"}


def test_cli_pairs_profile_and_split_filters() -> None:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "sast", "--profile", "synthetic", "--split", "holdout", "--json"]) == 0
    payload = json.loads(buf.getvalue())
    assert payload["overall"]["pairs"] >= 3
    assert set(payload["per_profile"]) == {"synthetic"}
    assert "per_mechanism" in payload and "loss" in payload and "achievable" in payload
    assert all(item["split"] == "holdout" for item in payload["outcomes"])


def test_new_slices_load_offline_and_score_with_profiles() -> None:
    from openultrasast.pairs import PROVENANCES

    catalog = load_pair_catalog()
    # agent-vfc rows load at tier `title` (Req 9.4); the candidates file is retired.
    assert not Path("benchmarks/pairs/agent-vfc/catalog-candidates.toml").exists()
    assert all(case.provenance == "agent" for case in select_slice(catalog, "agent-vfc"))
    for slice_name, expected_provenance in (("vibe-py", "human"), ("vfc-js", "human")):
        cases = select_slice(catalog, slice_name)
        assert cases, slice_name
        assert all(case.vuln_file.is_file() and case.fixed_file.is_file() for case in select_vendored(cases))
        assert all(case.license for case in select_vendored(cases)), slice_name  # pointer rows may be unlicensed (Req 10)
        assert all(case.provenance == expected_provenance for case in select_vendored(cases)), slice_name
        assert {case.split for case in cases} <= {"train", "holdout"}
        vendored = select_vendored(cases)  # pointer rows have no excerpt in the repository (Req 10)
        header = vendored[0].vuln_file.read_text()[:600]
        assert "Provenance:" in header and "license:" in header
        result = evaluate_catalog(vendored[:2])
        assert result.per_slice[slice_name].pairs == 2
        assert set(result.per_profile) <= PROVENANCES and expected_provenance in result.per_profile
        assert result.per_mechanism and slice_name in result.loss


# --- review round 1 remediation (RED first) -----------------------------------


def test_weak_label_never_matches_on_inventory_fallback(tmp_path: Path) -> None:
    # A syntax error forces parse_failed on both sides -> overlay falls back to inventory.
    src = "from flask import request\n\ndef f(:\n    return eval(request.args.get('x'))\n"
    weak = ExpectedFinding(cwe="CWE-95", vulnerability_class="code injection", path="app.py", evidence="", mechanism="source_reaches_sink")
    outcome = evaluate_pair(_case(tmp_path, "weakfb", src, "def f():\n    return 1\n", weak))
    assert outcome.parse_failed_vuln == 1
    assert outcome.weak_labels == 1
    assert not outcome.detected_vuln
    assert outcome.misses == ("-:app.py:CWE-95",)


def test_sink_match_is_exact_or_alias_not_substring() -> None:
    from openultrasast.pairs import _overlay_matches_expected
    from openultrasast.semantic import OverlayRecord

    record = OverlayRecord(
        proposal_id="overlay-coverage:app.py:3:execute",
        path="app.py",
        line=3,
        disposition="coverage",
        reason="x",
        cwe="CWE-89",
        sources=("request",),
        sinks=("execute",),
        sanitizers=(),
        evidence_level="static_corroboration",
    )
    exec_row = ExpectedFinding(
        cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", sink="exec", mechanism="source_reaches_sink"
    )
    assert not _overlay_matches_expected(exec_row, [record], "python")
    exact = ExpectedFinding(
        cwe="CWE-89", vulnerability_class="x", path="app.py", evidence="", sink="execute", mechanism="source_reaches_sink"
    )
    assert _overlay_matches_expected(exact, [record], "python")
    alias = ExpectedFinding(
        cwe="CWE-89", vulnerability_class="x", path="app.py", evidence="", rule_id="python-sql-injection", mechanism="source_reaches_sink"
    )
    assert _overlay_matches_expected(alias, [record], "python")


def test_vfc_style_slice_rows_require_a_named_function(tmp_path: Path) -> None:
    from openultrasast.pairs import CatalogError, _load_catalog_file

    (tmp_path / "v.js").write_text("x = 1\n")
    (tmp_path / "f.js").write_text("x = 1\n")
    head = (
        '[[pair]]\nname = "t"\nslice = "vfc-js"\nvuln = "v.js"\nfixed = "f.js"\nrelpath = "a.js"\n\n'
        '[[pair.expected]]\ncwe = "CWE-78"\nclass = "x"\npath = "a.js"\nmechanism = "source_reaches_sink"\n'
    )
    (tmp_path / "nofn.toml").write_text(head + 'sink = "exec"\n')
    with pytest.raises(CatalogError, match="function"):
        _load_catalog_file(tmp_path / "nofn.toml")
    (tmp_path / "anon.toml").write_text(head + 'function = "<anon>"\n')
    with pytest.raises(CatalogError, match="function"):
        _load_catalog_file(tmp_path / "anon.toml")
    (tmp_path / "ok.toml").write_text(head + 'function = "run"\n')
    assert _load_catalog_file(tmp_path / "ok.toml")[0].expected[0].function == "run"


def test_known_limit_pairs_emit_no_improve_signals(tmp_path: Path) -> None:
    src = "def f():\n    return 1\n"
    row = ExpectedFinding(
        cwe="CWE-95",
        vulnerability_class="x",
        path="app.py",
        evidence="",
        rule_id="python-unsafe-eval",
        sink="eval",
        mechanism="cross_artifact",
    )
    limited = _case(tmp_path, "lim2", src, src, row, known_limit="cross_artifact: needs a properties file")
    result = evaluate_catalog([limited])
    assert not result.outcomes[0].detected_vuln
    assert all(signal["pair"] != "lim2" for signal in result.signals)


# --- review round 2 remediation (RED first) -----------------------------------


def test_function_at_skips_anonymous_and_module_ranges() -> None:
    from openultrasast.semantic.overlay import function_at

    ranges = (("<module>", 1, 40), ("handler", 3, 20), ("<anon>", 5, 12))
    assert function_at(ranges, 7) == "handler"  # innermost *named* function, never "<anon>"
    assert function_at(ranges, 25) is None
    assert function_at((("<anon>", 1, 9),), 4) is None


@pytest.mark.semantic
def test_promotion_inside_a_callback_matches_the_enclosing_named_function(tmp_path: Path) -> None:
    from openultrasast.semantic.extra import has_semantic_extra

    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    src = (
        "const cp = require('child_process');\n"
        "function handler(req, res) {\n"
        "  [req.query.cmd].forEach(function (c) {\n"
        "    cp.exec(c);\n"
        "  });\n"
        "}\n"
    )
    fixed = "function handler(req, res) {\n  res.end('ok');\n}\n"
    vuln = tmp_path / "v.js"
    fix = tmp_path / "f.js"
    vuln.write_text(src)
    fix.write_text(fixed)
    row = ExpectedFinding(
        cwe="CWE-78", vulnerability_class="x", path="app.js", evidence="", function="handler", sink="exec", mechanism="source_reaches_sink"
    )
    case = PairCase(
        name="cb",
        slice="vfc-js",
        language="javascript",
        origin="test",
        vuln_file=vuln,
        fixed_file=fix,
        relpath="app.js",
        expected=(row,),
        min_recall=1.0,
        fix_policy="silent",
        provenance="human",
    )
    outcome = evaluate_pair(case)
    assert outcome.detected_vuln, outcome
    assert outcome.pair_correct


def test_loader_rejects_reserved_words_as_function_labels(tmp_path: Path) -> None:
    from openultrasast.pairs import CatalogError, _load_catalog_file

    (tmp_path / "v.js").write_text("x = 1\n")
    (tmp_path / "f.js").write_text("x = 1\n")
    head = (
        '[[pair]]\nname = "t"\nslice = "vfc-js"\nvuln = "v.js"\nfixed = "f.js"\nrelpath = "a.js"\n\n'
        '[[pair.expected]]\ncwe = "CWE-78"\nclass = "x"\npath = "a.js"\nmechanism = "source_reaches_sink"\nsink = "exec"\n'
    )
    for bad in ("function", "def", "return"):
        (tmp_path / "bad.toml").write_text(head + f'function = "{bad}"\n')
        with pytest.raises(CatalogError, match="function"):
            _load_catalog_file(tmp_path / "bad.toml")


def test_agent_vfc_loads_at_title_tier_and_tiers_default_per_slice() -> None:
    from openultrasast.pairs import REVIEW_TIERS

    catalog = load_pair_catalog()
    loaded = select_slice(catalog, "agent-vfc")
    # Req 9.4: `reviewer = "pending"` rows are the review queue; they load at tier `title` and never gate.
    assert len(loaded) >= 1
    assert all(case.review_tier in {"title", "reviewed"} and case.provenance == "agent" for case in loaded)
    assert all(case.review_tier == "title" for case in loaded if not case.reviewer)  # pending rows are the review queue
    assert all(case.review_tier in REVIEW_TIERS for case in catalog)
    by_slice = {
        slice_name: {case.review_tier for case in select_slice(catalog, slice_name)}
        for slice_name in ("local", "sast", "vfc", "vibe-py", "vfc-js")
    }
    assert by_slice == {"local": {"reviewed"}, "sast": {"advisory"}, "vfc": {"advisory"}, "vibe-py": {"seeded"}, "vfc-js": {"advisory"}}


def test_reviewed_tier_requires_a_reviewer_and_unknown_tiers_are_rejected(tmp_path: Path) -> None:
    from openultrasast.pairs import CatalogError, _load_catalog_file

    (tmp_path / "v.py").write_text("x = 1\n")
    (tmp_path / "f.py").write_text("x = 1\n")
    head = '[[pair]]\nname = "t"\nslice = "sast"\nvuln = "v.py"\nfixed = "f.py"\nrelpath = "app.py"\n'
    tail = '\n[[pair.expected]]\ncwe = "CWE-95"\nclass = "x"\npath = "app.py"\nsink = "eval"\nmechanism = "other"\n'
    (tmp_path / "no_reviewer.toml").write_text(head + 'review_tier = "reviewed"\n' + tail)
    with pytest.raises(CatalogError, match="reviewer"):
        _load_catalog_file(tmp_path / "no_reviewer.toml")
    (tmp_path / "bad_tier.toml").write_text(head + 'review_tier = "guessed"\n' + tail)
    with pytest.raises(CatalogError, match="unknown review_tier"):
        _load_catalog_file(tmp_path / "bad_tier.toml")
    (tmp_path / "ok.toml").write_text(head + 'review_tier = "reviewed"\nreviewer = "mc"\n' + tail)
    (case,) = _load_catalog_file(tmp_path / "ok.toml")
    assert case.review_tier == "reviewed" and case.reviewer == "mc"
    (tmp_path / "pending.toml").write_text(head + 'reviewer = "pending"\n' + tail)
    (pending,) = _load_catalog_file(tmp_path / "pending.toml")
    assert pending.review_tier == "title"


def test_payload_reports_metrics_per_review_tier(tmp_path: Path) -> None:
    from openultrasast.pairs import evaluate_catalog, result_payload, select_tier

    src = "from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n"
    row = ExpectedFinding(
        cwe="CWE-95", vulnerability_class="code injection", path="app.py", evidence="", sink="eval", mechanism="source_reaches_sink"
    )
    seeded = _case(tmp_path, "seeded", src, "def f():\n    return 1\n", row)
    title = _case(tmp_path, "title", src, "def f():\n    return 1\n", row)
    seeded = PairCase(**{**seeded.__dict__, "review_tier": "seeded"})
    title = PairCase(**{**title.__dict__, "review_tier": "title"})
    result = evaluate_catalog([seeded, title])
    payload = result_payload(result)
    assert set(payload["per_tier"]) == {"seeded", "title"}
    assert payload["per_tier"]["seeded"]["pairs"] == 1
    assert all(outcome["review_tier"] in {"seeded", "title"} for outcome in payload["outcomes"])
    assert select_tier([seeded, title], ("seeded", "reviewed")) == (seeded,)


def test_default_catalog_has_the_new_slices_on_disk_and_off_the_stage1_list() -> None:
    catalog = load_pair_catalog()
    assert {"vibe-py", "vfc-js", "agent-vfc"} <= {case.slice for case in catalog}  # Req 8.1
    assert all(case.vuln_file.is_file() and case.fixed_file.is_file() for case in select_vendored(catalog))
    stage1 = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    assert not ({case.name for case in catalog} & stage1)


def test_cli_new_slices_exit_zero_with_tier_profile_and_mechanism_metrics(capsys: pytest.CaptureFixture[str]) -> None:
    for slice_name in ("vibe-py", "vfc-js", "agent-vfc"):
        assert main(["pairs", "--slice", slice_name, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["per_tier"] and payload["per_profile"] and "per_mechanism" in payload, slice_name


# --- debug round after review 3: shared named ranges, containment-only matching -----


def _js_case(tmp_path: Path, name: str, src: str, function: str) -> PairCase:
    vuln = tmp_path / f"{name}-v.js"
    fix = tmp_path / f"{name}-f.js"
    vuln.write_text(src)
    fix.write_text("function untouched() {\n  return 1;\n}\n")
    row = ExpectedFinding(
        cwe="CWE-78", vulnerability_class="x", path="app.js", evidence="", function=function, sink="exec", mechanism="source_reaches_sink"
    )
    return PairCase(
        name=name,
        slice="vfc-js",
        language="javascript",
        origin="test",
        vuln_file=vuln,
        fixed_file=fix,
        relpath="app.js",
        expected=(row,),
        min_recall=1.0,
        fix_policy="silent",
        provenance="human",
    )


_JS_FORMS = {
    "arrow": "const cp = require('child_process');\nconst h = (req, res) => {\n  cp.exec(req.query.cmd);\n};\n",
    "exports": "const cp = require('child_process');\nexports.h = function (req, res) {\n  cp.exec(req.query.cmd);\n};\n",
    "method": "const cp = require('child_process');\nclass Ctl {\n  h(req, res) {\n    cp.exec(req.query.cmd);\n  }\n}\n",
    "property": (
        "const cp = require('child_process');\nmodule.exports = {\n  h: function (req, res) {\n    cp.exec(req.query.cmd);\n  },\n};\n"
    ),
}


@pytest.mark.semantic
@pytest.mark.parametrize("form", sorted(_JS_FORMS))
def test_declarator_named_functions_match_their_labels(tmp_path: Path, form: str) -> None:
    from openultrasast.semantic.extra import has_semantic_extra

    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    outcome = evaluate_pair(_js_case(tmp_path, form, _JS_FORMS[form], "h"))
    assert outcome.detected_vuln, (form, outcome)


@pytest.mark.semantic
def test_containment_matches_outer_label_and_rejects_inner_label(tmp_path: Path) -> None:
    from openultrasast.semantic.extra import has_semantic_extra

    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    src = (
        "const cp = require('child_process');\n"
        "function outer(req) {\n"
        "  function inner(c) {\n"
        "    cp.exec(c);\n"
        "  }\n"
        "  inner(req.query.cmd);\n"
        "  cp.exec(req.query.top);\n"
        "}\n"
    )
    # The sink inside `inner` also lies inside `outer`'s range: containment says yes, name equality would say no.
    assert evaluate_pair(_js_case(tmp_path, "outer", src, "outer")).detected_vuln
    # A label naming `inner` must not match the promote at line 7, which is outside `inner`.
    only_top = src.replace("    cp.exec(c);\n", "    return c;\n")
    assert not evaluate_pair(_js_case(tmp_path, "inner", only_top, "inner")).detected_vuln


def test_unresolvable_function_label_is_a_visible_loss_not_a_silent_miss(tmp_path: Path) -> None:
    src = "from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n"
    row = ExpectedFinding(
        cwe="CWE-95",
        vulnerability_class="x",
        path="app.py",
        evidence="",
        function="does_not_exist",
        sink="eval",
        mechanism="source_reaches_sink",
    )
    outcome = evaluate_pair(_case(tmp_path, "unres", src, "def f():\n    return 1\n", row))
    assert not outcome.detected_vuln
    assert outcome.unresolved_labels == 1
    assert any(miss.endswith("!unresolved") for miss in outcome.misses)
    result = evaluate_catalog([_case(tmp_path, "unres2", src, "def f():\n    return 1\n", row)])
    assert result.loss["sast"]["unresolved_function_labels"] == 1


def test_named_function_ranges_use_declarator_names() -> None:
    from openultrasast.semantic.extra import has_semantic_extra
    from openultrasast.semantic.functions import declarator_name, named_function_ranges

    assert declarator_name("const listProcessesOnPort = module.exports.listProcessesOnPort = async port => {") == "listProcessesOnPort"
    assert declarator_name("  exec('df -k ' + path, function(err, stdout) {") is None
    assert declarator_name("    function (req, res) {") is None
    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    src = "\n".join(
        [
            "function a() { return 1; }",
            "const b = (x) => { return x; };",
            "exports.c = function (y) { return y; };",
            "class K {",
            "  d(z) {",
            "    return z;",
            "  }",
            "}",
            "const o = {",
            "  e: function (w) {",
            "    return w;",
            "  },",
            "};",
            "",
        ]
    )
    ranges = named_function_ranges("f.js", src, "javascript")
    assert ranges is not None
    assert {name for name, _, _ in ranges} >= {"a", "b", "c", "d", "e"}
    assert "<anon>" not in {name for name, _, _ in ranges}


# --- review round 4 remediation (RED first) -----------------------------------


@pytest.mark.semantic
def test_c_function_with_return_type_on_previous_line_keeps_its_parser_name() -> None:
    from openultrasast.semantic.extra import has_semantic_extra
    from openultrasast.semantic.functions import function_at, named_function_ranges

    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    ranges = named_function_ranges("a.c", "static int\nfoo(int x)\n{\n  return x;\n}\n", "c")
    assert ranges is not None and any(name == "foo" and start <= 4 <= end for name, start, end in ranges)
    assert function_at(ranges, 4) == "foo"


def test_declarator_name_knows_perl_subs_and_never_names_calls() -> None:
    from openultrasast.semantic.functions import declarator_name

    assert declarator_name("sub link_hash_cert {") == "link_hash_cert"
    assert declarator_name("    return foo(bar)") is None
    assert declarator_name("    print(x)") is None
    assert declarator_name("synchronized (lock) {") is None
    assert declarator_name("int main(int argc, char **argv)") == "main"


# --- review round 5 remediation (RED first) -----------------------------------


def test_declarator_name_strips_cpp_qualification_to_match_unqualified_labels() -> None:
    from openultrasast.semantic.functions import declarator_name

    assert declarator_name("bool FileReaderLoader::ArrayBufferResult(int a) {") == "ArrayBufferResult"
    assert declarator_name("void ns::Klass::run(const std::string& s) const {") == "run"
    assert declarator_name("std::string Foo::bar() {") == "bar"


@pytest.mark.semantic
def test_cpp_qualified_method_range_is_found_by_its_unqualified_label() -> None:
    from openultrasast.semantic.extra import has_semantic_extra
    from openultrasast.semantic.functions import function_at, named_function_ranges, spans_named

    if not has_semantic_extra():
        pytest.skip("tree-sitter extra absent")
    ranges = named_function_ranges("a.cc", "bool K::m(int a) {\n  return a;\n}\n", "cpp")
    assert ranges is not None
    assert spans_named(ranges, "m") == ((1, 3),)
    assert function_at(ranges, 2) == "m"


# --- task 8.3: pointer pairs (Req 10) -----------------------------------------


_POINTER_ROW = (
    '[[pair]]\nname = "ptr"\nslice = "vibe-py"\nlanguage = "python"\nvendored = false\nrepo = "o/r"\nparent = "aaa"\ncommit = "bbb"\n'
    'path = "app.py"\nmode = "enclosing"\nline = 3\nrelpath = "app.py"\nprovenance = "agent"\nreview_tier = "seeded"\nlicense = ""\n\n'
    '[[pair.expected]]\ncwe = "CWE-95"\nclass = "code injection"\npath = "app.py"\nfunction = "f"\n'
    'sink = "eval"\nmechanism = "source_reaches_sink"\n'
)


def test_pointer_rows_load_without_excerpts_and_point_into_the_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.pairs import CatalogError, _load_catalog_file, pointer_recipe, select_vendored

    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path / "cache"))
    (tmp_path / "c.toml").write_text(_POINTER_ROW)
    (case,) = _load_catalog_file(tmp_path / "c.toml")
    assert case.vendored is False
    assert case.vuln_file == (tmp_path / "cache" / "vibe-py" / "ptr" / "vuln.py").resolve()
    assert pointer_recipe(case)["parent"] == "aaa" and pointer_recipe(case)["mode"] == "enclosing"
    assert select_vendored([case]) == ()
    (tmp_path / "bad.toml").write_text(_POINTER_ROW.replace('parent = "aaa"\n', ""))
    with pytest.raises(CatalogError, match="parent"):
        _load_catalog_file(tmp_path / "bad.toml")


def test_pointer_pairs_skip_with_a_degradation_when_network_is_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.pairs import _load_catalog_file, evaluate_catalog

    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    (tmp_path / "c.toml").write_text(_POINTER_ROW)
    result = evaluate_catalog(_load_catalog_file(tmp_path / "c.toml"))
    assert result.outcomes == ()
    assert {"stage": "pairs", "reason": "pointer_pair_skipped", "pair": "ptr"} in result.degradations
    assert not (tmp_path / "cache").exists()


def test_pointer_pairs_materialize_into_the_cache_and_score_like_vendored_pairs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import pairs as pairs_mod

    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("OPENULTRASAST_PAIRS_NETWORK", "1")
    (tmp_path / "c.toml").write_text(_POINTER_ROW)
    (case,) = pairs_mod._load_catalog_file(tmp_path / "c.toml")

    def fake_materialize(recipe: dict[str, object], cache_root: Path) -> tuple[Path, Path]:
        folder = cache_root / "vibe-py" / str(recipe["name"])
        folder.mkdir(parents=True)
        (folder / "vuln.py").write_text("from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n")
        (folder / "fixed.py").write_text("def f():\n    return 1\n")
        return folder / "vuln.py", folder / "fixed.py"

    monkeypatch.setattr(pairs_mod, "_materialize_pointer", fake_materialize)
    result = pairs_mod.evaluate_catalog([case])
    assert len(result.outcomes) == 1 and result.outcomes[0].name == "ptr" and result.outcomes[0].detected_vuln
    assert not any(item.get("reason", "").startswith("pointer_pair") for item in result.degradations)
    # a second evaluation reuses the cache: no fetch
    monkeypatch.setattr(pairs_mod, "_materialize_pointer", lambda *_: pytest.fail("cache hit expected"))
    assert pairs_mod.evaluate_catalog([case]).outcomes[0].pair_correct
    # a failing fetch is a recorded loss, never an exception
    (tmp_path / "c2.toml").write_text(_POINTER_ROW.replace('name = "ptr"', 'name = "ptr2"'))
    (case2,) = pairs_mod._load_catalog_file(tmp_path / "c2.toml")

    def boom(recipe: dict[str, object], cache_root: Path) -> tuple[Path, Path]:
        raise OSError("offline")

    monkeypatch.setattr(pairs_mod, "_materialize_pointer", boom)
    failed = pairs_mod.evaluate_catalog([case2])
    assert failed.outcomes == () and any(
        item["reason"] == "pointer_pair_fetch_failed" and item["pair"] == "ptr2" for item in failed.degradations
    )


def test_cli_pairs_pointers_flag_turns_network_on_for_one_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    from contextlib import redirect_stdout

    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "local", "--pointers", "--json"]) == 0
    assert json.loads(buf.getvalue())["overall"]["pairs"] == 3
    assert "OPENULTRASAST_PAIRS_NETWORK" not in __import__("os").environ  # the flag is per run, not a persistent env change


def test_warm_cache_never_scores_pointer_pairs_when_network_is_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 10.3: the cache only spares the fetch under --pointers; it never turns a default run into a pointer run."""
    from openultrasast.pairs import _load_catalog_file, evaluate_catalog

    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    (tmp_path / "c.toml").write_text(_POINTER_ROW)
    (case,) = _load_catalog_file(tmp_path / "c.toml")
    case.vuln_file.parent.mkdir(parents=True)
    case.vuln_file.write_text("from flask import request\n\ndef f():\n    return eval(request.args.get('x'))\n")
    case.fixed_file.write_text("def f():\n    return 1\n")
    result = evaluate_catalog([case])
    assert result.outcomes == ()
    assert {"stage": "pairs", "reason": "pointer_pair_skipped", "pair": "ptr"} in result.degradations
    assert evaluate_catalog([case], pointers=True).outcomes[0].pair_correct  # warm cache, network on: no fetch, scored


def test_vibe_py_and_agent_vfc_carry_pointer_rows_and_the_default_run_skips_them() -> None:
    """Req 10.6: LLM-generated Real-Vuln repos are agent/seeded pointer rows; unlicensed agent fixes are title pointer rows."""
    import io
    from contextlib import redirect_stdout

    catalog = load_pair_catalog()
    vibe = select_slice(catalog, "vibe-py")
    pointers = [case for case in vibe if not case.vendored]
    assert len(pointers) >= 40 and len({case.repo for case in pointers}) >= 40
    assert all(case.provenance == "agent" and case.review_tier == "seeded" and not case.vuln_file.exists() for case in pointers)
    assert len(select_vendored(vibe)) == 35 and all(case.provenance == "human" for case in select_vendored(vibe))
    agent_pointers = [case for case in select_slice(catalog, "agent-vfc") if not case.vendored]
    assert len(agent_pointers) >= 20 and all(case.review_tier == "title" and case.license == "unlicensed" for case in agent_pointers)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "vibe-py", "--json"]) == 0
    payload = json.loads(buf.getvalue())
    skipped = [item for item in payload["degradations"] if item["reason"] == "pointer_pair_skipped"]
    assert len(skipped) == len(pointers) and payload["overall"]["pairs"] == 35
