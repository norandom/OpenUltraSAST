"""Offline coverage of the Semgrep benchmark arm: rule conversion, result mapping, record shape."""

import hashlib
import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
semgrep_arm = importlib.import_module("benchmarks.valid.semgrep_arm")
catalog = importlib.import_module("benchmarks.valid.catalog")
score = importlib.import_module("benchmarks.unseen.score")

RULES_TOML = """
[[rule]]
rule_id = "python-shell-true"
title = "Subprocess shell execution needs review"
languages = ["python"]
cwe = "CWE-78"
tags = ["syscall_entry"]
status = "enabled"
precision_estimate = 0.0
version = "1"
pattern = '''subprocess\\.[a-zA-Z_]+\\s*\\([^\\n]*shell\\s*=\\s*True'''

[[rule]]
rule_id = "php-sql-shadow"
title = "PHP SQL call composed from a variable"
languages = ["php"]
cwe = "CWE-89"
tags = ["injection"]
status = "shadow"
precision_estimate = 0.25
version = "1"
pattern = '''mysqli_query\\s*\\([^\\n]*\\$'''

[[rule]]
rule_id = "php-sql-bounded"
title = "PHP sprintf-built SQL"
languages = ["php"]
cwe = "CWE-89"
tags = ["injection"]
status = "enabled"
precision_estimate = 0.1
version = "1"
pattern = '''(sprintf)\\((?=(?:(?!\\);)[\\s\\S]){0,2000}?'%s')'''

[[rule]]
rule_id = "groovy-xss-unescaped"
title = "Groovy template unescaped output needs review"
languages = ["groovy"]
cwe = "CWE-79"
tags = ["injection"]
status = "enabled"
precision_estimate = 0.0
version = "1"
pattern = '''(yieldUnescaped)\\s+[A-Za-z_]'''
"""

FACTS_TOML = """
version = "1"
language = "python"

[[source]]
id = "request"
patterns = ["request.args", "request.get_json", "input("]

[[sink]]
id = "os.system"
cwe = "CWE-78"
calls = ["os.system", "subprocess.run"]
rule_ids = ["python-os-command"]

[[sink]]
id = "execute"
cwe = "CWE-89"
calls = ["execute"]
rule_ids = []

[[sink]]
id = "hashlib"
cwe = "CWE-327"
calls = ["hashlib.md5", "hashlib.new"]
rule_ids = []
weak_literals = ["md5", "sha1"]

[[sanitizer]]
id = "shlex.quote"
calls = ["shlex.quote"]

[[sanitizer]]
id = "parameterized_execute"
calls = ["execute"]
parameterized = true

[[sanitizer]]
id = "url_allowlist"
calls = ["url_has_allowed_host_and_scheme"]
guard = true
"""

SEMGREP_SAMPLE = {
    "version": "1.179.0",
    "results": [
        {
            "check_id": "rules.ousast.python.taint.os.system",
            "path": "app/views.py",
            "start": {"line": 12, "col": 5, "offset": 300},
            "end": {"line": 12, "col": 30, "offset": 325},
            "extra": {
                "message": "os.system: untrusted input reaches os.system, subprocess.run",
                "metadata": {"family": "injection", "cwe": "CWE-78", "origin": "sink:python:os.system", "precision_estimate": "unmeasured"},
                "severity": "ERROR",
                "lines": '    os.system("ls " + c)',
                "dataflow_trace": {"taint_source": ["CliLoc", [{"path": "app/views.py", "start": {"line": 11}}, "request.args"]]},
            },
        },
        {
            "check_id": "rules.ousast.python.regex.python-os-command",
            "path": "app/views.py",
            "start": {"line": 12, "col": 5, "offset": 300},
            "end": {"line": 12, "col": 15, "offset": 310},
            "extra": {
                "message": "Python OS command execution needs review",
                "metadata": {"family": "injection", "cwe": "CWE-78", "origin": "python-os-command", "precision_estimate": "0.0"},
                "severity": "WARNING",
                "lines": '    os.system("ls " + c)',
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": ["app/views.py"]},
}


@pytest.fixture
def ruleset(tmp_path):
    root = tmp_path / "ruleset"
    (root / "python").mkdir(parents=True)
    (root / "python" / "rules.toml").write_text(RULES_TOML)
    (root / "obligations").mkdir()
    (root / "obligations" / "python.toml").write_text('[[operation]]\nid = "x"\n[[discharger]]\nid = "y"\n')
    facts = root / "semantic"
    facts.mkdir()
    (facts / "python.toml").write_text(FACTS_TOML)
    return root


def test_regex_rules_convert_with_metadata_and_skip_reasons(ruleset):
    converted, skipped, rewrites = semgrep_arm.convert_regex_rules(ruleset)
    by_origin = {rule["metadata"]["origin"]: rule for rules in converted.values() for rule in rules}
    shell = by_origin["python-shell-true"]
    assert shell["languages"] == ["python"]
    assert shell["pattern-regex"] == r"subprocess\.[a-zA-Z_]+\s*\([^\n]*shell\s*=\s*True"
    assert shell["metadata"]["family"] == "injection"
    assert shell["metadata"]["cwe"] == "CWE-78"
    assert shell["metadata"]["precision_estimate"] == "0.0"
    assert shell["id"].startswith("ousast.python.regex.")
    groovy = by_origin["groovy-xss-unescaped"]
    assert groovy["languages"] == ["generic"]
    assert groovy["paths"] == {"include": ["*.groovy", "*.tpl"]}
    assert groovy["metadata"]["family"] == "output_encoding"
    assert by_origin["php-sql-bounded"]["pattern-regex"] == r"(sprintf)\((?=(?:(?!\);)[\s\S])*?'%s')"
    assert [rewrite["origin"] for rewrite in rewrites] == ["php-sql-bounded"]
    assert [entry["origin"] for entry in skipped] == ["php-sql-shadow"]
    assert "shadow" in skipped[0]["reason"]


def test_emit_floor_skips_rules_below_precision(ruleset):
    _, skipped, _ = semgrep_arm.convert_regex_rules(ruleset, min_precision=0.05)
    reasons = {entry["origin"]: entry["reason"] for entry in skipped}
    assert reasons["python-shell-true"].startswith("emit floor")
    assert reasons["groovy-xss-unescaped"].startswith("emit floor")
    assert "php-sql-bounded" not in reasons


def test_fact_triple_becomes_a_taint_rule(ruleset):
    converted, skipped, lossy = semgrep_arm.convert_facts(ruleset / "semantic")
    rules = {rule["metadata"]["origin"]: rule for rule in converted["python"]}
    taint = rules["sink:python:os.system"]
    assert taint["mode"] == "taint"
    assert taint["languages"] == ["python"]
    assert taint["metadata"] == {
        "family": "injection",
        "cwe": "CWE-78",
        "origin": "sink:python:os.system",
        "precision_estimate": "unmeasured",
        "kind": "taint",
        "calls": ["os.system", "subprocess.run"],
    }
    sources = [entry["pattern"] for entry in taint["pattern-sources"][0]["pattern-either"]]
    assert {"request.args", "request.get_json(...)", "input(...)"} <= set(sources)
    sinks = [entry["pattern"] for entry in taint["pattern-sinks"][0]["pattern-either"]]
    assert sinks == ["os.system(...)", "subprocess.run(...)"]
    sanitizers = [entry["pattern"] for entry in taint["pattern-sanitizers"][0]["pattern-either"]]
    assert sanitizers == ["shlex.quote(...)"]
    execute = rules["sink:python:execute"]["pattern-sinks"][0]["pattern-either"]
    assert execute[0] == {"patterns": [{"pattern": "execute($QUERY)"}, {"focus-metavariable": "$QUERY"}]}
    weak = rules["sink:python:hashlib"]
    assert "mode" not in weak and weak["metadata"]["kind"] == "weak_literal" and weak["metadata"]["family"] == "config_secrets"
    reasons = {entry["origin"]: entry["reason"] for entry in skipped}
    assert reasons["sanitizer:python:url_allowlist"].startswith("guard")
    assert reasons["sanitizer:python:parameterized_execute"].startswith("parameterized")
    assert lossy == []


def test_write_rules_emits_one_yaml_per_language_and_a_report(ruleset, tmp_path):
    out = tmp_path / "rules"
    report = semgrep_arm.write_rules(out, ruleset_dir=ruleset, facts_dir=ruleset / "semantic", semgrep="/nonexistent/semgrep")
    assert sorted(path.name for path in out.glob("*.yaml")) == ["groovy.yaml", "php.yaml", "python.yaml"]
    assert report["files"] == {"groovy.yaml": 1, "php.yaml": 1, "python.yaml": 4}
    loaded = yaml.safe_load((out / "python.yaml").read_text())
    ids = [rule["id"] for rule in loaded["rules"]]
    assert len(ids) == len(set(ids)) == 4
    for rule in loaded["rules"]:
        assert set(rule) >= {"id", "languages", "severity", "message", "metadata"}
        assert {"family", "cwe", "origin", "precision_estimate"} <= set(rule["metadata"])
        assert isinstance(rule["metadata"]["precision_estimate"], str)
        assert ("pattern-regex" in rule) or ("pattern-either" in rule) or (rule.get("mode") == "taint")
    saved = json.loads((out / "conversion_report.json").read_text())
    assert saved["obligations"]["skipped_tables"] == 2
    assert saved["regex"]["converted"] == ["groovy-xss-unescaped", "php-sql-bounded", "python-shell-true"]
    assert saved["facts"]["converted"] == ["sink:python:execute", "sink:python:hashlib", "sink:python:os.system"]
    # A missing binary is recorded, never reported as a successful validation.
    assert report["validation"]["exit"] is None and "not found" in report["validation"]["error"]


def test_result_to_defect_mapping():
    defects = [semgrep_arm.result_defect(result) for result in SEMGREP_SAMPLE["results"]]
    assert defects[0] == {
        "defect_id": "sink:python:os.system:app/views.py:12",
        "family": "injection",
        "cwe": "CWE-78",
        "locations": [["app/views.py", 12]],
        "source": "semgrep",
        "rule_id": "rules.ousast.python.taint.os.system",
        "origin": "sink:python:os.system",
        "title": "os.system: untrusted input reaches os.system, subprocess.run",
        "rationale": "os.system: untrusted input reaches os.system, subprocess.run",
        "confidence": "ERROR",
        "dataflow": True,
    }
    assert defects[1]["dataflow"] is False
    assert defects[1]["confidence"] == "WARNING"
    assert defects[1]["origin"] == "python-os-command"


def _change(**overrides):
    change = dict(
        id="fixture-positive",
        repo="fixture/app",
        repository_url="https://example.invalid/app",
        kind="vulnerability",
        base="b" * 40,
        head="a" * 40,
        family="injection",
        cwe="CWE-78",
        path="app/views.py",
        function="handler",
        function_lines=[10, 14],
        files=[{"path": "app/views.py", "head_lines": [[10, 14]]}],
        method="fix_site",
        slice="1",
    )
    change.update(overrides)
    return change


def test_record_shape_is_accepted_by_the_scorer(tmp_path):
    out = tmp_path / "semgrep"
    change = _change()
    digest = hashlib.sha256(json.dumps(change, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    semgrep_arm._write_json(out / "inputs.json", [{"item_id": change["id"], "change": change, "input_digest": digest}])
    record = {
        "id": change["id"],
        "done": True,
        "status": "semgrep_covered",
        "input_digest": digest,
        "instrument": {
            "hook_exit": 0,
            "hook_bytes_read": 412,
            "changed_bytes": {"app/views.py": 412},
            "head_verified": True,
            "base_verified": True,
            "failure": None,
            "suspect_fast": False,
            "semgrep": {"exit": 0, "wall_seconds": 4.9, "scanned": ["app/views.py"], "errors": [], "results": 2},
        },
        "push": {
            "admission": {"defects": [semgrep_arm.result_defect(result) for result in SEMGREP_SAMPLE["results"]], "dispositions": []},
            "quick_tier": [],
        },
        "skipped": [],
    }
    semgrep_arm._write_json(semgrep_arm._record_path(out, change["id"]), record)
    rows = score.load_records(out)
    assert len(rows) == 1 and rows[0]["status"] == "semgrep_covered"
    assert score.coverage(rows[0]) == "quick_only"
    assert score.catches(rows[0]) == ["alerts"]
    assert score.false_alarm(rows[0])
    # A family mismatch is not a catch, exactly as the hunter arm is scored.
    rows = score.load_records(out)
    rows[0]["family"] = "path"
    assert score.catches(rows[0]) == []
    scored = score.score(rows)
    assert scored["coverage"]["quick_only"] == 1


def test_instrument_failure_record_is_not_covered(tmp_path):
    out = tmp_path / "semgrep"
    change = _change()
    digest = "0" * 64
    semgrep_arm._write_json(out / "inputs.json", [{"item_id": change["id"], "change": change, "input_digest": digest}])
    record = {
        "id": change["id"],
        "done": True,
        "status": "instrument_failure",
        "input_digest": digest,
        "instrument": {
            "hook_exit": 2,
            "hook_bytes_read": 0,
            "changed_bytes": {},
            "head_verified": True,
            "base_verified": True,
            "failure": "semgrep_exit_2",
            "suspect_fast": False,
        },
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
        "skipped": [],
    }
    semgrep_arm._write_json(semgrep_arm._record_path(out, change["id"]), record)
    rows = score.load_records(out)
    assert score.coverage(rows[0]) == "instrument_failure"
    assert not score.false_alarm(rows[0])


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git = catalog.local_git(root)
    git.run("init", "-q")
    git.run("config", "user.name", "Fixture")
    git.run("config", "user.email", "fixture@example.invalid")
    heads = []
    for text in (
        "import os\nfrom flask import request\n\n\ndef handler():\n    c = request.args.get('c')\n    os.system('ls ' + c)\n",
        "# Later checkout\n",
    ):
        (root / "app.py").write_text(text)
        git.run("add", "app.py")
        git.run("-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
        heads.append(git.run("rev-parse", "HEAD").strip())
    change = _change(
        base=heads[1],
        head=heads[0],
        path="app.py",
        function="handler",
        function_lines=[5, 7],
        files=[{"path": "app.py", "head_lines": [[5, 7]]}, {"path": "gone.py", "head_lines": [[1, 1]]}],
    )
    frozen = tmp_path / "frozen.json"
    frozen.write_text(
        json.dumps({"changes": [change], "sha256": hashlib.sha256(json.dumps([change], sort_keys=True).encode()).hexdigest()})
    )
    repos = tmp_path / "repos.json"
    repos.write_text(json.dumps({change["repo"]: str(root)}))
    return {"root": root, "git": git, "change": change, "frozen": frozen, "repos": repos}


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_run_scans_changed_files_and_cleans_up(fixture, tmp_path):
    rules = tmp_path / "rules"
    semgrep_arm.write_rules(rules, semgrep="/nonexistent/semgrep")
    out = tmp_path / "out"
    assert semgrep_arm.run(fixture["frozen"], fixture["repos"], rules, out, only="vulnerability") == 0
    rows = score.load_records(out)
    assert len(rows) == 1
    record = rows[0]
    assert record["status"] == "semgrep_covered"
    assert record["instrument"]["changed_bytes"] == {"app.py": record["instrument"]["hook_bytes_read"]}
    assert record["instrument"]["hook_bytes_read"] > 0
    assert record["instrument"]["semgrep"]["exit"] == 0 and not record["instrument"]["suspect_fast"]
    assert record["skipped"] == [{"path": "gone.py", "reason": "missing_at_head"}]
    assert record["instrument"]["semgrep"]["scanned"] == ["app.py"]
    origins = {defect["origin"] for defect in record["push"]["admission"]["defects"]}
    assert {"python-os-command", "sink:python:os.system"} <= origins
    assert any(defect["dataflow"] for defect in record["push"]["admission"]["defects"])
    assert score.coverage(record) == "quick_only"
    assert score.catches(record) == ["alerts"]
    assert fixture["git"].run("worktree", "list").strip().count("\n") == 0
    # A second run resumes without touching the record.
    assert semgrep_arm.run(fixture["frozen"], fixture["repos"], rules, out, only="vulnerability") == 0
