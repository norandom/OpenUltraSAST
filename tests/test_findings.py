import json
from pathlib import Path

from openultrasast.findings import build_quick_hunter_prompt, quick_scan_findings, write_findings
from openultrasast.mapping import analyze_entry_points, attach_reachability_hints
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets
from openultrasast.reports import write_markdown_report


def test_quick_scan_findings_emit_static_corroboration(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.c").write_text("void parse(char *src) { char dst[8]; strcpy(dst, src); }\n")
    _, targets = preprocess_repository(repo)
    rankings = rank_targets(targets)

    findings = quick_scan_findings(repo, targets, rankings)

    assert len(findings) == 1
    assert findings[0].evidence_level == "static_corroboration"
    assert findings[0].path == "parser.c"
    assert findings[0].line == 1


def test_findings_and_report_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "runner.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    _, targets = preprocess_repository(repo)
    findings = quick_scan_findings(repo, targets, rank_targets(targets))
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"

    write_findings(findings, findings_path)
    write_markdown_report(findings, report_path)

    assert json.loads(findings_path.read_text())["findings"][0]["severity"] == "medium"
    assert "Subprocess shell execution" in report_path.read_text()


def test_findings_inherit_only_matching_function_level_reachability(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/admin')\n"
        "@login_required\n"
        "def admin_upload():\n"
        "    if feature_flags.enabled('dangerous_upload'):\n"
        "        return eval(request.data)\n"
        "    return 'disabled'\n"
        "\n"
        "def helper(user_input):\n"
        "    return exec(user_input)\n"
    )
    _, targets = preprocess_repository(repo)
    targets = attach_reachability_hints(targets, analyze_entry_points(repo, targets))

    findings = quick_scan_findings(repo, targets, rank_targets(targets))

    reachable = next(finding for finding in findings if finding.line == 5)
    unreachable = next(finding for finding in findings if finding.line == 9)

    assert reachable.function_name == "admin_upload"
    assert reachable.reachability_status == "reachable"
    assert reachable.reachability_evidence[0]["access_level"] == "authenticated"
    assert reachable.reachability_conditions == ["feature_flags.enabled('dangerous_upload')"]
    assert unreachable.function_name is None
    assert unreachable.reachability_status == "unknown"
    assert unreachable.ranking_priority <= 1.5


def test_quick_hunter_prompt_is_bounded() -> None:
    repo = Path("/repo/example.py")
    target = next(iter(preprocess_repository(repo.parent)[1]), None) if repo.parent.exists() else None
    assert target is None
    class Target:
        path = "example.py"
        language = "python"
        tags = ["auth_boundary"]

    prompt = build_quick_hunter_prompt(Target(), "x" * 5000)  # type: ignore[arg-type]

    assert "example.py" in prompt
    assert len(prompt) < 4300
