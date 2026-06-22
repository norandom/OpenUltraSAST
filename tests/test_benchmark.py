import json
from pathlib import Path

from openultrasast.benchmark import (
    create_benchmark_run,
    evaluate_benchmark,
    load_baseline_findings,
    load_benchmark_manifest,
    write_benchmark_artifacts,
)
from openultrasast.cli import main
from openultrasast.findings import StaticFinding


def test_benchmark_manifest_loads_expected_findings(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"
frameworks = ["native"]
setup = ["make"]
modes = ["quick"]
known_noise = ["sample-only fixture warning"]
baselines = ["clang-tidy"]

[source]
type = "local"
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 3
rule_id = "c-unsafe-memory-copy"
evidence = "memcpy copies attacker-controlled input"
function = "copy_user"
sink = "memcpy"
""".strip()
        + "\n"
    )

    manifest = load_benchmark_manifest(manifest_path)

    assert manifest.name == "cpp-smoke"
    assert manifest.language == "c_cpp"
    assert manifest.setup == ["make"]
    assert manifest.source.path == "repo"
    assert manifest.known_noise == ["sample-only fixture warning"]
    assert manifest.expected[0].rule_id == "c-unsafe-memory-copy"
    assert manifest.expected[0].function == "copy_user"
    assert manifest.expected[0].sink == "memcpy"


def test_repository_benchmark_manifests_load_and_point_to_fixtures() -> None:
    manifest_paths = sorted(Path("benchmarks/manifests").glob("*.toml"))

    assert {path.name for path in manifest_paths} == {
        "c-cpp-smoke.toml",
        "cpp-damn-vulnerable.toml",
        "java-spring-boot-vulnerable.toml",
        "java-web-smoke.toml",
        "javascript-node-web-smoke.toml",
        "javascript-vulnerable.toml",
        "python-vulnerable.toml",
        "python-web-smoke.toml",
    }
    for manifest_path in manifest_paths:
        manifest = load_benchmark_manifest(manifest_path)
        assert manifest.expected
        assert manifest.language in {"c_cpp", "java_web", "javascript_node_web", "python_web"}
        assert (manifest_path.parent / manifest.source.path).resolve().exists()


def test_benchmark_result_records_missed_expected_findings(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 3
rule_id = "c-unsafe-memory-copy"
evidence = "memcpy copies attacker-controlled input"
""".strip()
        + "\n"
    )
    manifest = load_benchmark_manifest(manifest_path)
    run = create_benchmark_run(repo, manifest)

    result = evaluate_benchmark(run=run, mode="quick", findings=[], scan_id="scan-1", scan_run_dir=repo / ".runs" / "scan-1")
    write_benchmark_artifacts(run, manifest_path, result)

    payload = json.loads((run.root / "benchmark_result.json").read_text())
    assert payload["metrics"]["expected_findings_total"] == 1
    assert payload["metrics"]["matched_findings_total"] == 0
    assert payload["metrics"]["missed_findings_total"] == 1
    assert payload["metrics"]["false_positive_findings_total"] == 0
    assert payload["metrics"]["recall"] == 0.0
    assert payload["metrics"]["precision"] is None
    assert payload["misses"][0]["reason"] == "no OpenUltraSAST finding matched the expected benchmark vulnerability"


def test_benchmark_cli_runs_scan_and_writes_scoreboard(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    (source / "vuln.cpp").write_text("#include <string.h>\nvoid f(char *a, char *b) {\n  memcpy(a, b, 10);\n}\n")
    manifest_path = tmp_path / "benchmark.toml"
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 3
rule_id = "c-unsafe-memory-copy"
evidence = "memcpy copies attacker-controlled input"
""".strip()
        + "\n"
    )
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["benchmark", str(manifest_path), "--mode", "quick"]) == 0

    benchmark_dir = sorted((repo / ".openultrasast" / "benchmarks").iterdir())[-1]
    payload = json.loads((benchmark_dir / "benchmark_result.json").read_text())

    assert payload["benchmark_name"] == "cpp-smoke"
    assert payload["metrics"]["expected_findings_total"] == 1
    assert payload["metrics"]["matched_findings_total"] == 1
    assert payload["metrics"]["recall"] == 1.0
    assert payload["metrics"]["precision"] == 1.0
    assert payload["metrics"]["artifact_links"]["findings"].endswith("findings.json")


def test_benchmark_matching_uses_function_sink_and_evidence_text(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 9
rule_id = "c-unsafe-memory-copy"
function = "copy_user"
sink = "memcpy"
evidence = "attacker-controlled memcpy"
""".strip()
        + "\n"
    )
    manifest = load_benchmark_manifest(manifest_path)
    run = create_benchmark_run(repo, manifest)
    findings = [
        _finding(
            finding_id="c-unsafe-memory-copy:src/vuln.cpp:9",
            path="src/vuln.cpp",
            line=9,
            function_name="copy_user",
            rationale="Static pattern c-unsafe-memory-copy matched memcpy with attacker-controlled input.",
        )
    ]

    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id="scan-1", scan_run_dir=repo / ".runs" / "scan-1")

    assert result.metrics.matched_findings_total == 1
    assert result.metrics.missed_findings_total == 0
    assert result.metrics.false_positive_findings_total == 0
    assert result.metrics.recall == 1.0
    assert result.metrics.precision == 1.0


def test_benchmark_records_unmatched_findings_as_false_positives(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 9
rule_id = "c-unsafe-memory-copy"
sink = "memcpy"
evidence = "memcpy"
""".strip()
        + "\n"
    )
    manifest = load_benchmark_manifest(manifest_path)
    run = create_benchmark_run(repo, manifest)
    findings = [
        _finding(
            finding_id="c-shell-exec:src/other.cpp:12",
            path="src/other.cpp",
            line=12,
            rationale="Static pattern c-shell-exec matched system.",
        )
    ]

    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id="scan-1", scan_run_dir=repo / ".runs" / "scan-1")

    assert result.metrics.matched_findings_total == 0
    assert result.metrics.missed_findings_total == 1
    assert result.metrics.false_positive_findings_total == 1
    assert result.metrics.precision == 0.0
    assert result.false_positives[0].finding_id == "c-shell-exec:src/other.cpp:12"
    assert result.false_positives[0].reason == "finding did not match any expected benchmark vulnerability"


def test_benchmark_ingests_baselines_and_writes_calibration_records(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    baseline_path = tmp_path / "clearwing-normalized.json"
    repo = tmp_path / "repo"
    repo.mkdir()
    baseline_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "tool": "clearwing",
                        "finding_id": "cw-1",
                        "path": "src/vuln.cpp",
                        "line": 9,
                        "rule_id": "c-unsafe-memory-copy",
                        "cwe": "CWE-120",
                        "evidence": "memcpy copies attacker-controlled input",
                    },
                    {
                        "tool": "clearwing",
                        "finding_id": "cw-extra",
                        "path": "src/other.cpp",
                        "line": 12,
                        "rule_id": "c-shell-exec",
                        "cwe": "CWE-78",
                        "evidence": "system executes shell command",
                    },
                ]
            }
        )
        + "\n"
    )
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"
baselines = ["clearwing-normalized.json"]

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "unsafe memory copy"
path = "src/vuln.cpp"
line = 9
rule_id = "c-unsafe-memory-copy"
sink = "memcpy"
evidence = "memcpy copies attacker-controlled input"
""".strip()
        + "\n"
    )
    manifest = load_benchmark_manifest(manifest_path)
    run = create_benchmark_run(repo, manifest)
    baseline_findings = load_baseline_findings(manifest_path, manifest)
    unrelated_finding = _finding(
        finding_id="c-shell-exec:src/other.cpp:12",
        path="src/other.cpp",
        line=12,
        rationale="Static pattern c-shell-exec matched system.",
    )

    result = evaluate_benchmark(
        run=run,
        mode="quick",
        findings=[unrelated_finding],
        scan_id="scan-1",
        scan_run_dir=repo / ".runs" / "scan-1",
        baseline_findings=baseline_findings,
    )
    write_benchmark_artifacts(run, manifest_path, result)

    payload = json.loads((run.root / "benchmark_result.json").read_text())
    calibration = json.loads((run.root / "calibration_records.json").read_text())
    deltas = json.loads((run.root / "external_baseline_deltas.json").read_text())
    assert payload["metrics"]["missed_findings_total"] == 1
    assert payload["metrics"]["false_positive_findings_total"] == 1
    assert payload["false_positives"][0]["finding_id"] == "c-shell-exec:src/other.cpp:12"
    assert calibration == [
        {
            "cwe": "CWE-120",
            "evidence": "memcpy copies attacker-controlled input",
            "failed_stage": "benchmark_ground_truth_matching",
            "next_improvement_candidate": "rule:c-unsafe-memory-copy",
            "path": "src/vuln.cpp",
            "reason": "no OpenUltraSAST finding matched the expected benchmark vulnerability",
            "rule_id": "c-unsafe-memory-copy",
            "vulnerability_class": "unsafe memory copy",
        }
    ]
    assert deltas == [{"extra_findings_total": 1, "matched_expected_total": 1, "missed_expected_total": 0, "tool": "clearwing"}]


def test_benchmark_attributes_per_rule_signals_and_recommendations(tmp_path: Path) -> None:
    manifest_path = tmp_path / "benchmark.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest_path.write_text(
        """
name = "cpp-smoke"
language = "c_cpp"

[source]
path = "repo"

[[expected]]
cwe = "CWE-120"
class = "buffer overflow"
path = "src/vuln.cpp"
line = 9
rule_id = "c-unsafe-memory-copy"
sink = "memcpy"
evidence = "memcpy copies attacker-controlled input"

[[expected]]
cwe = "CWE-78"
class = "command injection"
path = "src/vuln.cpp"
line = 20
rule_id = "c-shell-exec"
sink = "system"
evidence = "system runs attacker input"
""".strip()
        + "\n"
    )
    manifest = load_benchmark_manifest(manifest_path)
    run = create_benchmark_run(repo, manifest)
    findings = [
        _finding(
            finding_id="c-unsafe-memory-copy:src/vuln.cpp:9",
            path="src/vuln.cpp",
            line=9,
            rationale="Static pattern c-unsafe-memory-copy matched memcpy with attacker-controlled input.",
        ),
        _finding(
            finding_id="js-eval:src/app.js:3",
            path="src/app.js",
            line=3,
            rationale="Static pattern js-eval matched eval.",
        ),
    ]

    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id="scan-1", scan_run_dir=repo / ".runs" / "scan-1")
    write_benchmark_artifacts(run, manifest_path, result)

    per_rule = result.metrics.per_rule
    assert per_rule["c-unsafe-memory-copy"] == {"matched": 1, "missed": 0, "false_positives": 0}
    assert per_rule["c-shell-exec"]["missed"] == 1
    assert per_rule["js-eval"]["false_positives"] == 1

    actions = {rec.rule_id: rec.action for rec in result.rule_recommendations}
    assert actions["c-unsafe-memory-copy"] == "keep"
    assert actions["c-shell-exec"] == "loosen"
    assert actions["js-eval"] == "shadow"

    delta = json.loads((run.root / "rule_policy_delta.json").read_text())
    assert {item["rule_id"] for item in delta} == {"c-unsafe-memory-copy", "c-shell-exec", "js-eval"}


def _finding(
    *,
    finding_id: str,
    path: str,
    line: int,
    rationale: str,
    function_name: str | None = None,
) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path=path,
        title="Test finding",
        severity="high",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale=rationale,
        line=line,
        function_name=function_name,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[],
        ranking_priority=1.0,
    )
