import json
from pathlib import Path

from openultrasast.mapping import (
    analyze_entry_points,
    attach_reachability_hints,
    attach_static_hints,
    codeql_mapping_tasks,
    differential_mapping_record,
    ingest_sarif,
    semgrep_mapping_tasks,
    sharp_edge_record,
    verifier_evidence_candidates,
    write_entry_points,
    write_static_hints,
)
from openultrasast.preprocess import preprocess_repository


def test_ingest_sarif_normalizes_semgrep_hints(tmp_path: Path) -> None:
    sarif = tmp_path / "semgrep.sarif"
    sarif.write_text(json.dumps(_sarif_payload("Semgrep", "python.lang.security.audit.eval", "app.py")))

    hints = ingest_sarif(sarif)

    assert len(hints) == 1
    assert hints[0].analyzer == "semgrep"
    assert hints[0].rule_id == "python.lang.security.audit.eval"
    assert hints[0].path == "app.py"
    assert hints[0].start_line == 7
    assert hints[0].severity == "high"
    assert hints[0].provenance == "sarif:semgrep:python.lang.security.audit.eval"


def test_static_hints_attach_to_file_targets_and_evidence_candidates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("eval(user_input)\n")
    hints = ingest_sarif(_write_sarif(tmp_path, "CodeQL", "py/code-injection", "app.py"))
    _, targets = preprocess_repository(repo, static_hints=hints)

    enriched = attach_static_hints(targets, hints)
    evidence = verifier_evidence_candidates(hints, path="app.py")

    assert enriched[0].static_hints[0]["analyzer"] == "codeql"
    assert evidence == [
        {
            "source": "codeql",
            "rule_id": "py/code-injection",
            "path": "app.py",
            "line": 7,
            "severity": "high",
            "message": "Potential injection",
            "provenance": "sarif:codeql:py/code-injection",
        }
    ]


def test_mapping_task_records_cover_disciplines(tmp_path: Path) -> None:
    semgrep_hints = ingest_sarif(_write_sarif(tmp_path, "Semgrep", "sg.rule", "parser.c"))
    codeql_hints = ingest_sarif(_write_sarif(tmp_path, "CodeQL", "cpp/overflow", "parser.c"))

    assert semgrep_mapping_tasks(semgrep_hints)[0].task == "pattern_variant_review"
    assert codeql_mapping_tasks(codeql_hints)[0].task == "source_sink_sanitizer_path_review"
    assert differential_mapping_record(
        "parser.c",
        change_kind="modified_function",
        trust_boundary="network_input",
        rationale="Parser changed behind a socket boundary.",
    ).trust_boundary == "network_input"
    assert sharp_edge_record(
        "config.py",
        category="insecure_default",
        surface="debug mode",
        rationale="Debug default changes production risk.",
    ).category == "insecure_default"


def test_write_static_hints_artifact(tmp_path: Path) -> None:
    hints = ingest_sarif(_write_sarif(tmp_path, "Semgrep", "sg.rule", "app.py"))
    output = tmp_path / "mapping" / "static_hints.json"

    write_static_hints(hints, output)

    assert json.loads(output.read_text())["static_hints"][0]["analyzer"] == "semgrep"


def test_entry_point_mapping_classifies_routes_and_attaches_reachability(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/upload')\ndef upload():\n    return parse(request.data)\n")
    _, targets = preprocess_repository(repo)

    entry_points = analyze_entry_points(repo, targets)
    enriched = attach_reachability_hints(targets, entry_points)

    assert entry_points[0].kind == "route"
    assert entry_points[0].access_level == "public"
    assert enriched[0].reachability_hints[0]["trust_boundary"] == "http_request"


def test_entry_point_mapping_distinguishes_authenticated_routes_and_conditions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/admin')\n"
        "@login_required\n"
        "def admin_upload():\n"
        "    if feature_flags.enabled('dangerous_upload'):\n"
        "        return eval(request.data)\n"
        "    return 'disabled'\n"
    )
    _, targets = preprocess_repository(repo)

    entry_points = analyze_entry_points(repo, targets)

    route = next(entry_point for entry_point in entry_points if entry_point.kind == "route")
    assert route.function_name == "admin_upload"
    assert route.line == 3
    assert route.end_line == 6
    assert route.access_level == "authenticated"
    assert route.access_evidence == ["login_required"]
    assert route.conditions == ["feature_flags.enabled('dangerous_upload')"]


def test_entry_point_mapping_covers_solidity_state_changing_access(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Vault.sol").write_text(
        "contract Vault {\n"
        "  function withdraw(uint256 amount) external onlyOwner { }\n"
        "  function balance() external view returns (uint256) { return 0; }\n"
        "}\n"
    )
    _, targets = preprocess_repository(repo)

    entry_points = analyze_entry_points(repo, targets)

    assert len(entry_points) == 1
    assert entry_points[0].name == "withdraw"
    assert entry_points[0].access_level == "role-restricted"


def test_entry_point_mapping_records_solidity_feature_conditions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Vault.sol").write_text(
        "contract Vault {\n"
        "  function withdraw(uint256 amount) external onlyOwner whenNotPaused { }\n"
        "}\n"
    )
    _, targets = preprocess_repository(repo)

    entry_points = analyze_entry_points(repo, targets)

    assert entry_points[0].access_level == "role-restricted"
    assert entry_points[0].access_evidence == ["onlyOwner"]
    assert entry_points[0].conditions == ["whenNotPaused"]


def test_write_entry_points_artifact(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "cli.py").write_text("if __name__ == '__main__':\n    main()\n")
    _, targets = preprocess_repository(repo)
    output = tmp_path / "mapping" / "entry_points.json"

    write_entry_points(analyze_entry_points(repo, targets), output)

    payload = json.loads(output.read_text())
    assert payload["entry_points"][0]["kind"] == "cli"


def _write_sarif(tmp_path: Path, analyzer: str, rule_id: str, result_path: str) -> Path:
    path = tmp_path / f"{analyzer.lower()}.sarif"
    path.write_text(json.dumps(_sarif_payload(analyzer, rule_id, result_path)))
    return path


def _sarif_payload(analyzer: str, rule_id: str, result_path: str) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": analyzer,
                        "rules": [
                            {
                                "id": rule_id,
                                "name": "Injection rule",
                                "properties": {"security-severity": "8.1"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": "Potential injection"},
                        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": result_path},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
