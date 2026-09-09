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
    assert (
        differential_mapping_record(
            "parser.c",
            change_kind="modified_function",
            trust_boundary="network_input",
            rationale="Parser changed behind a socket boundary.",
        ).trust_boundary
        == "network_input"
    )
    assert (
        sharp_edge_record(
            "config.py",
            category="insecure_default",
            surface="debug mode",
            rationale="Debug default changes production risk.",
        ).category
        == "insecure_default"
    )


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
    (repo / "Vault.sol").write_text("contract Vault {\n  function withdraw(uint256 amount) external onlyOwner whenNotPaused { }\n}\n")
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


def test_entry_points_name_handlers_registered_by_call_or_convention(tmp_path: Path) -> None:
    """authorization-obligations 2.6: a handler registered by a call or by convention is still a named route entry."""
    from openultrasast.mapping import analyze_entry_points
    from openultrasast.preprocess import preprocess_repository

    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "books.py").write_text(
        "from flask_restx import Resource\n\n\n"
        "def get_by_title(book_title):\n    return Book.query.filter_by(book_title=book_title).first()\n\n\n"
        "class UserProfile(Resource):\n"
        "    @login_required\n"
        "    def get(self):\n        return db.users.find_one({'id': request.args.get('user_id')})\n\n"
        "    def delete(self, user_id):\n        return db.users.delete_one({'id': user_id})\n\n\n"
        "app.add_url_rule('/books/<book_title>', view_func=get_by_title)\n"
        "api.add_resource(UserProfile, '/users/profile')\n"
    )
    (tmp_path / "routes.js").write_text(
        "function listBooks(req, res) { return res.json(Book.find({})); }\n"
        "function stats(req, res) { return res.json({}); }\n"
        "router.get('/books', requireAuth, listBooks);\n"
        "router.get('/stats', stats);\n"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "api").mkdir()
    (tmp_path / "app" / "api" / "route.ts").write_text(
        "export async function GET(request: NextRequest) {\n  return NextResponse.json(await db.from('opportunities').select());\n}\n"
        "export async function PATCH(request: NextRequest) {\n  return NextResponse.json(await db.from('claims').update({}));\n}\n"
        "function helper() { return 1; }\n"
    )
    _, targets = preprocess_repository(tmp_path)
    routes = {(e.path, e.function_name): e for e in analyze_entry_points(tmp_path, targets) if e.kind == "route" and e.function_name}
    named = {(path.replace("\\", "/"), function) for path, function in routes}
    assert ("api_views/books.py", "get_by_title") in named  # registered by add_url_rule, no decorator on the function
    assert ("api_views/books.py", "get") in named and ("api_views/books.py", "delete") in named  # Resource verb methods
    assert ("routes.js", "listBooks") in named and ("routes.js", "stats") in named
    assert ("app/api/route.ts", "GET") in named and ("app/api/route.ts", "PATCH") in named
    assert ("app/api/route.ts", "helper") not in named  # only the HTTP-verb exports are handlers
    assert routes[("routes.js", "listBooks")].access_level == "authenticated"  # requireAuth middleware on the registration
    assert any("requireAuth" in item for item in routes[("routes.js", "listBooks")].access_evidence)
    assert routes[("routes.js", "stats")].access_level == "public"
    assert routes[("api_views/books.py", "get")].access_level == "authenticated"  # @login_required on the verb method
    assert routes[("api_views/books.py", "delete")].access_level == "public"
    body = routes[("api_views/books.py", "get_by_title")]
    assert body.line == 4 and body.end_line == 5  # the record spans the handler, not the registration line


def test_wordpress_hooks_declare_their_access(tmp_path: Path) -> None:
    """contributor-scan 5.4. WordPress registers handlers rather than decorating them, and the hook name is
    the declaration: `wp_ajax_nopriv_*` is WordPress saying logged-out callers reach this."""
    from openultrasast.mapping import analyze_entry_points
    from openultrasast.preprocess import preprocess_repository

    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_fetch', 'mp_fetch');\n"
        "add_action('wp_ajax_save', 'mp_save');\n"
        "add_shortcode('box', 'mp_box');\n"
        "function mp_fetch() { echo $_GET['id']; }\n"
        "function mp_save() { echo $_POST['t']; }\n"
        "function mp_box($a) { echo $a; }\n"
        "function mp_helper($x) { return intval($x); }\n"
    )
    _, targets = preprocess_repository(tmp_path)

    by_name = {entry.function_name: entry for entry in analyze_entry_points(tmp_path, targets)}

    assert by_name["mp_fetch"].access_level == "public", "nopriv is declared unauthenticated"
    assert by_name["mp_save"].access_level == "authenticated", "wp_ajax_ fires only for logged-in callers"
    assert by_name["mp_box"].access_level == "public", "a shortcode renders in page content"
    assert by_name["mp_helper"].access_level == "review-required", "a plain function is not a declared endpoint"


def test_every_php_function_becomes_a_region(tmp_path: Path) -> None:
    """Without this a PHP file is ONE region however many functions it holds, and a region that spans a file
    attributes every finding to the file rather than to the function that holds it."""
    from openultrasast.mapping import analyze_entry_points
    from openultrasast.model.regions import regions_for
    from openultrasast.preprocess import preprocess_repository

    (tmp_path / "lib.php").write_text("<?php\nfunction a() { echo 1; }\nfunction b() { echo 2; }\n")
    _, targets = preprocess_repository(tmp_path)

    regions = regions_for(analyze_entry_points(tmp_path, targets), targets)

    assert {region.function for region in regions} >= {"a", "b"}
