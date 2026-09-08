"""Absence rows travel with the statements that register them (learning-harness 4.1, Req 10.2).

An access-control bug is the absence of a guard, so the excerpt has to carry the code that says the
handler is reachable at all: its decorators, the class its framework registers, and — when the
registration lives in another document — that document. Without it the entry-point mapper names no
handler, every obligation on the row is unreachable, and the pair scores as ``missing_context``
forever rather than as a detector miss.
"""

from __future__ import annotations

import runpy
import shutil
import tempfile
import tomllib
from pathlib import Path

import pytest

from openultrasast.mapping import analyze_entry_points
from openultrasast.model.taxonomy import load_families
from openultrasast.pairs import DEFAULT_CATALOG, load_pair_catalog, select_vendored
from openultrasast.preprocess import preprocess_repository
from openultrasast.semantic.extra import has_semantic_extra

LIB = Path("benchmarks/pairs/harvest.py")
FAMILIES = Path("src/openultrasast/ruleset/families.toml")


def _lib() -> dict[str, object]:
    return runpy.run_path(str(LIB), run_name="pair_harvest_lib")


# --- extraction --------------------------------------------------------------


RESTX_SOURCE = """from flask_restx import Resource

@ns.route('/profile')
class UserProfile(Resource):
    @ns.expect(profile_query)
    #@token_required
    def get(self):
        return dict(User.by_id(request.args['user_id'])), 200

@ns.route('/settings')
class Settings(Resource):
    @token_required
    def get(self, current_user):
        return dict(current_user.settings), 200
"""


def test_handler_context_carries_the_class_its_framework_registers() -> None:
    """A flask-restx handler is a method: the route decorator sits on the class, not the function."""
    lib = _lib()
    excerpt = lib["extract_handler_context"](RESTX_SOURCE, "get", "python", line=7)
    assert "@ns.route('/profile')" in excerpt
    assert "class UserProfile(Resource):" in excerpt
    assert "def get(self):" in excerpt
    assert "class Settings" not in excerpt and "current_user.settings" not in excerpt
    compile(excerpt, "<excerpt>", "exec")  # a class fragment must still be importable Python


def test_handler_context_anchors_on_the_line_when_the_method_name_repeats() -> None:
    """Two `def get` in one file: the name alone cannot say which handler the row labels."""
    lib = _lib()
    second = lib["extract_handler_context"](RESTX_SOURCE, "get", "python", line=13)
    assert "class Settings(Resource):" in second and "@token_required" in second
    assert "UserProfile" not in second


def test_registration_context_returns_the_openapi_operation_stanza() -> None:
    """connexion registers by operationId in a separate document; that stanza is the registration."""
    lib = _lib()
    spec = (
        "paths:\n"
        "  /users/v1/{username}/password:\n"
        "    put:\n"
        "      security:\n"
        "        - bearerAuth: [ ]\n"
        "      operationId: api_views.users.update_password\n"
        "  /books/v1/{book_title}:\n"
        "    get:\n"
        "      security:\n"
        "        - bearerAuth: [ ]\n"
        "      summary: Only the owner may retrieve it\n"
        "      operationId: api_views.books.get_by_title\n"
    )
    stanza = lib["extract_registration_context"](spec, "get_by_title", "yaml")
    assert "/books/v1/{book_title}:" in stanza
    assert "operationId: api_views.books.get_by_title" in stanza
    assert "security:" in stanza and "Only the owner may retrieve it" in stanza, "the guard the route declares is the point"
    assert "update_password" not in stanza and "/users/v1" not in stanza


def test_registration_context_returns_a_whole_multiline_router_call() -> None:
    """An express router registers over several lines; the middleware between them is the guard."""
    lib = _lib()
    router = (
        "webRouter.post(\n"
        "  '/project/:project_id/rename',\n"
        "  AuthorizationMiddleware.ensureUserCanAdminProject,\n"
        "  ProjectController.renameProject\n"
        ")\n"
        "webRouter.post(\n"
        "  '/project/:project_id/export/:brand_variation_id',\n"
        "  AuthorizationMiddleware.ensureUserCanWriteProjectContent,\n"
        "  ExportsController.exportProject\n"
        ")\n"
        "// exportProject is named in a comment too\n"
    )
    call = lib["extract_registration_context"](router, "exportProject", "javascript")
    assert "ExportsController.exportProject" in call
    assert "ensureUserCanWriteProjectContent" in call
    assert "renameProject" not in call and "named in a comment" not in call


def test_registration_context_is_empty_when_the_document_never_names_the_handler() -> None:
    lib = _lib()
    assert lib["extract_registration_context"]("paths:\n  /x:\n    get: {}\n", "get_by_title", "yaml") == ""


# --- harvest -----------------------------------------------------------------


CONTEXT_RECIPE = {
    "name": "vampi-books-get-by-title",
    "repo": "erev0s/VAmPI",
    "parent": "p" * 40,
    "commit": "p" * 40,
    "path": "api_views/books.py",
    "relpath": "api_views/books.py",
    "mode": "handler_context",
    "function": "get_by_title",
    "language": "python",
    "license": "MIT",
    "context": ["openapi_specs/openapi3.yml"],
}

HANDLER_SOURCE = "def get_by_title(book_title):\n    return Book.query.filter_by(book_title=book_title).first()\n"
SPEC_SOURCE = (
    "paths:\n"
    "  /books/v1/{book_title}:\n"
    "    get:\n"
    "      security:\n"
    "        - bearerAuth: [ ]\n"
    "      operationId: api_views.books.get_by_title\n"
)


def _patch_fetch(lib: dict[str, object], bodies: dict[str, str], fail: frozenset[str] = frozenset()) -> None:
    """`runpy.run_path` hands back a copy of the globals, so the module's own name has to be rebound."""

    def fetch(url: str, timeout: int = 60) -> str:
        for fragment in fail:
            if fragment in url:
                raise OSError(f"fetch failed: {url}")
        for fragment, body in bodies.items():
            if fragment in url:
                return body
        raise AssertionError(f"unexpected url {url}")

    lib["harvest_recipe"].__globals__["fetch_url"] = fetch  # type: ignore[attr-defined]


def test_context_documents_are_harvested_for_both_sides(tmp_path: Path) -> None:
    lib = _lib()
    _patch_fetch(lib, {"books.py": HANDLER_SOURCE, "openapi3.yml": SPEC_SOURCE})
    lib["harvest_recipe"](CONTEXT_RECIPE, tmp_path)
    for side in ("vuln", "fixed"):
        doc = tmp_path / "vampi-books-get-by-title" / "context" / side / "openapi_specs" / "openapi3.yml"
        assert doc.is_file(), f"{side} context document missing"
        text = doc.read_text()
        assert "# license: MIT" in text, "context documents carry the licence line too"
        assert "operationId: api_views.books.get_by_title" in text
    assert lib["context_paths"](CONTEXT_RECIPE, tmp_path) == (
        (
            "openapi_specs/openapi3.yml",
            tmp_path / "vampi-books-get-by-title" / "context" / "vuln" / "openapi_specs" / "openapi3.yml",
            tmp_path / "vampi-books-get-by-title" / "context" / "fixed" / "openapi_specs" / "openapi3.yml",
        ),
    )


def test_context_documents_are_redacted_like_every_other_excerpt(tmp_path: Path) -> None:
    lib = _lib()
    secret = "ghp_" + "A" * 30
    _patch_fetch(
        lib,
        {"books.py": HANDLER_SOURCE, "openapi3.yml": SPEC_SOURCE + f"      description: token {secret}\n      x: get_by_title\n"},
    )
    lib["harvest_recipe"](CONTEXT_RECIPE, tmp_path)
    text = (tmp_path / "vampi-books-get-by-title" / "context" / "vuln" / "openapi_specs" / "openapi3.yml").read_text()
    assert secret not in text and "***REDACTED***" in text


def test_a_failed_fetch_keeps_the_old_excerpt_and_records_the_reason(tmp_path: Path) -> None:
    """A re-harvest that cannot reach the network must not truncate a reviewed excerpt."""
    lib = _lib()
    folder = tmp_path / "vampi-books-get-by-title"
    folder.mkdir(parents=True)
    (folder / "vuln.py").write_text("# reviewed excerpt\n")
    (folder / "fixed.py").write_text("# reviewed excerpt\n")
    _patch_fetch(lib, {"books.py": HANDLER_SOURCE}, fail=frozenset({"openapi3.yml"}))
    with pytest.raises(OSError):
        lib["harvest_recipe"](CONTEXT_RECIPE, tmp_path)
    assert (folder / "vuln.py").read_text() == "# reviewed excerpt\n", "a failed fetch rewrote a reviewed excerpt"


def test_the_driver_records_every_failed_fetch_with_its_reason(tmp_path: Path) -> None:
    lib = _lib()
    recipes = tmp_path / "recipes.toml"
    recipes.write_text(
        "[[recipe]]\n"
        'name = "vampi-books-get-by-title"\n'
        'repo = "erev0s/VAmPI"\n'
        f'parent = "{"p" * 40}"\n'
        f'commit = "{"p" * 40}"\n'
        'path = "api_views/books.py"\n'
        'relpath = "api_views/books.py"\n'
        'mode = "handler_context"\n'
        'function = "get_by_title"\n'
        'language = "python"\n'
        'license = "MIT"\n'
        'context = ["openapi_specs/openapi3.yml"]\n'
    )
    _patch_fetch(lib, {"books.py": HANDLER_SOURCE}, fail=frozenset({"openapi3.yml"}))
    report = tmp_path / "report.json"
    code = lib["main"](["--recipes", str(recipes), "--out", str(tmp_path), "--all", "--fetch", "--force", "--report", str(report)])
    assert code == 1
    import json

    rows = json.loads(report.read_text())
    assert [row["name"] for row in rows] == ["vampi-books-get-by-title"]
    assert rows[0]["status"] == "failed" and "openapi3.yml" in rows[0]["reason"]


# --- the entry-point mapper --------------------------------------------------


def _entry_point_names(root: Path) -> set[str]:
    _, targets = preprocess_repository(root)
    return {record.function_name for record in analyze_entry_points(root, targets) if record.function_name}


def test_an_openapi_operation_id_names_its_python_handler(tmp_path: Path) -> None:
    """Req 10.2: a handler registered from a spec document is an entry point, not an orphan function."""
    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "books.py").write_text(HANDLER_SOURCE)
    (tmp_path / "openapi_specs").mkdir()
    (tmp_path / "openapi_specs" / "openapi3.yml").write_text(SPEC_SOURCE)
    _, targets = preprocess_repository(tmp_path)
    records = analyze_entry_points(tmp_path, targets)
    named = [record for record in records if record.function_name == "get_by_title"]
    assert named, "the operationId did not name its handler"
    assert named[0].path == "api_views/books.py", "the record belongs to the handler file, not the spec"
    assert named[0].access_level == "authenticated"
    assert any("bearerAuth" in item or "security" in item for item in named[0].access_evidence)


def test_an_openapi_operation_without_security_is_public(tmp_path: Path) -> None:
    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "books.py").write_text(HANDLER_SOURCE)
    (tmp_path / "spec.yml").write_text("paths:\n  /books:\n    get:\n      operationId: api_views.books.get_by_title\n")
    assert "get_by_title" in _entry_point_names(tmp_path)
    _, targets = preprocess_repository(tmp_path)
    record = next(item for item in analyze_entry_points(tmp_path, targets) if item.function_name == "get_by_title")
    assert record.access_level == "public"


def test_a_document_without_operation_ids_adds_no_entry_point(tmp_path: Path) -> None:
    (tmp_path / "api_views").mkdir()
    (tmp_path / "api_views" / "books.py").write_text(HANDLER_SOURCE)
    (tmp_path / "compose.yml").write_text("services:\n  web:\n    image: python\n")
    assert _entry_point_names(tmp_path) == set()


def test_es_and_commonjs_modules_are_javascript(tmp_path: Path) -> None:
    """`.mjs` was not a known suffix, so the one pair vendored as an ES module had no file target at all: no entry
    point, no finding, and a pair that could only ever score as a miss."""
    (tmp_path / "controller.mjs").write_text("export function handler(req, res) {}\n")
    (tmp_path / "legacy.cjs").write_text("module.exports = function handler(req, res) {}\n")
    _, targets = preprocess_repository(tmp_path)
    assert {target.path: target.language for target in targets} == {"controller.mjs": "javascript", "legacy.cjs": "javascript"}


def test_the_overleaf_pair_is_scannable_at_all() -> None:
    case = next(
        item for item in select_vendored(load_pair_catalog(DEFAULT_CATALOG)) if item.name == "overleaf-with-claude-exportscontroller-3980b9"
    )
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        target = root / case.relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(case.vuln_file, target)
        _, targets = preprocess_repository(root)
    assert [item.language for item in targets] == ["javascript"]


def test_a_multiline_router_call_names_its_handler(tmp_path: Path) -> None:
    (tmp_path / "Exports").mkdir()
    (tmp_path / "Exports" / "ExportsController.mjs").write_text(
        "async function exportProject(req, res, next) {\n  return res.send(req.params.project_id)\n}\nexport default { exportProject }\n"
    )
    (tmp_path / "router.mjs").write_text(
        "webRouter.post(\n"
        "  '/project/:project_id/export/:brand_variation_id',\n"
        "  AuthorizationMiddleware.ensureUserCanWriteProjectContent,\n"
        "  ExportsController.exportProject\n"
        ")\n"
    )
    _, targets = preprocess_repository(tmp_path)
    records = [item for item in analyze_entry_points(tmp_path, targets) if item.function_name == "exportProject"]
    assert records, "the multi-line registration named no handler"
    assert any(record.access_level == "authenticated" for record in records)


# --- the corpus --------------------------------------------------------------


def _absence_rows() -> tuple[object, ...]:
    taxonomy = load_families(FAMILIES)
    rows = []
    for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG)):
        for expected in case.expected:
            declared = getattr(expected, "family", None)
            family = declared or (
                (taxonomy.family_of_cwe(expected.cwe or "") or taxonomy.family_of_mechanism(expected.mechanism or "")) or None
            )
            resolved = family if isinstance(family, str) else getattr(family, "id", "")
            if resolved:
                if resolved == "access_control":
                    rows.append(case)
                break
    return tuple(rows)


def test_every_absence_row_declares_its_family() -> None:
    """Req 1: the family is the key that routes the work; an absence row must not depend on a CWE lookup."""
    rows = _absence_rows()
    assert len(rows) >= 10
    undeclared = [case.name for case in rows if not any(getattr(row, "family", None) for row in case.expected)]
    assert undeclared == [], f"absence rows with no declared family: {undeclared}"


def test_absence_recipes_use_the_handler_context_mode() -> None:
    names = {case.name for case in _absence_rows()}
    seen = set()
    for slice_name in ("vibe-py", "agent-vfc"):
        for recipe in tomllib.loads((Path("benchmarks/pairs") / slice_name / "recipes.toml").read_text())["recipe"]:
            if str(recipe["name"]) in names:
                seen.add(str(recipe["name"]))
                assert recipe.get("mode") == "handler_context", f"{recipe['name']} is not harvested with its handler context"
                assert recipe.get("family") == "access_control", f"{recipe['name']} carries no family"
    assert seen == names, f"absence rows with no recipe: {sorted(names - seen)}"


@pytest.mark.parametrize(
    ("name", "registration"),
    [
        ("vampi-books-get-by-title", "operationId: api_views.books.get_by_title"),
        ("vampi-users-update-password", "operationId: api_views.users.update_password"),
        ("threatbyte-api-v1-get", "@ns.route('/profile')"),
        ("threatbyte-api-v1-delete", "@ns.route('/delete-user/<int:user_id>')"),
        ("openniw-jobs-0fc947", '@router.get("/{job_id}")'),
        ("overleaf-with-claude-exportscontroller-3980b9", "ExportsController.exportProject"),
    ],
)
def test_the_named_absence_rows_carry_their_registration(name: str, registration: str) -> None:
    """The observable of task 4.1: these excerpts used to arrive without the line that makes them reachable."""
    case = next(item for item in select_vendored(load_pair_catalog(DEFAULT_CATALOG)) if item.name == name)
    texts = [case.vuln_file.read_text(), case.fixed_file.read_text()]
    texts += [vuln.read_text() for _, vuln, _ in case.context_files]
    assert any(registration in text for text in texts), f"{name} lost its registration"
    assert all("license:" in text for text in [case.vuln_file.read_text(), case.fixed_file.read_text()])


def test_every_absence_row_has_a_named_handler_or_a_stated_reason() -> None:
    """Either the mapper names the labeled handler, or the row says out loud why it cannot be scored."""
    orphans = []
    for case in _absence_rows():
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "vuln"
            root.mkdir()
            target = root / case.relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(case.vuln_file, target)
            for relpath, vuln, _fixed in case.context_files:
                context = root / relpath
                context.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(vuln, context)
            named = _entry_point_names(root)
        labeled = {row.function for row in case.expected if row.function}
        if not (labeled & named) and not case.unscorable:
            orphans.append(f"{case.name} labeled={sorted(labeled)} named={sorted(named)}")
    assert orphans == [], "absence rows with neither a named handler nor a stated reason:\n" + "\n".join(orphans)


def test_the_vendored_count_is_unchanged_by_the_re_harvest() -> None:
    """A re-harvest repairs excerpts; it must not quietly add or drop rows."""
    cases = select_vendored(load_pair_catalog(DEFAULT_CATALOG))
    per_slice: dict[str, int] = {}
    for case in cases:
        per_slice[case.slice] = per_slice.get(case.slice, 0) + 1
    assert per_slice == {"agent-vfc": 29, "github": 6, "local": 3, "owasp": 40, "sast": 11, "vfc": 176, "vfc-js": 17, "vibe-py": 35}


def test_prose_inside_a_decorator_never_grants_a_guard(tmp_path: Path) -> None:
    """`@ns.doc(description='... without proper authorization checks')` describes the *bug*.

    Matching auth words anywhere in a decorator, string literals included, reads an unguarded endpoint as guarded and
    silences every obligation on it — the exact absence this corpus exists to catch."""
    (tmp_path / "api.py").write_text(
        "@ns.route('/delete-user/<int:user_id>')\n"
        "@ns.doc(description='Delete a user without proper authorization checks. Broken Function Level Authorization.')\n"
        "class UserDelete(Resource):\n"
        "    def delete(self, user_id):\n"
        "        return db.delete(user_id)\n\n"
        "@ns.route('/settings')\n"
        "class Settings(Resource):\n"
        "    @token_required\n"
        "    def get(self, current_user):\n"
        "        return current_user.settings\n"
    )
    _, targets = preprocess_repository(tmp_path)
    access = {record.function_name: record.access_level for record in analyze_entry_points(tmp_path, targets) if record.function_name}
    assert access == {"delete": "public", "get": "authenticated"}


def test_a_javascript_excerpt_never_starts_in_the_middle_of_an_import() -> None:
    """`_declarator_start` walks back to the previous `;` or `}`. In JavaScript written without semicolons the
    nearest `}` is the one in `import { expressify } from ...`, so the excerpt began mid-statement and the file
    did not parse at all — a pair that cannot be parsed cannot be scored."""
    lib = _lib()
    source = (
        "import { expressify } from '@overleaf/promise-utils'\n"
        "import SessionManager from '../Authentication/SessionManager.mjs'\n\n"
        "async function exportProject(req, res, next) {\n"
        "  return res.send(req.params.project_id)\n"
        "}\n"
    )
    excerpt = lib["extract_function"](source, "exportProject", "javascript")
    assert excerpt.startswith("async function exportProject("), excerpt.splitlines()[0]
    assert "from '@overleaf" not in excerpt


@pytest.mark.semantic
@pytest.mark.skipif(not has_semantic_extra(), reason="parsing JavaScript needs the tree-sitter grammar")
def test_the_overleaf_excerpt_parses_on_both_sides() -> None:
    from openultrasast.semantic.ir import parse_file

    case = next(
        item for item in select_vendored(load_pair_catalog(DEFAULT_CATALOG)) if item.name == "overleaf-with-claude-exportscontroller-3980b9"
    )
    for path in (case.vuln_file, case.fixed_file):
        ir = parse_file(case.relpath, path.read_text(), "javascript")
        assert ir.parse_ok, f"{path.name}: {ir.reason}"
        assert any(function.name == "exportProject" for function in ir.functions)
