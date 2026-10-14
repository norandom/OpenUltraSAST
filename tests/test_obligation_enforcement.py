"""Framework enforcement is scoped to the registered handler, never a nearby method."""

import pytest

from openultrasast.mapping import analyze_entry_points
from openultrasast.preprocess import build_file_target
from openultrasast.semantic.obligations.dominance import OrderDominance
from openultrasast.semantic.obligations.operations import Operation


def mapped(tmp_path, files):
    targets = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if path.suffix in {".php", ".py"}:
            targets.append(build_file_target(tmp_path, path))
    return [
        e for e in analyze_entry_points(tmp_path, targets, texts=files, include_manifests=False) if e.kind == "route" and e.function_name
    ]


@pytest.mark.parametrize("guard", ["auth", "can:edit", "role:admin", "permission:edit"])
def test_laravel_route_middleware(tmp_path, guard):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": "<?php class Editor extends Controller { public function store() {} public function other() {} }",
        "routes/web.php": f"<?php Route::post('/items', [Editor::class, 'store'])->middleware(['{guard}']);",
    }
    rows = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php")
    (witness,) = rows
    assert (witness.path, witness.function, witness.line, witness.scope) == ("Editor.php", "store", None, "router")
    assert "routes/web.php" in witness.detail
    assert OrderDominance(files).dominates(
        witness, Operation("Editor.php", 1, "store", "protected_write", "x", None, ("path_guard",)), None
    )


@pytest.mark.parametrize("guard", ["$this->middleware('auth');", "$this->authorizeResource(Item::class, 'item');"])
def test_laravel_constructor(tmp_path, guard):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": f"""<?php class Editor extends Controller {{
 public function __construct() {{ {guard} }}
 public function store() {{}}
}}
Route::post('/items', [Editor::class, 'store']);
"""
    }
    (witness,) = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php")
    assert witness.scope == "router" and witness.function == "store"
    assert OrderDominance(files).dominates(
        witness, Operation("Editor.php", 3, "store", "protected_write", "x", None, ("path_guard",)), None
    )


@pytest.mark.parametrize("guard", ['#[IsGranted("ROLE_ADMIN")]', "#[Security(\"is_granted('ROLE_ADMIN')\")]"])
def test_symfony_attributes(tmp_path, guard):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": f"""<?php class Editor extends AbstractController {{
 #[Route('/items')]
 {guard}
 public function store() {{}}
 #[Route('/other')]
 public function other() {{}}
}}"""
    }
    (witness,) = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php")
    assert witness.scope == "decorator" and witness.function == "store"
    assert OrderDominance(files).dominates(
        witness, Operation("Editor.php", 4, "store", "protected_write", "x", None, ("path_guard",)), None
    )


def test_symfony_security_yaml(tmp_path):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": "<?php class Editor extends AbstractController { #[Route('/admin')] public function store() {} }",
        "config/packages/security.yaml": "security:\n  access_control:\n    - { path: ^/admin, roles: ROLE_ADMIN }\n",
    }
    (witness,) = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php")
    assert witness.scope == "router" and "security.yaml" in witness.detail
    assert OrderDominance(files).dominates(
        witness, Operation("Editor.php", 1, "store", "protected_write", "x", None, ("path_guard",)), None
    )


@pytest.mark.parametrize("guard", ["authenticated", "tornado.web.authenticated"])
def test_tornado_decorator(tmp_path, guard):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "app.py": f"""import tornado.web
class Handler(tornado.web.RequestHandler):
    @{guard}
    def get(self):
        pass
    def post(self):
        pass
"""
    }
    (witness,) = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="python")
    assert witness.scope == "decorator" and witness.function == "get"
    assert OrderDominance(files).dominates(witness, Operation("app.py", 4, "get", "protected_read", "x", None, ("path_guard",)), None)


@pytest.mark.parametrize("restriction", ["->only(['store'])", "->except(['other'])"])
def test_constructor_restrictions_do_not_guard_other_handlers(tmp_path, restriction):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": f"""<?php class Editor extends Controller {{
 public function __construct() {{ $this->middleware('auth'){restriction}; }}
 public function store() {{}}
 public function other() {{}}
}}
Route::post('/items', [Editor::class, 'store']);
Route::get('/other', [Editor::class, 'other']);
"""
    }
    rows = witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php")
    assert [row.function for row in rows] == ["store"]


def test_symfony_first_public_rule_does_not_become_a_guard(tmp_path):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": "<?php class Editor extends AbstractController { #[Route('/admin')] public function store() {} }",
        "config/packages/security.yaml": (
            "security:\n  access_control:\n    - { path: ^/admin, roles: PUBLIC_ACCESS }\n    - { path: ^/admin, roles: ROLE_ADMIN }\n"
        ),
    }
    assert witnesses(root=tmp_path, texts=files, entries=mapped(tmp_path, files), language="php") == []


def test_unrelated_guards_and_comments_are_not_witnesses(tmp_path):
    from openultrasast.semantic.obligations.enforcement import witnesses

    files = {
        "Editor.php": """<?php class Editor extends Controller {
 public function store() {}
}
// Route::post('/items', [Editor::class, 'store'])->middleware('auth');
Route::post('/items', [Editor::class, 'store'])->middleware('throttle:10');
""",
        "app.py": "class Handler(RequestHandler):\n    @not_authenticated\n    def get(self):\n        pass\n",
    }
    entries = mapped(tmp_path, files)
    assert witnesses(root=tmp_path, texts=files, entries=entries, language="php") == []
    assert witnesses(root=tmp_path, texts=files, entries=entries, language="python") == []
