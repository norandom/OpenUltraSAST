"""Java framework entries are tied to their declaring class and public method."""

import pytest

from openultrasast.mapping import analyze_entry_points
from openultrasast.preprocess import build_file_target


def entries(tmp_path, text):
    path = tmp_path / "Fixture.java"
    path.write_text(text)
    return [e for e in analyze_entry_points(tmp_path, [build_file_target(tmp_path, path)]) if e.function_name]


def test_stapler_class_scope_visibility_and_ranges(tmp_path):
    rows = entries(
        tmp_path,
        """class Exposed extends Descriptor<Thing> {
 public String doTestConnection() {
  return lookupCredentials();
 }
 private void doHidden() {}
 public void ordinary() {}
}
class Plain {
 public void doUnexposed() {}
 public void doCheck(@QueryParameter String value) {}
}
""",
    )
    assert [(e.function_name, e.line, e.end_line) for e in rows] == [("doTestConnection", 2, 4), ("doCheck", 10, 10)]
    assert all(e.access_level == "unknown" and e.trust_boundary == "http_request" and e.access_evidence for e in rows)


@pytest.mark.parametrize("base", ["Action", "RootAction", "Plugin", "AbstractDescribableImpl<Thing>", "Descriptor<Thing>"])
def test_exposed_types(tmp_path, base):
    assert len(entries(tmp_path, f"class X extends {base} {{ public void doCheckX() {{}} }}")) == 1


def test_unprotected_root_and_stapler_parameters(tmp_path):
    rows = entries(
        tmp_path,
        """class Open implements UnprotectedRootAction {
 public void doTest() {}
}
class Plain {
 public void doCheck(StaplerRequest2 request, StaplerResponse response) {}
 public void doLowercase() {}
}""",
    )
    assert [e.access_level for e in rows] == ["public", "unknown"]
    assert rows[0].access_declared


@pytest.mark.parametrize(
    "text,name",
    [
        ("class X extends AbstractHandler { public void handle(String target) {} }", "handle"),
        ("class X extends HttpServlet { protected void doGet(Request r) {} }", "doGet"),
        ('@Path("/api") class X { @GET public String read() { return "ok"; } }', "read"),
    ],
)
def test_jetty_servlet_and_jaxrs(tmp_path, text, name):
    (row,) = entries(tmp_path, text)
    assert row.function_name == name and row.kind == "route" and row.access_evidence


def test_unrecognised_and_comments(tmp_path):
    assert entries(tmp_path, "/* class X extends Descriptor { public void doFake() {} } */\nclass Plain { public void doCheck() {} }") == []


def framework_entries(tmp_path, files):
    targets = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        targets.append(build_file_target(tmp_path, path))
    return [
        e for e in analyze_entry_points(tmp_path, targets, texts=files, include_manifests=False) if e.kind == "route" and e.function_name
    ]


@pytest.mark.parametrize("annotation", ['#[Route("/items")]', '/** @Route("/items") */'])
def test_symfony_actions(tmp_path, annotation):
    rows = framework_entries(
        tmp_path,
        {
            "Controller.php": f"""<?php
class Items extends AbstractController {{
 {annotation}
 public function show() {{ return 1; }}
 private function hidden() {{}}
}}
class Plain {{ public function helper() {{}} }}
"""
        },
    )
    assert [e.function_name for e in rows] == ["show"]
    assert "Symfony" in " ".join(rows[0].access_evidence)
    assert "/items" in " ".join(rows[0].access_evidence)


def test_livewire_public_methods_and_bindings(tmp_path):
    rows = framework_entries(
        tmp_path,
        {
            "Component.php": """<?php
use Livewire\\Component;
class Editor extends Component {
 public function store() {}
 public function _helper() {}
 protected function hidden() {}
}
class Other { public function store() {} }
""",
            "view.blade.php": '<button wire:click="store">Save</button>',
        },
    )
    assert [(e.path, e.function_name) for e in rows] == [("Component.php", "store")]
    assert "Livewire" in " ".join(rows[0].access_evidence)


@pytest.mark.parametrize("middleware,access", [("", "public"), ("->middleware(['auth', 'can:edit'])", "unknown")])
def test_laravel_cross_file_registration(tmp_path, middleware, access):
    rows = framework_entries(
        tmp_path,
        {
            "app/Http/Controllers/Editor.php": """<?php
class Editor extends Controller {
 public function store() {}
 public function helper() {}
}
class Other extends Controller { public function store() {} }
""",
            "routes/web.php": f"<?php Route::post('/items', [Editor::class, 'store']){middleware};",
        },
    )
    assert [(e.function_name, e.access_level) for e in rows] == [("store", access)]
    assert rows[0].path == "app/Http/Controllers/Editor.php"
    assert "Laravel" in " ".join(rows[0].access_evidence)


def test_symfony_route_config(tmp_path):
    rows = framework_entries(
        tmp_path,
        {
            "Controller.php": "<?php class Editor extends AbstractController { public function show() {} public function helper() {} }",
            "config/routes.yaml": "items:\n  path: /items\n  controller: App\\Controller\\Editor::show\n",
        },
    )
    assert [e.function_name for e in rows] == ["show"]


@pytest.mark.parametrize(
    "declaration",
    [
        "export async function action() { return 1; }",
        "export const action = async () => { return 1; }",
        "export const action: ActionFunction = async () => { return 1; }",
    ],
)
def test_remix_exports(tmp_path, declaration):
    rows = framework_entries(tmp_path, {"apps/web/app/routes/items.ts": declaration + "\nexport function loader() { return 1; }"})
    assert [e.function_name for e in rows] == ["action", "loader"]
    assert all("Remix" in " ".join(e.access_evidence) and e.access_level == "unknown" for e in rows)
    assert framework_entries(tmp_path, {"app/helpers/items.ts": declaration}) == []


@pytest.mark.parametrize("base", ["tornado.web.RequestHandler", "tornado.websocket.WebSocketHandler", "RequestHandler"])
def test_tornado_methods(tmp_path, base):
    rows = framework_entries(
        tmp_path,
        {
            "app.py": f"""from tornado.web import RequestHandler
class Handler({base}):
    def get(self):
        return 1
    def open(self):
        pass
    def helper(self):
        pass
class Plain:
    def get(self):
        pass
"""
        },
    )
    assert [e.function_name for e in rows] == ["get", "open"]
    assert all("Tornado" in " ".join(e.access_evidence) for e in rows)


@pytest.mark.parametrize("prefix", ["", "\n" * 320])
def test_symfony_named_paths_and_class_prefix(tmp_path, prefix):
    rows = framework_entries(
        tmp_path,
        {
            "Controller.php": prefix
            + """<?php
/** @Route(path="/admin") */
class Editor extends AbstractController {
 /** @Route(path="/items") */
 public function show() {}
}
"""
        },
    )
    assert [row.name for row in rows] == ["/admin/items"]
    assert rows[0].line == 5 + prefix.count("\n")


def test_tornado_inherited_and_explicit_super_handler(tmp_path):
    rows = framework_entries(
        tmp_path,
        {
            "app.py": """import tornado.websocket
import terminado
class Base(tornado.websocket.WebSocketHandler):
    pass
class Child(Base):
    def open(self):
        pass
class Terminal(terminado.TermSocket):
    def open(self):
        tornado.websocket.WebSocketHandler.open(self)
"""
        },
    )
    assert [row.function_name for row in rows] == ["open", "open"]


def test_remix_tsx_with_jsx(tmp_path):
    rows = framework_entries(
        tmp_path,
        {
            "app/routes/items.tsx": """export const action = async () => { return 1; };
export default function Items() { return <div>Items</div>; }
"""
        },
    )
    assert [row.function_name for row in rows] == ["action"]


def test_java_parameters_are_names_without_annotations():
    from openultrasast.semantic.ir import parse_file

    text = """class Exposed extends Descriptor<Thing> {
 public Object doCheckUrl(@QueryParameter("url") final String value, @AncestorInPath Item item, StaplerRequest2 req, String... rest) {
  return FormValidation.ok();
 }
}
"""
    ir = parse_file("Fixture.java", text, "java")
    if not ir.parse_ok:
        pytest.skip("no Java grammar installed")
    assert [fn.params for fn in ir.functions if fn.name == "doCheckUrl"] == [("value", "item", "req", "rest")]
