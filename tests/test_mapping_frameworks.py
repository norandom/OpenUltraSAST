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
