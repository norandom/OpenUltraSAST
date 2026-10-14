"""Repository facts use the same names, ranges and calls in every consumer."""

import pytest

from openultrasast import source
from openultrasast.semantic import cst
from openultrasast.semantic.extra import grammar_for

SAMPLES = [
    ("python", "app.py", "def run(x):\n    return x\n", (1, 2)),
    ("javascript", "app.js", "function run(x) {\n  return x;\n}\n", (1, 3)),
    ("java", "App.java", "class App {\n  public int run(int x) {\n    return x;\n  }\n}\n", (2, 4)),
    ("go", "app.go", "package app\nfunc (r *Repo) run(x int) int {\n  return x\n}\n", (2, 4)),
    ("ruby", "app.rb", "class App\n  def run(x)\n    x\n  end\nend\n", (2, 4)),
    ("php", "app.php", "<?php\nfunction run($x) {\n  return $x;\n}\n", (2, 4)),
]


@pytest.mark.parametrize(("language", "path", "text", "expected"), SAMPLES)
@pytest.mark.parametrize("with_grammar", [False, True])
def test_ranges_with_and_without_grammars(monkeypatch, language, path, text, expected, with_grammar):
    if not with_grammar:
        monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "off")
    else:
        monkeypatch.delenv("OPENULTRASAST_TREE_SITTER_PROBE", raising=False)
    items = source.ranges(path, text, language)
    assert source.bounds(items, "run") == expected
    assert source.enclosing(items, expected[0]) == "run"
    assert source.enclosing(items, expected[1]) == "run"
    if with_grammar and grammar_for(language) is not None:
        assert cst.parse_with_cst(path, text, language).engine == "tree-sitter"


def test_nested_ranges_and_module_bounds():
    text = "def outer():\n    def inner():\n        pass\n    inner()\nouter()\n"
    items = source.ranges("app.py", text, "python")
    assert source.enclosing(items, 3) == "inner"
    assert source.enclosing(items, 4) == "outer"
    assert source.enclosing(items, 5) == source.MODULE_FUNCTION
    assert source.enclosing(items, None) == source.MODULE_FUNCTION
    assert source.bounds(items, "outer") == (1, 4)
    assert source.bounds(items, source.MODULE_FUNCTION) == (1, 5)
    assert source.bounds(items, "missing") is None


def test_fallback_does_not_include_siblings_or_strings(monkeypatch):
    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "off")
    items = source.ranges("app.js", 'function first() {\n  const s = "}"; // }\n}\nfunction last() {}\nfirst();', "javascript")
    assert source.bounds(items, "first") == (1, 3)
    assert source.bounds(items, "last") == (4, 4)
    assert source.enclosing(items, 5) == source.MODULE_FUNCTION


def test_calls_skip_declarations_comments_strings_and_duplicate_mentions():
    text = 'def run():\n    target(1); target(2)\n# target(3)\ns = "target(4)"\nobj.target(5)\nrun()\n'
    assert source.call_sites(text, ["target", "run"]) == (
        source.CallSite(2, "target"),
        source.CallSite(5, "target"),
        source.CallSite(6, "run"),
    )
    assert source.call_sites(text, []) == ()
    assert source.call_sites("function run() { return run(); }", ["run"]) == (source.CallSite(1, "run"),)


def test_callers_scan_only_supplied_files(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    pass\nrun()\n")
    (tmp_path / "web.py").write_text("def handler():\n    run()\n")
    assert source.callers_of(tmp_path, "run", files=["web.py", "app.py"]) == (("app.py", 3), ("web.py", 2))
    assert source.callers_of(tmp_path, "run", files=["web.py"]) == (("web.py", 2),)
    assert source.callers_of(tmp_path, "absent", files=["web.py"]) == ()
    with pytest.raises(OSError):
        source.callers_of(tmp_path, "run", files=["missing.py"])
    with pytest.raises(ValueError):
        source.callers_of(tmp_path, "run", files=["../outside.py"])


def test_product_files_exclude_vendor_tests_and_private_paths(tmp_path):
    names = [
        "src/app.py",
        "vendor/a.py",
        "node_modules/a.js",
        "tests/a.py",
        "spec/a.rb",
        "src/a_test.go",
        "src/AppTest.java",
        "src/a.test.js",
        "dist/a.js",
        ".hidden/a.py",
        ".env",
        "src/a.min.js",
    ]
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("run()\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "src/app.py")
    assert source.product_files(tmp_path) == ["src/app.py"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("py", "python"),
        ("python_web", "python"),
        ("node", "javascript"),
        ("js", "javascript"),
        ("ts", "typescript"),
        ("typescript", "typescript"),
        ("c_cpp", "cpp"),
        ("c++", "cpp"),
        ("cpp", "cpp"),
        ("Ruby", "ruby"),
        ("unknown", "unknown"),
    ],
)
def test_canonical_language(name, expected):
    assert source.canonical_language(name) == expected


def test_facts_reuse_supplied_entry_points_and_read_only_repository(tmp_path, monkeypatch):
    from openultrasast import mapping

    (tmp_path / "app.py").write_text("def run(x):\n    return x\n")
    (tmp_path / "web.py").write_text("def handler():\n    run(1)\n")
    monkeypatch.setattr(mapping, "analyze_entry_points", lambda *_: pytest.fail("entry points were recomputed"))
    result = source.facts_for(tmp_path, "app.py", 2, entry_points=[])
    assert result == source.SourceFacts("python", "run", (1, 2), (("web.py", 2),), ())


def test_parse_rejection_is_not_an_empty_result(monkeypatch):
    from openultrasast.semantic.ir import FileIR

    monkeypatch.setattr(
        cst, "parse_with_cst", lambda path, text, language: FileIR(path, language, "tree-sitter", (), False, "parse_failed")
    )
    with pytest.raises(ValueError, match="source parse failed"):
        source.ranges("app.py", "def broken(", "python")


def test_facts_for_reuses_supplied_product_files_and_texts(tmp_path, monkeypatch):
    """With files and texts supplied, facts_for neither walks the tree nor reads the files it was given."""
    from openultrasast import source

    (tmp_path / "app.py").write_text("def handler(value):\n    return value\n")
    (tmp_path / "other.py").write_text("from app import handler\n\n\ndef run():\n    return handler(1)\n")
    monkeypatch.setattr(source, "product_files", lambda root: (_ for _ in ()).throw(AssertionError("walked the tree")))
    texts = {"other.py": (tmp_path / "other.py").read_text()}
    (tmp_path / "other.py").write_text("")  # the supplied text, not the disk, is what callers_of reads
    facts = source.facts_for(tmp_path, "app.py", 2, entry_points=[], files=["app.py", "other.py"], texts=texts)
    assert facts.function == "handler" and facts.callers == (("other.py", 5),)


def test_call_index_gives_the_same_call_sites_and_is_reused_across_names(tmp_path):
    from openultrasast import source

    text = "def handler(value):\n    return value\n\n\ndef run():\n    x = handler(1)  # handler\n    return other(x)\n"
    index = source.code_index(text)
    assert source.call_sites(text, ("handler", "other")) == source.call_sites("", ("handler", "other"), index=index)
    assert [call.line for call in source.call_sites("", ("handler",), index=index)] == [6]
    (tmp_path / "other.py").write_text(text)
    cache: dict = {}
    assert source.callers_of(tmp_path, "handler", files=["other.py"], index=cache) == (("other.py", 6),)
    (tmp_path / "other.py").write_text("")  # the cached index, not the disk, answers the second name
    assert source.callers_of(tmp_path, "other", files=["other.py"], index=cache) == (("other.py", 7),)


def test_a_minified_line_is_not_scanned_once_per_function(monkeypatch):
    text = "".join(f"function f{i}(){{return {i}}}" for i in range(3000)) + "\n"
    assert len(text) > source.MINIFIED_LINE_CHARS
    calls: list[str] = []
    original = source._declares
    monkeypatch.setattr(source, "_declares", lambda line, name: calls.append(line) or original(line, name))
    result = source.ranges("bundle.js", text, "javascript")
    assert len(result) == 3001 and result[0].name == source.MODULE_FUNCTION
    assert set(calls) == {""}  # the long line itself never reaches the per-function scan
    assert {r.name for r in result[1:]} == {source.ANON_FUNCTION}


def test_generated_reason_names_build_output_only(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("function a() {}\n")
    (tmp_path / "app.min.js").write_text("function b() {}\n")
    (tmp_path / "one.js").write_text("".join(f"function f{i}(){{}}" for i in range(400)) + "\n")
    (tmp_path / "big.js").write_text("function c() {}\n" + "// padding\n" * 100_000)
    (tmp_path / "app.js").write_text("function d() {}\n")
    assert source.generated_reason(tmp_path, "dist/bundle.js") == "excluded_dir"
    assert source.generated_reason(tmp_path, "app.min.js") == "minified_name"
    assert source.generated_reason(tmp_path, "one.js") == "long_line"
    assert source.generated_reason(tmp_path, "big.js") == "too_large"
    assert source.generated_reason(tmp_path, "app.js") is None
    assert source.generated_reason(tmp_path, "missing.js") is None


def test_facts_keep_only_the_entry_points_in_the_file_or_a_caller_file(tmp_path):
    from openultrasast.mapping import EntryPointRecord

    (tmp_path / "app.py").write_text("def run(x):\n    return x\n")
    (tmp_path / "web.py").write_text("from app import run\n\ndef view():\n    return run(1)\n")
    (tmp_path / "far.py").write_text("def other():\n    return 2\n")

    def entry(path):
        return EntryPointRecord(path, 1, 2, None, path, "route", "public", "external", [], [], "test", "fixture")

    entries = [entry("app.py"), entry("web.py"), entry("far.py")]
    facts = source.facts_for(tmp_path, "app.py", 2, entry_points=entries, files=["app.py", "web.py", "far.py"])
    assert facts.callers == (("web.py", 4),)
    assert [e.path for e in facts.entry_points] == ["app.py", "web.py"]
