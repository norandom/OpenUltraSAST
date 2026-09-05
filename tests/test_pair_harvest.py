"""Maintainer VFC harvest stays offline in CI: extract and reject, no HTTP."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

HARVEST = Path("benchmarks/pairs/vfc/harvest.py")


def _harvest() -> dict[str, object]:
    return runpy.run_path(str(HARVEST))


def test_extract_function_round_trips_perl_sub_without_parens() -> None:
    harvest = _harvest()
    source = """
sub other { return 0; }
sub link_hash_cert {
    my ($hash, $fprint) = `"$openssl" x509 -in "$fname"`;
}
sub later { return 1; }
"""
    body = harvest["extract_function"](source, "link_hash_cert")
    assert "sub link_hash_cert {" in body
    assert '`"$openssl" x509' in body
    assert "sub other" not in body
    assert "sub later" not in body


def test_extract_function_round_trips_a_local_body() -> None:
    harvest = _harvest()
    source = """
int before(void) { return 0; }

int target_fn(char *name, int namelen) {
    memcpy(name, name, namelen + 1);
    return namelen;
}

int after(void) { return 1; }
"""
    body = harvest["extract_function"](source, "target_fn")
    assert "int target_fn(char *name, int namelen)" in body
    assert "memcpy(name, name, namelen + 1);" in body
    assert "int before" not in body
    assert "int after" not in body


def test_extract_function_skips_prototype_before_definition() -> None:
    harvest = _harvest()
    source = """
class Loader {
 public:
    char *ArrayBufferResult();
};

char *Loader::ArrayBufferResult() {
    return raw_data_->ToArrayBuffer();
}
"""
    body = harvest["extract_function"](source, "ArrayBufferResult")
    assert "Loader::ArrayBufferResult" in body
    assert "return raw_data_->ToArrayBuffer();" in body
    assert "class Loader" not in body


def test_validate_recipe_rejects_advisory_only_and_fixfox() -> None:
    harvest = _harvest()
    validate = harvest["validate_recipe"]
    with pytest.raises(harvest["RecipeError"], match="advisory-only"):
        validate({"name": "mfsa-only", "cve": "CVE-2019-11730"})
    with pytest.raises(harvest["RecipeError"], match="embargoed"):
        validate(
            {
                "name": "fixfox",
                "parent": "abc",
                "commit": "def",
                "path": "a.c",
                "function": "f",
                "license": "MIT",
                "url": "https://zenodo.org/record/fixfox",
            }
        )


def test_harvest_dry_run_accepts_seed_recipes() -> None:
    harvest = _harvest()
    recipes = {str(item["name"]): item for item in harvest["load_recipes"](Path("benchmarks/pairs/vfc/recipes.toml"))}
    assert {"openssl-cve-2014-0160", "firefox-cve-2020-15667", "chromium-cve-2019-5786"} <= set(recipes)
    for recipe in recipes.values():
        harvest["validate_recipe"](recipe)
    assert harvest["main"](["--name", "openssl-cve-2014-0160"]) == 0


# --- pair-corpus-honesty: shared library, comment-blind anchor, modes ---------

LIB = Path("benchmarks/pairs/harvest.py")


def _lib() -> dict[str, object]:
    return runpy.run_path(str(LIB), run_name="pair_harvest_lib")


def test_name_mode_ignores_doc_comment_mention_and_anchors_on_declarator() -> None:
    lib = _lib()
    source = """
/*
 * Curl_follow() handles the URL redirect magic. Pass in the 'newurl' string
 * as given by the remote server and set up the new URL to request.
 */
CURLcode Curl_follow(struct Curl_easy *data,
                     char *newurl,
                     followtype type)
{
    const char *msg = "Curl_follow(";
    return CURLE_OK;
}
"""
    body = lib["extract_function"](source, "Curl_follow", "c")
    assert body.startswith("CURLcode Curl_follow(struct Curl_easy *data,")
    assert "redirect magic" not in body
    assert 'const char *msg = "Curl_follow(";' in body


def test_name_mode_skips_prototype_and_string_mentions() -> None:
    lib = _lib()
    source = 'int f(void);\nconst char *s = "f(";\nint f(void)\n{\n    return 0;\n}\n'
    body = lib["extract_function"](source, "f", "c")
    assert body == "int f(void)\n{\n    return 0;\n}\n"


def test_python_block_mode_cuts_by_indentation_and_keeps_decorators() -> None:
    lib = _lib()
    source = (
        "import os\n\n"
        "@router.post('/runs')\n"
        "async def create_run(body):\n"
        "    user_id = body.user_id\n"
        "    if not user_id:\n"
        "        return None\n"
        "    return user_id\n\n"
        "def other():\n"
        "    return 1\n"
    )
    body = lib["extract_function"](source, "create_run", "python")
    assert body.startswith("@router.post('/runs')\nasync def create_run(body):")
    assert "return user_id" in body
    assert "def other" not in body


def test_line_range_mode_round_trips_exact_lines() -> None:
    lib = _lib()
    source = "a\nb\nc\nd\n"
    assert lib["extract_line_range"](source, 2, 3) == "b\nc\n"
    with pytest.raises(lib["RecipeError"]):
        lib["extract_line_range"](source, 3, 9)


def test_hunk_mode_returns_enclosing_functions_on_both_sides() -> None:
    lib = _lib()
    parent = (
        "int a(void) { return 0; }\n\nint target(int n)\n{\n    char buf[8];\n    memcpy(buf, src, n);\n"
        "    return n;\n}\n\nint z(void) { return 1; }\n"
    )
    fixed = parent.replace("    memcpy(buf, src, n);", "    if (n > 8)\n        return -1;\n    memcpy(buf, src, n);")
    vuln_fn, fixed_fn = lib["extract_hunk"](parent, fixed, "c")
    assert vuln_fn.startswith("int target(int n)")
    assert "if (n > 8)" not in vuln_fn and "if (n > 8)" in fixed_fn
    assert "int a(void)" not in fixed_fn and "int z(void)" not in fixed_fn


def test_hunk_mode_python() -> None:
    lib = _lib()
    parent = "def a():\n    return 0\n\ndef create_run(body):\n    user_id = body.user_id\n    return user_id\n\ndef z():\n    return 1\n"
    fixed = parent.replace("    user_id = body.user_id", "    user_id = request.state.user_id")
    vuln_fn, fixed_fn = lib["extract_hunk"](parent, fixed, "python")
    assert vuln_fn.startswith("def create_run(body):") and "body.user_id" in vuln_fn
    assert "request.state.user_id" in fixed_fn and "def z" not in fixed_fn


def test_extract_pair_dispatches_modes_and_validate_requires_mode_fields() -> None:
    lib = _lib()
    base = {"name": "x", "parent": "p", "commit": "c", "path": "a.py", "license": "MIT", "language": "python"}
    with pytest.raises(lib["RecipeError"], match="line_start"):
        lib["validate_recipe"]({**base, "mode": "line_range"})
    with pytest.raises(lib["RecipeError"], match="unknown mode"):
        lib["validate_recipe"]({**base, "mode": "magic"})
    lib["validate_recipe"]({**base, "mode": "hunk"})
    src = "def f():\n    return 1\n"
    vuln, fixed = lib["extract_pair"]({**base, "mode": "line_range", "line_start": 1, "line_end": 2}, src, src)
    assert vuln == src and fixed == src


def test_provenance_header_uses_language_comment_style() -> None:
    lib = _lib()
    py = lib["provenance_header"]({"path": "a.py", "repo": "r", "mechanism": "identity_from_request_body"}, side="vuln", sha="abc")
    assert py.startswith("# Provenance:") and "# mechanism: identity_from_request_body" in py
    ts = lib["provenance_header"]({"path": "a.ts", "repo": "r"}, side="vuln", sha="abc")
    assert ts.startswith("// Provenance:")
    c = lib["provenance_header"]({"path": "a.c", "repo": "r"}, side="vuln", sha="abc")
    assert c.startswith("/* Provenance:")


def test_hunk_mode_skips_module_level_hunk_and_uses_next_function_hunk() -> None:
    lib = _lib()
    parent = "const x = 1;\n\nfunction f(a) {\n    return a;\n}\n"
    fixed = "const x = 2;\n\nfunction f(a) {\n    if (!a) return null;\n    return a;\n}\n"
    vuln_fn, fixed_fn = lib["extract_hunk"](parent, fixed, "javascript")
    assert vuln_fn.startswith("function f(a)") and "if (!a)" in fixed_fn


def test_hunk_mode_falls_back_to_whole_small_file() -> None:
    lib = _lib()
    parent = "module.exports = { cors: '*' };\n"
    fixed = "module.exports = { cors: 'https://example.test' };\n"
    vuln_fn, fixed_fn = lib["extract_hunk"](parent, fixed, "javascript")
    assert vuln_fn == parent and fixed_fn == fixed
    big = "\n".join(f"const v{i} = {i};" for i in range(200)) + "\n"
    with pytest.raises(lib["RecipeError"], match="too large"):
        lib["extract_hunk"](big, big.replace("v0 = 0", "v0 = 1"), "javascript")


def test_catalog_gen_derives_function_past_the_provenance_header_and_never_anon(tmp_path: Path) -> None:
    gen = runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib")
    slice_root = tmp_path / "s"
    pair = slice_root / "p"
    pair.mkdir(parents=True)
    header_v = "// Provenance: r go (vuln).\n// repo: r\n// commit: a\n// license: MIT\n\n"
    header_f = "// Provenance: r go (fixed).\n// repo: r\n// commit: b\n// license: MIT\n\n"
    body_v = "function first(a) {\n  return a;\n}\n\nfunction go(cmd) {\n  return exec(cmd);\n}\n"
    body_f = "function first(a) {\n  return a;\n}\n\nfunction go(cmd) {\n  if (!ok(cmd)) return null;\n  return exec(cmd);\n}\n"
    (pair / "vuln.js").write_text(header_v + body_v)
    (pair / "fixed.js").write_text(header_f + body_f)
    recipe = {"name": "p", "path": "a.js", "language": "javascript"}
    assert gen["derive_function"](slice_root, recipe) == "go"
    # a change inside an anonymous callback resolves to the enclosing named function, never "<anon>"
    body_v2 = "function handler(req) {\n  items.forEach(function (i) {\n    exec(i);\n  });\n}\n"
    body_f2 = "function handler(req) {\n  items.forEach(function (i) {\n    if (safe(i)) exec(i);\n  });\n}\n"
    (pair / "vuln.js").write_text(header_v + body_v2)
    (pair / "fixed.js").write_text(header_f + body_f2)
    assert gen["derive_function"](slice_root, recipe) == "handler"


def test_write_excerpt_redacts_credential_literals_but_not_code() -> None:
    lib = _lib()
    redact = lib["redact"]
    google = "AIza" + "SyDEMOKEYDEMOKEYDEMOKEYDEMOKEY0000"  # assembled at runtime, never a contiguous key literal
    assert redact(f"apiKey: '{google}',") == "apiKey: '***REDACTED***',"
    assert redact('password = "hunter2hunter2"') == 'password = "***REDACTED***"'
    assert redact("password = request.form['password']") == "password = request.form['password']"
    assert redact("const token = getToken();") == "const token = getToken();"


def test_catalog_gen_prefers_declarator_names_and_rejects_reserved_words(tmp_path: Path) -> None:
    gen = runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib")
    slice_root = tmp_path / "s"
    pair = slice_root / "p"
    pair.mkdir(parents=True)
    header_v = "// Provenance: r x (vuln).\n// license: MIT\n\n"
    header_f = "// Provenance: r x (fixed).\n// license: MIT\n\n"
    # An arrow function assigned to a const: the label must be the const name, never the parameter name.
    body_v = "const listProcessesOnPort = (port) => {\n  return exec('lsof -i :' + port);\n};\n"
    body_f = (
        "const listProcessesOnPort = (port) => {\n  if (!/^\\d+$/.test(port)) throw new Error('bad');\n"
        "  return exec('lsof -i :' + port);\n};\n"
    )
    (pair / "vuln.js").write_text(header_v + body_v)
    (pair / "fixed.js").write_text(header_f + body_f)
    recipe = {"name": "p", "path": "a.js", "language": "javascript"}
    assert gen["derive_function"](slice_root, recipe) == "listProcessesOnPort"
    # A bare anonymous function expression must not yield the keyword "function".
    (pair / "vuln.js").write_text(header_v + "module.exports = function (req, res) {\n  exec(req.query.c);\n};\n")
    (pair / "fixed.js").write_text(header_f + "module.exports = function (req, res) {\n  res.end();\n};\n")
    assert gen["derive_function"](slice_root, recipe) is None


def test_catalog_gen_labels_from_sink_location_not_from_formatting_hunk(tmp_path: Path) -> None:
    gen = runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib")
    slice_root = tmp_path / "s"
    pair = slice_root / "p"
    pair.mkdir(parents=True)
    # Excerpt starts at upstream line 10; the sink sits at upstream line 17 (excerpt body line 8) inside performAction.
    header_v = "// Provenance: r x (vuln).\n// license: MIT\n// upstream_start: 10\n\n"
    header_f = "// Provenance: r x (fixed).\n// license: MIT\n// upstream_start: 10\n\n"
    body_v = (
        "function trace() { }\n\nfunction other(a) {\n  return a;\n}\n\nfunction performAction(yytext) {\n"
        "  return eval('[' + yytext + ']');\n}\n"
    )
    body_f = (
        "function trace () { }\n\nfunction other(a) {\n  return a;\n}\n\nfunction performAction(yytext) {\n"
        "  return JSON.parse('[' + yytext + ']');\n}\n"
    )
    (pair / "vuln.js").write_text(header_v + body_v)
    (pair / "fixed.js").write_text(header_f + body_f)
    recipe = {"name": "p", "path": "a.js", "relpath": "a.js", "language": "javascript", "sink_location": "a.js:17:10"}
    assert gen["derive_function"](slice_root, recipe) == "performAction"
    assert recipe.get("sink") == "eval"
    # A callback callee is never a declarator and never a label: the sink inside `exec(..., function(err){` belongs to `ps`.
    body_v2 = "function ps(pid) {\n  exec('ps -p ' + pid, function (err, out) {\n    return out;\n  });\n}\n"
    body_f2 = (
        "function ps(pid) {\n  if (!/^\\d+$/.test(pid)) return null;\n  exec('ps -p ' + pid, function (err, out) {\n"
        "    return out;\n  });\n}\n"
    )
    (pair / "vuln.js").write_text(header_v + body_v2)
    (pair / "fixed.js").write_text(header_f + body_f2)
    recipe2 = {"name": "p", "path": "a.js", "relpath": "a.js", "language": "javascript", "sink_location": "a.js:11:3"}
    assert gen["derive_function"](slice_root, recipe2) == "ps"
    assert recipe2.get("sink") == "exec"


def test_extract_pair_with_lines_and_header_record_upstream_start() -> None:
    lib = _lib()
    parent = "int a(void) { return 0; }\n\nint target(int n)\n{\n    char buf[8];\n    memcpy(buf, src, n);\n    return n;\n}\n"
    fixed = parent.replace("    memcpy(buf, src, n);", "    if (n > 8)\n        return -1;\n    memcpy(buf, src, n);")
    (vuln_text, vuln_start), (fix_text, fix_start) = lib["extract_pair_with_lines"]({"mode": "hunk", "language": "c"}, parent, fixed)
    assert vuln_text.startswith("int target(int n)") and vuln_start == 3 and fix_start == 3
    header = lib["provenance_header"]({"path": "a.js", "repo": "r"}, side="vuln", sha="abc", upstream_start=42)
    assert "// upstream_start: 42" in header


def test_python_block_survives_dedented_triple_quoted_string() -> None:
    lib = _lib()
    source = (
        "import x\n\n"
        "async def put_user(user):\n"
        "    user.password = h(user.password)\n"
        "    query = f'''\n"
        "UPDATE users SET password = '{user.password}'\n"
        "WHERE name = '{user.name}'\n"
        "'''\n"
        "    return await db.execute(query)\n\n"
        "def other():\n    return 1\n"
    )
    body = lib["extract_function"](source, "put_user", "python")
    assert body.endswith("    return await db.execute(query)\n")
    assert "def other" not in body
    import ast

    ast.parse(body)


def test_catalog_gen_fails_loud_without_the_package_and_refuses_to_prune_an_empty_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    gen = runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib")
    slice_root = tmp_path / "s"
    pair = slice_root / "p"
    pair.mkdir(parents=True)
    (pair / "vuln.js").write_text("// Provenance: r x (vuln).\n// license: MIT\n\nconst x = 1;\n")
    (pair / "fixed.js").write_text("// Provenance: r x (fixed).\n// license: MIT\n\nconst x = 2;\n")
    (slice_root / "recipes.toml").write_text('[[recipe]]\nname = "p"\npath = "a.js"\nlanguage = "javascript"\nmechanism = "other"\n')
    gen["generate"].__globals__["ROOT"] = tmp_path  # runpy returns a copy; patch the live module globals
    # No recipe can derive a label -> the generator must refuse to prune rather than delete the corpus.
    with pytest.raises(SystemExit, match="refusing"):
        gen["generate"]("s", prune=True)
    assert pair.is_dir()
    # The package import must fail loud, never degrade into "no named function".
    monkeypatch.setitem(sys.modules, "openultrasast.semantic.functions", None)
    with pytest.raises((SystemExit, ImportError)):
        runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib_blocked")
