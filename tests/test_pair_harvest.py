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


# --- task 8.3: pointer pairs (Req 10) -----------------------------------------


def test_materialize_pointer_writes_only_into_the_cache_root_and_needs_no_license(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lib = _lib()
    recipe = {
        "name": "ptr",
        "repo": "o/r",
        "parent": "aaa",
        "commit": "bbb",
        "path": "app.py",
        "mode": "enclosing",
        "line": 3,
        "license": "",
    }
    with pytest.raises(lib["RecipeError"], match="license"):
        lib["validate_recipe"](recipe)
    lib["validate_recipe"](recipe, require_license=False)
    sources = {"aaa": "import os\n\ndef f(x):\n    return eval(x)\n", "bbb": "import os\n\ndef f(x):\n    return int(x)\n"}
    fetched: list[str] = []

    def fake_fetch(url: str, timeout: int = 60) -> str:
        fetched.append(url)
        return sources[url.split("/")[5]]

    lib["fetch_url"] = fake_fetch
    lib["harvest_recipe"].__globals__["fetch_url"] = fake_fetch
    vuln, fixed = lib["materialize_pointer"](recipe, tmp_path / "cache", slice_name="vibe-py")
    assert vuln == tmp_path / "cache" / "vibe-py" / "ptr" / "vuln.py" and fixed.is_file()
    assert "def f(x):" in vuln.read_text() and "upstream_start" in vuln.read_text()
    assert len(fetched) == 2 and not list(Path("benchmarks/pairs/vibe-py").glob("ptr*"))


def test_catalog_gen_emits_pointer_rows_without_excerpts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tomllib

    gen = runpy.run_path(str(Path("benchmarks/pairs/catalog_gen.py")), run_name="catalog_gen_lib")
    slice_root = tmp_path / "vibe-py"
    slice_root.mkdir()
    (slice_root / "recipes.toml").write_text(
        '[[recipe]]\nname = "ptr"\nrepo = "o/r"\nparent = "aaa"\ncommit = "bbb"\npath = "app.py"\nfix_path = "trap.py"\n'
        'mode = "enclosing"\n'
        'line = 3\nfix_line = 9\nfunction = "f"\nlanguage = "python"\nrelpath = "app.py"\nlicense = "unlicensed"\ncwe = "CWE-95"\n'
        'class = "code injection"\nmechanism = "source_reaches_sink"\nprovenance = "agent"\nvendored = false\nsplit = "holdout"\n'
    )
    gen["ROOT"] = tmp_path
    gen["generate"].__globals__["ROOT"] = tmp_path
    catalog, count = gen["generate"]("vibe-py")
    assert count == 1
    (row,) = tomllib.loads(catalog.read_text())["pair"]
    assert row["vendored"] is False and "vuln" not in row and "fixed" not in row
    assert row["parent"] == "aaa" and row["fix_path"] == "trap.py" and row["fix_line"] == 9 and row["mode"] == "enclosing"
    assert row["expected"][0]["function"] == "f"
    from openultrasast.pairs import _load_catalog_file

    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path / "cache"))
    (case,) = _load_catalog_file(catalog)
    assert case.vendored is False and case.provenance == "agent"
    assert not (slice_root / "training" / "manifest.jsonl").read_text().strip()  # pointer rows have no vendored files to train on


# --- task 8.4: pointer recipes from the builders (Req 10.6) ---------------------


def _ground_truth(tmp_path: Path) -> Path:
    import json

    gt = tmp_path / "gt"
    gt.mkdir()
    repos = {
        "realvuln-vc-llm-app": {
            "repo_url": "https://github.com/k/vc-llm-app",
            "commit_sha": "c1",
            "authorship": "llm_generated",
            "framework": "flask",
        },
        "realvuln-human-nolic": {
            "repo_url": "https://github.com/h/nolic",
            "commit_sha": "c2",
            "authorship": "human_authored",
            "framework": "flask",
        },
        "realvuln-human-mit": {
            "repo_url": "https://github.com/h/mit",
            "commit_sha": "c3",
            "authorship": "human_authored",
            "framework": "flask",
        },
    }
    (gt / "manifest.json").write_text(json.dumps({"repos": repos}))
    findings = [
        {
            "id": "v1",
            "is_vulnerable": True,
            "file": "app.py",
            "location": {"function": "run", "start_line": 3},
            "vulnerability_class": "command_injection",
            "primary_cwe": "CWE-78",
            "evidence": {"description": "x"},
        },
        {
            "id": "t1",
            "is_vulnerable": False,
            "file": "app.py",
            "location": {"function": "safe", "start_line": 9},
            "vulnerability_class": "command_injection",
            "primary_cwe": "CWE-78",
        },
    ]
    for repo_id in repos:
        (gt / f"{repo_id}.json").write_text(json.dumps({"findings": findings}))
    (gt / "licenses.json").write_text(
        json.dumps(
            {
                "realvuln-vc-llm-app": {"full": "k/vc-llm-app", "license": ""},
                "realvuln-human-nolic": {"full": "h/nolic", "license": ""},
                "realvuln-human-mit": {"full": "h/mit", "license": "MIT"},
            }
        )
    )
    return gt


def test_vibe_py_builder_pointers_mode_emits_llm_repos_as_unvendored_agent_rows(tmp_path: Path) -> None:
    b = runpy.run_path(str(Path("benchmarks/pairs/vibe-py/build_recipes.py")), run_name="vibe_builder")
    gt = _ground_truth(tmp_path)
    recipes, skipped = b["build"](
        gt, gt / "licenses.json", per_repo=2, classes={"command_injection"}, allow_unlicensed=False, pointers=True
    )
    by_repo = {r["repo"]: r for r in recipes}
    assert set(by_repo) == {"k/vc-llm-app", "h/mit"}  # unlicensed human repos are neither vendored nor pointed at
    llm = by_repo["k/vc-llm-app"]
    assert llm["vendored"] is False and llm["provenance"] == "agent" and llm["review_tier"] == "seeded" and llm["license"] == "unlicensed"
    assert llm["function"] == "run" and llm["fix_path"] == "app.py" and llm["fix_line"] == 9
    assert "vendored" not in by_repo["h/mit"] and by_repo["h/mit"]["provenance"] == "human"
    assert skipped["unlicensed"] == 1
    text = b["to_toml"](recipes)
    import tomllib

    rows = tomllib.loads(text)["recipe"]
    assert any(row.get("vendored") is False for row in rows)


def test_merge_recipes_keeps_existing_rows_and_appends_new_by_name() -> None:
    lib = _lib()
    existing = [{"name": "a", "repo": "x", "license": "MIT"}, {"name": "b", "repo": "y", "license": "MIT"}]
    new = [{"name": "b", "repo": "changed"}, {"name": "c", "repo": "z", "vendored": False}]
    merged, added = lib["merge_recipes"](existing, new)
    assert [r["name"] for r in merged] == ["a", "b", "c"] and merged[1]["repo"] == "y" and added == ["c"]


def test_agent_vfc_builder_writes_toml_booleans() -> None:
    import tomllib

    b = runpy.run_path(str(Path("benchmarks/pairs/agent-vfc/build_recipes.py")), run_name="agent_builder")
    (row,) = tomllib.loads(b["to_toml"]([{"name": "p", "vendored": False, "line": 3, "reviewer": "pending"}]))["recipe"]
    assert row["vendored"] is False and row["line"] == 3


def test_handler_context_mode_keeps_decorators_and_registration() -> None:
    """authorization-obligations 4.1 (Req 7.1): the handler travels with the statements that register it."""
    lib = _lib()
    source = (
        "from flask import request\n\n"
        "@app.route('/books/<title>')\n"
        "@login_required\n"
        "def guarded(title):\n"
        "    return Book.query.filter_by(book_title=title).first()\n\n\n"
        "def other():\n"
        "    return 1\n\n\n"
        "app.add_url_rule('/legacy/books/<title>', view_func=guarded)\n"
        "# guarded is mentioned in a comment and 'guarded' in a string: neither is a registration\n"
        "label = 'guarded'\n"
    )
    excerpt = lib["extract_handler_context"](source, "guarded", "python")
    assert excerpt.startswith("@app.route('/books/<title>')\n@login_required\ndef guarded(title):")
    assert "app.add_url_rule('/legacy/books/<title>', view_func=guarded)" in excerpt
    assert "def other" not in excerpt and "mentioned in a comment" not in excerpt and "label = 'guarded'" not in excerpt
    js = "function list(req, res) {\n  return Book.find({});\n}\n\nfunction other() {}\n\nrouter.get('/books', requireAuth, list);\n"
    js_excerpt = lib["extract_handler_context"](js, "list", "javascript")
    assert "function list(req, res)" in js_excerpt and "router.get('/books', requireAuth, list);" in js_excerpt
    assert "function other" not in js_excerpt
    recipe = {
        "name": "r",
        "parent": "p",
        "commit": "c",
        "path": "app.py",
        "mode": "handler_context",
        "function": "guarded",
        "license": "MIT",
    }
    lib["validate_recipe"](recipe)
    with pytest.raises(lib["RecipeError"], match="function"):
        lib["validate_recipe"]({**recipe, "function": ""})
    (vuln, start), (fixed, _) = lib["extract_pair_with_lines"]({**recipe}, source, source.replace("@login_required\n", ""))
    assert start == 3 and "add_url_rule" in vuln and "@login_required" not in fixed and "add_url_rule" in fixed
