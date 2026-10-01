"""Excerpts for the decision engine (learned-decision-engine design 4.2): bounds, centring, no identities, advisory ids
and security wording in comments redacted, the delta diff."""

from __future__ import annotations

from openultrasast.learn.excerpt import (
    CANDIDATE,
    EXAMPLE,
    REDACTED,
    Bounds,
    delta_diff,
    excerpt,
    excerpt_sha,
    identities_of,
    normalise,
    redact,
)

PY = [
    "import os",
    "",
    "def handler(request):",
    "    # CVE-2021-1234: prevent SQL injection by quoting",
    "    name = request.args['name']",
    '    """Fetch the user. Fixes GHSA-abcd-efgh-ijkm."""',
    "    query = 'SELECT * FROM users WHERE name = ' + name  # build the query",
    "    return db.execute(query)",
    "",
    "def other():",
    "    return 1",
]


def _long_function(n: int, width: int = 10) -> list[str]:
    return ["def big(x):"] + [f"    v{i} = x + {i}" + " " * width for i in range(n)] + ["    return v0", "", "def after():", "    pass"]


def test_function_only_numbered_from_its_first_line() -> None:
    shown = excerpt(PY, "python", "handler")
    assert shown is not None
    lines = shown.text.splitlines()
    assert lines[0].split()[0] == "3" and "def handler" in lines[0]
    assert "def other" not in shown.text and shown.first == 3 and shown.last == 9
    assert shown.sha == excerpt_sha(shown.text) and not shown.truncated


def test_unread_file_or_unknown_function_is_none_never_empty() -> None:
    assert excerpt(None, "python", "handler") is None
    assert excerpt([], "python", "handler") is None
    assert excerpt(PY, "python", "missing") is None
    assert excerpt(PY, "cobol", "handler") is None


def test_security_comments_and_advisory_ids_are_redacted() -> None:
    shown = excerpt(PY, "python", "handler")
    assert shown is not None
    assert "CVE-2021" not in shown.text and "GHSA" not in shown.text and "injection" not in shown.text
    assert "prevent" not in shown.text and REDACTED in shown.text
    assert "# build the query" in shown.text  # an ordinary comment stays
    assert "query = 'SELECT * FROM users WHERE name = ' + name" in shown.text  # code is never redacted


def test_redaction_covers_block_comments_and_other_languages() -> None:
    php = ["function f($id) {", "  /* sanitize to avoid XSS", "     (see report) */", "  echo $id; // 修复越权", "}"]
    out = redact(php, "php")
    assert "XSS" not in "\n".join(out) and "修复越权" not in out[3] and out[3].startswith("  echo $id;")
    assert "#" not in redact(["x = '#not a comment'"], "python")[0].replace("'#not a comment'", "")
    assert redact(["s = 'CVE-2020-0001'"], "python") == [f"s = '{REDACTED}'"]


def test_no_path_repository_or_commit_in_the_excerpt() -> None:
    lines = [
        "def handler(request):",
        "    # see https://github.com/acme-corp/webapp/blob/0123456789abcdef0123456789abcdef01234567/app/views.py",
        "    log('app/views.py')",
        "    return request",
    ]
    ids = identities_of("https://github.com/acme-corp/webapp", "app/views.py", ["0123456789abcdef0123456789abcdef01234567"])
    shown = excerpt(lines, "python", "handler", identities=ids)
    assert shown is not None
    for identity in ("acme-corp", "0123456789abcdef", "app/views.py"):
        assert identity not in shown.text
    assert "webapp" in shown.text or REDACTED in shown.text  # the bare name is code-level, the owner and slug are not


def test_bounds_lines_and_characters() -> None:
    lines = _long_function(200)
    shown = excerpt(lines, "python", "big", bounds=CANDIDATE)
    assert shown is not None and shown.truncated
    assert len(shown.text.splitlines()) <= CANDIDATE.lines and len(shown.text) <= CANDIDATE.chars
    small = excerpt(lines, "python", "big", bounds=EXAMPLE)
    assert small is not None and len(small.text.splitlines()) <= EXAMPLE.lines and len(small.text) <= EXAMPLE.chars
    wide = _long_function(60, width=120)
    tight = excerpt(wide, "python", "big", bounds=Bounds(80, 2000))
    assert tight is not None and len(tight.text) <= 2000 and tight.truncated


def test_window_centres_on_the_focus_lines() -> None:
    lines = _long_function(300)
    shown = excerpt(lines, "python", "big", bounds=Bounds(40, 100_000), focus=[200])
    assert shown is not None and shown.first <= 200 <= shown.last
    assert abs((shown.first + shown.last) / 2 - 200) <= 1
    chars = excerpt(lines, "python", "big", bounds=Bounds(80, 1200), focus=[200])
    assert chars is not None and chars.first <= 200 <= chars.last


def test_delta_diff_is_redacted_and_bounded() -> None:
    base = ["def f(x):", "    return escape(x)"]
    head = ["def f(x):", "    # CVE-2022-2222 sanitize later", "    return x"]
    diff = delta_diff(base, head, "python")
    assert diff.startswith("@@") and "+    return x" in diff and "-    return escape(x)" in diff
    assert "CVE-2022" not in diff and "sanitize" not in diff and "---" not in diff
    long = delta_diff([f"a{i}" for i in range(100)], [f"b{i}" for i in range(100)], "python", max_lines=40)
    assert len(long.splitlines()) == 40 and long.splitlines()[-1].startswith("...")
    shown = excerpt(head, "python", "f", diff=diff)
    assert shown is not None and "\ndiff:\n@@" in shown.text


def test_normalised_text_names_the_content() -> None:
    assert normalise("a  \r\nb\n\n\n") == "a\nb\n"
    assert excerpt_sha("a  \nb") == excerpt_sha("a\nb\n")


def test_brace_languages_without_a_declaration_pattern() -> None:
    c = [
        "/* CVE-2016-0001: heap overflow fixed */",
        "static int",
        "parse_header(const char *buf, size_t len)",
        "{",
        "    if (len > 4) { memcpy(out, buf, len); }",
        "    return parse_header_inner(buf); /* not a definition */",
        "}",
        "int other(void) { return parse_header(0, 0); }",
    ]
    shown = excerpt(c, "c_cpp", "parse_header")
    assert shown is not None and shown.first == 3 and shown.last == 7 and "other(void)" not in shown.text
    assert excerpt(c, "cpp", "Parser::parse_header") is not None
    assert excerpt(["int f(void);", "int g(void) { return f(); }"], "c", "f") is None  # a prototype is not a body
