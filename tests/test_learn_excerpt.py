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


# --- declaration forms the brace matcher must know (each form once; a call or prototype is never a declaration) -------


def _span(code: list[str], language: str, function: str) -> tuple[int, int] | None:
    found = excerpt(code, language, function)
    return None if found is None else (found.first, found.last)


def test_js_object_literal_methods() -> None:
    js = [
        "module.exports = {",
        "  getInfo: function () {",
        "    return this.exec('pdfinfo ' + this.path)",
        "  },",
        "  ps: function(pid, options, done) {",
        "    var cmd = 'ps -o pcpu,rss -p ' + pid",
        "    exec(cmd, done)",
        "  },",
        "  performAction: function anonymous(yytext, yyleng) {",
        "    return eval(yytext)",
        "  },",
        "  short: (a) => a + 1,",
        "  use: function () { return this.getInfo().then(function (info) { return info }) },",
        "}",
    ]
    assert _span(js, "javascript", "getInfo") == (2, 4)
    assert _span(js, "javascript", "ps") == (5, 8)
    assert _span(js, "javascript", "performAction") == (9, 11)  # the key, not the expression's own name
    assert _span(js, "javascript", "short") == (12, 12)  # an expression body ends at its comma
    assert _span(js, "javascript", "then") is None  # a call inside a body is not a declaration


def test_js_property_assignment_functions_and_arrows() -> None:
    js = [
        "module.exports.ConfigureFilePath = (Options, FilePath) => {",
        "  return path.join(Options.root, FilePath)",
        "}",
        "const listProcessesOnPort = module.exports.listProcessesOnPort = async port => {",
        "  return exec(`lsof -i :${port}`)",
        "}",
        "Glance.prototype.serveRequest = function Glance$serveRequest (req, res) {",
        "  fs.createReadStream(req.url).pipe(res)",
        "}",
        "this.getDaqValue = function (tagid, fromts, tots) {",
        "  return conn.query('SELECT ' + tagid)",
        "}",
        "const total = sum(prices)",
    ]
    assert _span(js, "javascript", "ConfigureFilePath") == (1, 3)
    assert _span(js, "javascript", "listProcessesOnPort") == (4, 6)
    assert _span(js, "javascript", "Glance$serveRequest") == (7, 9)  # `$` is an identifier character
    assert _span(js, "javascript", "serveRequest") == (7, 9)
    assert _span(js, "javascript", "getDaqValue") == (10, 12)
    assert _span(js, "javascript", "sum") is None  # an assignment of a call result declares nothing


def test_ts_class_methods_with_modifiers_and_multiline_parameters() -> None:
    ts = [
        "export class Client {",
        "  private retries = 3",
        "  private async fetchRetry(",
        "    url: string,",
        "    options: any = {},",
        "  ): Promise<Response> {",
        "    return fetch(url, options)",
        "  }",
        "  handle = async (req: Request): Promise<void> => {",
        "    await this.fetchRetry(req.url)",
        "  }",
        "}",
    ]
    assert _span(ts, "typescript", "fetchRetry") == (3, 8)  # not the `{}` default value inside the parameter list
    assert _span(ts, "typescript", "handle") == (9, 11)


def test_perl_sub_under_an_unknown_language() -> None:
    perl = [
        "#!/usr/bin/perl",
        "use strict;",
        "sub link_hash_cert;",  # a forward declaration has no body
        "# CVE-2022-1292: shell injection fixed",
        "sub link_hash_cert {",
        "    my $fname = $_[0];",
        "    system(\"openssl x509 -in '$fname'\");",
        "}",
        "sub hash_dir { opendir(my $dh, $_[0]) or die; }",
    ]
    assert _span(perl, "unknown", "link_hash_cert") == (5, 8)
    assert _span(perl, "other", "hash_dir") == (9, 9)
    shown = excerpt(perl, "unknown", "link_hash_cert", focus=(4,))
    assert shown is not None and "CVE-2022" not in shown.text  # `#` comments are redacted once the language is known


def test_c_declaration_with_a_long_parameter_list_and_qualifiers() -> None:
    c = [
        "CURLcode Curl_add_custom_headers(struct Curl_easy *data, bool is_connect, void *req);",
        "",
        "CURLcode Curl_add_custom_headers(struct Curl_easy *data,",
        "                                 bool is_connect,",
        "#ifndef USE_HYPER",
        "                                 struct dynbuf *req",
        "#else",
        "                                 void *req",
        "#endif",
        "  )",
        "{",
        "  return CURLE_OK;",
        "}",
        "std::string Parser::header(int index) const noexcept {",
        "  return headers[index];",
        "}",
        "Parser::Parser(int n) : size_(n), data_(nullptr) {",
        "  data_ = alloc(n);",
        "}",
        "int main(void) { if (check(1)) { return 1; } else if (header(2)) { return 2; } return 0; }",
    ]
    assert _span(c, "c", "Curl_add_custom_headers") == (3, 13)  # the prototype is skipped, the body is 9 lines down
    assert _span(c, "cpp", "Parser::header") == (14, 16)
    assert _span(c, "cpp", "Parser") == (17, 19)  # an initializer list's commas are not statement ends
    assert _span(c, "c", "check") is None  # `if (check(1)) {` is a call: its `)` closes an outer parenthesis


def test_php_methods_with_modifiers_and_return_types() -> None:
    php = [
        "<?php",
        "class Export {",
        "    public static function &byRef(array $rows): ?array",
        "    {",
        "        return $rows;",
        "    }",
        "    final protected function render(string $name): void { echo $name; }",
        "}",
    ]
    assert _span(php, "php", "byRef") == (3, 6)
    assert _span(php, "php", "render") == (7, 8)  # a pattern language's span runs to the next declaration or the end


def test_go_receivers_and_rust_generics() -> None:
    go = [
        "package main",
        "",
        "func (s *Server) handle(w http.ResponseWriter, r *http.Request) {",
        "\tio.Copy(w, r.Body)",
        "}",
        "",
        "func main() {}",
    ]
    assert _span(go, "go", "handle") == (3, 6)  # the declaration pattern: to the next `func`
    assert _span(go, "other", "handle") == (3, 5)  # the feature vocabulary's bucket for Go: brace-matched to the body
    rust = ["pub fn parse<T: Read>(input: &mut T) -> Result<(), Error> {", "    Ok(())", "}"]
    assert _span(rust, "rust", "parse") == (1, 3)


def test_ruby_defs_under_the_other_language_are_sniffed() -> None:
    ruby = [
        "module Kredis",
        "  class Type",
        "    def self.cast_value(value)",
        "      YAML.load(value)",
        "    end",
        "",
        "    def fetch_file(path)",
        "      files.each { |f| return f if f.name == path }",
        "      nil",
        "    end",
        "  end",
        "end",
    ]
    assert _span(ruby, "ruby", "cast_value") == (3, 6)
    assert _span(ruby, "other", "cast_value") == (3, 6)  # not None: the file is sniffed as Ruby
    assert _span(ruby, "other", "fetch_file") == _span(ruby, "ruby", "fetch_file") == (7, 12)  # to the end: no later `def`
    assert _span(ruby, "c", "fetch_file") == (7, 8)  # what a brace matcher takes under a named brace language: the block


def test_csharp_attributes_modifiers_and_expression_bodies() -> None:
    cs = [
        "public class UploadController : Controller",
        "{",
        "    [HttpPost]",
        "    public async Task<IActionResult> Upload(IFormFile file)",
        "    {",
        "        var path = Path.Combine(root, file.FileName);",
        "        return Ok(path);",
        "    }",
        "    protected override string Name(int index) => names[index];",
        "    public abstract int Size(string key);",
        "}",
    ]
    assert _span(cs, "csharp", "Upload") == (4, 8)
    assert _span(cs, "csharp", "Name") == (9, 9)  # an expression-bodied member ends at its `;`
    assert _span(cs, "csharp", "Size") is None  # abstract: no body


def test_java_and_statement_heads_are_not_declarations() -> None:
    java = [
        "public class Handler {",
        "    @Override",
        "    public synchronized <T> List<T> load(String name, Class<T> type)",
        "            throws IOException, SQLException {",
        "        return run(name, type);",
        "    }",
        "    void other() {",
        '        while (load("x", null) != null) { break; }',
        "    }",
        "}",
    ]
    assert _span(java, "java", "load") == (3, 6)  # `throws A, B {`: the comma is not a statement end
    assert _span(java, "java", "run") is None
    assert _span(java[2:], "java", "load") == _span(java[2:], "c", "load") == (1, 4)  # pattern and brace matcher agree


def test_resolve_language_sniffs_only_unknown_languages() -> None:
    from openultrasast.learn.excerpt import resolve_language

    assert resolve_language(["sub x {", "}"], "unknown") == "perl"
    assert resolve_language(["def x", "end"], "other") == "ruby"
    assert resolve_language(["def x(a):", "    return a"], "other") == "other"  # Python has no `end` lines
    assert resolve_language(["sub x {", "}"], "python") == "python"  # a named language is never second-guessed
    assert resolve_language([], "unknown") == "unknown"
