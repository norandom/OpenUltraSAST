"""Verify each reserved case by READING its source, and propose a benign change -- without scanning anything.

Freezing the independent population (pre-push-safety-net 15.1) needs, per case: both pins present and in the
right order, the vulnerable sink confirmed where the advisory says it is, the fix touching that file, and a
benign change from the same history. This does exactly that with git and file reads. It never imports or runs
the analyzer, its queries, or any project tooling: a case this script touched is still unscanned.

The benign change is a PROPOSAL for review, chosen mechanically: the first commit after the fix, on the first
-parent line, that changes source files of the case's language, does not touch the sink file, does not talk
about security in its message, and stays small. A reviewer confirms or replaces it before the status becomes
`frozen`.

Usage: python benchmarks/independent/freeze.py [--population population-vN.toml] [--cache DIR] [--only ID,...]
Writes: benchmarks/independent/freeze-vN.json (v1 by default)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
POPULATION = HERE / "population-v1.toml"


def freeze_record(population: Path) -> Path:
    """`population-v2.toml` -> `freeze-v2.json`, next to it."""
    return population.with_name("freeze-" + population.stem.removeprefix("population-") + ".json")


EXTENSIONS = {
    "php": (".php",),
    "javascript": (".js", ".mjs", ".cjs", ".jsx"),
    "typescript": (".ts", ".tsx"),
    "python": (".py",),
}
# A benign change must not be a security change in disguise. The first pass let through "Restrict access to
# routine logs to owners only", "querybuilder missing the valid_filter_params check" and "add access mode and
# scopes to API tokens" -- access control and input validation, which is exactly what a benign control must not be.
SECURITY_WORDS = re.compile(
    r"secur|cve|ghsa|vuln|inject|xss|csrf|ssrf|sanitiz|escap|exploit|attack|auth|permission|cors|access|restrict|harden"
    r"|token|scope|valid|filter|privileg|role|owner|password|secret|redirect|sql|query|login|log in|ldap|session|ssl|tls|verif|cert|crypt|hash|cookie",  # noqa: E501
    re.I,
)
MAX_BENIGN_LINES = 200


def git(repo: Path, *args: str, check: bool = True) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)
    if check and done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()[:300]}")
    return done.stdout


def clone(url: str, target: Path) -> None:
    if (target / ".git").is_dir():
        git(target, "fetch", "--quiet", "origin")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", url, str(target)], check=True)


def blob(repo: Path, commit: str, path: str) -> bytes | None:
    done = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"], capture_output=True, check=False)
    return done.stdout if done.returncode == 0 else None


def sink_parts(sink: str) -> tuple[str, list[str]]:
    """The sink file and the function names the record claims, from `path :: A::b (...), c`."""
    path, _, rest = sink.partition("::")
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?=\s*(?:\(|,|$|;))", rest.split("(")[0] + ",")
    functions = [n for n in names if n not in {"used", "by", "source", "callers", "and", "from", "the"}]
    return path.strip(), functions


PHP_FUNCTION = re.compile(r"\bfunction\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def php_code(text: str) -> str:
    """`text` with comments, string contents and inline HTML blanked to spaces, newlines kept (line numbers hold).

    Enough to find function bodies by brace matching; heredoc/nowdoc bodies are blanked too. Not a parser: a file
    that defeats it yields no function, and the site falls back to `<global>`, which the freeze record shows."""
    out, i, n, php = list(text), 0, len(text), False

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if not php:
            j = text.find("<?", i)
            blank(i, n if j < 0 else j)
            if j < 0:
                break
            php, i = True, j + (5 if text.startswith("<?php", j) else 2)
            continue
        if text.startswith("?>", i):
            php, i = False, i + 2
        elif text.startswith("//", i) or text[i] == "#" and not text.startswith("#[", i):
            j = min(k for k in (text.find("\n", i), text.find("?>", i), n) if k >= 0)
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif text.startswith("<<<", i):
            label = re.match(r"<<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            end = re.compile(r"^\s*" + re.escape(label.group(1)) + r"\b", re.M) if label else None
            found = end.search(text, text.find("\n", i) + 1) if end else None
            j = found.end() if found else i + 3
            blank(i, j)
            i = j
        elif text[i] in "'\"":
            quote, j = text[i], i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        else:
            i += 1
    return "".join(out)


def php_functions(text: str) -> list[tuple[str, int, int]]:
    """(name, first line, last line) of every named function or method body in a PHP file, 1-based."""
    code, spans = php_code(text), []
    for match in PHP_FUNCTION.finditer(code):
        brace, semi = code.find("{", match.end()), code.find(";", match.end())
        if brace < 0 or 0 <= semi < brace:  # abstract or interface method: no body
            continue
        depth, k = 0, brace
        while k < len(code):
            depth += {"{": 1, "}": -1}.get(code[k], 0)
            if depth == 0:
                break
            k += 1
        spans.append((match.group(1), code.count("\n", 0, match.start()) + 1, code.count("\n", 0, k) + 1))
    return spans


def enclosing(spans: list[tuple[str, int, int]], line: int, inserted: bool = False) -> str:
    """The innermost named function containing `line`, or `<global>`. For a pure insertion, `line` is the line the
    new code follows, so a function whose closing brace is on that line does not contain it."""
    inside = [(last - first, name) for name, first, last in spans if first <= line <= last and not (inserted and line == last)]
    return min(inside)[1] if inside else "<global>"


def old_hunks(repo: Path, vulnerable: str, fixed: str, path: str) -> list[tuple[int, int, bool]]:
    """Vulnerable-side line ranges the fix changes in `path`, and whether each is a pure insertion (then the range
    is the line it follows, at least 1)."""
    diff = git(repo, "diff", "-U0", vulnerable, fixed, "--", path)
    ranges = []
    for start, count in re.findall(r"^@@ -(\d+)(?:,(\d+))? \+", diff, re.M):
        first, size = int(start), 1 if count == "" else int(count)
        ranges.append((max(first, 1), max(first, 1), True) if size == 0 else (first, first + size - 1, False))
    return ranges


def changed_functions(repo: Path, vulnerable: str, fixed: str, path: str) -> list[str]:
    """The functions (or `<global>`) of `path` at the vulnerable pin that the fix's hunks touch, in hunk order."""
    text = (blob(repo, vulnerable, path) or b"").decode(errors="replace")
    spans, names = php_functions(text), []
    for first, last, inserted in old_hunks(repo, vulnerable, fixed, path):
        for line in range(first, last + 1):
            name = enclosing(spans, line, inserted)
            # New code added between functions (a new helper) changes no vulnerable-side code: no site.
            if name not in names and not (inserted and name == "<global>"):
                names.append(name)
    return names


def resolve_sites(repo: Path, case: dict[str, object], changed: list[str]) -> dict[str, object]:
    """Decision 2 of population v3: a file the advisory names without a function gets, as its declared site, the
    function(s) the fix's diff of that file changes. Advisory-named sites are kept and marked as such."""
    declared = [str(s) for s in case.get("sites", [])]  # type: ignore[union-attr]
    recorded = case.get("site_basis") or {}  # a frozen population keeps each site's basis
    basis = {site: recorded.get(site, "advisory-named") for site in declared}  # type: ignore[union-attr]
    unresolved = {}
    named_files = {site.partition("::")[0] for site in declared}
    for path in [str(f) for f in case.get("site_files", [])]:  # type: ignore[union-attr]
        if path in named_files:
            continue
        if path not in changed:
            unresolved[path] = "the fix does not change this file"
            continue
        for name in changed_functions(repo, str(case["vulnerable"]), str(case["fixed"]), path):
            basis.setdefault(f"{path}::{name}", "resolved-from-fix-diff")
    return {"sites": list(basis), "site_basis": basis, "site_files_unresolved": unresolved}


def fix_changes_sites(repo: Path, case: dict[str, object], sites: list[str]) -> dict[str, bool]:
    """Per declared site: does the fix's diff change a line inside that function (or the file, for `<global>`)?"""
    result = {}
    for site in sites:
        path, _, name = site.partition("::")
        hunks = old_hunks(repo, str(case["vulnerable"]), str(case["fixed"]), path)
        if name == "<global>" or not hunks:
            result[site] = bool(hunks)
            continue
        spans = php_functions((blob(repo, str(case["vulnerable"]), path) or b"").decode(errors="replace"))
        result[site] = any(enclosing(spans, line, inserted) == name for first, last, inserted in hunks for line in range(first, last + 1))
    return result


def benign(
    repo: Path, fixed: str, sink_file: str, extensions: tuple[str, ...], strict: bool = False, vulnerable: str = ""
) -> dict[str, object] | None:
    """The first acceptable change after the fix (see the module docstring).

    `strict` (a single-language population, v3) tightens the proposal: the change is measured against its first
    parent, so a merge counts with everything it brings in, and every message it brings in is checked for security
    words (a branch-sync merge can carry the fix itself); it must change a file of the population's language; and
    when no commit after the fix qualifies, the history before the vulnerable pin is searched, newest first."""
    head = git(repo, "rev-parse", "origin/HEAD", check=False).strip() or git(repo, "rev-parse", "HEAD").strip()
    span = [f"{fixed}..{head}"]
    if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", fixed, head], check=False).returncode:
        # A fix on a maintenance branch (population v3: kirby 4.x, roundcube 1.6): the default branch's commits
        # after the fix date, not its whole history outside the branch.
        span = [f"--since={git(repo, 'log', '-1', '--format=%cI', fixed).strip()}", head]
    commits = git(repo, "rev-list", "--first-parent", "--reverse", *span, check=False).split()[:400]
    after = set(commits)
    if strict and vulnerable:
        commits += git(repo, "rev-list", "--first-parent", "--max-count=400", f"{vulnerable}^", check=False).split()
    for commit in commits:
        parent = git(repo, "rev-parse", f"{commit}^", check=False).strip()
        if not parent:
            continue
        if strict:
            message = git(repo, "log", "--format=%s%n%b", f"{parent}..{commit}")
            stat = git(repo, "diff", "--numstat", parent, commit).splitlines()
        else:
            message = git(repo, "log", "-1", "--format=%s%n%b", commit)
            stat = git(repo, "show", "--numstat", "--format=", commit).splitlines()
        if SECURITY_WORDS.search(message):
            continue
        files = [line.split("\t") for line in stat if line.count("\t") == 2]
        if not files or any(f[2] == sink_file for f in files):
            continue
        source = [f for f in files if f[2].endswith(extensions)]
        lines = sum(int(a) + int(b) for a, b, _ in files if a.isdigit() and b.isdigit())
        if source and 0 < lines <= MAX_BENIGN_LINES:
            subject = git(repo, "log", "-1", "--format=%s", commit).strip()
            side = "after the fix" if commit in after else "before the vulnerable pin"
            return {"base": parent, "tip": commit, "subject": subject[:120], "files": [f[2] for f in files], "lines": lines, "side": side}
    return None


def verify(case: dict[str, object], cache: Path) -> dict[str, object]:
    url, vulnerable, fixed = str(case["repo"]), str(case["vulnerable"]), str(case["fixed"])
    repo = cache / str(case["id"])
    clone(url, repo)
    record: dict[str, object] = {"id": case["id"], "repo": url, "vulnerable": vulnerable, "fixed": fixed, "problems": []}
    problems: list[str] = record["problems"]  # type: ignore[assignment]
    for pin in (vulnerable, fixed):
        if git(repo, "cat-file", "-t", pin, check=False).strip() != "commit":
            problems.append(f"pin {pin[:12]} is not a commit in the repository")
    if problems:
        return record
    ordered = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", vulnerable, fixed], check=False).returncode == 0
    record["vulnerable_is_ancestor_of_fixed"] = ordered
    if not ordered:
        problems.append("the vulnerable pin is not an ancestor of the fixed pin")
    changed = git(repo, "diff", "--name-only", vulnerable, fixed).splitlines()
    sites = [str(site) for site in case.get("sites", [])]  # type: ignore[union-attr]
    if case.get("site_files"):
        # Population v3: files the advisory names without a function are resolved from the fix's diff.
        record.update(resolve_sites(repo, case, changed))
        sites = record["sites"]  # type: ignore[assignment]
        if not sites:
            problems.append("no declared site: the advisory names no function and the fix changes no named file")
    if case.get("fix_named_by_advisory") is False:
        # An inferred fix must change the declared sink file and at least one declared site function.
        basis = record.get("site_basis") or {}
        named = [s for s in sites if basis.get(s, "advisory-named") == "advisory-named"]  # type: ignore[union-attr]
        touched = fix_changes_sites(repo, case, named)
        record["inferred_fix_changes_sites"] = touched
        if not any(touched.values()):
            problems.append("the inferred fix changes none of the declared site functions: drop the case")
    if sites:
        # Declared `path::function` sites (population v2) are what the verification reads; the first names the
        # sink file, and every function declared in that file must appear in it.
        sink_file = sites[0].partition("::")[0]
        functions = [site.partition("::")[2] for site in sites if site.partition("::")[0] == sink_file and not site.endswith("::<global>")]
    else:
        sink_file, functions = sink_parts(str(case["sink"]))
    record["sink_file"], record["sink_functions"] = sink_file, functions
    before, after = blob(repo, vulnerable, sink_file), blob(repo, fixed, sink_file)
    if before is None:
        problems.append(f"sink file {sink_file} is absent at the vulnerable pin")
    else:
        record["sink_sha256_vulnerable"] = hashlib.sha256(before).hexdigest()
        text = before.decode(errors="replace")
        evidence = str(case.get("sink_evidence", ""))
        if evidence:
            record["sink_evidence_found"] = evidence in text
            if evidence not in text:
                problems.append(f"sink evidence {evidence!r} is absent from {sink_file} at the vulnerable pin")
        else:
            missing = [f for f in functions if f.split("::")[-1] not in text]
            record["sink_functions_missing"] = missing
            if functions and len(missing) == len(functions):
                problems.append(f"none of {functions} appears in {sink_file} at the vulnerable pin")
    if after is not None:
        record["sink_sha256_fixed"] = hashlib.sha256(after).hexdigest()
    record["fix_changed_files"] = len(changed)
    record["fix_touches_sink_file"] = sink_file in changed
    fix_site = str(case.get("fix_site", "")).partition("::")[0].strip()
    record["fix_touches_fix_site"] = bool(fix_site) and fix_site in changed
    if sink_file not in changed and not record["fix_touches_fix_site"]:
        problems.append(f"the fix changes neither {sink_file} nor a declared fix_site")
    languages = [str(case["language"]), *[str(x) for x in case.get("also", [])]]  # type: ignore[union-attr]
    extensions = tuple(e for lang in languages for e in EXTENSIONS.get(lang, ()))
    strict = bool(case.get("_population_language"))
    if strict:
        extensions = EXTENSIONS.get(str(case["_population_language"]), extensions)
    record["benign_proposal"] = benign(repo, fixed, sink_file, extensions, strict, vulnerable)
    if record["benign_proposal"] is None and not case.get("benign"):
        problems.append("no benign change found automatically; choose one by hand")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "openultrasast" / "independent")
    parser.add_argument("--only", default="")
    parser.add_argument("--population", type=Path, default=POPULATION, help="a population-vN.toml in this directory")
    args = parser.parse_args()
    population = args.population if args.population.is_absolute() else HERE / args.population.name
    data = tomllib.loads(population.read_text())
    cases = data["case"]
    for case in cases:
        # A single-language population (v3) gets the strict benign proposal (see `benign`).
        case["_population_language"] = data.get("language", "")
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    records = []
    for case in cases:
        if only and case["id"] not in only:
            continue
        try:
            record = verify(case, args.cache)
        except (RuntimeError, subprocess.CalledProcessError) as error:
            record = {"id": case["id"], "problems": [f"could not verify: {error}"]}
        records.append(record)
        print(
            json.dumps(
                {"id": record["id"], "problems": record["problems"], "benign": (record.get("benign_proposal") or {}).get("subject")}
            ),
            flush=True,
        )
    freeze_record(population).write_text(
        json.dumps({"schema_version": 1, "population": population.name, "cases": records}, indent=2) + "\n"
    )
    return 0 if all(not r["problems"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
