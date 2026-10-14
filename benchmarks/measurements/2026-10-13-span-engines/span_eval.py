"""Compare the project's two function-span engines against lizard and tree-sitter-language-pack.

Run with the project venv from the repository root:
    .venv/bin/python /home/mc/ousast-results/fossil/span-eval/span_eval.py
Writes results.json and tables.md next to this file. Single process, modest memory, 10 s cap per file per engine.
"""

from __future__ import annotations

import json
import re
import signal
import statistics
import sys
import time
import traceback
from collections import defaultdict
from pathlib import Path

REPO = Path("/home/mc/Source/OpenUltraSAST")
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

import lizard  # noqa: E402
import tree_sitter_language_pack as tslp  # noqa: E402
from lizard_ext import lizardnd  # noqa: E402,F401  (registers max_nesting_depth)

from openultrasast.complexity.signals import measure_nesting  # noqa: E402
from openultrasast.pairs import load_pair_catalog  # noqa: E402
from openultrasast.source import (  # noqa: E402
    MODULE_FUNCTION,
    canonical_language,
    declared_functions,
    function_bounds,
    ranges,
    spans_named,
)

TIMEOUT_S = 10
EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".in": "perl",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}
LIZARD_EXT = {".in": ".pl"}  # lizard picks its reader by extension; the *.in pairs are Perl (c_rehash.in), which lizard has no reader for
ANON = {"<anon>", "(anonymous)", "", "<module>"}


class Timeout(Exception):
    pass


def _alarm(signum, frame):  # noqa: ANN001
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def timed(fn, *args):
    """Return (result, seconds, error-string|None); error is 'timeout' after TIMEOUT_S."""
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_S)
    t0 = time.perf_counter()
    try:
        return fn(*args), time.perf_counter() - t0, None
    except Timeout:
        return None, time.perf_counter() - t0, "timeout"
    except Exception as exc:  # noqa: BLE001
        return None, time.perf_counter() - t0, f"{type(exc).__name__}: {str(exc)[:120]}"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def _keep_earliest(out: dict, name: str, span: tuple[int, int]) -> None:
    """One span per name: the earliest declaration, like source.function_bounds."""
    if name not in out or span[0] < out[name][0]:
        out[name] = span


def base_name(name: str) -> str:
    """Reduce Class::method, a.b, obj->m to the last segment, as source.function_bounds does."""
    return re.split(r"::|\.|->", name)[-1].strip()


# ---------------------------------------------------------------- engines: each returns {name: (start1, end1)} first span


def ours_parser(path: str, text: str, language: str) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for r in ranges(path, text, language):
        if r.name == MODULE_FUNCTION or r.name in ANON:
            continue
        _keep_earliest(out, base_name(r.name), (r.start, r.end))
    return out


def ours_line(path: str, lines: list[str], language: str) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for name in declared_functions(lines, language):
        b = function_bounds(lines, language, name)
        if b is not None:
            _keep_earliest(out, base_name(name), (b[0] + 1, b[1]))
    return out


_LIZ = lizard.FileAnalyzer(lizard.get_extensions(["nd"]))


def lizard_units(path: str, text: str, language: str):
    suffix = Path(path).suffix
    fake = "x" + LIZARD_EXT.get(suffix, suffix)
    return _LIZ.analyze_source_code(fake, text)


def lizard_spans(info) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for f in info.function_list:
        n = base_name(f.name)
        if n in ANON:
            continue
        _keep_earliest(out, n, (f.start_line, f.end_line))
    return out


TS_LANG = {
    "perl": None,
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "cpp": "cpp",
    "c": "c",
    "go": "go",
    "ruby": "ruby",
    "php": "php",
}
TS_FUNC = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function", "function_expression", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition", "arrow_function", "function_expression", "generator_function_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "cpp": {"function_definition"},
    "c": {"function_definition"},
    "go": {"function_declaration", "method_declaration"},
    "ruby": {"method", "singleton_method"},
    "php": {"function_definition", "method_declaration"},
}
_parsers: dict[str, object] = {}


def _ts_parser(language: str, path: str):
    key = "tsx" if language == "typescript" and path.endswith(".tsx") else TS_LANG[language]
    if key not in _parsers:
        _parsers[key] = tslp.get_parser(key)
    return _parsers[key]


def _c_name(node) -> str:
    d = node.child_by_field_name("declarator")
    while d is not None:
        if d.type in ("identifier", "field_identifier", "qualified_identifier", "destructor_name", "operator_name", "template_function"):
            return d.text.decode(errors="replace")
        nxt = d.child_by_field_name("declarator")
        if nxt is None:
            # parenthesized_declarator / pointer_declarator without the field: take the first named child
            nxt = next((c for c in d.children if c.is_named), None)
        d = nxt
    return ""


def _js_name(node) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return name.text.decode(errors="replace")
    p = node.parent
    if p is not None and p.type == "variable_declarator":
        n = p.child_by_field_name("name")
        return n.text.decode(errors="replace") if n is not None else ""
    if p is not None and p.type == "pair":
        k = p.child_by_field_name("key")
        return k.text.decode(errors="replace") if k is not None else ""
    if p is not None and p.type == "assignment_expression":
        left = p.child_by_field_name("left")
        return left.text.decode(errors="replace") if left is not None else ""
    return ""


def tslp_spans(path: str, text: str, language: str) -> dict[str, tuple[int, int]]:
    if TS_LANG.get(language) is None:
        raise ValueError("no grammar for " + language)
    parser = _ts_parser(language, path)
    tree = parser.parse(text.encode())
    if tree.root_node.has_error:
        raise ValueError("parse error")
    kinds = TS_FUNC[language]
    out: dict[str, tuple[int, int]] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in kinds:
            if language in ("cpp", "c"):
                name = _c_name(node)
            elif language in ("javascript", "typescript"):
                name = _js_name(node)
            else:
                n = node.child_by_field_name("name")
                name = n.text.decode(errors="replace") if n is not None else ""
            name = base_name(name)
            if name and name not in ANON and re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                _keep_earliest(out, name, (node.start_point[0] + 1, node.end_point[0] + 1))
        stack.extend(node.children)
    return out


# ---------------------------------------------------------------- corpus


def corpus() -> tuple[list[tuple[Path, str]], list[tuple[Path, str, str]]]:
    cases = load_pair_catalog()
    lang_of: dict[Path, str] = {}
    labels: list[tuple[Path, str, str]] = []
    for c in cases:
        if not c.vendored:
            continue
        lang = canonical_language(c.language)
        for f in (c.vuln_file, c.fixed_file):
            if f.suffix == ".in":
                lang = "perl"  # catalog says cpp; the text is c_rehash.in Perl and ours sniffs it (resolve_language)
            if lang in EXT_LANG.values():
                lang_of[f.resolve()] = lang
        for row in c.expected:
            if row.function:
                labels.append((c.vuln_file.resolve(), row.function, c.name))
                labels.append((c.fixed_file.resolve(), c.fix_function or row.function, c.name))
    files: list[tuple[Path, str]] = []
    pair_files = (REPO / "benchmarks/pairs").rglob("*")
    candidates = set(lang_of) | {f.resolve() for f in pair_files if re.fullmatch(r"(vuln|fixed)\.[a-z]+", f.name)}
    for f in sorted(candidates):
        if not f.is_file() or "/private/" in f.as_posix():
            continue
        lang = lang_of.get(f.resolve()) or EXT_LANG.get(f.suffix)
        if lang is None or f.stat().st_size > 1_000_000:
            continue
        files.append((f.resolve(), lang))
    seen = set()
    labels = [label for label in labels if not (label[:2] in seen or seen.add(label[:2]))]
    return files, labels


# ---------------------------------------------------------------- spearman without scipy


def _ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    r = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def spearman(xs, ys) -> float | None:
    if len(xs) < 3:
        return None
    rx, ry = _ranks(xs), _ranks(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return None if den == 0 else num / den


# ---------------------------------------------------------------- main


def main() -> None:
    files, labels = corpus()
    print(f"corpus files={len(files)} labelled (file,function)={len(labels)}", file=sys.stderr)
    engines = ("ours_parser", "ours_line", "lizard", "tslp")
    per_file: dict[Path, dict] = {}
    runtime = {e: 0.0 for e in engines}
    failures = {e: [] for e in engines}
    rel = lambda p: p.relative_to(REPO).as_posix()  # noqa: E731
    first_check = True
    for path, lang in files:
        text = path.read_text(errors="replace")
        lines = text.splitlines()
        if first_check:
            print(f"instrument check: read {rel(path)} size={len(text)} bytes lines={len(lines)}", file=sys.stderr)
            first_check = False
        rec = {"lang": lang, "lines": len(lines), "spans": {}, "liz": None}
        r, dt, err = timed(ours_parser, rel(path), text, lang)
        runtime["ours_parser"] += dt
        rec["spans"]["ours_parser"] = r
        if err:
            failures["ours_parser"].append((rel(path), err))
        r, dt, err = timed(ours_line, rel(path), lines, lang)
        runtime["ours_line"] += dt
        rec["spans"]["ours_line"] = r
        if err:
            failures["ours_line"].append((rel(path), err))
        info, dt, err = timed(lizard_units, rel(path), text, lang)
        runtime["lizard"] += dt
        if err:
            failures["lizard"].append((rel(path), err))
            rec["spans"]["lizard"] = None
        else:
            rec["spans"]["lizard"] = lizard_spans(info)
            covered = set()
            for f in info.function_list:
                covered.update(range(f.start_line, f.end_line + 1))
            code_lines = [i + 1 for i, line in enumerate(lines) if line.strip()]
            rec["liz"] = {
                "max_nd": max((f.max_nesting_depth for f in info.function_list), default=0),
                "max_ccn": max((f.cyclomatic_complexity for f in info.function_list), default=0),
                "sum_ccn": sum(f.cyclomatic_complexity for f in info.function_list),
                "n_units": len(info.function_list),
                "module_code_lines": sum(1 for i in code_lines if i not in covered),
                "code_lines": len(code_lines),
            }
            rec["ours_nesting"] = measure_nesting(text)
        r, dt, err = timed(tslp_spans, rel(path), text, lang)
        runtime["tslp"] += dt
        rec["spans"]["tslp"] = r
        if err:
            failures["tslp"].append((rel(path), err))
        per_file[path] = rec

    # 1. coverage of labelled functions, 2. span agreement
    cov = defaultdict(lambda: {e: [0, 0] for e in engines})  # lang -> engine -> [hit, total]
    agree = defaultdict(lambda: defaultdict(list))  # (ours, cand) -> lang -> list of (start_eq, |end diff|)
    misses = defaultdict(list)
    for path, function, case in labels:
        rec = per_file.get(path)
        if rec is None:
            continue
        lang = rec["lang"]
        name = base_name(function)
        found = {}
        for e in engines:
            spans = rec["spans"][e] or {}
            s = spans.get(name)
            if e == "ours_line" and s is None and rec["spans"][e] is not None:
                b = function_bounds(path.read_text(errors="replace").splitlines(), lang, function)
                s = (b[0] + 1, b[1]) if b else None
            if e == "ours_parser" and s is None and rec["spans"][e] is not None:
                try:
                    sp = spans_named(ranges(rel(path), path.read_text(errors="replace"), lang), function)
                    s = sp[0] if sp else None
                except ValueError:
                    s = None
            found[e] = s
            cov[lang][e][1] += 1
            cov["all"][e][1] += 1
            if s is not None:
                cov[lang][e][0] += 1
                cov["all"][e][0] += 1
            elif e in ("lizard", "tslp"):
                misses[e].append(f"{case}:{rel(path)}:{function}")
        for ours in ("ours_parser", "ours_line"):
            for cand in ("lizard", "tslp"):
                a, b = found[ours], found[cand]
                if a and b:
                    for key in (lang, "all"):
                        agree[(ours, cand)][key].append((a[0] == b[0], abs(a[1] - b[1])))

    # 3. name Jaccard on whole files
    jac = defaultdict(lambda: defaultdict(list))
    for rec in per_file.values():
        for ours in ("ours_parser", "ours_line"):
            for cand in ("lizard", "tslp"):
                a, b = rec["spans"][ours], rec["spans"][cand]
                if a is None or b is None:
                    continue
                sa, sb = set(a), set(b)
                if not sa and not sb:
                    continue
                for key in (rec["lang"], "all"):
                    jac[(ours, cand)][key].append(len(sa & sb) / len(sa | sb))

    # 5. lizard nesting / ccn vs measure_nesting on 50 python + 50 JS files
    corr = {}
    for label, pick in (("python", lambda r: r["lang"] == "python"), ("javascript", lambda r: r["lang"] in ("javascript", "typescript"))):
        recs = [r for r in per_file.values() if pick(r) and r["liz"] is not None][:50]
        ours_v = [r["ours_nesting"] for r in recs]
        corr[label] = {
            "n": len(recs),
            "spearman_max_nesting_depth": spearman(ours_v, [r["liz"]["max_nd"] for r in recs]),
            "spearman_max_ccn": spearman(ours_v, [r["liz"]["max_ccn"] for r in recs]),
            "spearman_sum_ccn": spearman(ours_v, [r["liz"]["sum_ccn"] for r in recs]),
            "exact_equal_max_nd": sum(1 for r in recs if r["ours_nesting"] == r["liz"]["max_nd"]),
        }

    # 6. module-level share
    module = defaultdict(lambda: [0, 0, 0])
    for rec in per_file.values():
        if rec["liz"]:
            for key in (rec["lang"], "all"):
                module[key][0] += rec["liz"]["module_code_lines"]
                module[key][1] += rec["liz"]["code_lines"]
                module[key][2] += 1 if rec["liz"]["n_units"] == 0 else 0

    n = len(files)
    out = {
        "files": n,
        "labels": len(labels),
        "runtime_s_per_1000": {e: runtime[e] / n * 1000 for e in engines},
        "failures": failures,
        "coverage": {k: {e: v for e, v in d.items()} for k, d in cov.items()},
        "agreement": {
            f"{o}~{c}": {
                k: {
                    "n": len(v),
                    "start_eq": sum(x for x, _ in v) / len(v),
                    "end_mad": statistics.mean(y for _, y in v),
                    "end_within_1": sum(1 for _, y in v if y <= 1) / len(v),
                }
                for k, v in d.items()
            }
            for (o, c), d in agree.items()
        },
        "jaccard": {f"{o}~{c}": {k: {"n": len(v), "mean": statistics.mean(v)} for k, v in d.items()} for (o, c), d in jac.items()},
        "nesting": corr,
        "module_share": {k: {"module_code_lines": v[0], "code_lines": v[1], "files_without_units": v[2]} for k, v in module.items()},
        "candidate_misses": {e: v[:40] for e, v in misses.items()},
        "lang_counts": dict(sorted({lang: sum(1 for _, x in files if x == lang) for lang in {x for _, x in files}}.items())),
    }
    (OUT / "results.json").write_text(json.dumps(out, indent=1, default=str))

    # markdown tables
    md = []
    langs = [lang for lang in ("cpp", "python", "java", "javascript", "typescript", "perl", "all") if lang in cov]
    md.append("### Coverage of labelled functions (hit/total)\n")
    md.append("| language | " + " | ".join(engines) + " |")
    md.append("|---|" + "---|" * len(engines))
    for lang in langs:
        cells = (f"{cov[lang][e][0]}/{cov[lang][e][1]} ({cov[lang][e][0] / max(cov[lang][e][1], 1):.0%})" for e in engines)
        md.append(f"| {lang} | " + " | ".join(cells) + " |")
    md.append("\n### Span agreement on labelled functions both found (start equal %, end mean abs diff, end within 1 line %)\n")
    md.append("| pair | language | n | start= | end MAD | end<=1 |")
    md.append("|---|---|---|---|---|---|")
    for key, d in out["agreement"].items():
        for lang in langs:
            if lang in d:
                v = d[lang]
                md.append(f"| {key} | {lang} | {v['n']} | {v['start_eq']:.0%} | {v['end_mad']:.2f} | {v['end_within_1']:.0%} |")
    md.append("\n### Name-set Jaccard per file (mean)\n")
    md.append("| pair | " + " | ".join(langs) + " |")
    md.append("|---|" + "---|" * len(langs))
    for key, d in out["jaccard"].items():
        md.append(f"| {key} | " + " | ".join(f"{d[lang]['mean']:.2f} (n={d[lang]['n']})" if lang in d else "-" for lang in langs) + " |")
    md.append("\n### Runtime (seconds per 1,000 files, this corpus) and failures\n")
    md.append("| engine | s/1000 files | failures |")
    md.append("|---|---|---|")
    for e in engines:
        md.append(f"| {e} | {out['runtime_s_per_1000'][e]:.1f} | {len(failures[e])} |")
    md.append("\n### lizard nesting/CCN vs measure_nesting (file level, Spearman)\n")
    md.append("| set | n | rho(max_nesting_depth) | rho(max CCN) | rho(sum CCN) | exact == max_nesting_depth |")
    md.append("|---|---|---|---|---|---|")
    for lang, v in corr.items():
        f = lambda x: "-" if x is None else f"{x:.2f}"  # noqa: E731
        rho = f"{f(v['spearman_max_nesting_depth'])} | {f(v['spearman_max_ccn'])} | {f(v['spearman_sum_ccn'])}"
        md.append(f"| {lang} | {v['n']} | {rho} | {v['exact_equal_max_nd']} |")
    md.append("\n### Code lines outside any lizard unit (module-level share)\n")
    md.append("| language | module code lines | code lines | share | files with zero units |")
    md.append("|---|---|---|---|---|")
    for lang in langs:
        if lang in module:
            v = module[lang]
            md.append(f"| {lang} | {v[0]} | {v[1]} | {v[0] / max(v[1], 1):.0%} | {v[2]} |")
    (OUT / "tables.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    print("\nfailures:", json.dumps(failures, indent=1))
    print("\ncandidate misses (first 40):", json.dumps(out["candidate_misses"], indent=1))
    print("\nlang counts:", out["lang_counts"])


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
