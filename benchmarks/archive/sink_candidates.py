"""Diagnostic: would SINK-FIRST selection, from source alone, put the vulnerable function in scope?

The v2 hunter experiment showed scope selection is the bottleneck: the ranker's top 20 entry-point regions held
the vulnerable file in 1 of 17 cases. This asks the opposite direction without any engine or model: at each
case's vulnerable pin, every call matching the family's shipped sink vocabulary (`taint_specs`) in product
source is a candidate, attributed to its enclosing function by a per-language declaration scan. It reports how
many candidates a repository yields (the budget a hunter would need) and whether a declared site function, or
at least a file the fix changes, is among them.

Source only: the checkout is the pin's tree; git is used to export it and, for the score, to read the fix's
changed files -- never to choose scope.

v2 is spent for tuning; this informs the selection design and qualifies nothing.

Usage: python benchmarks/archive/sink_candidates.py [--population population-v2.toml] [--only ID,...]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

# Archived 2026-10-02 from benchmarks/independent/: HERE stays that directory (population, evaluate.py, results).
HERE = Path(__file__).resolve().parents[1] / "independent"
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402

from openultrasast.model.specs import taint_specs  # noqa: E402
from openultrasast.preprocess import detect_language, enumerate_source_files  # noqa: E402

DECLARATION = {
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)"),
    "php": re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)"),
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)|^\s*(?:(?:public|private|protected|static|async)\s+)*(\w+)\s*\([^;]*\)\s*(?::[^{=]+)?\{\s*$|^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function|\()"),
}
DECLARATION["typescript"] = DECLARATION["javascript"]
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "else"}


def token(name: str) -> re.Pattern[str]:
    before = r"(?<![A-Za-z0-9_$])" if name[:1].isalnum() or name[:1] in "_$" else ""
    return re.compile(before + re.escape(name) + r"\s*\(")


def enclosing(lines: list[str], index: int, language: str) -> str:
    pattern = DECLARATION.get(language)
    if pattern is None:
        return ""
    for back in range(index, -1, -1):
        match = pattern.match(lines[back])
        if match:
            name = next((g for g in match.groups() if g), "")
            if name and name not in KEYWORDS:
                return name
    return "<global>"


def candidates(root: Path, family: str) -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    patterns: dict[str, list[re.Pattern[str]]] = {}
    for path in enumerate_source_files(root):
        language = detect_language(path)
        if language not in patterns:
            spec = taint_specs(language=language).get(family) if language != "unknown" else None
            patterns[language] = [token(n) for n in spec.sinks] if spec else []
        if not patterns[language]:
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*")):
                continue
            if any(p.search(line) for p in patterns[language]):
                found.setdefault((relative, enclosing(lines, index, language)), []).append(index + 1)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=HERE / "population-v2.toml")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    evaluate.use(args.population)
    evaluate.RESULTS = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-sinkfirst")
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    rows = []
    for case in evaluate.cases():
        if only and case["id"] not in only:
            continue
        checkout = evaluate.export(case, "vulnerable", case["vulnerable"])
        try:
            found = candidates(checkout, case["family"])
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
        changed = set(evaluate.hunks(case, "old"))
        sites = {tuple(site.split("::", 1)) for site in case.get("sites", [])}
        site_hit = sorted(f"{p}::{f}" for p, f in found if (p, f) in sites)
        file_hit = sorted({p for p, _ in found if p in changed or p in {s[0] for s in sites}})
        row = {
            "id": case["id"], "family": case["family"], "candidate_functions": len(found),
            "candidate_files": len({p for p, _ in found}), "declared_site_in_candidates": site_hit,
            "fix_or_site_file_in_candidates": file_hit[:5],
        }  # fmt: skip
        rows.append(row)
        print(json.dumps(row), flush=True)
    sites_in = sum(bool(r["declared_site_in_candidates"]) for r in rows)
    files_in = sum(bool(r["fix_or_site_file_in_candidates"]) for r in rows)
    print(json.dumps({"cases": len(rows), "declared_site_in_candidates": sites_in, "fix_or_site_file_in_candidates": files_in}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
