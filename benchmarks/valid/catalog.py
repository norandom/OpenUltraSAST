"""Build fix-site pairs from resolved advisories and local Git objects only."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
from dataclasses import asdict, is_dataclass
from functools import cache
from pathlib import Path

from benchmarks.unseen import extract
from benchmarks.unseen.draft import toml
from benchmarks.unseen.eligibility import normalize

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",  # added 2026-10-13 for the training set: extract.fix_sites and function_bounds both read Java and PHP
    ".php": "php",
}


def local_git(path: Path):
    """Disable partial-clone lazy fetches while reading existing local objects."""

    def runner(argv, **kwargs):
        return subprocess.run(argv, env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}, **kwargs)

    return extract.Git(path, runner=runner)


@cache
def pair_builder():
    path = Path(__file__).resolve().parents[1] / "pairs/advisory-fixes/materialize.py"
    spec = importlib.util.spec_from_file_location("valid_pair_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pair builder could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_functions(git, case: dict, *, report=None) -> dict:
    """Use the pair builder's function_bounds cutter on both pinned snapshots."""
    result = {}
    for side, sha in (("pre_fix", case["parent"]), ("post_fix", case["commit"])):
        source = git.blob(sha, case["path"])
        cut = pair_builder().extract(source, case["language"], case["function"]) if source else None
        if cut is None and report:
            report(side, 0)
        if cut is None:
            raise extract.InstrumentFailure(f"{side} function unread or undeclared")
        lines, (start, end) = cut
        function = "\n".join(lines[start:end])
        if report:
            report(side, len(function.encode("utf-8")))
        if not function.strip():
            raise extract.InstrumentFailure(f"{side} function empty")
        result[side] = function
        result[side + "_lines"] = [start + 1, end]
        result[side + "_context"] = "\n".join(lines[max(0, start - 30) : min(len(lines), end + 30)])
    return result


def build_cases(git, source, *, cwe: str | None = None, advisory_text: str = "") -> list[dict]:
    """Accept source.Candidate or its resolved dictionary, with advisory metadata."""
    source = asdict(source) if is_dataclass(source) else dict(source)
    repo = normalize(source.get("repository") or source["repo"])
    fix, parent = source.get("fix") or source["commit"], source["parent"]
    if not extract.SHA.fullmatch(fix) or not extract.SHA.fullmatch(parent) or fix == parent:
        raise ValueError("fix and parent must be distinct full SHAs")
    if git.parents(fix) != [parent]:
        raise ValueError("fix must have exactly the supplied parent")
    cwe = cwe or source.get("cwe")
    if not cwe or not re.fullmatch(r"CWE-\d+", cwe) or not source.get("family"):
        raise ValueError("advisory CWE and family are required")
    rows = []
    for site in extract.fix_sites(git, fix, parent):
        language = LANGUAGES.get(Path(site["path"]).suffix)
        if language is None:
            continue
        identity = [repo, source["advisory"], fix, site["path"], site["function"]]
        from benchmarks.unseen.journal import digest

        case = dict(
            id=repo.replace("/", "-") + "-" + digest(identity)[:16],
            repo=repo,
            url=source["url"],
            advisory=source["advisory"],
            cwe=cwe,
            family=source["family"],
            language=language,
            commit=fix,
            parent=parent,
            path=site["path"],
            function=site["function"],
            method="fix_site",
        )
        try:
            sides = read_functions(git, case)
        except extract.InstrumentFailure:
            # The fix renamed, moved, or removed the function, so there is no clean
            # pre/post pair at this site. Skip it during enumeration. Verification
            # stays strict: a verdict on an unread case is still rejected there.
            continue
        if extract.normalized(sides["pre_fix"]) == extract.normalized(sides["post_fix"]):
            continue
        case["function_lines"] = [sides["pre_fix_lines"]]
        case.update(pre_fix=sides["pre_fix"], post_fix=sides["post_fix"], advisory_text=advisory_text or source.get("advisory_text", ""))
        rows.append(case)
    return sorted(rows, key=lambda row: row["id"])


def write_catalog(path: Path, cases: list[dict]) -> None:
    if len({row["id"] for row in cases}) != len(cases):
        raise ValueError("duplicate case id")
    text = "\n".join(
        "[[case]]\n" + "\n".join(f"{key} = {toml(value)}" for key, value in sorted(row.items())) + "\n"
        for row in sorted(cases, key=lambda row: row["id"])
    )
    path.write_text(text, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", type=Path, help="JSON array of resolved Candidate dictionaries with CWE and advisory_text")
    parser.add_argument("--repos", type=Path, required=True, help="JSON map of repository names to local Git directories")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    repos = {normalize(k): local_git(Path(v)) for k, v in json.loads(args.repos.read_text()).items()}
    cases = [
        case
        for source in json.loads(args.sources.read_text())
        for case in build_cases(repos[normalize(source.get("repository") or source["repo"])], source)
    ]
    write_catalog(args.out, cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
