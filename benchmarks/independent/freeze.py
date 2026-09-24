"""Verify each reserved case by READING its source, and propose a benign change -- without scanning anything.

Freezing the independent population (pre-push-safety-net 15.1) needs, per case: both pins present and in the
right order, the vulnerable sink confirmed where the advisory says it is, the fix touching that file, and a
benign change from the same history. This does exactly that with git and file reads. It never imports or runs
the analyzer, its queries, or any project tooling: a case this script touched is still unscanned.

The benign change is a PROPOSAL for review, chosen mechanically: the first commit after the fix, on the first
-parent line, that changes source files of the case's language, does not touch the sink file, does not talk
about security in its message, and stays small. A reviewer confirms or replaces it before the status becomes
`frozen`.

Usage: python benchmarks/independent/freeze.py [--cache DIR] [--only ID,...]
Writes: benchmarks/independent/freeze-v1.json
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
OUT = HERE / "freeze-v1.json"
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
    r"|token|scope|valid|filter|privileg|role|owner|password|secret|redirect|sql|query|login|log in|ldap|session|ssl|tls|verif|cert|crypt|hash|cookie",
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


def benign(repo: Path, fixed: str, sink_file: str, extensions: tuple[str, ...]) -> dict[str, object] | None:
    head = git(repo, "rev-parse", "origin/HEAD", check=False).strip() or git(repo, "rev-parse", "HEAD").strip()
    commits = git(repo, "rev-list", "--first-parent", "--reverse", f"{fixed}..{head}", check=False).split()[:400]
    for commit in commits:
        message = git(repo, "log", "-1", "--format=%s%n%b", commit)
        if SECURITY_WORDS.search(message):
            continue
        stat = git(repo, "show", "--numstat", "--format=", commit).splitlines()
        files = [line.split("\t") for line in stat if line.count("\t") == 2]
        if not files or any(f[2] == sink_file for f in files):
            continue
        source = [f for f in files if f[2].endswith(extensions)]
        lines = sum(int(a) + int(b) for a, b, _ in files if a.isdigit() and b.isdigit())
        if source and 0 < lines <= MAX_BENIGN_LINES:
            parent = git(repo, "rev-parse", f"{commit}^").strip()
            return {"base": parent, "tip": commit, "subject": message.splitlines()[0][:120], "files": [f[2] for f in files], "lines": lines}
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
    changed = git(repo, "diff", "--name-only", vulnerable, fixed).splitlines()
    record["fix_changed_files"] = len(changed)
    record["fix_touches_sink_file"] = sink_file in changed
    fix_site = str(case.get("fix_site", "")).partition("::")[0].strip()
    record["fix_touches_fix_site"] = bool(fix_site) and fix_site in changed
    if sink_file not in changed and not record["fix_touches_fix_site"]:
        problems.append(f"the fix changes neither {sink_file} nor a declared fix_site")
    languages = [str(case["language"]), *[str(x) for x in case.get("also", [])]]  # type: ignore[union-attr]
    extensions = tuple(e for lang in languages for e in EXTENSIONS.get(lang, ()))
    record["benign_proposal"] = benign(repo, fixed, sink_file, extensions)
    if record["benign_proposal"] is None:
        problems.append("no benign change found automatically; choose one by hand")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "openultrasast" / "independent")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    cases = tomllib.loads(POPULATION.read_text())["case"]
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
    OUT.write_text(json.dumps({"schema_version": 1, "population": POPULATION.name, "cases": records}, indent=2) + "\n")
    return 0 if all(not r["problems"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
