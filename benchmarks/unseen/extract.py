"""Git-only change extraction; clients and subprocess execution are injectable.

No scanner, engine or model runs here. Function boundaries are syntax, not a security
judgement: the first removed code line of a fix is the SZZ sink proxy. Ambiguous sites
are dropped, and the recorded SZZ bias remains subject to task 2.6's label check.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import time
from pathlib import Path

from .source import Candidate, Rejected

LANGUAGES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java"}
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)
SHA = re.compile(r"[a-f0-9]{40}")
BIAS = {
    "introducing": "SZZ last-writer proxy: refactors, moves and reformats can misidentify the introduction in either direction.",
    "last_touch": "Pessimistic lower bound: the flaw may already exist in base, so a delta hook can correctly stay quiet.",
}


class InstrumentFailure(ValueError):
    """A failed read or command must never masquerade as an empty history."""


class ExtractionTimeout(Rejected):
    """A slow repository is skipped without aborting the draft."""


class Git:
    def __init__(self, path: Path, *, runner=None, limit_bytes: int | None = None, deadline_seconds: float | None = None, _now=None):
        self._now = _now or time.monotonic
        self.started = self._now()
        self.deadline_seconds = deadline_seconds
        self.path = path
        self.runner = runner or subprocess.run
        self.bytes_read = 0
        self.files_read = 0
        self.last_blob_bytes = 0
        self.limit_bytes = limit_bytes

    def command_timeout(self) -> float:
        if self.deadline_seconds is None:
            return 180
        remaining = self.deadline_seconds - (self._now() - self.started)
        if remaining <= 0:
            raise ExtractionTimeout("extraction_timeout")
        return min(180, remaining)

    def run(self, *args: str, allowed=(0,), input_data: bytes | None = None) -> str:
        timeout = self.command_timeout()
        try:
            done = self.runner(
                ["git", "-c", "core.quotePath=false", "-C", str(self.path), *args],
                **({"stdin": subprocess.DEVNULL} if input_data is None else {"input": input_data}),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ExtractionTimeout("extraction_timeout") from None
        except Exception:
            raise InstrumentFailure("git_launch_failed") from None
        if done.returncode not in allowed:
            raise InstrumentFailure("git_exit_" + str(done.returncode))
        if self.limit_bytes is not None and self.disk_bytes() > self.limit_bytes:
            raise InstrumentFailure("clone_size_cap")
        self.last_blob_bytes = len(done.stdout)
        return done.stdout.decode("utf-8", errors="replace")

    def materialize(self, revisions: list[str]) -> None:
        """Fetch missing historical blobs in one pack, without changing content reads.

        ordinary_history inspects the complete first-parent history, including both
        sides, attributes and non-source diffs. Blame -M/-C and log -L can walk all
        ancestors and copy sources. Include the reachable trees, not only tip files,
        so these commands keep exactly their original semantics. This is a safe
        superset (merge-side trees included), still subject to the disk/deadline caps.
        Missing-object enumeration itself does not trigger lazy blob fetches.
        """
        data = ("\n".join(revisions) + "\n").encode()
        objects = self.run("rev-list", "--objects", "--missing=print", "--stdin", input_data=data)
        missing = sorted({line[1:] for line in objects.splitlines() if line.startswith("?")})
        if not all(SHA.fullmatch(oid) for oid in missing):
            raise InstrumentFailure("invalid_missing_object")
        if missing:
            # stdin avoids argv limits; explicit object wants avoid one promisor
            # request per show/blame. --no-filter overrides clone's stored filter.
            self.run(
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-filter",
                "--stdin",
                "origin",
                input_data=("\n".join(missing) + "\n").encode(),
            )
            remaining = self.run("rev-list", "--objects", "--missing=print", "--stdin", input_data=data)
            if any(line.startswith("?") for line in remaining.splitlines()):
                raise InstrumentFailure("missing_blobs_after_fetch")

    def disk_bytes(self) -> int:
        # git churns .git/objects/pack (incl. transient *.rev) during on-demand blob
        # fetches, so a path rglob just listed can vanish before stat(): skip it.
        total = 0
        for p in self.path.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except OSError:
                continue
        return total

    def parents(self, sha: str) -> list[str]:
        return self.run("rev-list", "--parents", "-n", "1", sha).split()[1:]

    def blob(self, sha: str, path: str) -> str | None:
        # Missing is established by a successful tree read, never by swallowing a show error.
        if not self.run("ls-tree", sha, "--", path).strip():
            return None
        text = self.run("show", f"{sha}:{path}")
        if Path(path).suffix in LANGUAGES:
            self.files_read += 1
            self.bytes_read += self.last_blob_bytes
        return text

    def stats(self, base: str, head: str) -> list[tuple[str, int, int]]:
        rows = []
        for line in self.run("diff", "--no-renames", "--numstat", base, head, "--").splitlines():
            added, removed, path = line.split("\t", 2)
            rows.append((path, int(added) if added.isdigit() else 0, int(removed) if removed.isdigit() else 0))
        return rows

    def hunks(self, base: str, head: str, path: str) -> list[tuple[int, int, int, int]]:
        diff = self.run("diff", "--no-ext-diff", "--no-renames", "-U0", base, head, "--", path)
        return [(int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)) for m in HUNK.finditer(diff)]

    def ancestor(self, older: str, newer: str) -> bool:
        # rev-list avoids interpreting a command failure as a negative ancestry result.
        return not self.run("rev-list", "--max-count=1", older, "--not", newer).strip()

    def blame(self, revision: str, path: str, line: int) -> tuple[str, str, int]:
        text = self.run("blame", "-w", "-M", "-C", "--porcelain", f"-L{line},{line}", revision, "--", path)
        header = text.splitlines()[0].split()
        if len(header) < 3 or not SHA.fullmatch(header[0]):
            raise InstrumentFailure("invalid_blame")
        filename = next((row[9:] for row in text.splitlines() if row.startswith("filename ")), path)
        if filename.startswith('"'):
            filename = json.loads(filename)
        return header[0], filename, int(header[1])


def functions(path: str, text: str) -> list[tuple[str, int, int]]:
    """Conservative syntax boundaries. No scanner import; unresolved sites are rejected."""
    if Path(path).suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            raise Rejected("function_parse") from None
        return [
            (n.name, n.lineno, n.end_lineno or n.lineno) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
    # Blank comments and quoted strings before brace matching. Keep newlines/offsets.
    masked = re.sub(
        r'/\*.*?\*/|//[^\n]*|\#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`',
        lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
        text,
        flags=re.S,
    )
    declaration = re.compile(
        r"\bfunction\s*&?\s*(\w+)\s*\([^)]*\)\s*(?::[^\n{]+)?\s*\{|"
        r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*\{|"
        r"\b([\w$]+)\s*\([^;{}]*\)\s*(?:throws\s+[\w., ]+)?\s*\{"
    )
    found = []
    for match in declaration.finditer(masked):
        name = next(g for g in match.groups() if g)
        if name in {"if", "while", "for", "switch", "catch", "with", "synchronized"}:
            continue
        depth = 1
        end = match.end()
        while end < len(masked) and depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        if depth == 0:
            found.append((name, masked.count("\n", 0, match.start()) + 1, masked.count("\n", 0, end) + 1))
    return found


def enclosing(path: str, text: str, line: int, *, global_ok=False) -> tuple[str, int, int] | None:
    spans = [s for s in functions(path, text) if s[1] <= line <= s[2]]
    if spans:
        return min(spans, key=lambda s: s[2] - s[1])
    return ("<global>", 1, max(1, len(text.splitlines()))) if global_ok else None


def normalized(text: str) -> str:
    return re.sub(r"\s+", "", text)


def site_at(git, revision: str, path: str, name: str):
    text = git.blob(revision, path)
    if text is None:
        return None
    spans = [("<global>", 1, max(1, len(text.splitlines())))] if name == "<global>" else [s for s in functions(path, text) if s[0] == name]
    if len(spans) != 1:
        return None
    return text, spans[0]


def fix_sites(git, fix: str, parent: str, *, global_ok=False) -> list[dict]:
    sites = []
    for path, _, _ in git.stats(parent, fix):
        if Path(path).suffix not in LANGUAGES:
            continue
        text = git.blob(parent, path)
        if text is None:
            continue
        lines = text.splitlines()
        for start, count, _, _ in git.hunks(parent, fix, path):
            for line in range(max(1, start), max(1, start) + max(1, count)):
                if line > len(lines):
                    continue
                span = enclosing(path, text, line, global_ok=global_ok)
                if span is None:
                    continue
                sink_line = line if count else span[1]
                sink = lines[sink_line - 1]
                if not sink.strip() or sink.lstrip().startswith(("#", "//", "/*", "*")):
                    continue
                key = (path, span[0])
                if any((s["path"], s["function"]) == key for s in sites):
                    continue
                sites.append({"path": path, "function": span[0], "line": sink_line, "text": sink, "absence": count == 0, "span": span})
    return sites


def version_bracket(git, candidate: Candidate, revision: str) -> bool:
    if not candidate.first_affected:
        return True
    tags = git.run("tag", "--sort=version:refname").splitlines()
    matching = [t for t in tags if t.removeprefix("v") == candidate.first_affected]
    if len(matching) != 1:
        return False
    affected = matching[0]
    earlier = [t for t in tags[: tags.index(affected)] if git.ancestor(t, affected)]
    return bool(earlier) and git.ancestor(revision, affected) and not git.ancestor(revision, earlier[-1])


def change_files(git, base: str, head: str) -> list[dict]:
    return [
        {"path": path, "head_lines": [[max(1, new), max(1, new + max(count, 1) - 1)] for _, _, new, count in git.hunks(base, head, path)]}
        for path, _, _ in git.stats(base, head)
    ]


def introducing(git, candidate: Candidate) -> dict:
    from collections import Counter

    if git.parents(candidate.fix) != [candidate.parent]:
        raise Rejected("fix_parents")
    sites = fix_sites(git, candidate.fix, candidate.parent, global_ok=candidate.family == "config_secrets")
    reasons = Counter()

    def record(method, base, head, path, name):
        resolved = site_at(git, head, path, name)
        if resolved is None:
            return None
        return {
            "kind": "vulnerability",
            "base": base,
            "head": head,
            "method": method,
            "family": candidate.family,
            "function": name,
            "path": path,
            "function_lines": list(resolved[1][1:]),
            "files": change_files(git, base, head),
            "post_cutoff": candidate.post_cutoff,
            "advisory": candidate.advisory,
            "bias": BIAS[method],
            "fallback_reasons": dict(reasons),
        }

    for site in sites:
        revision, path, line = candidate.parent, site["path"], site["line"]
        for _ in range(6):  # initial blame plus at most five walk-back steps
            blamed, blamed_path, blamed_line = git.blame(revision, path, line)
            parents = git.parents(blamed)
            if len(parents) != 1:
                reasons["merge_or_root"] += 1
                break
            base = parents[0]
            head_site = site_at(git, blamed, blamed_path, site["function"])
            if head_site is None:
                reasons["unresolved_function"] += 1
                break
            parent_text = git.blob(base, blamed_path)
            if parent_text is not None and site["function"] != "<global>":
                matching = [span for span in functions(blamed_path, parent_text) if span[0] == site["function"]]
                if len(matching) > 1:
                    reasons["ambiguous_parent"] += 1
                    break
            old_site = site_at(git, base, blamed_path, site["function"])
            occurrences = []
            if old_site:
                text, (_, start, end) = old_site
                occurrences = [
                    i for i, value in enumerate(text.splitlines(), 1) if start <= i <= end and normalized(value) == normalized(site["text"])
                ]
            if occurrences:
                reasons["text_present"] += 1
                revision, path, line = base, blamed_path, occurrences[0]
                continue
            stats = git.stats(base, blamed)
            if len(stats) > 50 or sum(a + d for _, a, d in stats) > 2000:
                reasons["size_cap"] += 1
                break
            if not version_bracket(git, candidate, blamed):
                reasons["version_bracket"] += 1
                break
            result = record("introducing", base, blamed, blamed_path, site["function"])
            if result:
                return result
        else:
            reasons["walkback_limit"] += 1
    for site in sites:
        # Numeric function extent implements log -L for all five languages, including
        # languages for which Git has no built-in :function: driver.
        _, start, end = site["span"]
        history = git.run("log", "--format=%H", "--no-patch", f"-L{start},{end}:{site['path']}", candidate.parent).splitlines()
        if not history:
            continue
        latest = history[0]
        parents = git.parents(latest)
        if len(parents) != 1:
            continue
        result = record("last_touch", parents[0], candidate.parent, site["path"], site["function"])
        if result:
            return result
    raise Rejected("no_range")


SECURITY = re.compile(r"secur|cve|ghsa|vuln|inject|xss|csrf|ssrf|exploit|sanitiz|escap", re.I)
DEPENDENCY = re.compile(r"\bbump\b|\bupgrade .* from\b", re.I)
MANIFESTS = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
}


def generated_path(path: str) -> bool:
    return bool({"vendor", "node_modules", "dist"} & set(Path(path).parts)) or path.endswith(".min.js")


def manifest(path: str) -> bool:
    name = Path(path).name
    return name in MANIFESTS or name.endswith(".lock") or bool(re.fullmatch(r"requirements[^/]*\.txt", name))


def ordinary_rejection(row: dict, fixes: set[str], known_functions: set[tuple[str, str]]) -> str | None:
    if len(row["parents"]) != 1:
        return "merge_or_root"
    if row["head"] in fixes:
        return "advisory_fix"
    if SECURITY.search(row["message"]):
        return "security"
    if re.search(r"^Revert|This reverts commit", row["message"], re.I | re.M):
        return "revert"
    if re.search(r"dependabot|renovate|\[bot\]", row["author"], re.I) or DEPENDENCY.search(row["message"]):
        return "dependency"
    files = row["files"]
    if files and all(manifest(f["path"]) for f in files):
        return "manifest_only"
    source = [f for f in files if Path(f["path"]).suffix in LANGUAGES and not manifest(f["path"])]
    if not source:
        return "no_source"
    if all(f["generated"] or generated_path(f["path"]) for f in source):
        return "generated"
    if any((f["path"], name) in known_functions for f in files for name in f["functions"]):
        return "vulnerable_function"
    if any((f["path"], "<global>") in known_functions for f in files):
        return "vulnerable_function"
    if sum(f["added"] + f["removed"] for f in source) > 1000:
        return "size_cap"
    return None


def generated(git, revision: str, path: str, text: str) -> bool:
    import fnmatch

    if generated_path(path):
        return True
    header = "\n".join(text.splitlines()[:20])
    if re.search(r"(?im)^\s*(?:#|//|/\*|\*|<!--).*?(?:@generated|auto.?generated|generated\s+(?:by|file|code)|do not edit)", header):
        return True
    result = False
    parts = Path(path).parts
    for index in range(len(parts)):
        directory = "/".join(parts[:index])
        attributes = git.blob(revision, (directory + "/" if directory else "") + ".gitattributes") or ""
        relative = "/".join(parts[index:])
        for line in attributes.splitlines():
            tokens = line.split()
            if not tokens or tokens[0].startswith("#"):
                continue
            pattern = tokens[0].lstrip("/")
            target = relative if "/" in pattern else Path(relative).name
            if fnmatch.fnmatchcase(target, pattern):
                for token in tokens[1:]:
                    if token in {"linguist-generated", "linguist-generated=true"}:
                        result = True
                    elif token in {"-linguist-generated", "!linguist-generated", "linguist-generated=false"}:
                        result = False
    return result


def ordinary_history(git, head: str) -> list[dict]:
    raw = git.run("log", "--first-parent", "--format=%H%x00%P%x00%ct%x00%an%x00%B%x1e", head)
    rows = []
    for entry in raw.split("\x1e"):
        if not entry.strip():
            continue
        fields = entry.strip().split("\x00")
        if len(fields) != 5 or not SHA.fullmatch(fields[0]):
            raise InstrumentFailure("invalid_history")
        sha, parents, timestamp, author, message = fields
        row = {"head": sha, "parents": parents.split(), "timestamp": int(timestamp), "author": author, "message": message, "files": []}
        rows.append(row)
        if len(row["parents"]) != 1:
            continue
        base = row["parents"][0]
        for path, added, removed in git.stats(base, sha):
            hunks = git.hunks(base, sha, path)
            info = {
                "path": path,
                "added": added,
                "removed": removed,
                "head_lines": [[max(1, n), max(1, n + max(c, 1) - 1)] for _, _, n, c in hunks],
                "functions": [],
                "generated": False,
            }
            if Path(path).suffix in LANGUAGES:
                # Inspect both sides: deleting a vulnerable function is still touching it.
                for revision, side in ((base, 0), (sha, 2)):
                    text = git.blob(revision, path)
                    if text is None:
                        continue
                    spans = functions(path, text)
                    for hunk in hunks:
                        start, count = hunk[side : side + 2]
                        for name, lo, hi in spans:
                            if max(1, start) <= hi and start + max(count, 1) - 1 >= lo:
                                info["functions"].append(name)
                    info["generated"] |= generated(git, revision, path, text)
            row["files"].append(info)
    return rows


def draw_ordinary(rows: list[dict], fixes: set[str], known_functions: set[tuple[str, str]], *, seed: int) -> tuple[list[dict], dict]:
    import random
    from collections import Counter, defaultdict

    counts = Counter()
    eligible = []
    for row in rows:
        reason = ordinary_rejection(row, fixes, known_functions)
        counts[reason or "eligible"] += 1
        if reason is None:
            eligible.append(row)
    if len(eligible) < 40:
        failure = Rejected("ordinary_floor")
        failure.counts = dict(counts)
        raise failure
    earliest, latest = min(r["timestamp"] for r in rows), max(r["timestamp"] for r in rows)
    cells = defaultdict(list)
    for row in eligible:
        third = min(2, 3 * (row["timestamp"] - earliest) // max(1, latest - earliest + 1))
        size = sum(f["added"] + f["removed"] for f in row["files"] if Path(f["path"]).suffix in LANGUAGES and not manifest(f["path"]))
        bucket = 0 if size <= 10 else 1 if size <= 50 else 2 if size <= 200 else 3
        cells[third, bucket].append(row)
    if {t for t, _ in cells} != {0, 1, 2}:
        failure = Rejected("time_thirds")
        failure.counts = dict(counts)
        raise failure
    # Largest-deficit rounding with the mandatory minimum of one per time third.
    # No cell can receive more draws than it has eligible commits.
    allocation = Counter()
    targets = {cell: 12 * len(items) / len(eligible) for cell, items in cells.items()}
    for third in range(3):
        cell = max(sorted(c for c in cells if c[0] == third), key=lambda c: targets[c])
        allocation[cell] = 1
    while sum(allocation.values()) < 12:
        cell = max(sorted(c for c in cells if allocation[c] < len(cells[c])), key=lambda c: targets[c] - allocation[c])
        allocation[cell] += 1
    rng = random.Random(seed)
    drawn = []
    for cell in sorted(cells):
        for row in rng.sample(sorted(cells[cell], key=lambda r: r["head"]), allocation[cell]):
            drawn.append(
                {
                    "kind": "ordinary",
                    "base": row["parents"][0],
                    "head": row["head"],
                    "method": "first_parent",
                    "time_third": cell[0],
                    "size_bucket": cell[1],
                    "files": [{"path": f["path"], "head_lines": f["head_lines"]} for f in row["files"]],
                }
            )
    return drawn, dict(counts)
