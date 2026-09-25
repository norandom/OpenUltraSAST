from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

IGNORED_DIRS = {".git", ".hg", ".svn", ".openultrasast", "__pycache__", "node_modules", ".venv", "venv"}

LANGUAGE_BY_EXTENSION = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",  # ES modules and CommonJS modules are JavaScript; without them the file has no target at all
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".groovy": "groovy",
    ".tpl": "groovy",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".sol": "solidity",
}

MEMORY_UNSAFE_LANGUAGES = {"c", "cpp"}


@dataclass(frozen=True)
class RepoSnapshot:
    root: str
    commit: str | None
    file_count: int
    languages: dict[str, int]


@dataclass(frozen=True)
class FileTarget:
    path: str
    absolute_path: str
    language: str
    loc: int
    tags: list[str]
    has_fuzz_entry_point: bool
    static_hints: list[dict[str, object]] = field(default_factory=list)
    reachability_hints: list[dict[str, object]] = field(default_factory=list)


def preprocess_repository(
    root: Path,
    output_path: Path | None = None,
    static_hints: list[object] | None = None,
) -> tuple[RepoSnapshot, list[FileTarget]]:
    resolved = root.resolve()
    files = enumerate_source_files(resolved)
    targets = [build_file_target(resolved, path) for path in files]
    if static_hints:
        from .mapping import attach_static_hints

        targets = attach_static_hints(targets, static_hints)  # type: ignore[arg-type]
    languages: dict[str, int] = {}
    for target in targets:
        languages[target.language] = languages.get(target.language, 0) + 1

    snapshot = RepoSnapshot(
        root=str(resolved),
        commit=_git_commit(resolved),
        file_count=len(targets),
        languages=dict(sorted(languages.items())),
    )

    if output_path is not None:
        write_preprocess_artifact(snapshot, targets, output_path)

    return snapshot, targets


def write_preprocess_artifact(snapshot: RepoSnapshot, targets: list[FileTarget], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"snapshot": asdict(snapshot), "file_targets": [asdict(target) for target in targets]}
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def enumerate_source_files(root: Path) -> list[Path]:
    patterns = _load_ignore_patterns(root)
    tracked = _tracked_files(root) if patterns else None
    paths: list[Path] = []
    for path in root.rglob("*"):
        if (
            path.is_symlink()
            or not path.is_file()
            or _has_ignored_dir(root, path)
            or _is_ignored(root, path, patterns, tracked)
            or _is_vendored(root, path)
        ):
            continue
        if detect_language(path) != "unknown":
            paths.append(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def build_file_target(root: Path, path: Path) -> FileTarget:
    language = detect_language(path)
    text = _read_text(path)
    tags = detect_tags(path.relative_to(root).as_posix(), language, text)
    return FileTarget(
        path=path.relative_to(root).as_posix(),
        absolute_path=str(path),
        language=language,
        loc=count_loc(text),
        tags=tags,
        has_fuzz_entry_point="LLVMFuzzerTestOneInput" in text,
        static_hints=[],
        reachability_hints=[],
    )


def detect_language(path: Path) -> str:
    language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
    if language is not None:
        return language
    first_line = _read_first_line(path)
    if first_line.startswith("#!") and "python" in first_line:
        return "python"
    if first_line.startswith("#!") and "node" in first_line:
        return "javascript"
    return "unknown"


def count_loc(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def detect_tags(relative_path: str, language: str, text: str) -> list[str]:
    haystack = f"{relative_path}\n{text}".lower()
    tags: set[str] = set()
    if language in MEMORY_UNSAFE_LANGUAGES:
        tags.add("memory_unsafe")
    if any(token in haystack for token in ("parse", "parser", "decode", "lexer")):
        tags.add("parser")
    if any(token in haystack for token in ("crypto", "cipher", "hash", "hmac", "rsa", "ecdsa", "encrypt", "decrypt")):
        tags.add("crypto")
    if any(token in haystack for token in ("auth", "login", "permission", "jwt", "session")):
        tags.add("auth_boundary")
    if any(token in haystack for token in ("deserialize", "pickle", "yaml.load", "json.parse", "unmarshal")):
        tags.add("deserialization")
    if any(token in haystack for token in ("exec(", "system(", "popen", "subprocess", "fork(", "spawn")):
        tags.add("syscall_entry")
    if any(token in haystack for token in ("socket", "listen(", "accept(", "http", "route", "endpoint")):
        tags.add("network_entry")
    if any(token in haystack for token in ("open(", "readfile", "writefile", "filepath", "pathlib", "fs.")):
        tags.add("filesystem_entry")
    if "llvmfuzzertestoneinput" in haystack:
        tags.add("fuzzable")
    return sorted(tags)


# One `.gitignore` rule: whether it re-includes (`!`), whether it names directories only (trailing `/`), and
# the path it matches as a regular expression over the repository-relative POSIX path.
_IgnoreRule = tuple[bool, bool, "re.Pattern[str]"]


def _glob_regex(body: str) -> str:
    """Git's wildmatch for one pattern body: `*` and `?` stay inside a path component, `**` crosses them."""
    out, i = "", 0
    while i < len(body):
        if body.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif body.startswith("/**", i) and i + 3 == len(body):
            out, i = out + "/.*", i + 3
        elif body.startswith("**", i):
            out, i = out + ".*", i + 2
        elif body[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif body[i] == "?":
            out, i = out + "[^/]", i + 1
        elif body[i] == "[" and "]" in body[i + 1 :]:
            end = body.index("]", i + 1)
            members = body[i + 1 : end]
            members = "^" + members[1:] if members.startswith("!") else members
            out, i = out + "[" + members.replace("\\", "\\\\") + "]", end + 1
        elif body[i] == "\\" and i + 1 < len(body):
            out, i = out + re.escape(body[i + 1]), i + 2
        else:
            out, i = out + re.escape(body[i]), i + 1
    return out


def _load_ignore_patterns(root: Path) -> list[_IgnoreRule]:
    """The root `.gitignore`, with git's semantics.

    The first version dropped every `!` line and matched with `fnmatch`, whose `*` crosses `/`. YesWiki's
    `tools/*` followed by `!tools/bazar` therefore removed all 583 of its tool PHP files -- the vulnerable one
    among them -- and the scan read 243 files of 803, completed every question it had, and reported the
    answer as clean.
    """
    ignore_file = root / ".gitignore"
    if not ignore_file.exists():
        return []
    rules: list[_IgnoreRule] = []
    for line in ignore_file.read_text(errors="ignore").splitlines():
        text = line.rstrip()
        if not text or text.startswith("#"):
            continue
        negate = text.startswith("!")
        text = text[1:] if negate else text.removeprefix("\\")
        directory_only = text.endswith("/")
        text = text.rstrip("/")
        if not text:
            continue
        anchored = "/" in text
        body = _glob_regex(text.lstrip("/"))
        rules.append((negate, directory_only, re.compile("^" + ("" if anchored else "(?:.*/)?") + body + "$")))
    return rules


def _ignored_by(rules: list[_IgnoreRule], relative: str, is_dir: bool) -> bool:
    verdict = False
    for negate, directory_only, pattern in rules:
        if (is_dir or not directory_only) and pattern.match(relative):
            verdict = not negate
    return verdict


def _tracked_files(root: Path) -> set[str] | None:
    """What git tracks under `root`, or None where `root` is not a work tree (a `git archive` export)."""
    try:
        done = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True, timeout=60)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return {name for name in done.stdout.decode(errors="replace").split("\0") if name}


def _has_ignored_dir(root: Path, path: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in IGNORED_DIRS for part in relative_parts[:-1])


def _is_vendored(root: Path, path: Path) -> bool:
    """A tree the `[[layout]]` facts call somebody else's code. Out of the targets entirely: a bundled
    library is a separate unit, analysed as one or not at all (contributor-scan 5.13; the decision is the
    maintainer's and lives in the fact table, not here)."""
    from .model.layout import is_vendored

    return is_vendored(path.relative_to(root).as_posix())


def _is_ignored(root: Path, path: Path, rules: list[_IgnoreRule], tracked: set[str] | None = None) -> bool:
    relative = path.relative_to(root).as_posix()
    # Git never ignores a tracked file; `.gitignore` is about what is NOT in the repository.
    if not rules or (tracked is not None and relative in tracked):
        return False
    parts = relative.split("/")
    # Nothing under an ignored directory can be re-included, which is git's rule too.
    for depth in range(1, len(parts)):
        if _ignored_by(rules, "/".join(parts[:depth]), is_dir=True):
            return True
    return _ignored_by(rules, relative, is_dir=False)


def _read_text(path: Path) -> str:
    return path.read_text(errors="ignore")


def _read_first_line(path: Path) -> str:
    try:
        with path.open("r", errors="ignore") as handle:
            return handle.readline().strip().lower()
    except OSError:
        return ""


def _git_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None
