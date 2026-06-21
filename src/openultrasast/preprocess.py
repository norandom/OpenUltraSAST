from __future__ import annotations

import fnmatch
import json
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
    paths: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or _has_ignored_dir(root, path) or _is_ignored(root, path, patterns):
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


def _load_ignore_patterns(root: Path) -> list[str]:
    ignore_file = root / ".gitignore"
    if not ignore_file.exists():
        return []
    patterns: list[str] = []
    for line in ignore_file.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("!"):
            patterns.append(stripped.rstrip("/"))
    return patterns


def _has_ignored_dir(root: Path, path: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in IGNORED_DIRS for part in relative_parts[:-1])


def _is_ignored(root: Path, path: Path, patterns: list[str]) -> bool:
    relative = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in patterns)


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
