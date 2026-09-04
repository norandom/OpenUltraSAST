"""Source, sink, and sanitizer facts as versioned data next to the ruleset."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_FACTS_DIR = Path(__file__).resolve().parents[1] / "ruleset" / "semantic"

_LANGUAGE_ALIASES = {
    "c": "c",
    "cpp": "c",
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
}


class FactLoadError(ValueError):
    """Raised when semantic fact files are missing or invalid."""

    def __init__(self, message: str, reason: str = "facts_unavailable") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class SourceFact:
    id: str
    patterns: tuple[str, ...]
    language: str


@dataclass(frozen=True)
class SinkFact:
    id: str
    cwe: str
    calls: tuple[str, ...]
    rule_ids: tuple[str, ...]
    language: str
    weak_literals: tuple[str, ...] = ()
    format_arg: int | None = None


@dataclass(frozen=True)
class SanitizerFact:
    id: str
    calls: tuple[str, ...]
    language: str
    parameterized: bool = False
    literal_format_arg: int | None = None


@dataclass(frozen=True)
class SemanticFacts:
    version: str
    sources: tuple[SourceFact, ...]
    sinks: tuple[SinkFact, ...]
    sanitizers: tuple[SanitizerFact, ...]

    def for_language(self, language: str) -> SemanticFacts:
        key = _LANGUAGE_ALIASES.get(language, language)
        return SemanticFacts(
            version=self.version,
            sources=tuple(item for item in self.sources if item.language == key),
            sinks=tuple(item for item in self.sinks if item.language == key),
            sanitizers=tuple(item for item in self.sanitizers if item.language == key),
        )


def load_facts(directory: Path | None = None) -> SemanticFacts:
    root = directory if directory is not None else DEFAULT_FACTS_DIR
    if not root.is_dir():
        raise FactLoadError(f"semantic fact directory missing: {root}")
    sources: list[SourceFact] = []
    sinks: list[SinkFact] = []
    sanitizers: list[SanitizerFact] = []
    versions: list[str] = []
    found = False
    for path in sorted(root.glob("*.toml")):
        found = True
        try:
            payload = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise FactLoadError(f"invalid semantic fact file {path}: {exc}") from exc
        language = str(payload.get("language") or path.stem)
        versions.append(str(payload.get("version", "1")))
        sources.extend(_sources(payload.get("source"), language, path))
        sinks.extend(_sinks(payload.get("sink"), language, path))
        sanitizers.extend(_sanitizers(payload.get("sanitizer"), language, path))
    if not found:
        raise FactLoadError(f"no semantic fact files in {root}")
    return SemanticFacts(version=versions[0] if versions else "1", sources=tuple(sources), sinks=tuple(sinks), sanitizers=tuple(sanitizers))


def _items(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise FactLoadError("fact tables must be arrays")
    rows: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            raise FactLoadError("each fact row must be a table")
        rows.append(item)
    return rows


def _strings(value: object, field: str, path: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise FactLoadError(f"{path} has invalid {field} list")
    return tuple(str(item) for item in value)


def _sources(value: object, language: str, path: Path) -> list[SourceFact]:
    rows: list[SourceFact] = []
    for item in _items(value):
        ident = item.get("id")
        if not isinstance(ident, str) or not ident:
            raise FactLoadError(f"{path} source is missing id")
        patterns = _strings(item.get("patterns"), "patterns", path)
        if not patterns:
            raise FactLoadError(f"{path} source {ident} has no patterns")
        rows.append(SourceFact(id=ident, patterns=patterns, language=language))
    return rows


def _sinks(value: object, language: str, path: Path) -> list[SinkFact]:
    rows: list[SinkFact] = []
    for item in _items(value):
        ident = item.get("id")
        cwe = item.get("cwe")
        if not isinstance(ident, str) or not ident:
            raise FactLoadError(f"{path} sink is missing id")
        if not isinstance(cwe, str) or not cwe.startswith("CWE-"):
            raise FactLoadError(f"{path} sink {ident} must bind a CWE id")
        calls = _strings(item.get("calls"), "calls", path)
        if not calls:
            raise FactLoadError(f"{path} sink {ident} has no calls")
        format_arg = item.get("format_arg")
        if format_arg is not None and (not isinstance(format_arg, int) or isinstance(format_arg, bool)):
            raise FactLoadError(f"{path} sink {ident} has invalid format_arg")
        rows.append(
            SinkFact(
                id=ident,
                cwe=cwe,
                calls=calls,
                rule_ids=_strings(item.get("rule_ids"), "rule_ids", path),
                language=language,
                weak_literals=_strings(item.get("weak_literals"), "weak_literals", path),
                format_arg=format_arg if isinstance(format_arg, int) else None,
            )
        )
    return rows


def _sanitizers(value: object, language: str, path: Path) -> list[SanitizerFact]:
    rows: list[SanitizerFact] = []
    for item in _items(value):
        ident = item.get("id")
        if not isinstance(ident, str) or not ident:
            raise FactLoadError(f"{path} sanitizer is missing id")
        calls = _strings(item.get("calls"), "calls", path)
        if not calls:
            raise FactLoadError(f"{path} sanitizer {ident} has no calls")
        literal = item.get("literal_format_arg")
        if literal is not None and (not isinstance(literal, int) or isinstance(literal, bool)):
            raise FactLoadError(f"{path} sanitizer {ident} has invalid literal_format_arg")
        rows.append(
            SanitizerFact(
                id=ident,
                calls=calls,
                language=language,
                parameterized=bool(item.get("parameterized", False)),
                literal_format_arg=literal if isinstance(literal, int) else None,
            )
        )
    return rows
