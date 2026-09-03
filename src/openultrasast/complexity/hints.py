from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from ..preprocess import FileTarget
from .signals import _is_test_filename

if TYPE_CHECKING:
    from .map import Hotspot

GAP_NO_ADJACENT_TEST = "no_adjacent_test"
GAP_NO_FUNCTION_REFERENCE = "no_function_reference"
GAP_NO_FUZZ_ENTRY = "no_fuzz_entry"
GAP_COVERED = "covered"
GAPS = frozenset({GAP_NO_ADJACENT_TEST, GAP_NO_FUNCTION_REFERENCE, GAP_NO_FUZZ_ENTRY, GAP_COVERED})

KIND_UNIT = "unit"
KIND_PROPERTY = "property"
KIND_SANITIZER = "sanitizer"
KIND_HTTP_CONTRACT = "http-contract"
KIND_FUZZ_HARNESS = "fuzz-harness"
TEST_KINDS = frozenset({KIND_UNIT, KIND_PROPERTY, KIND_SANITIZER, KIND_HTTP_CONTRACT, KIND_FUZZ_HARNESS})

_MEMORY_UNSAFE_LANGUAGES = frozenset({"c", "cpp"})


@dataclass(frozen=True)
class TestHint:
    path: str
    function_name: str | None
    gap: str  # no_adjacent_test | no_function_reference | no_fuzz_entry | covered
    test_kind: str | None
    reason: str
    __test__ = False

    def __post_init__(self) -> None:
        if self.gap not in GAPS:
            raise ValueError(f"unknown test gap: {self.gap}")
        if self.test_kind is not None and self.test_kind not in TEST_KINDS:
            raise ValueError(f"unknown test kind: {self.test_kind}")
        if self.gap == GAP_COVERED:
            if self.test_kind is not None:
                raise ValueError("covered gap must omit test_kind")
        elif self.test_kind is None:
            raise ValueError(f"{self.gap} gap requires a test_kind")


def attach_test_hints(
    hotspots: Sequence[Hotspot],
    targets: Sequence[FileTarget] = (),
    *,
    repo_files: Iterable[str] = (),
    sources: Mapping[str, str] | None = None,
) -> tuple[Hotspot, ...]:
    targets_by_path = {target.path: target for target in targets}
    repo_paths = {str(path).replace("\\", "/") for path in repo_files}
    repo_root = _repo_root(targets)
    test_files = tuple(path for path in repo_paths if _is_test_filename(PurePosixPath(path).name))
    advised: list[Hotspot] = []
    for hotspot in hotspots:
        target = targets_by_path.get(hotspot.path)
        hint = advise_test_hint(
            path=hotspot.path,
            function_name=hotspot.function_name,
            has_adjacent_test=bool(hotspot.signals.get("has_adjacent_test")),
            language=_language(target, hotspot.path),
            tags=_tags(target, hotspot.signals),
            has_fuzz_entry_point=_has_fuzz_harness(target, hotspot.path, sources, repo_root),
            function_referenced=_function_referenced(hotspot.function_name, test_files, sources, repo_root),
        )
        advised.append(replace(hotspot, test_hint=hint))
    return tuple(advised)


def advise_test_hint(
    *,
    path: str,
    function_name: str | None,
    has_adjacent_test: bool,
    language: str,
    tags: Sequence[str],
    has_fuzz_entry_point: bool,
    function_referenced: bool,
) -> TestHint:
    tag_set = tuple(tags)
    if _needs_fuzz_or_sanitizer(language, tag_set) and not has_fuzz_entry_point:
        gap, test_kind = GAP_NO_FUZZ_ENTRY, (KIND_FUZZ_HARNESS if "parser" in tag_set else KIND_SANITIZER)
    elif not has_adjacent_test:
        gap, test_kind = GAP_NO_ADJACENT_TEST, _kind_for_surface(tag_set)
    elif function_name and not function_referenced:
        gap, test_kind = GAP_NO_FUNCTION_REFERENCE, _kind_for_surface(tag_set)
    else:
        gap, test_kind = GAP_COVERED, None
    return TestHint(
        path=path,
        function_name=function_name,
        gap=gap,
        test_kind=test_kind,
        reason=_reason(
            gap,
            test_kind,
            path=path,
            function_name=function_name,
            language=language,
            tags=tag_set,
            has_adjacent_test=has_adjacent_test,
        ),
    )


def _needs_fuzz_or_sanitizer(language: str, tags: Sequence[str]) -> bool:
    if language not in _MEMORY_UNSAFE_LANGUAGES:
        return False
    return "parser" in tags or "memory_unsafe" in tags


def _kind_for_surface(tags: Sequence[str]) -> str:
    if "network_entry" in tags:
        return KIND_HTTP_CONTRACT
    if "parser" in tags or "deserialization" in tags:
        return KIND_PROPERTY
    return KIND_UNIT


def _reason(
    gap: str,
    test_kind: str | None,
    *,
    path: str,
    function_name: str | None,
    language: str,
    tags: Sequence[str],
    has_adjacent_test: bool,
) -> str:
    identity = f"{path}::{function_name}" if function_name else path
    tag_text = ",".join(tags) or "none"
    if gap == GAP_COVERED:
        return f"covering tests already exist for {identity}; has_adjacent_test=true."
    if gap == GAP_NO_FUZZ_ENTRY:
        return f"{language} tags={tag_text} surface {identity} has no sanitizer or fuzz harness; recommend {test_kind}."
    if gap == GAP_NO_FUNCTION_REFERENCE:
        return f"adjacent tests do not reference {function_name}; recommend {test_kind}."
    return f"no adjacent test file for {identity}; has_adjacent_test={str(has_adjacent_test).lower()}; recommend {test_kind}."


def _language(target: FileTarget | None, path: str) -> str:
    if target is not None:
        return target.language
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".c", ".h"}:
        return "c"
    if suffix in {".cc", ".cpp", ".cxx", ".hpp"}:
        return "cpp"
    return "unknown"


def _tags(target: FileTarget | None, signals: Mapping[str, float | int | bool | str]) -> tuple[str, ...]:
    if target is not None:
        return tuple(target.tags)
    raw = signals.get("tags", "")
    if not isinstance(raw, str) or not raw:
        return ()
    return tuple(tag for tag in raw.split(",") if tag)


def _has_fuzz_harness(
    target: FileTarget | None,
    path: str,
    sources: Mapping[str, str] | None,
    repo_root: Path | None,
) -> bool:
    if target is not None and target.has_fuzz_entry_point:
        return True
    return "LLVMFuzzerTestOneInput" in _lookup_source(path, sources, repo_root)


def _function_referenced(
    function_name: str | None,
    test_files: Sequence[str],
    sources: Mapping[str, str] | None,
    repo_root: Path | None,
) -> bool:
    if not function_name:
        return True
    pattern = re.compile(rf"\b{re.escape(function_name)}\b")
    return any(pattern.search(_lookup_source(path, sources, repo_root)) for path in test_files)


def _lookup_source(path: str, sources: Mapping[str, str] | None, repo_root: Path | None) -> str:
    normalized = path.replace("\\", "/")
    if sources:
        if normalized in sources:
            return sources[normalized]
        if path in sources:
            return sources[path]
    if repo_root is None:
        return ""
    candidate = repo_root / normalized
    if not candidate.is_file():
        return ""
    try:
        return candidate.read_text(errors="ignore")
    except OSError:
        return ""


def _repo_root(targets: Sequence[FileTarget]) -> Path | None:
    for target in targets:
        absolute = Path(target.absolute_path).as_posix()
        relative = target.path.replace("\\", "/")
        if not relative or not absolute.endswith(relative):
            continue
        root = Path(absolute[: -len(relative)].rstrip("/"))
        if root.exists():
            return root
    return None
