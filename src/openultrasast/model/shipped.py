"""What the project itself says it ships (contributor-scan Req 4.2, 8.1).

libpng's first repository scan spent its expensive analysis on the wrong two thirds of the tree. Every one
of its twenty-five entry-point regions was a ``main()``, twenty-three of them under ``contrib/`` -- the
example programs and test tools shipped beside the library -- and those regions produced the fifty
interprocedural taint requests that dominated a 243-second query phase. A library has no entry points, so
entry-point-driven analysis had nothing to anchor to except its examples.

The fix is not a list of directory names invented here. A project already declares what it ships, in its own
build files, and that declaration is evidence in the repository rather than a convention someone assumed:

    Makefile.am      ``lib_LTLIBRARIES``/``bin_PROGRAMS`` name what is INSTALLED, and each target's
                     ``<target>_SOURCES`` names its files. ``check_PROGRAMS`` and ``noinst_PROGRAMS`` are
                     declared by automake as not installed -- that is the project saying "these are our
                     tests and internal tools", which is exactly the distinction wanted here.
    CMakeLists.txt   ``add_library(png ...)``, ``target_sources(png PRIVATE ...)``

Two rules keep this honest:

* **Silence is not exclusion.** A project that declares nothing gets ``None`` back and nothing changes. No
  repository is penalised for not using a build system this module can read.
* **Not shipped is not unscanned.** A file outside the declaration is still analysed; it is ranked below
  everything shipped and does not receive the interprocedural treatment. A contributor editing a test must
  still get an answer about it.
"""

from __future__ import annotations

import re
from pathlib import Path

# `libpng16_la_SOURCES = ...`, `foo_SOURCES += ...`. The value continues while lines end in a backslash.
_AUTOMAKE_SOURCES = re.compile(r"^\s*(?P<target>\w[\w@.]*)_SOURCES\s*\+?=(?P<value>.*)$")
# Which targets automake INSTALLS. `check_` and `noinst_` are declared not-installed and are skipped.
_AUTOMAKE_INSTALLED = re.compile(r"^\s*(?:bin|sbin|lib|pkglib|libexec)_(?:PROGRAMS|LTLIBRARIES|LIBRARIES)\s*\+?=(?P<value>.*)$")
_AT_SUBSTITUTION = re.compile(r"@[^@]*@")
# `add_library(png SHARED a.c b.c)` and `target_sources(png PRIVATE a.c)`.
_CMAKE_SOURCES = re.compile(r"\b(?:add_library|target_sources)\s*\((?P<value>[^)]*)\)", re.IGNORECASE | re.DOTALL)
_CMAKE_KEYWORDS = frozenset({"static", "shared", "module", "interface", "object", "public", "private", "excludefromall"})

_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".py", ".js", ".ts", ".java"})
_MANIFESTS = ("Makefile.am", "CMakeLists.txt")


def declared_sources(root: Path) -> frozenset[str] | None:
    """Repository-relative paths the build files declare, or ``None`` when the project declares nothing.

    Paths are resolved against the manifest's own directory, because a nested ``Makefile.am`` names its
    sources relative to itself.
    """
    found: set[str] = set()
    seen_manifest = False
    for name in _MANIFESTS:
        for manifest in sorted(root.rglob(name)):
            if not manifest.is_file():
                continue
            seen_manifest = True
            try:
                text = manifest.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            base = manifest.parent
            for token in _tokens(name, text):
                path = (base / token).resolve()
                try:
                    found.add(str(path.relative_to(root.resolve())))
                except ValueError:  # a declaration pointing outside the tree
                    continue
    if not seen_manifest:
        return None
    return frozenset(found)


def _tokens(manifest: str, text: str) -> list[str]:
    if manifest == "Makefile.am":
        return _automake_tokens(text)
    return _cmake_tokens(text)


def _automake_tokens(text: str) -> list[str]:
    """Sources of INSTALLED targets only.

    Taking every ``_SOURCES`` would defeat the purpose: libpng's `check_PROGRAMS` are pngstest, pngvalid and
    the rest of contrib/libtests, and they declare their sources the same way the library does.
    """
    lines = text.splitlines()
    installed: set[str] = set()
    for index in range(len(lines)):
        match = _AUTOMAKE_INSTALLED.match(lines[index])
        if match is not None:
            installed.update(_targets(_continued(lines, index)[0]))

    out: list[str] = []
    index = 0
    while index < len(lines):
        match = _AUTOMAKE_SOURCES.match(lines[index])
        if match is None:
            index += 1
            continue
        value, index = _continued(lines, index)
        value = value.split("=", 1)[1] if "=" in value else value
        if _normalise(match.group("target")) in installed:
            out.extend(_files(value))
        index += 1
    return out


def _continued(lines: list[str], index: int) -> tuple[str, int]:
    """One logical line, following automake's backslash continuations, and where it ended."""
    value = lines[index]
    while value.rstrip().endswith("\\") and index + 1 < len(lines):
        index += 1
        value = value.rstrip().removesuffix("\\") + " " + lines[index]
    return value, index


def _targets(line: str) -> set[str]:
    """The target names on an installed-targets line, normalised the way a `_SOURCES` prefix appears."""
    value = line.split("=", 1)[1] if "=" in line else line
    out = set()
    for raw in value.replace("\\", " ").split():
        # `libpng16.la` declares `libpng16_la_SOURCES`; a plain program name is used as-is.
        out.add(_normalise(raw.replace(".", "_").removesuffix("_la") + "_la" if raw.endswith(".la") else raw))
    return out


def _normalise(name: str) -> str:
    """`libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la` and `libpng16_la` must compare equal."""
    return _AT_SUBSTITUTION.sub("", name).replace(".", "_")


def _cmake_tokens(text: str) -> list[str]:
    out: list[str] = []
    for match in _CMAKE_SOURCES.finditer(text):
        for token in _files(match.group("value")):
            if token.lower() not in _CMAKE_KEYWORDS:
                out.append(token)
    return out


def _files(value: str) -> list[str]:
    out = []
    for raw in value.replace("\\", " ").split():
        token = raw.strip().strip("\"'")
        # `$(wildcard ...)` and `@PNGLIB_MAJOR@` expand at build time and cannot be resolved here.
        if not token or "$" in token or "@" in token or "*" in token:
            continue
        if Path(token).suffix.lower() in _SOURCE_SUFFIXES:
            out.append(token)
    return out


__all__ = ["declared_sources"]
