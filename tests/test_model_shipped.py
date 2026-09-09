"""contributor-scan 2.10: what a project declares it ships, read from its own build files."""

from __future__ import annotations

from pathlib import Path

MAKEFILE_AM = """\
check_PROGRAMS= pngtest pngvalid
bin_PROGRAMS= pngfix
lib_LTLIBRARIES=libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@.la

libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_SOURCES = png.c pngerror.c\\
\tpngget.c png.h

pngtest_SOURCES = contrib/libtests/pngtest.c
pngvalid_SOURCES = contrib/libtests/pngvalid.c
pngfix_SOURCES = contrib/tools/pngfix.c
"""


def test_only_installed_targets_count_as_shipped(tmp_path: Path) -> None:
    """`check_PROGRAMS` declare their sources exactly as the library does, and are automake's own word for
    "not installed". Taking every `_SOURCES` would call libpng's whole test suite shipped code."""
    from openultrasast.model.shipped import declared_sources

    (tmp_path / "Makefile.am").write_text(MAKEFILE_AM)
    for name in ("png.c", "pngerror.c", "pngget.c", "png.h"):
        (tmp_path / name).touch()

    declared = declared_sources(tmp_path)

    assert declared is not None
    assert {"png.c", "pngerror.c", "pngget.c", "png.h"} <= declared, "the library, across a continuation"
    assert "contrib/tools/pngfix.c" in declared, "bin_PROGRAMS is installed"
    assert "contrib/libtests/pngtest.c" not in declared, "check_PROGRAMS is not"
    assert "contrib/libtests/pngvalid.c" not in declared


def test_a_repository_with_no_readable_build_files_declares_nothing(tmp_path: Path) -> None:
    """None, not an empty set: the difference between "declares nothing" and "declares no sources"."""
    from openultrasast.model.shipped import declared_sources

    (tmp_path / "app.py").write_text("x = 1\n")

    assert declared_sources(tmp_path) is None


def test_cmake_targets_are_read_and_their_keywords_are_not_files(tmp_path: Path) -> None:
    from openultrasast.model.shipped import declared_sources

    (tmp_path / "CMakeLists.txt").write_text("add_library(png SHARED png.c png.h)\ntarget_sources(png PRIVATE extra.c)\n")

    declared = declared_sources(tmp_path)

    assert declared == frozenset({"png.c", "png.h", "extra.c"})


def test_build_time_substitutions_are_skipped(tmp_path: Path) -> None:
    """`$(wildcard ...)` and `@VERSION@` expand at build time; guessing at them would invent files."""
    from openultrasast.model.shipped import declared_sources

    (tmp_path / "CMakeLists.txt").write_text("add_library(x STATIC ${GENERATED}.c real.c @SUBST@.c *.c)\n")

    assert declared_sources(tmp_path) == frozenset({"real.c"})
