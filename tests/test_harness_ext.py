"""HarnessX optional-extra packaging + capability guard (Phase 3 task 5.2)."""

import re
import sys
import tomllib
from pathlib import Path

import pytest

from openultrasast.harness_ext import HARNESSX_EXTRA, HarnessXUnavailableError, has_harnessx, require_harnessx

PYPROJECT = tomllib.loads(Path("pyproject.toml").read_text())


def test_core_dependencies_stay_empty() -> None:
    assert PYPROJECT["project"]["dependencies"] == []


def test_harnessx_is_a_sha_pinned_optional_extra() -> None:
    extras = PYPROJECT["project"]["optional-dependencies"]["harnessx"]
    assert len(extras) == 1
    assert re.fullmatch(
        r"harnessx @ git\+https://github\.com/Darwin-Agent/HarnessX\.git@[0-9a-f]{40}",
        extras[0],
    ), extras[0]


def test_importing_openultrasast_does_not_import_harnessx() -> None:
    # The big modules (cli, harness_ext) must not eagerly import the heavy extra.
    import openultrasast.cli  # noqa: F401
    import openultrasast.harness_ext  # noqa: F401

    assert "harnessx" not in sys.modules


def test_has_harnessx_probes_without_importing() -> None:
    available = has_harnessx()
    assert isinstance(available, bool)
    assert "harnessx" not in sys.modules  # find_spec must not import the module


def test_require_harnessx_raises_with_install_guidance_when_absent() -> None:
    if has_harnessx():
        pytest.skip("HarnessX extra is installed in this environment")
    with pytest.raises(HarnessXUnavailableError, match=re.escape(HARNESSX_EXTRA)):
        require_harnessx()
