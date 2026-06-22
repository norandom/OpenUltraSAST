"""HarnessX optional-extra packaging + capability guard (Phase 3 task 5.2)."""

import re
import tomllib
from pathlib import Path

import pytest

from openultrasast.harness_ext import (
    HARNESSX_EXTRA,
    SUPPORTED_PROVIDERS,
    HarnessXUnavailableError,
    build_provider,
    has_harnessx,
    require_harnessx,
)

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


def test_importing_openultrasast_does_not_import_harnessx(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    # The big modules (cli, harness_ext) must not eagerly import the heavy extra.
    assert_cold_of_harnessx("import openultrasast.cli\nimport openultrasast.harness_ext")


def test_has_harnessx_probes_without_importing(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    assert isinstance(has_harnessx(), bool)
    # find_spec must not import the module.
    assert_cold_of_harnessx("from openultrasast.harness_ext import has_harnessx\nassert isinstance(has_harnessx(), bool)")


def test_require_harnessx_raises_with_install_guidance_when_absent() -> None:
    if has_harnessx():
        pytest.skip("HarnessX extra is installed in this environment")
    with pytest.raises(HarnessXUnavailableError, match=re.escape(HARNESSX_EXTRA)):
        require_harnessx()


def test_build_provider_rejects_unknown_provider_before_importing(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    # Name is validated before any import, so this fails loudly even without the extra.
    with pytest.raises(ValueError, match="unknown HarnessX provider"):
        build_provider("gpt-4o", "bogus")
    assert_cold_of_harnessx(
        "from openultrasast.harness_ext import build_provider\n"
        "try:\n    build_provider('gpt-4o', 'bogus')\n"
        "except ValueError:\n    pass\n"
        "else:\n    raise SystemExit('expected ValueError')\n"
    )


def test_supported_providers_cover_anthropic_and_openai() -> None:
    assert {"anthropic", "openai"} <= set(SUPPORTED_PROVIDERS)


@pytest.mark.parametrize(("provider", "class_name"), [("anthropic", "AnthropicProvider"), ("openai", "OpenAIProvider")])
def test_build_provider_constructs_selected_provider(provider: str, class_name: str) -> None:
    if not has_harnessx():
        pytest.skip("HarnessX extra not installed in this environment")
    built = build_provider("test-model", provider)
    assert type(built).__name__ == class_name
