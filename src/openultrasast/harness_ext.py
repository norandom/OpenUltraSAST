"""Capability guard for the optional HarnessX agentic plane.

HarnessX is an optional extra (``pip install 'openultrasast[harnessx]'``). The core
install is zero-dependency, so nothing here imports ``harnessx`` at module load:
:func:`has_harnessx` only probes importability via ``find_spec`` and
:func:`require_harnessx` performs the import lazily, on demand. Every HarnessX-backed
code path (Phase 3+: build_sast, the hunter sub-harness, the llm-judge verifier, the
MetaAgent.evolve loop) routes through this seam.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from harnessx.core.harness import HarnessConfig

HARNESSX_EXTRA = "openultrasast[harnessx]"

# HarnessX providers OpenUltraSAST can drive for the hunter / llm-judge stages.
# Each reads its own standard API-key env var (ANTHROPIC_API_KEY / OPENAI_API_KEY).
SUPPORTED_PROVIDERS = ("anthropic", "openai", "litellm")


class HarnessXUnavailableError(RuntimeError):
    """Raised when a HarnessX-backed capability is requested but the extra is absent."""


def has_harnessx() -> bool:
    """Return True if the HarnessX extra is importable, without importing it."""
    return importlib.util.find_spec("harnessx") is not None


def require_harnessx() -> ModuleType:
    """Lazily import and return the ``harnessx`` module, or raise with install guidance."""
    if not has_harnessx():
        raise HarnessXUnavailableError(f"HarnessX is not installed. Install the optional agentic extra: pip install '{HARNESSX_EXTRA}'")
    return importlib.import_module("harnessx")


def build_provider(model: str, provider: str = "anthropic") -> Any:
    """Build a HarnessX LLM provider for ``model`` (lazy, capability-guarded).

    The single place that knows HarnessX provider class names. The provider name is
    validated before any import so an unknown choice fails loudly even when the extra
    is absent; each provider reads its own standard API-key env var. Raises
    :class:`ValueError` on an unknown provider and :class:`HarnessXUnavailableError`
    when the extra is not installed.
    """
    key = provider.lower()
    if key not in SUPPORTED_PROVIDERS:
        raise ValueError(f"unknown HarnessX provider {provider!r}; choose one of {SUPPORTED_PROVIDERS}")
    require_harnessx()
    if key == "anthropic":
        from harnessx.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(model=model)
    if key == "openai":
        from harnessx.providers.openai_provider import OpenAIProvider

        return OpenAIProvider(model=model)
    from harnessx.providers.litellm_provider import LiteLLMProvider

    return LiteLLMProvider(model=model)


def build_sast(*, max_cost_usd: float = 2.0, token_threshold: int = 120_000) -> HarnessConfig:
    """Compose the SAST hunter HarnessConfig (behaviour pipeline, model-free).

    The single, strictly-localized HarnessX composition site (mirrors DocuHarnessX
    ``make_docgen``): every ``harnessx`` import is inside this function so importing
    this module never touches the optional extra. Raises :class:`HarnessXUnavailableError`
    when the extra is absent. The per-task step budget is enforced on the task at run
    time, not composed here.
    """
    require_harnessx()
    from harnessx.bundles.context import make_context
    from harnessx.bundles.control import make_control
    from harnessx.bundles.tools import make_tools
    from harnessx.core.builder import HarnessBuilder
    from harnessx.processors.context.strategies.system_prompt.default import DefaultSystemPromptBuilder

    builder = (
        HarnessBuilder()
        | make_context(system_builder=DefaultSystemPromptBuilder())
        | make_tools(skill_loading=False)
        | make_control(
            include_reliability=True,
            include_budget=True,
            token_threshold=token_threshold,
            max_cost_usd=max_cost_usd,
        )
    )
    return builder.build()
