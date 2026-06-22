"""HarnessX hunter sub-harness: guarding, findings parsing, construction smoke (task 6.1)."""

import pytest

from openultrasast.harness_ext import HarnessXUnavailableError, build_sast, has_harnessx
from openultrasast.hunter_harness import HxScanOrchestrator, _extract_findings


def test_module_import_does_not_pull_harnessx(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    assert_cold_of_harnessx("import openultrasast.hunter_harness")


def test_extract_findings_parses_json_array_and_tolerates_garbage() -> None:
    text = 'Here are the findings:\n[{"line": 9, "title": "SQLi", "cwe": "CWE-89", "rationale": "concat"}]\nDone.'
    items = _extract_findings(text)
    assert items == [{"line": 9, "title": "SQLi", "cwe": "CWE-89", "rationale": "concat"}]
    assert _extract_findings("no findings here") == []
    assert _extract_findings("[not, valid, json]") == []


@pytest.mark.skipif(has_harnessx(), reason="exercises the extra-absent guard")
def test_build_sast_raises_without_extra() -> None:
    with pytest.raises(HarnessXUnavailableError):
        build_sast()


@pytest.mark.skipif(has_harnessx(), reason="exercises the extra-absent guard")
def test_orchestrator_construction_raises_without_extra() -> None:
    with pytest.raises(HarnessXUnavailableError):
        HxScanOrchestrator(provider_model="claude-sonnet-4-6")


@pytest.mark.skipif(not has_harnessx(), reason="construction smoke; requires the harnessx extra")
def test_build_sast_returns_harness_config_offline() -> None:
    from harnessx.core.harness import HarnessConfig

    assert isinstance(build_sast(), HarnessConfig)


@pytest.mark.skipif(not has_harnessx(), reason="construction smoke; requires the harnessx extra")
def test_orchestrator_builds_agent_offline() -> None:
    # Constructs the model + harness without any LLM call (provider client is lazy).
    agent = HxScanOrchestrator(provider_model="claude-sonnet-4-6")._build_agent()
    assert type(agent).__name__ == "Harness"
