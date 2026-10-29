"""Entry-recognition strategy registry (task 11.1, Reqs 1.1, 1.5, 1.7)."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Generator
from pathlib import Path

import pytest

from openultrasast.mapping import EntryPointRecord
from openultrasast.mapping.registry import (
    EntryRecogniser,
    register,
    registered_strategies,
    registry_entries,
)
from openultrasast.preprocess import FileTarget, detect_language


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Each test registers its own strategies into the shared module registry."""
    from openultrasast.mapping import registry

    saved_strategies = dict(registry._STRATEGIES)
    registry._STRATEGIES.clear()
    stapler_module = importlib.import_module("openultrasast.mapping.stapler")
    importlib.reload(stapler_module)
    yield
    registry._STRATEGIES.clear()
    registry._STRATEGIES.update(saved_strategies)


class FixtureRouteStrategy:
    """A recogniser defined by the test, named nowhere in engine code."""

    identifier = "test-fixture"
    languages: tuple[str, ...] = ("java",)

    def recognize(self, target: FileTarget, text: str) -> list[EntryPointRecord]:
        marker = "fixture marker line 3"
        if marker not in text:
            return []
        return [
            EntryPointRecord(
                path=target.path,
                line=3,
                end_line=3,
                function_name="fixtureHandler",
                name="fixtureHandler",
                kind="route",
                access_level="unknown",
                trust_boundary="external",
                access_evidence=[marker],
                conditions=[],
                provenance="",
                rationale="fixture strategy",
            )
        ]


class SelfProvenanceStrategy:
    identifier = "test-self-provenance"
    languages: tuple[str, ...] = ("java",)

    def recognize(self, target: FileTarget, text: str) -> list[EntryPointRecord]:
        return [
            EntryPointRecord(
                path=target.path,
                line=1,
                end_line=1,
                function_name="selfProvenanceHandler",
                name="selfProvenanceHandler",
                kind="route",
                access_level="unknown",
                trust_boundary="external",
                access_evidence=["self provenance"],
                conditions=[],
                provenance="strategy-own:declaration",
                rationale="fixture",
            )
        ]


def _target(path: str, language: str) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language=language,
        loc=8,
        tags=[],
        has_fuzz_entry_point=False,
    )


JAVA_TEXT = "package p;\nclass H {\n  // fixture marker line 3\n  void fixtureHandler() {}\n}\n"


def test_registered_strategy_is_listed_for_its_language() -> None:
    register(FixtureRouteStrategy())
    strategies = registered_strategies("java")
    identifiers = [strategy.identifier for strategy in strategies]
    assert "test-fixture" in identifiers  # built-in strategies (e.g. stapler) may coexist
    assert registered_strategies("php") == ()


def test_registry_entries_stamp_strategy_identifier_and_keep_evidence() -> None:
    register(FixtureRouteStrategy())
    entries = registry_entries(_target("src/H.java", "java"), JAVA_TEXT)
    assert len(entries) == 1
    assert entries[0].provenance == "strategy:test-fixture"
    assert entries[0].access_evidence == ["fixture marker line 3"]
    assert entries[0].function_name == "fixtureHandler"


def test_strategy_set_provenance_is_preserved() -> None:
    register(SelfProvenanceStrategy())
    entries = registry_entries(_target("src/H.java", "java"), "class A {}")
    assert entries[0].provenance == "strategy-own:declaration"


def test_re_registration_replaces_the_strategy() -> None:
    register(FixtureRouteStrategy())
    register(FixtureRouteStrategy())
    identifiers = [s.identifier for s in registered_strategies("java")]
    assert identifiers.count("test-fixture") == 1  # replaced, never duplicated


def test_registry_entries_are_deterministic() -> None:
    register(FixtureRouteStrategy())
    first = registry_entries(_target("src/H.java", "java"), JAVA_TEXT)
    second = registry_entries(_target("src/H.java", "java"), JAVA_TEXT)
    assert first == second


def test_registry_module_names_no_targets() -> None:
    from openultrasast.mapping import registry

    source = inspect.getsource(registry)
    for target_name in (
        "symfony",
        "laravel",
        "tornado",
        "wordpress",
        "stapler",
        "jetty",
        "django",
        "flask",
        "rails",
        "spring",
        "express",
    ):
        assert target_name not in source.lower()


def test_dispatch_runs_registered_strategies_alongside_legacy_blocks(tmp_path: Path) -> None:
    from openultrasast.mapping import analyze_entry_points

    (tmp_path / "H.java").write_text(
        "package p;\n"
        "import hudson.model.Descriptor;\n"
        "class H extends Descriptor<Thing> {\n"
        "  // fixture marker line 3\n"
        "  public void doTest(org.kohsuke.stapler.StaplerRequest req) {}\n"
        "}\n",
        encoding="utf-8",
    )
    targets = [
        FileTarget(
            path="H.java",
            absolute_path=str(tmp_path / "H.java"),
            language=detect_language(tmp_path / "H.java"),
            loc=6,
            tags=[],
            has_fuzz_entry_point=False,
        )
    ]
    register(FixtureRouteStrategy())
    entries = analyze_entry_points(tmp_path, targets, include_manifests=False)
    names = {entry.function_name for entry in entries}
    assert "doTest" in names  # legacy Stapler block still runs
    assert "fixtureHandler" in names  # registry strategy contributed
    fixture = next(entry for entry in entries if entry.function_name == "fixtureHandler")
    assert fixture.provenance == "strategy:test-fixture"
    stapler = next(entry for entry in entries if entry.function_name == "doTest")
    assert stapler.provenance != "strategy:test-fixture"


def test_entry_recogniser_protocol_is_runtime_implemented() -> None:
    strategy = FixtureRouteStrategy()
    assert isinstance(strategy, EntryRecogniser)
