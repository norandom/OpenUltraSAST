"""Tests for the migrated Stapler entry-recognition strategy (task 11.6).

The migration moves the Stapler family out of inline legacy dispatch into a
registered strategy. The invariant pinned here (and by the untouched legacy
Stapler tests in tests/test_mapping_frameworks.py) is byte-equal entries on
the old fixtures: same fields, same provenance, same evidence.
"""

import importlib
from collections.abc import Generator
from pathlib import Path

import pytest

from openultrasast.mapping import analyze_entry_points, legacy, registry
from openultrasast.preprocess import FileTarget

JAVA_STAPLER = """package hudson.slaves;

import hudson.model.Descriptor;
import org.kohsuke.stapler.StaplerRequest;

public class FixtureDescriptor extends Descriptor<Thing> {
    public Object doTest(StaplerRequest req) {
        return null;
    }

    private Object helperNoEntry() {
        return null;
    }
}
"""

JAVA_UNPROTECTED = """package hudson.model;

import org.kohsuke.stapler.StaplerRequest;

public class OpenActions implements UnprotectedRootAction {
    public Object doExecute(StaplerRequest req) {
        return null;
    }
}
"""


@pytest.fixture(autouse=True)
def _fresh_stapler_strategy() -> Generator[None, None, None]:
    saved_strategies = dict(registry._STRATEGIES)
    registry._STRATEGIES.clear()
    stapler_module = importlib.import_module("openultrasast.mapping.stapler")
    importlib.reload(stapler_module)
    yield
    registry._STRATEGIES.clear()
    registry._STRATEGIES.update(saved_strategies)


def _target(path: str, text: str) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language="java",
        loc=len(text.splitlines()),
        tags=[],
        has_fuzz_entry_point=False,
    )


def test_stapler_strategy_is_registered_for_java() -> None:
    identifiers = tuple(strategy.identifier for strategy in registry.registered_strategies("java"))
    assert "stapler" in identifiers


def test_migrated_entries_match_the_legacy_shape(tmp_path: Path) -> None:
    (tmp_path / "Fixture.java").write_text(JAVA_STAPLER, encoding="utf-8")
    entries = analyze_entry_points(tmp_path, [_target("Fixture.java", JAVA_STAPLER)], include_manifests=False)
    stapler_entries = [entry for entry in entries if entry.function_name == "doTest"]
    assert len(stapler_entries) == 1
    entry = stapler_entries[0]
    assert entry.kind == "route"
    assert entry.access_level == "unknown"
    assert entry.trust_boundary == "http_request"
    assert entry.provenance == "entrypoint:route:unknown"
    assert entry.access_declared is False
    assert any("Stapler public do method" in line for line in entry.access_evidence)


def test_inline_stapler_matching_is_removed_from_legacy() -> None:
    assert not hasattr(legacy, "_stapler_entries")


def test_jetty_family_stays_inline_in_legacy() -> None:
    assert hasattr(legacy, "_jetty_entries")


def test_migrated_entries_are_deterministic(tmp_path: Path) -> None:
    (tmp_path / "Fixture.java").write_text(JAVA_STAPLER, encoding="utf-8")
    first = analyze_entry_points(tmp_path, [_target("Fixture.java", JAVA_STAPLER)], include_manifests=False)
    second = analyze_entry_points(tmp_path, [_target("Fixture.java", JAVA_STAPLER)], include_manifests=False)
    assert first == second


def test_unprotected_root_action_keeps_public_access() -> None:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "Open.java").write_text(JAVA_UNPROTECTED, encoding="utf-8")
        entries = analyze_entry_points(root, [_target("Open.java", JAVA_UNPROTECTED)], include_manifests=False)
    execute_entries = [entry for entry in entries if entry.function_name == "doExecute"]
    assert len(execute_entries) == 1
    entry = execute_entries[0]
    assert entry.access_level == "public"
    assert entry.access_declared is True
    assert entry.provenance == "entrypoint:route:public"
