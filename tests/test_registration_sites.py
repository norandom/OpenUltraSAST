"""Registration-site strategy tests (task 11.2).

The generic call-site registration adapter resolves handlers registered at
call sites through the same-file stable symbols and reports unresolved
registrations as coverage. Vocabulary is data supplied to the strategy; the
module itself names no target.
"""

from __future__ import annotations

import inspect

from openultrasast.mapping.registration_sites import RegistrationSiteStrategy
from openultrasast.mapping.registry import register, registry_entries
from openultrasast.preprocess import FileTarget

PATH = "src/Main.java"

JAVA_EXACT = """class Handler {
    void handle() {
    }

    void respond() {
    }
}

class Registry {
    void install() {
        addHandler(new Handler());
    }
}
"""

JAVA_UNRESOLVED = """class Registry {
    void install() {
        addHandler(new Elsewhere());
    }
}
"""


def _target(path: str = PATH, text: str = JAVA_EXACT) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language="java",
        loc=max(len(text.splitlines()), 1),
        tags=[],
        has_fuzz_entry_point=False,
    )


def _strategy(vocabulary: tuple[str, ...] = ("addHandler",)) -> RegistrationSiteStrategy:
    return RegistrationSiteStrategy(
        identifier="test-registration",
        languages=("java",),
        vocabulary=vocabulary,
    )


def test_registered_handler_methods_become_entries() -> None:
    entries = _strategy().recognize(_target(), JAVA_EXACT)
    by_function = {entry.function_name: entry for entry in entries}
    assert set(by_function) == {"handle", "respond"}
    entry = by_function["handle"]
    assert entry.path == PATH
    assert entry.kind == "route"
    assert entry.function_name == "handle"
    assert entry.access_level == "unknown"
    assert entry.access_evidence == [
        f"registration site {PATH}:11",
        "registered handler Handler",
    ]
    assert entry.registered_by == "addHandler"


def test_unresolved_registration_produces_no_entry_but_coverage() -> None:
    strategy = _strategy()
    assert strategy.recognize(_target(text=JAVA_UNRESOLVED), JAVA_UNRESOLVED) == []
    assert strategy.registration_coverage(_target(text=JAVA_UNRESOLVED), JAVA_UNRESOLVED) == {"registration_unresolved": 1}


def test_exact_registration_reports_zero_unresolved() -> None:
    assert _strategy().registration_coverage(_target(), JAVA_EXACT) == {}


def test_empty_vocabulary_matches_nothing() -> None:
    strategy = _strategy(vocabulary=())
    assert strategy.recognize(_target(), JAVA_EXACT) == []
    assert strategy.registration_coverage(_target(), JAVA_EXACT) == {}


def test_multiple_entries_are_deterministic() -> None:
    strategy = _strategy()
    first = strategy.recognize(_target(), JAVA_EXACT)
    second = strategy.recognize(_target(), JAVA_EXACT)
    assert first == second
    assert [entry.function_name for entry in first] == sorted(
        entry.function_name or "" for entry in first
    )


def test_registry_dispatch_stamps_strategy_provenance() -> None:
    strategy = _strategy()
    register(strategy)
    stamped = registry_entries(_target(), JAVA_EXACT)
    fixture_entries = [entry for entry in stamped if entry.provenance == "strategy:test-registration"]
    assert {entry.function_name for entry in fixture_entries} == {"handle", "respond"}


def test_module_names_no_targets() -> None:
    from openultrasast.mapping import registration_sites

    source = inspect.getsource(registration_sites).lower()
    for name in (
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
        assert name not in source
