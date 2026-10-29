"""Entry-recognition strategy registry (task 11.1, Reqs 1.1, 1.5, 1.7).

Target knowledge enters entry recognition through registered strategies; the
registry stamps every returned record with the strategy identifier unless the
strategy recorded its own provenance. The registry itself names no target.
"""

from dataclasses import replace
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .legacy import EntryPointRecord

__all__ = ["EntryRecogniser", "register", "registry_entries", "registered_strategies"]


@runtime_checkable
class EntryRecogniser(Protocol):
    """A target-specific entry-recognition strategy registered from data or a strategy module."""

    identifier: str
    languages: tuple[str, ...]

    def recognize(self, target: Any, text: str) -> list["EntryPointRecord"]:
        """Return the entry points this strategy recognises in one file."""
        ...


_STRATEGIES: dict[str, EntryRecogniser] = {}


def register(recogniser: EntryRecogniser) -> None:
    """Register a strategy; re-registering an identifier replaces the earlier strategy."""
    _STRATEGIES[recogniser.identifier] = recogniser


def registered_strategies(language: str) -> tuple[EntryRecogniser, ...]:
    """Return the strategies that recognise entries for one language, ordered by identifier."""
    return tuple(
        strategy for strategy in sorted(_STRATEGIES.values(), key=lambda strategy: strategy.identifier) if language in strategy.languages
    )


def registry_entries(target: Any, text: str) -> list["EntryPointRecord"]:
    """Run every matching strategy and stamp its identifier onto each returned record."""
    records: list[EntryPointRecord] = []
    for strategy in registered_strategies(getattr(target, "language", "")):
        for record in strategy.recognize(target, text):
            if record.provenance == "":
                record = replace(record, provenance=f"strategy:{strategy.identifier}")
            records.append(record)
    return records
